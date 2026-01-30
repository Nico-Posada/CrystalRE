#!/usr/bin/env python3

import sys
import io
from dataclasses import dataclass
from functools import wraps
from enum import Enum, auto

from elftools.elf.elffile import * # pip install pyelftools
import regex # pip install regex

def determine_file(filename: str):
    with open(filename, "rb") as f:
        data = f.read()
        magic = data[:4]

    if magic.startswith(b"\x7fELF"):
        file_type = 1
    elif magic.startswith(b"MZ"):
        file_type = 2
    else:
        raise Exception(f"Unknown file format for {filename}")
    
    return io.BytesIO(data), file_type

@dataclass(frozen=True, slots=True)
class CrystalSym:
    rva: int
    name: str
    type: str

# This is the internal function used to generate symbols.
# It's formatted nicely (except when its not) to extract all the details with a good regex.
r"""
def mangled_name(program, self_type)
  name = String.build do |str|
    str << '*'
    if owner = @owner
      if owner.metaclass?
        self_type.instance_type.llvm_name(str)
        if original_owner != self_type
          str << '@'
          original_owner.instance_type.llvm_name(str)
        end
        str << "::"
      elsif !owner.is_a?(Crystal::Program)
        self_type.llvm_name(str)
        if original_owner != self_type
          str << '@'
          original_owner.llvm_name(str)
        end
        str << '#'
      end
    end
    str << self.name.gsub('@', '.')
    next_def = self.next
    while next_def
      str << '\''
      next_def = next_def.next
    end
    if args.size > 0 || uses_block_arg?
      str << '<'
      if args.size > 0
        args.each_with_index do |arg, i|
          str << ", " if i > 0
          arg.type.llvm_name(str)
        end
      end
      if uses_block_arg?
        str << ", " if args.size > 0
        str << '&'
        block_arg.not_nil!.type.llvm_name(str)
      end
      str << '>'
    end
    if return_type = @type
      str << ':'
      return_type.llvm_name(str)
    end
  end
  Crystal.safe_mangling(program, name)
end
"""

def split_true_X(string: str, sep: str):
    paren_depth, cur_idx = 0, 0
    
    cur_part = ""
    parts = []
    
    while cur_idx < len(string):
        if paren_depth == 0 and string[cur_idx:cur_idx+len(sep)] == sep:
            parts.append(cur_part)
            cur_part = ""
            cur_idx += len(sep)
            continue
        
        c = string[cur_idx]
        if c == '(':
            paren_depth += 1
        elif c == ')':
            paren_depth -= 1
        
        cur_part += c
        cur_idx += 1
    
    if cur_part:
        parts.append(cur_part)
    
    return parts

def split_true_commas(string: str):
    return split_true_X(string, ", ")

def split_true_colons(string: str):
    return split_true_X(string, "::")

def parse_function(symbol_string):
    pattern = r"""
    (?(DEFINE)
        (?P<__IGNORE_PAREN>
            [^\(\)]*(?:\((?&__IGNORE_PAREN)?\))?
        )

        # You can see rules for valid symbols here (ignore quoted symbols). There's some other things like
        # var= for setters that we need to account for and the & prefix on mathematical operations.
        # https://crystal-lang.org/reference/1.16/syntax_and_semantics/literals/symbol.html
        (?<__CR_SYM>
            # Operator defs
            &?\+|&?\-|&?\*\*?|\/\/?|%|&|\||\^|>>|<<|===?|!=|<=?|>=?|<=>|\[\][\?=]?|!|~|!~|=~|`
            |
            # Freaky regex to match names that I'm going to look back on in the future and wonder how this even worked
            # (TODO: nonascii chars)
            [A-Za-z_]
            (?:
                # normal ident char or slash because symbols sometimes have filenames
                [\w/]
                |
                # a single colon (NOT double)
                :(?!$|:|(?:[^:]|::|\((?&__IGNORE_PAREN)\))*$)
                |
                # any parenthesized statement if not prefixed with a colon (which means it's a func that returns a union)
                (?<!:)\((?&__IGNORE_PAREN)\)
                |
                # an ending char (if followed by a single colon)
                [!\?=](?=:[^:])
            )*
            [\w!\?=]?
        )
    )

    # Funcs start with a *
    \*

    # Owner (optional)
    # We will parse out extra data afterwards if this exists
    (?P<self_type>[^<]+?(?:\#|::))?

    # Name (required)
    (?P<name>(?&__CR_SYM))
    
    # Next defs (optional)
    (?P<next_defs>\'+)?

    # Args (optional)
    (?:<(?P<args>.+?)>)?

    # Return type (optional)
    (?:(?<!:):(?P<return_type>(?:[^:]|\((?&__IGNORE_PAREN)\)|::)+))?
    """
    
    symbol_pattern = regex.compile(pattern, regex.VERBOSE | regex.V1)
    match = symbol_pattern.fullmatch(symbol_string)
    if match:
        result = match.groupdict()

        # Anything we don't care about is prefixed with "__"  
        result = {k: v for k, v in result.items() if not k.startswith("__")}
        
        if self_type := result.get("self_type"):
            # Extract possible metaclass and strip off the ending # or ::
            if "@" in self_type:
                self_type, metaclass = self_type.split("@", maxsplit=1)
                result["self_type"] = self_type
                result["metaclass"] = metaclass.rstrip(":#")
                result["class_method?"] = metaclass.endswith("::")
            else:
                result["self_type"] = self_type.rstrip(":#")
                result["class_method?"] = self_type.endswith("::")
            
        if result["args"]:
            result["args"] = split_true_commas(result["args"])
        
        # for good measure :)
        result["name"] = result["name"].replace(".", "@")
        
        return result

# procs are much simpler, they are named like this
"""
"~proc#{type}@#{Crystal.relative_filename(filename)}:#{location.line_number}"
"""
# so we can extract the proc signature by splitting on the rightmost @ and dropping the leading ~proc
def parse_proc(symbol_string: str):
    assert symbol_string.startswith("~proc")
    assert "@" in symbol_string
    
    symbol_string = symbol_string[5:]
    symbol_string, _, _ = symbol_string.rpartition("@")
    
    proc_num = 0
    while symbol_string[0].isdigit():
        proc_num = 10 * proc_num + int(symbol_string[0])
        symbol_string = symbol_string[1:]
    
    return symbol_string, proc_num

# Weird helper funcs to see if a type exists in a union or something, beats me
"""
"~match<#{type.llvm_name}>"
"""
def parse_match(symbol_string: str):
    assert symbol_string.startswith("~match<")
    assert symbol_string.endswith(">")
    
    # the name is fine as-is, whatever
    return symbol_string


def parse_data(data: io.BytesIO):
    elf_file = ELFFile(data)
    symbol_table = elf_file.get_section_by_name('.symtab')

    if not symbol_table:
        raise Exception("No .symtab section found in the ELF file (likely a stripped binary).")

    if not isinstance(symbol_table, SymbolTableSection):
        raise Exception("The .symtab section is not a symbol table.")

    syms = [CrystalSym(sym['st_value'], sym.name, sym['st_info']['type'])
            for sym in symbol_table.iter_symbols()]
    
    return syms

############################################################################
############################################################################

# decorator to enforce cache initialization
def requires_cache(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not SymbolCache.is_initialized():
            raise RuntimeError(f"Symbol cache not initialized. Call SymbolCache.init_cache() first before using {func.__name__}")
        return func(*args, **kwargs)
    return wrapper

class SymbolType(Enum):
    FUNCTION = auto()
    PROC = auto()
    MATCH = auto()
    OTHER = auto()

@dataclass(slots=True, frozen=True)
class ParsedSymbol:
    rva: int
    symbol_type: SymbolType
    symbol_data: dict
    orig_name: str

class SymbolCache:
    # class variables for symbol cache
    _symbols: dict[int, ParsedSymbol] | None = None
    _binary_path: str | None = None
    _initialized: bool = False

    @classmethod
    def init_cache(cls, binary_path: str) -> None:
        # parse and cache all symbols from binary
        data, file_type = determine_file(binary_path)

        if file_type == 2:
            raise Exception("Windows binaries are not yet supported. Symbol information is only in .pdb files.")

        raw_symbols = parse_data(data) # can raise an exception if the input binary is stripped
        cls._symbols = {}

        # parse each symbol and cache parsed results
        for sym in raw_symbols:
            # only process function symbols
            if sym.type != 'STT_FUNC':
                continue

            parsed_symbol = None

            # crystal functions start with *
            if sym.name.startswith("*"):
                parsed = parse_function(sym.name)
                if parsed is None:
                    continue

                func_info = {k: v for k, v in parsed.items() if v or isinstance(v, bool)}
                parsed_symbol = ParsedSymbol(
                    rva=sym.rva,
                    symbol_type=SymbolType.FUNCTION,
                    symbol_data=func_info,
                    orig_name=sym.name
                )

            # anonymous procs start with ~proc
            elif sym.name.startswith("~proc"):
                try:
                    symbol_string, proc_num = parse_proc(sym.name)
                    assert symbol_string.startswith("Proc(")
                    assert symbol_string.endswith(")")
                except (AssertionError, IndexError):
                    print(f"[!] Unable to parse symbol name for proc {sym.name!r}")
                    continue
                
                proc_args = split_true_commas(symbol_string[5:-1]) # Remove the Proc( and )
                proc_info = {
                    'symbol_string': symbol_string,
                    'proc_num': proc_num,
                    'args': proc_args[:-1],
                    'return_type': proc_args[-1],
                }

                parsed_symbol = ParsedSymbol(
                    rva=sym.rva,
                    symbol_type=SymbolType.PROC,
                    symbol_data=proc_info,
                    orig_name=sym.name
                )
            
            # funcs that see if a type id matches a hardcoded list
            elif sym.name.startswith("~match"):
                match_info = {
                    'name': parse_match(sym.name),
                    # all these match funcstake a single type_id which is a UInt32
                    'args': ['UInt32'],
                    'return_type': "Bool"
                }
                
                parsed_symbol = ParsedSymbol(
                    rva=sym.rva,
                    symbol_type=SymbolType.MATCH,
                    symbol_data=match_info,
                    orig_name=sym.name
                )
            
            # Weird helper functions, keep as-is
            elif sym.name.startswith("~") and \
                any(sym.name.endswith(suffix) for suffix in [":init", ":read", ":const_init", ":const_read"]):
                helper_info = {
                    'name': sym.name,
                    'args': [],
                    # init funcs are void, const_read/read return the object in the function name, but we don't know the type so guess Void*
                    'return_type': "Nil" if sym.name.endswith("init") else "Pointer(Void)"
                }
                
                parsed_symbol = ParsedSymbol(
                    rva=sym.rva,
                    symbol_type=SymbolType.OTHER,
                    symbol_data=helper_info,
                    orig_name=sym.name
                )
            else:
                ...
                # TODO: Maybe other types of symbols if it ever matters in the future.
                # print(f"Got an else: {sym.name}")

            # store parsed symbol if we successfully parsed it
            if parsed_symbol:
                cls._symbols[sym.rva] = parsed_symbol

        cls._binary_path = binary_path
        cls._initialized = True

    @classmethod
    def reset_cache(cls, binary_path: str | None = None) -> None:
        # reset and reparse the cache
        if binary_path is None:
            if cls._binary_path is None:
                raise RuntimeError("No binary path available. Provide a path to reset_cache().")
            binary_path = cls._binary_path

        # clear cache
        cls._symbols = None
        cls._binary_path = None
        cls._initialized = False

        # reinitialize with new/same path
        cls.init_cache(binary_path)

    @classmethod
    def is_initialized(cls) -> bool:
        return cls._initialized

    @classmethod
    @requires_cache
    def get_symbols(cls) -> dict[int, ParsedSymbol]:
        return cls._symbols

    @classmethod
    @requires_cache
    def get_binary_path(cls) -> str:
        return cls._binary_path

    @classmethod
    @requires_cache
    def get_function_symbols(cls) -> dict[int, ParsedSymbol]:
        # helper to get only function symbols (not procs)
        return {rva: sym for rva, sym in cls._symbols.items()
                if sym.symbol_type == SymbolType.FUNCTION}

    @classmethod
    @requires_cache
    def get_proc_symbols(cls) -> dict[int, ParsedSymbol]:
        # helper to get only proc symbols
        return {rva: sym for rva, sym in cls._symbols.items()
                if sym.symbol_type == SymbolType.PROC}

    @classmethod
    @requires_cache
    def find_symbol_by_address(cls, rva: int) -> ParsedSymbol | None:
        # helper to find symbol by address
        return cls._symbols.get(rva)


# can run as a standalone script too
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <crystal binary>", file=sys.stderr)
        exit(1)

    binary_path = sys.argv[1]

    # initialize symbol cache
    # may error here but I'm nothing catching anything bc im lazy
    SymbolCache.init_cache(binary_path)

    # get all parsed symbols
    symbols = SymbolCache.get_symbols()

    print(f"Found {len(symbols)} parsed symbols\n")

    # display parsed symbols
    for rva, parsed_sym in symbols.items():
        # if "match" not in parsed_sym.orig_name: continue
        # if parsed_sym.symbol_data.get("class_method?", False) and "metaclass" in parsed_sym.symbol_data:
        if "Hash" in parsed_sym.orig_name and "new" in parsed_sym.orig_name:
            print(f"RVA: {rva:#x}")
            print(f"  Type: {parsed_sym.symbol_type.name}")
            print(f"  Original: {parsed_sym.orig_name}")
            print(f"  Parsed data: {parsed_sym.symbol_data}")
            print()