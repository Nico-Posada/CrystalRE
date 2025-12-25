#!/usr/bin/env python3

import sys
import io
from dataclasses import dataclass
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

def split_true_commas(string: str):
    paren_depth, cur_idx = 0, 0
    
    cur_part = ""
    parts = []
    
    while cur_idx < len(string):
        if paren_depth == 0 and string[cur_idx:cur_idx+2] == ", ":
            parts.append(cur_part)
            cur_part = ""
            cur_idx += 2
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
                result["metaclass"] = metaclass.rstrip(":#")
                result["self_type"] = self_type
            else:
                result["self_type"] = self_type.rstrip(":#")
            
            if result["args"]:
                result["args"] = split_true_commas(result["args"]) 
        
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
        
    

def parse_data(data: io.BytesIO):
    elf_file = ELFFile(data)
    symbol_table = elf_file.get_section_by_name('.symtab')

    if not symbol_table:
        raise Exception("No .symtab section found in the ELF file.")

    if not isinstance(symbol_table, SymbolTableSection):
        raise Exception("The .symtab section is not a symbol table.")

    syms = [CrystalSym(sym['st_value'], sym.name, sym['st_info']['type'])
            for sym in symbol_table.iter_symbols()]
    
    return syms


# can run as a standalone script too
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <crystal binary>", file=sys.stderr)
        exit(1)
    
    data, file_type = determine_file(sys.argv[1])

    if file_type == 2:
        print("Symbols for windows crystal binaries are only saved in their .pdb files.\n"
              "If you do not have access to it, you cannot use this.",
              file=sys.stderr)
        exit(1)
    
    syms = parse_data(data)
    if syms is None:
        exit()

    from pprint import pp
    # pp(syms)
    for sym in syms:
        if sym.type != 'STT_FUNC':
            continue

        if sym.name.startswith("*"):
            parsed = parse_function(sym.name)
            if parsed is None:
                print("Failed to parse", sym.name)
                exit()

            fixed = {k: v for k, v in parsed.items() if v}
            print(sym.name, fixed, sep=" ||| ")
        elif sym.name.startswith("__crystal"):
            print(f"CRYSTAL_FUNC: {sym.name}", file=sys.stderr)