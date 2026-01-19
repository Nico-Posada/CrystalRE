import ida_name
import ida_idp
import idc
import ida_typeinf
import ida_ida

from .log import log, warning
from .symbols import split_true_commas
from typing import Callable, Optional

# Scattered return registers for x64 (in order)
SRET_REGS = ["rax", "rdx", "rcx", "r8"]

# All normal types
_TYPE_CONVERSIONS = {
    ("Bool", "bool"),
    ("Int8", "__int8"),
    ("UInt8", "unsigned __int8"),
    ("Int16", "__int16"),
    ("UInt16", "unsigned __int16"),
    ("Int32", "__int32"),
    ("UInt32", "unsigned __int32"),
    ("Int64", "__int64"),
    ("UInt64", "unsigned __int64"),
    ("Int128", "__int128"),
    ("UInt128", "unsigned __int128"),
    ("Float32", "float"),
    ("Float64", "double"),

    ("char32_t", "unsigned __int32"), # weird one lol
    ("Char", "char32_t"),

    ("Symbol", "unsigned int"),
    ("Void", "void")
}

CR_BASE_TYPES = [v for (v, _) in _TYPE_CONVERSIONS if v != "char32_t"]
NO_POINTER_TYPES = ["Slice", "Union", "Tuple", "NamedTuple", "Range", "Proc"]

def _type_exists(name: str):
    return ida_typeinf.tinfo_t().get_named_type(None, name)

def is_numeric_type(type_name: str):
    return type_name in CR_BASE_TYPES and type_name != "String"

def should_type_be_ptr(type_name: str):
    return (type_name == "String" or type_name not in CR_BASE_TYPES) and all(not type_name.startswith(s) for s in NO_POINTER_TYPES)
    # return (type_name == "String" or type_name not in CR_BASE_TYPES) # and all(not type_name.startswith(s) for s in NO_POINTER_TYPES)

_TYPE_HANDLERS: list[tuple[tuple[str, str], Callable[[str], Optional[ida_typeinf.tinfo_t]]]] = []
def _register_handler(*signatures: str):
    global _TYPE_HANDLERS
    assert all("..." in signature for signature in signatures)
    def wrapper(func):
        nonlocal signatures
        _TYPE_HANDLERS.extend((
            tuple(signature.split("...")),
            func
        ) for signature in signatures)
        return staticmethod(func)
    return wrapper

# NOTE: sret registers are rax, rdx, rcx, rsi
# NOTE: structs passed by value are annoying to deal with, so im just disabling them until I can get a somewhat stable version going
class BuiltinTypeHandler:
    @staticmethod
    def name_to_tif(type_name: str) -> Optional[ida_typeinf.tinfo_t]:
        global _TYPE_HANDLERS
        
        # edge case for `&Proc`, it should just be treated as `Proc`
        if type_name.startswith("&Proc"):
            type_name = type_name[1:]
        
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(None, type_name):
            if should_type_be_ptr(type_name):
                tif.create_ptr(tif)
            return tif
        
        for (lhs, rhs), handler in _TYPE_HANDLERS:
            if type_name.startswith(lhs) and type_name.endswith(rhs):
                return handler(type_name[len(lhs):-len(rhs)])
        
        return None
    
    @_register_handler("Pointer(...)")
    def handle_pointer(type_name: str):
        tif = BuiltinTypeHandler.name_to_tif(type_name)
        if tif is not None:
            tif.create_ptr(tif)
            return tif
        else:
            # default to _UNKNOWN *
            return ida_typeinf.tinfo_t().get_stock(ida_typeinf.STI_PUNKNOWN)
    
    # @_register_handler("StaticArray(...)")
    def handle_staticarray(type_name: str):
        return None
    
    @_register_handler("Array(...)")
    def handle_array(type_name: str):
        """
        struct Array(xxx) {
            UInt32 type_id;
            Int32 size;
            Int32 capacity;
            Int32 offset_to_buffer;
            xxx* buffer;
        };
        """

        buffer_tif = BuiltinTypeHandler.name_to_tif(type_name)
        if buffer_tif is None:
            # set it to void as a fallback if it's an unknown type
            buffer_tif = ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)

        if not buffer_tif.create_ptr(buffer_tif):
            warning(f"Failed to create ptr out of tif for {type_name!r}")
            return None

        udt = ida_typeinf.udt_type_data_t()

        # add hardcoded fields
        fields = [
            ("type_id", "UInt32"),
            ("size", "Int32"),
            ("capacity", "Int32"),
            ("offset_to_buffer", "Int32"),
        ]

        for field_name, field_type in fields:
            udt_member = ida_typeinf.udt_member_t()
            udt_member.name = field_name
            udt_member.type = ida_typeinf.tinfo_t()
            udt_member.type.get_named_type(None, field_type)
            udt.push_back(udt_member)

        # add buffer field (xxx*)
        udt_member = ida_typeinf.udt_member_t()
        udt_member.name = "buffer"
        udt_member.type = buffer_tif
        udt.push_back(udt_member)

        # create tinfo_t from udt
        tif = ida_typeinf.tinfo_t()
        if not tif.create_udt(udt, ida_typeinf.BTF_STRUCT):
            warning(f"Failed to create Array struct for {type_name!r}")
            return None

        # set named type so it's not anonymous
        array_type_name = f"Array({type_name})"
        tif.set_named_type(None, array_type_name)

        # make it a pointer (Arrays are passed by reference)
        if not tif.create_ptr(tif):
            warning(f"Failed to create ptr to Array struct for {type_name!r}")
            return None

        return tif
    
    @_register_handler("Slice(...)")
    def handle_slice(type_name: str):
        """
        struct Slice(xxx) {
            Int32 size;
            Bool read_only;
            xxx* pointer;
        };
        """

        pointer_tif = BuiltinTypeHandler.name_to_tif(type_name)
        if pointer_tif is None:
            # set it to void as a fallback if it's an unknown type
            pointer_tif = ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)

        if not pointer_tif.create_ptr(pointer_tif):
            warning(f"Failed to create ptr out of tif for {type_name!r}")
            return None

        udt = ida_typeinf.udt_type_data_t()

        # add hardcoded fields
        fields = [
            ("size", "Int32"),
            ("read_only", "Bool"),
        ]

        for field_name, field_type in fields:
            udt_member = ida_typeinf.udt_member_t()
            udt_member.name = field_name
            udt_member.type = ida_typeinf.tinfo_t()
            udt_member.type.get_named_type(None, field_type)
            udt.push_back(udt_member)

        # add pointer field (xxx*)
        udt_member = ida_typeinf.udt_member_t()
        udt_member.name = "pointer"
        udt_member.type = pointer_tif
        udt.push_back(udt_member)

        # create tinfo_t from udt
        tif = ida_typeinf.tinfo_t()
        if not tif.create_udt(udt, ida_typeinf.BTF_STRUCT):
            warning(f"Failed to create Slice struct for {type_name!r}")
            return None

        # set named type so it's not anonymous
        slice_type_name = f"Slice({type_name})"
        tif.set_named_type(None, slice_type_name)

        # don't make it a pointer, Slices are passed by value
        return tif
    
    # @_register_handler("(...)")
    def handle_union(type_name: str):
        return None
    
    @_register_handler("Proc(...)")
    def handle_proc(type_name: str):
        """
        struct Proc(...) {
            void* function;
            void* closure;
        }
        """

        # create void* type for both fields
        void_ptr = ida_typeinf.tinfo_t().get_stock(ida_typeinf.STI_PVOID)

        udt = ida_typeinf.udt_type_data_t()

        # add function field (void*)
        udt_member = ida_typeinf.udt_member_t()
        udt_member.name = "function"
        udt_member.type = void_ptr
        udt.push_back(udt_member)

        # add closure field (void*)
        udt_member = ida_typeinf.udt_member_t()
        udt_member.name = "closure"
        udt_member.type = void_ptr
        udt.push_back(udt_member)

        # create tinfo_t from udt
        tif = ida_typeinf.tinfo_t()
        if not tif.create_udt(udt, ida_typeinf.BTF_STRUCT):
            warning(f"Failed to create Proc struct for {type_name!r}")
            return None

        # set named type so it's not anonymous
        proc_type_name = f"Proc({type_name})"
        tif.set_named_type(None, proc_type_name)

        # don't make it a pointer, Procs are passed by value (16 bytes)
        return tif

def name_to_tif(type_name: str):
    return BuiltinTypeHandler.name_to_tif(type_name)

def create_scattered_retloc(parts: list[tuple[int, int, str]]) -> ida_typeinf.argloc_t:
    """
    Create a scattered argloc from a list of (offset, size, register_name) tuples.

    Example: [(0, 4, "rax"), (4, 4, "rdx"), (8, 4, "rcx")]
    Results in: <0:rax.4, 4:rdx.4, 8:rcx.4>
    """
    scattered = ida_typeinf.scattered_aloc_t()

    for off, size, reg_name in parts:
        part = ida_typeinf.argpart_t()
        part.off = off
        part.size = size
        part.set_reg1(ida_idp.str2reg(reg_name))
        scattered.push_back(part)

    retloc = ida_typeinf.argloc_t()
    retloc.consume_scattered(scattered)
    return retloc

_RETLOC_HANDLERS: list[tuple[tuple[str, str], Callable[[str], Optional[ida_typeinf.argloc_t]]]] = []

def _register_retloc_handler(signature: str):
    """Register a handler for return locations matching a signature pattern."""
    global _RETLOC_HANDLERS
    assert "..." in signature
    def wrapper(func):
        nonlocal signature
        _RETLOC_HANDLERS.append((
            tuple(signature.split("...")),
            func
        ))
        return staticmethod(func)
    return wrapper

class BuiltinRetlocHandler:
    @staticmethod
    def name_to_retloc(type_name: str) -> Optional[ida_typeinf.argloc_t]:
        global _RETLOC_HANDLERS

        # check registered handlers first
        for (lhs, rhs), handler in _RETLOC_HANDLERS:
            if type_name.startswith(lhs) and type_name.endswith(rhs):
                if rhs:
                    return handler(type_name[len(lhs):-len(rhs)])
                else:
                    return handler(type_name[len(lhs):])

        # TODO: other checks? idk
        return None

    @_register_retloc_handler("Slice(...)")
    def handle_slice_retloc(type_name: str):
        # <0:rax.4, 4:rdx.1, 8:rcx.8>
        return create_scattered_retloc([
            (0, 4, SRET_REGS[0]),   # size
            (4, 1, SRET_REGS[1]),   # read_only
            (8, 8, SRET_REGS[2]),   # pointer
        ])

    # @_register_retloc_handler("Tuple(...)")
    @staticmethod
    def handle_tuple_retloc(type_name: str):
        return None

    # @_register_retloc_handler("NamedTuple(...)")
    @staticmethod
    def handle_namedtuple_retloc(type_name: str):
        return None

def name_to_retloc(type_name: str):
    return BuiltinRetlocHandler.name_to_retloc(type_name)

def _get_expected_tif(ida_type_name: str):
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, ida_type_name):
        return tif
    # try parsing as a type string for built-in types
    if ida_typeinf.parse_decl(tif, None, f"{ida_type_name};", ida_typeinf.PT_SIL):
        return tif
    return None

def _types_match(existing_tif: ida_typeinf.tinfo_t, expected_ida_name: str):
    expected_tif = _get_expected_tif(expected_ida_name)
    if expected_tif is None:
        return False

    return existing_tif.equals_to(expected_tif)

def apply_crystal_base_types():
    global _TYPE_CONVERSIONS
    for cr_name, ida_name in _TYPE_CONVERSIONS:
        existing_tif = ida_typeinf.tinfo_t()
        type_exists = existing_tif.get_named_type(None, cr_name)

        # NOTE: this was added because sometimes idbs load and define types before we can. A common one is `typedef int Bool;` (???)
        if type_exists:
            # check if the existing type matches what we expect
            if _types_match(existing_tif, ida_name):
                continue
            # type exists but doesn't match, so we need to replace it
            log(f"Updating mismatched type {cr_name} (was incorrect, setting to {ida_name})")

        typedef_str = f"typedef {ida_name} {cr_name};"
        tif = ida_typeinf.tinfo_t()
        if not ida_typeinf.parse_decl(tif, None, typedef_str, ida_typeinf.PT_SIL):
            warning(f"Failed to parse typedef: {typedef_str}")
            continue

        # Use NTF_REPLACE to update existing types
        flags = ida_typeinf.NTF_REPLACE if type_exists else 0
        tif.set_named_type(None, cr_name, flags)
    
    if _type_exists("String"):
        return

    # create String struct.
    # `__strlit(C,"UTF-8")` makes it so defining global strings
    # shows the `c` var as a string rather than an array
    string_struct = """\
    struct String
    {
        UInt32 type_id;
        Int32 bytesize;
        Int32 length;
        UInt8 c[] __strlit(C,"UTF-8");
    }
    """

    tif = ida_typeinf.tinfo_t(string_struct)
    tif.set_named_type(None, "String")