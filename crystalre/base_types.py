import ida_name
import ida_idp
import idc
import ida_typeinf
import ida_ida

from .log import log, warning
from .symbols import split_true_commas
from typing import Callable, Optional

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

# these are builtin "struct" types
NO_POINTER_TYPES = (
    "Slice",
    "Union",
    "Tuple",
    "NamedTuple",
    "Range",
    "Proc",
    "Atomic",
    "Hash::Entry"
)

def _type_exists(name: str):
    return ida_typeinf.tinfo_t().get_named_type(None, name)

def is_numeric_type(type_name: str):
    return type_name in CR_BASE_TYPES and type_name not in ("String", "Void")

def should_type_be_ptr(type_name: str):
    return (type_name == "String" or type_name not in CR_BASE_TYPES) and all(not type_name.startswith(s) for s in NO_POINTER_TYPES)
    # return (type_name == "String" or type_name not in CR_BASE_TYPES) # and all(not type_name.startswith(s) for s in NO_POINTER_TYPES)

def _get_expected_tif(ida_type_name: str):
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, ida_type_name):
        return tif
    # try parsing as a type string for built-in types
    if ida_typeinf.parse_decl(tif, None, f"{ida_type_name};", ida_typeinf.PT_SIL):
        return tif
    return None

def _make_member(field_name: str, field_type: str | ida_typeinf.tinfo_t):
    assert isinstance(field_type, (str, ida_typeinf.tinfo_t)), f"Got {type(field_type) = !r}"
    udt_member = ida_typeinf.udt_member_t()
    udt_member.name = field_name
    if isinstance(field_type, str):
        udt_member.type = ida_typeinf.tinfo_t()
        udt_member.type.get_named_type(None, field_type)
    else:
        udt_member.type = field_type
    return udt_member

def _udt_to_named_tif(udt: ida_typeinf.udt_type_data_t, name: str, make_ptr: bool):
    # create tinfo_t from udt
    tif = ida_typeinf.tinfo_t()
    if not tif.create_udt(udt, ida_typeinf.BTF_STRUCT):
        warning(f"Failed to create struct for {name!r}")
        return None

    # set named type so it's not anonymous
    tif.set_named_type(None, name)

    # make it a pointer if needed
    if make_ptr and not tif.create_ptr(tif):
        warning(f"Failed to create ptr for {name!r}")
        return None

    return tif

def _udt_from_fields(fields: list[tuple[str, str | ida_typeinf.tinfo_t]]):
    udt = ida_typeinf.udt_type_data_t()
    for field_name, field_type in fields:
        udt.push_back(_make_member(field_name, field_type))
    
    return udt

_TYPE_HANDLERS: list[tuple[tuple[str, str], Callable[[str], Optional[ida_typeinf.tinfo_t]]]] = []
def _register_handler(*signatures: str):
    global _TYPE_HANDLERS
    assert all("..." in signature for signature in signatures)
    def wrapper(func):
        nonlocal signatures
        _TYPE_HANDLERS.extend((
            tuple(signature.split("...", maxsplit=1)),
            func
        ) for signature in signatures)
        return staticmethod(func)
    return wrapper

class BuiltinTypeHandler:
    @staticmethod
    def name_to_tif(type_name: str, assume_ptrs: bool) -> Optional[ida_typeinf.tinfo_t]:
        global _TYPE_HANDLERS
        
        type_name = type_name.strip()
        
        # the "Set Crystal Type" UI option allows users to input data now, and people would rather
        # end types with * instead of wrapping the type in `Pointer`, so normalize the behavior
        
        # edge case for `&Proc`, it should just be treated as `Proc`
        if type_name.startswith("&Proc"):
            type_name = type_name[1:]
        
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(None, type_name):
            if assume_ptrs and should_type_be_ptr(type_name):
                tif.create_ptr(tif)
            return tif
        
        for (lhs, rhs), handler in _TYPE_HANDLERS:
            if type_name.startswith(lhs) and type_name.endswith(rhs):
                return handler(type_name[len(lhs):-len(rhs)], assume_ptrs)
        
        return None
    
    @_register_handler("Pointer(...)")
    def handle_pointer(type_name: str, assume_ptrs: bool):
        tif = BuiltinTypeHandler.name_to_tif(type_name, assume_ptrs)
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
    def handle_array(type_name: str, assume_ptrs: bool):
        """
        struct Array(xxx) {
            UInt32 type_id;
            Int32 size;
            Int32 capacity;
            Int32 offset_to_buffer;
            xxx* buffer;
        };
        """

        buffer_tif = BuiltinTypeHandler.name_to_tif(type_name, True)
        if buffer_tif is None:
            # set it to void as a fallback if it's an unknown type
            buffer_tif = ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)

        if not buffer_tif.create_ptr(buffer_tif):
            warning(f"Failed to create ptr out of tif for {type_name!r}")
            return None

        # add fields
        fields = [
            ("type_id", "UInt32"),
            ("size", "Int32"),
            ("capacity", "Int32"),
            ("offset_to_buffer", "Int32"),
            ("buffer", buffer_tif)
        ]

        udt = _udt_from_fields(fields)
        return _udt_to_named_tif(udt, f"Array({type_name})", assume_ptrs)
    
    @_register_handler("Slice(...)")
    def handle_slice(type_name: str, assume_ptrs: bool):
        """
        struct Slice(xxx) {
            Int32 size;
            Bool read_only;
            xxx* pointer;
        };
        """

        pointer_tif = BuiltinTypeHandler.name_to_tif(type_name, assume_ptrs)
        if pointer_tif is None:
            # set it to void as a fallback if it's an unknown type
            pointer_tif = ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)

        if not pointer_tif.create_ptr(pointer_tif):
            warning(f"Failed to create ptr out of tif for {type_name!r}")
            return None

        # add fields
        fields = [
            ("size", "Int32"),
            ("read_only", "Bool"),
            ("pointer", pointer_tif)
        ]

        udt = _udt_from_fields(fields)
        return _udt_to_named_tif(udt, f"Slice({type_name})", False)
    
    # @_register_handler("(...)", "Union(...)")
    def handle_union(type_name: str, assume_ptrs: bool):
        return None
    
    @_register_handler("Proc(...)")
    def handle_proc(type_name: str, assume_ptrs: bool):
        """
        struct Proc(...) {
            void* function;
            void* closure;
        }
        """

        # create void* type for both fields
        void_ptr = ida_typeinf.tinfo_t().get_stock(ida_typeinf.STI_PVOID)

        # add fields
        fields = [
            ("function", void_ptr),
            ("closure", void_ptr)
        ]

        udt = _udt_from_fields(fields)
        return _udt_to_named_tif(udt, f"Proc({type_name})", False)
    
    @_register_handler("Atomic(...)")
    def handle_atomic(type_name: str, assume_ptrs: bool):
        """
        struct Atomic(...) {
            ... value;
        }
        """

        value_tif = BuiltinTypeHandler.name_to_tif(type_name, assume_ptrs)
        if value_tif is None:
            # set it to void* as a fallback if it's an unknown type
            value_tif = ida_typeinf.tinfo_t().get_stock(ida_typeinf.STI_PVOID)

        udt = _udt_from_fields([("value", value_tif)])
        return _udt_to_named_tif(udt, f"Atomic({type_name})", False)
    
    @_register_handler("Hash::Entry(...)")
    def handle_hash_entry(type_name: str, assume_ptrs: bool):
        """
        struct Hash::Entry(K, V) {
            UInt32 hash;
            K key;
            V value;
        }
        """
        args = split_true_commas(type_name)
        if len(args) != 2:
            warning(f"Got {len(args)} args when parsing Hash::Entry({type_name})")
            return None

        key, value = args
        use_key = key != "Nil"
        use_value = value != "Nil"

        # both key and value must return tifs for us to make the type
        if use_key:
            key_tif = name_to_tif(key, True)
            if key_tif is None:
                return None
        
        if use_value:
            value_tif = name_to_tif(value, True)
            if value_tif is None:
                return None

        fields = [
            ("hash", "UInt32"),
        ]
        
        if use_key:
            fields.append(("key", key_tif))
        if use_value:
            fields.append(("value", value_tif))
        
        udt = _udt_from_fields(fields)
        return _udt_to_named_tif(udt, f"Hash::Entry({type_name})", False)
    
    @_register_handler("Hash(...)")
    def handle_hash(type_name: str, assume_ptrs: bool):
        """
        struct Hash(K, V) {
            UInt32 type_id;
            Int32 first;
            Hash::Entry(K, V) *entries;
            UInt8 *indices;
            Int32 size;
            Int32 deleted_count;
            Int8 indices_bytesize;
            UInt8 indices_size_pow2;
            Bool compare_by_identity;
            void *block_ptr;
            void *block_data;
        }
        """
        
        void_ptr = ida_typeinf.tinfo_t().get_stock(ida_typeinf.STI_PVOID)

        entries_tif = name_to_tif(f"Hash::Entry({type_name})", True)
        if entries_tif is None:
            # its safe to use void* here, this isn't that relevant for the type
            entries_tif = void_ptr
        else:
            if not entries_tif.create_ptr(entries_tif):
                warning(f"Failed to create ptr for {type_name!r}")
                return None
        
        if not (p_uint8 := name_to_tif("UInt8", False)) or \
            not p_uint8.create_ptr(p_uint8):
            warning(f"Failed to get UInt8* type")
            return None
        
        fields = [
            ("type_id", "UInt32"),
            ("first", "Int32"),
            ("entries", entries_tif),
            ("indices", p_uint8),
            ("size", "Int32"),
            ("deleted_count", "Int32"),
            ("indices_bytesize", "Int8"),
            ("indices_size_pow2", "UInt8"),
            ("compare_by_identity", "Bool"),
            ("block_ptr", void_ptr),
            ("block_data", void_ptr),
        ]
        
        udt = _udt_from_fields(fields)
        return _udt_to_named_tif(udt, f"Hash({type_name})", assume_ptrs)
    
    @_register_handler("Range(...)")
    def handle_range(type_name: str, assume_ptrs: bool):
        """
        struct Range(B, E) {
            B begin;
            E end;
            Bool exclusive;
        }
        """
        
        args = split_true_commas(type_name)
        if len(args) != 2:
            warning(f"Got {len(args)} args when splitting Range({type_name})")
            return None
        
        begin, end = args
        use_begin = begin != "Nil"
        use_end = end != "Nil"

        if use_begin:
            begin_tif = name_to_tif(begin, False)
            if not begin_tif:
                warning(f"Failed to get tif for {begin!r} when parsing Range")
                return None

        if use_end:
            end_tif = name_to_tif(end, False)
            if not end_tif:
                warning(f"Failed to get tif for {end!r} when parsing Range")
                return None
        
        fields = []
        if use_begin:
            fields.append(("begin", begin_tif))
        if use_end:
            fields.append(("end", end_tif))
        fields.append(("exclusive", "Bool"))

        udt = _udt_from_fields(fields)
        return _udt_to_named_tif(udt, f"Range({type_name})", False)
    
    @_register_handler("....class")
    def handle_class(type_name: str, assume_ptrs: bool):
        # .class types are just UInt32's lol
        tif = ida_typeinf.tinfo_t()
        tif.get_named_type(None, "UInt32")
        return tif

def name_to_tif(type_name: str, assume_ptrs: bool):
    return BuiltinTypeHandler.name_to_tif(type_name, assume_ptrs)

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