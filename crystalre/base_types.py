import ida_name
import ida_idp
import idc
import ida_typeinf
import ida_ida

from .log import log, warning

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

    ("Symbol", "unsigned int")
}

CR_BASE_TYPES = [v for (v, _) in _TYPE_CONVERSIONS if v != "char32_t"]

def _type_exists(name: str):
    return bool(ida_typeinf.tinfo_t().get_named_type(None, name))

def should_type_be_ptr(type_name: str):
    return type_name == "String" or type_name not in CR_BASE_TYPES

def name_to_tif(type_name: str):
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, type_name):
        # type doesn't exist in the idb, default to void*
        tif = ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)
    elif should_type_be_ptr(type_name) and not tif.create_ptr(tif):
        warning(f"Failed to make type {type_name!r} a ptr")
    
    return tif

def apply_crystal_base_types():
    global _TYPE_CONVERSIONS
    for cr_name, ida_name in _TYPE_CONVERSIONS:
        if _type_exists(cr_name):
            continue
        
        typedef_str = f"typedef {ida_name} {cr_name};"
        tif = ida_typeinf.tinfo_t(typedef_str)
        tif.set_named_type(None, cr_name)
    
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