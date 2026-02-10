import ida_typeinf
import idc

from pathlib import Path
from typing import Optional
import json
import zlib

from .log import log, warning

_ENUM_MAP = None
def get_enums():
    global _ENUM_MAP
    if _ENUM_MAP is None:
        data_path = Path(__file__).parent / "data" / "cr_enums.json.zlib"
        with open(data_path, "rb") as f:
            _ENUM_MAP = json.loads(zlib.decompress(f.read(), wbits=-15))
    
    return _ENUM_MAP

def is_std_cr_enum(name: str) -> bool:
    return name in get_enums()

def define_enum(name: str) -> Optional[ida_typeinf.tinfo_t]:
    if not is_std_cr_enum(name):
        raise ValueError(f"Enum {name!r} is not a part of the Crystal stdlib")
    
    # return existing type if already defined
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, name):
        return tif

    size_str, members = get_enums()[name]
    signed = size_str[0] == "i"
    bits = int(size_str[1:])

    # ida requires globally unique enum member names, prefix to avoid collisions
    prefix = name.replace("::", "_") + "_"

    etd = ida_typeinf.enum_type_data_t()
    for member_name, member_value in members:
        edm = ida_typeinf.edm_t()
        edm.name = prefix + member_name
        edm.value = member_value
        etd.push_back(edm)

    byte_size = bits // 8
    sign = ida_typeinf.type_signed if signed else ida_typeinf.type_unsigned
    tid = ida_typeinf.create_enum_type(name, etd, byte_size, sign, False)
    if tid == idc.BADADDR:
        warning(f"Failed to create enum {name!r} (size={size_str})")
        return None

    # log(f"Created enum {name!r} (tid={tid:#x})")
    tif = ida_typeinf.tinfo_t()
    tif.get_named_type(None, name)
    return tif