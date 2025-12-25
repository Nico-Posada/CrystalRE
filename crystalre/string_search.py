import ida_segment
import ida_bytes
import ida_name
import idc

from .log import log, info, warning, error
from .base_types import _type_exists

def get_string_at(addr: int):
    type_id = ida_bytes.get_dword(addr)
    bytesize = ida_bytes.get_dword(addr + 4)
    length = ida_bytes.get_dword(addr + 8)
    
    # first verification
    # note: strings of size 1 and 0 are ignored because it's more likely to match false positives
    if type_id == 1 and bytesize == length and bytesize > 1:
        # second verification
        str_data = ida_bytes.get_bytes(addr + 12, bytesize)
        try:
            decoded = str_data.decode('utf-8')
            if any([c < " " and c not in "\r\n\t" for c in decoded]):
                raise UnicodeDecodeError
        except (UnicodeDecodeError, AttributeError):
            # str_data was None, or it was garbage data
            return None
    else:
        return None
    
    return str_data

# NOTE: may not work on strings with chars that are >1 byte since bytesize and length will differ
# causing the search to return a false negative for the string
def find_and_define_strings():
    if not _type_exists("String"):
        # String should 100% be defined at this point, use error log
        error("Running string search without the String struct defined! Skipping string search.")
        return 0
    
    # get .rodata segment
    rodata = ida_segment.get_segm_by_name(".rodata")
    if not rodata:
        # this shouldn't happen either, but less severe so only do a warning log
        warning("No .rodata segment found! Skipping string search.")
        return 0

    count = 0
    addr = rodata.start_ea

    # scan through rodata in 8-byte steps (all String objects are aligned to 8-byte boundaries)
    while addr < rodata.end_ea - 12:
        str_data = get_string_at(addr)
        if not str_data:
            # string not detected, continue
            addr += 8
            continue
        
        bytesize = len(str_data)
        total_size = bytesize + 12

        # make sure we don't overflow the segment
        if addr + total_size <= rodata.end_ea:
            # delete any existing items at this location
            ida_bytes.del_items(addr, ida_bytes.DELIT_SIMPLE, total_size)

            # set the name
            name = f"string_{addr:x}"
            ida_name.set_name(addr, name)

            # set the type declaration to prevent ida from grouping strings together into an array
            idc.SetType(addr, f"String {name};")
            
            # finally, create the String struct
            idc.create_struct(addr, total_size, "String")

            count += 1
            info(f"Found String at {addr:#x}, size {total_size}")

            # skip past this string to avoid overlapping detections (align too)
            addr += (total_size + 0x7) & ~0x7
            continue
        else:
            # move to next 8-byte aligned position
            addr += 8

    log(f"Found {count} String objects in .rodata")
    return count
