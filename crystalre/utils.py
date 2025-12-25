import ida_segment
import ida_bytes
import ida_ida

def is_elf() -> bool:
    return ida_ida.inf_get_filetype() == ida_ida.f_ELF

def is_crystal_binary() -> bool:
    rodata = ida_segment.get_segm_by_name(".rodata")
    if not rodata:
        return False

    data = ida_bytes.get_bytes(rodata.start_ea, rodata.size())
    if not data:
        return False

    return b"Crystal::" in data
