import ida_segment
import ida_bytes
import ida_name
import ida_nalt
import ida_hexrays
import ida_typeinf
import ida_idaapi
import idc

from .log import log, info, warning, error
from .base_types import _type_exists

def get_string_at(addr: int):
    type_id = ida_bytes.get_dword(addr)
    bytesize = ida_bytes.get_dword(addr + 4)
    length = ida_bytes.get_dword(addr + 8)
    
    # first verification
    # note: strings of size 0 are ignored because it's more likely to match false positives
    if type_id == 1 and bytesize == length and bytesize > 0:
        # second verification
        str_data = ida_bytes.get_bytes(addr + 12, bytesize)
        try:
            decoded = str_data.decode('utf-8')
            if any([c < " " and c not in "\r\n\t" for c in decoded]):
                # Nope.
                return None
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
            # info(f"Found String at {addr:#x}, size {total_size}")

            # skip past this string to avoid overlapping detections (align too)
            addr += (total_size + 0x7) & ~0x7
            continue
        else:
            # move to next 8-byte aligned position
            addr += 8

    log(f"Found {count} String objects in .rodata")
    return count


class StringRefVisitor(ida_hexrays.ctree_visitor_t):
    """visitor that finds references to String objects and adds comments with their contents"""

    def __init__(self, cfunc):
        super().__init__(ida_hexrays.CV_FAST)
        self.cfunc = cfunc

    # based on https://github.com/KasperskyLab/hrtng/blob/v3.7.74/src/rename.cpp#L982
    def visit_expr(self, expr):
        # check if this is a reference to a global object
        if expr.op == ida_hexrays.cot_obj:
            addr = expr.obj_ea

            # check if this address has a type and if it's a String
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, addr):
                type_name = tif.get_type_name()

                if type_name and type_name == "String":
                    # read the string data
                    bytesize = ida_bytes.get_dword(addr + 4)

                    # sanity check on size
                    if bytesize > 0 and bytesize < 1000:
                        str_data = ida_bytes.get_bytes(addr + 12, bytesize)
                        if str_data:
                            try:
                                decoded = str_data.decode('utf-8')

                                # create treeloc for comment placement
                                loc = ida_hexrays.treeloc_t()
                                loc.ea = expr.ea
                                loc.itp = ida_hexrays.ITP_SEMI

                                # find parent statement for better placement
                                p = self.cfunc.body.find_parent_of(expr)
                                while p and p.op <= ida_hexrays.cot_last:
                                    p = self.cfunc.body.find_parent_of(p)

                                if p:
                                    if p.ea != ida_idaapi.BADADDR:
                                        loc.ea = p.ea
                                    if p.op == ida_hexrays.cit_expr:
                                        loc.itp = ida_hexrays.ITP_SEMI
                                    elif p.op == ida_hexrays.cit_if:
                                        loc.itp = ida_hexrays.ITP_BRACE2

                                # set comment directly
                                self.cfunc.set_user_cmt(loc, f'"{decoded}"')
                            except (UnicodeDecodeError, AttributeError):
                                pass

        return 0


class StringCommenter(ida_hexrays.Hexrays_Hooks):
    """hexrays hook that adds string content comments to decompiled code"""

    def __init__(self):
        super().__init__()

    def maturity(self, cfunc, maturity):
        # only process at final maturity level
        if maturity != ida_hexrays.CMAT_FINAL:
            return 0

        # traverse the ctree and add comments for String references
        visitor = StringRefVisitor(cfunc)
        visitor.apply_to(cfunc.body, None)
        return 0
