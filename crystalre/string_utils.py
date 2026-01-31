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

def get_string_at(addr: int) -> bytes:
    type_id = ida_bytes.get_dword(addr)
    
    # first verification
    if type_id == 1:
        bytesize = ida_bytes.get_dword(addr + 4)

        # second verification
        # NOTE: strings of size 0 are ignored because it's more likely to match false positives
        if bytesize == 0 or bytesize > 1000:
            return None

        str_data = ida_bytes.get_bytes(addr + 12, bytesize)
        try:
            decoded = str_data.decode('utf-8')
            if any([c < " " and c not in "\r\n\t" for c in decoded]):
                # Nope.
                return None
            
            length = ida_bytes.get_dword(addr + 8)
            if len(decoded) != length:
                # Nope.
                return None
        except (UnicodeDecodeError, AttributeError):
            # str_data was None, or it was garbage data
            return None

        return str_data
    else:
        return None
    

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
        # collect comments to combine multiple strings at the same location
        self.comments = {}  # {(ea, itp): [comment1, comment2, ...]}

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
                    str_data = get_string_at(addr)
                    if str_data is not None:
                        try:
                            decoded = str_data.decode('utf-8')

                            # determine comment location
                            loc = ida_hexrays.treeloc_t()
                            loc.ea = expr.ea
                            loc.itp = ida_hexrays.ITP_SEMI

                            # find parent statement for valid ea
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

                            # collect comment for this location
                            key = (loc.ea, loc.itp)
                            if key not in self.comments:
                                self.comments[key] = []
                            self.comments[key].append(f'"{decoded}"')
                        except (UnicodeDecodeError, AttributeError):
                            pass

        return 0

    def apply_comments(self):
        """apply all collected comments"""
        for (ea, itp), comment_list in self.comments.items():
            loc = ida_hexrays.treeloc_t()
            loc.ea = ea
            loc.itp = itp
            # combine multiple comments with separator
            combined = ", ".join(comment_list)
            self.cfunc.set_user_cmt(loc, combined)


class StringCommenter(ida_hexrays.Hexrays_Hooks):
    """hexrays hook that adds string content comments to decompiled code"""

    def __init__(self):
        super().__init__()

    def maturity(self, cfunc, maturity):
        # only process at final maturity level
        if maturity != ida_hexrays.CMAT_FINAL:
            return 0

        # traverse the ctree and collect String references
        visitor = StringRefVisitor(cfunc)
        visitor.apply_to(cfunc.body, None)
        # apply all collected comments
        visitor.apply_comments()
        return 0


class ReturnTypeCommenter(ida_hexrays.Hexrays_Hooks):
    """hexrays hook that adds crystal return type comments to decompiled functions"""

    def __init__(self):
        super().__init__()

    def maturity(self, cfunc, maturity):
        # only process at final maturity level
        if maturity != ida_hexrays.CMAT_FINAL:
            return 0

        from .symbols import SymbolCache

        # get function address
        func_ea = cfunc.entry_ea

        try:
            # look up in symbol cache
            symbols = SymbolCache.get_symbols()
            if func_ea not in symbols:
                return 0
        except RuntimeError:
            # we are in a stripped binary, abort
            return 0
            

        parsed_sym = symbols[func_ea]
        return_type = parsed_sym.symbol_data.get("return_type")

        if not return_type:
            return 0

        # add comment above function signature
        comment_text = f"Parsed return type: {return_type}"
        idc.set_func_cmt(func_ea, comment_text, False)

        return 0
