# Custom calling convention (__crystal) that acts the exact same as __fastcall, but handles structs passed by value differently

import ida_typeinf
import ida_idp

from .log import log, warning

# argument registers for x86_64
ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
# floating-point argument registers
XMM_REGS = ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"]
# struct return registers
SRET_REGS = ["rax", "rdx", "rcx", "r8"]

class CrystalCC(ida_typeinf.custom_callcnv_t):
    def __init__(self):
        ida_typeinf.custom_callcnv_t.__init__(self)
        self.name = "__crystal"
        self.flags = 0
        self.abibits = 0

    def _get_reg_id(self, name: str) -> int:
        return ida_idp.str2reg(name)

    def _split_union_into_chunks(self, udt: ida_typeinf.udt_type_data_t, base_offset: int = 0) -> list[tuple[int, int]]:
        # find the largest member in the union
        max_size = 0
        for i in range(udt.size()):
            member = udt[i]
            member_size = member.size // 8
            if member_size > max_size:
                max_size = member_size

        # split into 8-byte chunks
        fields = []
        offset = 0
        while offset < max_size:
            chunk_size = 8
            fields.append((base_offset + offset, chunk_size))
            offset += chunk_size
        return fields

    def _get_struct_fields(self, tif: ida_typeinf.tinfo_t) -> list[tuple[int, int]]:
        # returns list of (offset, size) for each field, recursively flattening nested structs
        # unions are split into 8-byte chunks based on largest member
        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            return []

        # if this is a union, split it into 8-byte chunks
        if udt.is_union:
            return self._split_union_into_chunks(udt, 0)

        fields = []
        for i in range(udt.size()):
            member = udt[i]
            # offset is in bits, convert to bytes
            offset = member.offset // 8
            size = member.size // 8

            # check if this member is itself a non-pointer UDT
            member_type = member.type
            if member_type.is_udt() and not member_type.is_ptr():
                # check if it's a union or struct
                nested_udt = ida_typeinf.udt_type_data_t()
                if member_type.get_udt_details(nested_udt):
                    if nested_udt.is_union:
                        # union: split into 8-byte chunks based on largest member
                        union_fields = self._split_union_into_chunks(nested_udt, offset)
                        fields.extend(union_fields)
                    else:
                        # struct: recursively flatten
                        nested_fields = self._get_struct_fields(member_type)
                        if nested_fields:
                            # add nested fields with adjusted offsets
                            for nested_offset, nested_size in nested_fields:
                                fields.append((offset + nested_offset, nested_size))
                        else:
                            # couldn't get nested fields, treat as single field
                            fields.append((offset, size))
                else:
                    # couldn't get UDT details, treat as single field
                    fields.append((offset, size))
            else:
                # primitive type, pointer, or non-UDT. add as-is
                fields.append((offset, size))

        return fields

    def _is_float_type(self, tif: ida_typeinf.tinfo_t) -> bool:
        # check if type is floating-point (float, double, long double)
        return tif.is_floating()

    def validate_func(self, fti: ida_typeinf.func_type_data_t):
        # TODO: do something with this, returning True is fine for now
        return True

    def calc_retloc(self, fti: ida_typeinf.func_type_data_t) -> bool:
        if fti.rettype.is_void():
            return True

        # floating-point returns use xmm0
        if self._is_float_type(fti.rettype):
            fti.retloc.set_reg1(self._get_reg_id("xmm0"))
            return True

        if fti.rettype.is_udt():
            fields = self._get_struct_fields(fti.rettype)
            # filter out zero-sized fields (Nil type)
            fields = [(offset, size) for offset, size in fields if size > 0]

            # check for large gaps in scattered allocation (IDA can't handle these),
            # and this only happens with UInt128 types which is pretty rare
            has_large_gaps = False
            if len(fields) > 1:
                for i in range(len(fields) - 1):
                    current_end = fields[i][0] + fields[i][1]
                    next_start = fields[i + 1][0]
                    gap_size = next_start - current_end
                    if gap_size > 8:
                        has_large_gaps = True
                        break

            if len(fields) == 0:
                warning(f"Could not get fields for return type {fti.rettype}, using rax")
                fti.retloc.set_reg1(self._get_reg_id("rax"))
            elif has_large_gaps:
                # scattered allocations with large gaps cause decompiler errors
                warning(f"Return type {fti.rettype} has gaps >8 bytes, using rax only to avoid odd crash")
                fti.retloc.set_reg1(self._get_reg_id("rax"))
            elif len(fields) > 1 and len(fields) <= len(SRET_REGS):
                # split struct return into separate registers
                scattered = ida_typeinf.scattered_aloc_t()

                for i, (offset, size) in enumerate(fields):
                    part = ida_typeinf.argpart_t()
                    part.off = offset
                    part.size = size
                    part.set_reg1(self._get_reg_id(SRET_REGS[i]))
                    scattered.push_back(part)

                fti.retloc.consume_scattered(scattered)
                total_size = fti.rettype.get_size()
                ida_typeinf.optimize_argloc(fti.retloc, total_size, None)
            else:
                # single field struct or too many fields, use rax
                if len(fields) > len(SRET_REGS):
                    warning(f"Return struct has {len(fields)} fields (max {len(SRET_REGS)}), using rax only")
                fti.retloc.set_reg1(self._get_reg_id("rax"))
        else:
            # simple type. largest builtin type is UInt128 so hopefully nothing bad comes from this
            ret_size = fti.rettype.get_size()
            if ret_size > 16:
                warning(f"Non-UDT return type {fti.rettype} is {ret_size} bytes (>16), using rax:rdx")
                fti.retloc.set_reg2(self._get_reg_id("rax"), self._get_reg_id("rdx"))
            elif ret_size > 8:
                # split across rax:rdx like __fastcall
                fti.retloc.set_reg2(self._get_reg_id("rax"), self._get_reg_id("rdx"))
            else:
                fti.retloc.set_reg1(self._get_reg_id("rax"))

        return True

    def _use_fastcall(self, fti: ida_typeinf.func_type_data_t) -> bool:
        # delegate to __fastcall for cases we can't handle
        warning(f"Falling back to __fastcall")
        fti.set_cc(ida_typeinf.CM_CC_FASTCALL)
        return True

    def calc_arglocs(self, fti: ida_typeinf.func_type_data_t) -> bool:
        reg_idx = 0
        xmm_idx = 0
        stk_off = 0

        for i in range(fti.size()):
            fa = fti[i]
            arg_size = fa.type.get_size()

            # floating-point arguments use XMM registers
            if self._is_float_type(fa.type):
                if xmm_idx < len(XMM_REGS):
                    fa.argloc.set_reg1(self._get_reg_id(XMM_REGS[xmm_idx]))
                    xmm_idx += 1
                else:
                    # no xmm registers left, use stack
                    fa.argloc.set_stkoff(stk_off)
                    stk_off += (arg_size + 7) & ~7
                continue

            # check if we've run out of gp registers
            if reg_idx >= len(ARG_REGS):
                # allocate on stack
                fa.argloc.set_stkoff(stk_off)
                stk_off += (arg_size + 7) & ~7 # align to 8 bytes
                continue

            if fa.type.is_udt():
                fields = self._get_struct_fields(fa.type)
                # filter out zero-sized fields (Nil type)
                fields = [(offset, size) for offset, size in fields if size > 0]

                # check for large gaps in scattered allocation (IDA can't handle these)
                # has_large_gaps = False
                # if len(fields) > 1:
                #     for j in range(len(fields) - 1):
                #         current_end = fields[j][0] + fields[j][1]
                #         next_start = fields[j + 1][0]
                #         gap_size = next_start - current_end
                #         if gap_size > 12:
                #             has_large_gaps = True
                #             break

                regs_available = len(ARG_REGS) - reg_idx

                # if has_large_gaps:
                #     # scattered allocations with large gaps cause decompiler errors so use simple allocation
                #     if reg_idx < len(ARG_REGS):
                #         fa.argloc.set_reg1(self._get_reg_id(ARG_REGS[reg_idx]))
                #         reg_idx += 1
                #     else:
                #         fa.argloc.set_stkoff(stk_off)
                #         stk_off += (arg_size + 7) & ~7
                if len(fields) > 1 and regs_available >= len(fields):
                    # all fields fit in registers
                    scattered = ida_typeinf.scattered_aloc_t()
                    for offset, size in fields:
                        part = ida_typeinf.argpart_t()
                        part.off = offset
                        part.size = size
                        part.set_reg1(self._get_reg_id(ARG_REGS[reg_idx]))
                        scattered.push_back(part)
                        reg_idx += 1

                    fa.argloc.consume_scattered(scattered)
                    total_size = fa.type.get_size()
                    ida_typeinf.optimize_argloc(fa.argloc, total_size, None)
                elif len(fields) > 1 and regs_available > 0:
                    # struct spans registers and stack so split it
                    scattered = ida_typeinf.scattered_aloc_t()
                    for idx, (offset, size) in enumerate(fields):
                        part = ida_typeinf.argpart_t()
                        part.off = offset
                        part.size = size

                        if idx < regs_available:
                            # field goes in register
                            part.set_reg1(self._get_reg_id(ARG_REGS[reg_idx]))
                            reg_idx += 1
                        else:
                            # field goes on stack
                            part.set_stkoff(stk_off)
                            stk_off += (size + 7) & ~7

                        scattered.push_back(part)

                    fa.argloc.consume_scattered(scattered)
                    total_size = fa.type.get_size()
                    ida_typeinf.optimize_argloc(fa.argloc, total_size, None)
                elif reg_idx < len(ARG_REGS):
                    # single field struct or not enough regs for split, use one register
                    fa.argloc.set_reg1(self._get_reg_id(ARG_REGS[reg_idx]))
                    reg_idx += 1
                else:
                    # no registers left, use stack
                    fa.argloc.set_stkoff(stk_off)
                    stk_off += (arg_size + 7) & ~7
            else:
                # simple type - check size for large types like UInt128
                if arg_size > 8:
                    # need two registers
                    if reg_idx + 1 < len(ARG_REGS):
                        fa.argloc.set_reg2(self._get_reg_id(ARG_REGS[reg_idx]), self._get_reg_id(ARG_REGS[reg_idx + 1]))
                        reg_idx += 2
                    else:
                        # not enough registers, use stack
                        fa.argloc.set_stkoff(stk_off)
                        stk_off += (arg_size + 7) & ~7
                else:
                    fa.argloc.set_reg1(self._get_reg_id(ARG_REGS[reg_idx]))
                    reg_idx += 1

        fti.stkargs = stk_off
        return self.calc_retloc(fti)

    def get_cc_regs(self, callregs: ida_typeinf.callregs_t) -> bool:
        # register general-purpose registers
        for reg in ARG_REGS:
            callregs.gpregs.push_back(self._get_reg_id(reg))

        # register floating-point registers
        for reg in XMM_REGS:
            callregs.fpregs.push_back(self._get_reg_id(reg))

        callregs.nregs = len(ARG_REGS) + len(XMM_REGS)
        return True


# global state
_cc_instance = None
_cc_id = ida_typeinf.CM_CC_INVALID

def register_cc():
    global _cc_instance, _cc_id
    if _cc_instance is None:
        _cc_instance = CrystalCC()
        _cc_id = ida_typeinf.register_custom_callcnv(_cc_instance)
    return _cc_id

def get_cc_id():
    return _cc_id

def unregister_cc():
    global _cc_instance, _cc_id
    if _cc_instance is not None:
        try:
            ida_typeinf.unregister_custom_callcnv(_cc_instance)
        except RuntimeError:
            # database already closed
            pass
        _cc_instance = None
        _cc_id = ida_typeinf.CM_CC_INVALID
