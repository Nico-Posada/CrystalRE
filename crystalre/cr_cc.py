# Custom calling convention (__crystal) that acts the exact same as __fastcall, but handles structs passed by value differently

import ida_typeinf
import ida_idp

from .log import log

# argument registers for x86_64
ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
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

    def _get_struct_fields(self, tif: ida_typeinf.tinfo_t) -> list[tuple[int, int]]:
        # returns list of (offset, size) for each field
        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            return []

        fields = []
        for i in range(udt.size()):
            member = udt[i]
            # offset is in bits, convert to bytes
            offset = member.offset // 8
            size = member.size // 8
            fields.append((offset, size))
        return fields

    def validate_func(self, fti: ida_typeinf.func_type_data_t):
        # return True to accept, or a string with error message to reject
        # log(f"[CrystalCC] validate_func called")
        return True

    def calc_retloc(self, fti: ida_typeinf.func_type_data_t) -> bool:
        ret_str = str(fti.rettype)

        if fti.rettype.is_void():
            # log(f"[CrystalCC] calc_retloc: void")
            return True

        if fti.rettype.is_udt():
            fields = self._get_struct_fields(fti.rettype)
            # log(f"[CrystalCC] calc_retloc: struct {ret_str} with {len(fields)} fields")

            if len(fields) > 1 and len(fields) <= len(SRET_REGS):
                # split struct return into separate registers
                scattered = ida_typeinf.scattered_aloc_t()
                # field_regs = []

                for i, (offset, size) in enumerate(fields):
                    part = ida_typeinf.argpart_t()
                    part.off = offset
                    part.size = size
                    part.set_reg1(self._get_reg_id(SRET_REGS[i]))
                    scattered.push_back(part)
                    # field_regs.append(f"off={offset}:sz={size}->{SRET_REGS[i]}")

                fti.retloc.consume_scattered(scattered)
                total_size = fti.rettype.get_size()
                ida_typeinf.optimize_argloc(fti.retloc, total_size, None)
                # log(f"[CrystalCC]   split: [{', '.join(field_regs)}]")
            else:
                # single field struct or too many fields, use rax
                fti.retloc.set_reg1(self._get_reg_id("rax"))
                # log(f"[CrystalCC]   single reg: rax")
        else:
            # simple type - check size for large types like UInt128
            ret_size = fti.rettype.get_size()
            if ret_size > 8:
                # split across rax:rdx like __fastcall
                fti.retloc.set_reg2(self._get_reg_id("rax"), self._get_reg_id("rdx"))
                # log(f"[CrystalCC] calc_retloc: {ret_str} ({ret_size} bytes) -> rax:rdx")
            else:
                fti.retloc.set_reg1(self._get_reg_id("rax"))
                # log(f"[CrystalCC] calc_retloc: {ret_str} -> rax")

        return True

    def _use_fastcall(self, fti: ida_typeinf.func_type_data_t) -> bool:
        # delegate to __fastcall for cases we can't handle
        # log(f"[CrystalCC] falling back to __fastcall")
        fti.set_cc(ida_typeinf.CM_CC_FASTCALL)
        return True

    def calc_arglocs(self, fti: ida_typeinf.func_type_data_t) -> bool:
        # log(f"[CrystalCC] calc_arglocs called with {fti.size()} args")
        reg_idx = 0
        stk_off = 0

        for i in range(fti.size()):
            fa = fti[i]
            arg_type_str = str(fa.type)
            arg_size = fa.type.get_size()

            # check if we've run out of registers
            if reg_idx >= len(ARG_REGS):
                # allocate on stack
                fa.argloc.set_stkoff(stk_off)
                stk_off += (arg_size + 7) & ~7  # align to 8 bytes
                # log(f"[CrystalCC]   arg {i}: {arg_type_str} -> stack[{fa.argloc.stkoff()}]")
                continue

            if fa.type.is_udt():
                fields = self._get_struct_fields(fa.type)
                # log(f"[CrystalCC]   arg {i}: struct {arg_type_str} with {len(fields)} fields")

                # TODO: if the struct overlaps the end of the arg regs and the start of the
                # stack regs we need to be able to handle that
                if len(fields) > 1 and reg_idx + len(fields) <= len(ARG_REGS):
                    # split struct into separate registers
                    scattered = ida_typeinf.scattered_aloc_t()
                    field_regs = []

                    for offset, size in fields:
                        part = ida_typeinf.argpart_t()
                        part.off = offset
                        part.size = size
                        part.set_reg1(self._get_reg_id(ARG_REGS[reg_idx]))
                        scattered.push_back(part)
                        # field_regs.append(f"off={offset}:sz={size}->{ARG_REGS[reg_idx]}")
                        reg_idx += 1

                    fa.argloc.consume_scattered(scattered)
                    total_size = fa.type.get_size()
                    ida_typeinf.optimize_argloc(fa.argloc, total_size, None)
                    # log(f"[CrystalCC]     split: [{', '.join(field_regs)}]")
                elif reg_idx < len(ARG_REGS):
                    # single field struct or not enough regs for split, use one register
                    fa.argloc.set_reg1(self._get_reg_id(ARG_REGS[reg_idx]))
                    # log(f"[CrystalCC]     single reg: {ARG_REGS[reg_idx]}")
                    reg_idx += 1
                else:
                    # no registers left, use stack
                    fa.argloc.set_stkoff(stk_off)
                    stk_off += (arg_size + 7) & ~7
                    # log(f"[CrystalCC]     stack: [{fa.argloc.stkoff()}]")
            else:
                # simple type - check size for large types like UInt128
                if arg_size > 8:
                    # need two registers
                    if reg_idx + 1 < len(ARG_REGS):
                        fa.argloc.set_reg2(self._get_reg_id(ARG_REGS[reg_idx]), self._get_reg_id(ARG_REGS[reg_idx + 1]))
                        # log(f"[CrystalCC]   arg {i}: {arg_type_str} ({arg_size} bytes) -> {ARG_REGS[reg_idx]}:{ARG_REGS[reg_idx + 1]}")
                        reg_idx += 2
                    else:
                        # not enough registers, use stack
                        fa.argloc.set_stkoff(stk_off)
                        stk_off += (arg_size + 7) & ~7
                        # log(f"[CrystalCC]   arg {i}: {arg_type_str} ({arg_size} bytes) -> stack[{fa.argloc.stkoff()}]")
                else:
                    fa.argloc.set_reg1(self._get_reg_id(ARG_REGS[reg_idx]))
                    # log(f"[CrystalCC]   arg {i}: {arg_type_str} -> {ARG_REGS[reg_idx]}")
                    reg_idx += 1

        fti.stkargs = stk_off
        return self.calc_retloc(fti)

    def get_cc_regs(self, callregs: ida_typeinf.callregs_t) -> bool:
        # log(f"[CrystalCC] get_cc_regs called")
        callregs.nregs = len(ARG_REGS)
        for reg in ARG_REGS:
            callregs.gpregs.push_back(self._get_reg_id(reg))
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
