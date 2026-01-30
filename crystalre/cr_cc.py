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

    def _is_float_type(self, tif: ida_typeinf.tinfo_t) -> bool:
        # check if type is floating-point (float, double, long double)
        return tif.is_floating()

    def validate_func(self, fti: ida_typeinf.func_type_data_t):
        # return True to accept, or a string with error message to reject
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

            if len(fields) == 0:
                warning(f"Could not get fields for return type {fti.rettype}, using rax")
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
                warning(f"Non-UDT return type {fti.rettype} is {ret_size} bytes (>16), using rax")
                fti.retloc.set_reg1(self._get_reg_id("rax"))
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
        # log(f"[CrystalCC] calc_arglocs called with {fti.size()} args")
        reg_idx = 0  # general-purpose register index
        xmm_idx = 0  # floating-point register index
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
                stk_off += (arg_size + 7) & ~7  # align to 8 bytes
                continue

            if fa.type.is_udt():
                fields = self._get_struct_fields(fa.type)
                regs_available = len(ARG_REGS) - reg_idx

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
                    # struct spans registers and stack - split it
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
