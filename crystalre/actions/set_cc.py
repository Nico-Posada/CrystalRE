import ida_hexrays
import ida_typeinf
import idaapi

from ..log import log, warning
from ..cr_cc import get_cc_id

ACTION_SET_CRYSTAL_CC = "crystalre:setcrystalcc"

class SetCrystalCCAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # get current decompiler view
        vdui = idaapi.get_widget_vdui(ctx.widget)
        if not vdui:
            return 0

        # check if we're on the function prototype
        if vdui.item.citype != ida_hexrays.VDI_FUNC:
            return 0

        cfunc = vdui.cfunc
        if not cfunc:
            return 0

        # get crystal cc id
        cc_id = get_cc_id()
        if cc_id == ida_typeinf.CM_CC_INVALID:
            warning("CrystalCC not registered, cannot set calling convention")
            return 0

        # get current function type
        func_tif = ida_typeinf.tinfo_t()
        if not cfunc.get_func_type(func_tif):
            warning("Failed to get function type")
            return 0

        # get function details
        func_data = ida_typeinf.func_type_data_t()
        if not func_tif.get_func_details(func_data):
            warning("Failed to get function details")
            return 0

        # get current calling convention
        current_cc = func_data.get_explicit_cc()

        # check if already using crystal cc
        if current_cc == cc_id:
            return 1

        # set new calling convention on the func_data
        func_data.set_cc(cc_id)

        # create new function type with the modified calling convention
        new_func_tif = ida_typeinf.tinfo_t()
        if not new_func_tif.create_func(func_data):
            warning("Failed to create new function type")
            return 0

        # apply the new function type
        if idaapi.apply_tinfo(cfunc.entry_ea, new_func_tif, idaapi.TINFO_DEFINITE):
            vdui.refresh_view(True)
            return 1
        else:
            warning("Failed to apply new function type")
            return 0

    def update(self, ctx):
        vdui = idaapi.get_widget_vdui(ctx.widget)
        return idaapi.AST_ENABLE_FOR_WIDGET if vdui else idaapi.AST_DISABLE_FOR_WIDGET


class SetCCPopupHook(ida_hexrays.Hexrays_Hooks):
    def populating_popup(self, widget, popup, vu):
        # always attach in decompiler view, let update() control enable/disable
        idaapi.attach_action_to_popup(widget, popup, ACTION_SET_CRYSTAL_CC, None)
        return 0


def register_set_cc():
    action = idaapi.action_desc_t(
        ACTION_SET_CRYSTAL_CC,
        "[CrystalRE] Set __crystal calling convention",
        SetCrystalCCAction(),
        "Shift+C",
        "Update function to use __crystal calling convention",
        -1
    )
    if not idaapi.register_action(action):
        warning("Failed to register set crystal cc action")
        return None

    # install popup hook
    popup_hook = SetCCPopupHook()
    if not popup_hook.hook():
        warning("Failed to install set cc popup hook")
        idaapi.unregister_action(ACTION_SET_CRYSTAL_CC)
        return None

    log("Set __crystal calling convention action registered (Shift+C)")
    return popup_hook


def unregister_set_cc(popup_hook):
    if popup_hook:
        popup_hook.unhook()
    idaapi.unregister_action(ACTION_SET_CRYSTAL_CC)
