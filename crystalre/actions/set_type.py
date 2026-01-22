import ida_hexrays
import ida_typeinf
import ida_kernwin
import idaapi

try:
    from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
    from PySide6.QtCore import Qt
except ImportError:
    from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
    from PyQt5.QtCore import Qt

from ..base_types import name_to_tif
from ..log import log, warning

ACTION_CRYSTAL_SETTYPE = "crystalre:setcrystaltype"

# TODO: remove a lot of code duplication once this is stable

class SetTypePopupHook(ida_hexrays.Hexrays_Hooks):
    def populating_popup(self, widget, popup, vu):
        # attach action to context menu in decompiler view
        idaapi.attach_action_to_popup(widget, popup, ACTION_CRYSTAL_SETTYPE, None)
        return 0


class CrystalTypeDialog(QDialog):
    def __init__(self, item_info):
        super(CrystalTypeDialog, self).__init__()
        self.item_info = item_info

        # window setup
        self.setWindowTitle("Please enter a string")
        self.resize(500, 100)

        # main layout
        layout_main = QVBoxLayout()

        # label and input
        layout_input = QHBoxLayout()
        label = QLabel("Please enter the type declaration")
        self.edit_type = QLineEdit()

        # pre-fill with current type
        current_type_str = self._safe_print_type(item_info.get('current_type'))
        self.edit_type.setText(current_type_str)
        self.edit_type.selectAll()

        layout_input.addWidget(label)
        layout_input.addWidget(self.edit_type)

        # buttons
        layout_buttons = QHBoxLayout()
        layout_buttons.addStretch()

        self.btn_cancel = QPushButton("Cancel")
        self.btn_ok = QPushButton("OK")
        self.btn_ok.setDefault(True)

        layout_buttons.addWidget(self.btn_cancel)
        layout_buttons.addWidget(self.btn_ok)

        # connect signals
        self.btn_cancel.clicked.connect(self.reject)
        self.btn_ok.clicked.connect(self.accept)
        self.edit_type.returnPressed.connect(self.accept)

        # assemble layout
        layout_main.addLayout(layout_input)
        layout_main.addLayout(layout_buttons)
        self.setLayout(layout_main)

    def get_type_string(self):
        return self.edit_type.text().strip()

    def _safe_print_type(self, tif):
        if not tif:
            return ""
        try:
            # try using dstr() first
            type_str = str(tif)
            if type_str:
                return type_str
        except:
            pass
        try:
            # fallback to _print()
            return tif._print()
        except:
            return ""

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.reject()
        else:
            super(CrystalTypeDialog, self).keyPressEvent(event)


class SetTypeAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # get current decompiler view
        vdui = idaapi.get_widget_vdui(ctx.widget)
        if not vdui:
            return 0

        # get item under cursor
        if not vdui.get_current_item(ida_hexrays.USE_KEYBOARD):
            return 0

        # determine what type of item we're hovering over
        item_info = self._get_retypeable_item(vdui)
        if not item_info:
            print("Cannot retype this item")
            return 0

        # show crystal type setter dialog
        dialog = CrystalTypeDialog(item_info)
        if dialog.exec_():
            crystal_type = dialog.get_type_string()
            if crystal_type:
                self._apply_crystal_type(item_info, crystal_type)
                vdui.refresh_view(True)

        return 1

    def update(self, ctx):
        # enable only in decompiler view
        vdui = idaapi.get_widget_vdui(ctx.widget)
        if vdui:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET

    def _get_retypeable_item(self, vdui):
        """
        returns dict with:
            - 'type': 'lvar' | 'global' | 'rettype' | None
            - 'name': variable/field name
            - 'ea': effective address (for globals)
            - 'current_type': current tinfo_t
            - 'lvar': lvar_t object (for local vars)
            - 'cfunc': cfunc_t object (for local vars/params/rettypes)
        """
        cit = vdui.item.citype

        # function (for return type)
        if cit == ida_hexrays.VDI_FUNC:
            func_tif = ida_typeinf.tinfo_t()
            if vdui.cfunc.get_func_type(func_tif):
                func_data = ida_typeinf.func_type_data_t()
                if func_tif.get_func_details(func_data):
                    return {
                        'type': 'rettype',
                        'name': idaapi.get_name(vdui.cfunc.entry_ea),
                        'current_type': func_data.rettype,
                        'cfunc': vdui.cfunc
                    }

        # local variable
        elif cit == ida_hexrays.VDI_LVAR:
            lvar = vdui.item.l
            return {
                'type': 'lvar',
                'name': lvar.name,
                'current_type': lvar.type(),
                'lvar': lvar,
                'cfunc': vdui.cfunc
            }

        # expression (could be parameter, global, struct member access)
        elif cit == ida_hexrays.VDI_EXPR:
            expr = vdui.item.e

            # check for variable reference
            if expr.op == ida_hexrays.cot_var:
                # could be local var or parameter
                lvar = vdui.cfunc.get_lvars()[expr.v.idx]
                return {
                    'type': 'lvar',
                    'name': lvar.name,
                    'current_type': expr.type,
                    'lvar': lvar,
                    'cfunc': vdui.cfunc
                }

            # check for global variable
            elif expr.op == ida_hexrays.cot_obj:
                ea = expr.obj_ea
                return {
                    'type': 'global',
                    'name': idaapi.get_name(ea),
                    'ea': ea,
                    'current_type': expr.type
                }

        return None
    
    # Using `name_to_tif` creates the type if it doesn't exist in the db,
    # this is a safeguard to make sure wonky names don't get added by mistake
    def _show_warning(self, orig_type: str):
        QMessageBox.warning(
            None,
            "Invalid Type Syntax",
            f"Internal pointers detected in type '{orig_type}'.\n\n"
            "Please use the Pointer(...) wrapper for internal pointers.\n"
            "Example: Array(Pointer(UInt8)) instead of Array(UInt8*)"
        )

    # parse a crystal type string into a tinfo_t, handling trailing pointers
    def _parse_type_string(self, crystal_type: str):
        # strip the pointer asterisks first, we'll reapply later
        num_ptrs = 0
        stripped_type = crystal_type
        while stripped_type[-1].isspace() or stripped_type.endswith("*"):
            num_ptrs += stripped_type.endswith("*")
            stripped_type = stripped_type[:-1]

        # sanity check, name_to_tif creates the type if it's generated, so we need to make sure there's no extra * in here
        if "*" in stripped_type:
            self._show_warning(stripped_type)
            return None

        # use crystal's name_to_tif to convert type string
        tif = name_to_tif(stripped_type, False)
        if tif is None:
            warning(f"Failed to parse type using name_to_tif")
            # fallback: try standard ida parsing
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, crystal_type, 0):
                warning(f"Failed to parse type '{crystal_type}'")
                return None

        # apply trailing pointers
        for _ in range(num_ptrs):
            tif.create_ptr(tif)

        return tif

    def _apply_crystal_type(self, item_info, crystal_type):
        item_type = item_info['type']

        if item_type == 'lvar':
            # local variable or parameter
            self._apply_lvar_type(item_info, crystal_type)
        elif item_type == 'global':
            # global variable
            self._apply_global_type(item_info, crystal_type)
        elif item_type == 'rettype':
            # function return type
            self._apply_rettype(item_info, crystal_type)
        else:
            warning(f"Unsupported item type: {item_type}")
            return False

        return True

    def _apply_lvar_type(self, item_info, crystal_type):
        # parse the type string
        tif = self._parse_type_string(crystal_type)
        if tif is None:
            return False

        # get the lvar and create user info
        lvar = item_info['lvar']
        cfunc = item_info['cfunc']

        # check if this is a function parameter
        if lvar.is_arg_var:
            # for parameters, we need to modify the function prototype
            return self._apply_param_type(cfunc, lvar, tif, crystal_type)
        else:
            # for local variables, use the standard method
            # create lvar_saved_info_t to save the type
            lsi = ida_hexrays.lvar_saved_info_t()
            lsi.ll = lvar
            lsi.name = lvar.name
            lsi.type = tif
            lsi.size = tif.get_size()

            # modify the user lvar info
            if ida_hexrays.modify_user_lvar_info(cfunc.entry_ea, ida_hexrays.MLI_TYPE, lsi):
                return True
            else:
                warning(f"Failed to modify user lvar info for '{item_info['name']}'")
                return False

    def _apply_param_type(self, cfunc, lvar, tif, crystal_type):
        # get current function type
        func_tif = ida_typeinf.tinfo_t()
        if not cfunc.get_func_type(func_tif):
            warning(f"Failed to get function type")
            return False

        # get function details
        func_data = ida_typeinf.func_type_data_t()
        if not func_tif.get_func_details(func_data):
            warning(f"Failed to get function details")
            return False

        # find the parameter index
        param_idx = None
        for i, param in enumerate(func_data):
            if param.name == lvar.name:
                param_idx = i
                break

        if param_idx is None:
            warning(f"Could not find parameter '{lvar.name}' in function signature")
            return False

        # modify the parameter type
        func_data[param_idx].type = tif

        # create new function type with modified parameter
        new_func_tif = ida_typeinf.tinfo_t()
        if not new_func_tif.create_func(func_data):
            warning(f"Failed to create new function type")
            return False

        # apply the new function type
        if idaapi.apply_tinfo(cfunc.entry_ea, new_func_tif, idaapi.TINFO_DEFINITE):
            return True
        else:
            warning(f"Failed to apply new function type")
            return False

    def _apply_rettype(self, item_info, crystal_type):
        """modify function prototype to change return type"""
        # parse the type string
        tif = self._parse_type_string(crystal_type)
        if tif is None:
            return False

        cfunc = item_info['cfunc']

        # get current function type
        func_tif = ida_typeinf.tinfo_t()
        if not cfunc.get_func_type(func_tif):
            warning(f"Failed to get function type")
            return False

        # get function details
        func_data = ida_typeinf.func_type_data_t()
        if not func_tif.get_func_details(func_data):
            warning(f"Failed to get function details")
            return False

        # modify the return type
        func_data.rettype = tif

        # create new function type with modified return type
        new_func_tif = ida_typeinf.tinfo_t()
        if not new_func_tif.create_func(func_data):
            warning(f"Failed to create new function type")
            return False

        # apply the new function type
        if idaapi.apply_tinfo(cfunc.entry_ea, new_func_tif, idaapi.TINFO_DEFINITE):
            return True
        else:
            warning(f"Failed to apply new function type")
            return False

    def _apply_global_type(self, item_info, crystal_type):
        ea = item_info['ea']

        # parse the type string
        tif = self._parse_type_string(crystal_type)
        if tif is None:
            return False

        if idaapi.apply_tinfo(ea, tif, idaapi.TINFO_DEFINITE):
            return True
        else:
            warning(f"apply_tinfo failed for type '{crystal_type}' at {ea:#x}")
            return False


def register_type_action():
    crystal_action = idaapi.action_desc_t(
        ACTION_CRYSTAL_SETTYPE,
        "[CrystalRE] Set Crystal type...",
        SetTypeAction(),
        "Shift+Y",
        "Set type using Crystal syntax",
        -1
    )
    if not idaapi.register_action(crystal_action):
        warning("Failed to register type setter action")
        return None

    # install popup hook
    popup_hook = SetTypePopupHook()
    if not popup_hook.hook():
        warning("Failed to install type setter popup hook")
        idaapi.unregister_action(ACTION_CRYSTAL_SETTYPE)
        return None

    return popup_hook


def unregister_type_action(popup_hook):
    if popup_hook:
        popup_hook.unhook()
    idaapi.unregister_action(ACTION_CRYSTAL_SETTYPE)
