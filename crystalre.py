import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_name
import ida_hexrays
import ida_netnode
import ida_segment
import ida_bytes
import ida_ida
import ida_typeinf

from crystalre import *

def is_elf() -> bool:
    return ida_ida.inf_get_filetype() == ida_ida.f_ELF

def is_crystal_binary() -> bool:
    rodata = ida_segment.get_segm_by_name(".rodata")
    if not rodata:
        return False

    data = ida_bytes.get_bytes(rodata.start_ea, rodata.size())
    if not data:
        return False

    # These are substrings I observed in even the most minimal stripped crystal binaries
    return b"Crystal::" in data and b"CRYSTAL_LOAD_DEBUG_INFO" in data


class CrystalRE(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_MOD# | ida_idaapi.PLUGIN_MULTI

    # Required attributes - must be set by subclasses
    wanted_name: str = "CrystalRE"
    comment: str = "Make reversing crystal binaries less annoying."
    help: str = "Plugin that runs on IDB start to fix crystal lang decompilations. Installs some hooks and renames symbols."
    
    NODE_NAME = "$ CrystalRE plugin"

    def init(self) -> int:
        # return ida_idaapi.PLUGIN_SKIP
        self.initialized = False
        if not ida_hexrays.init_hexrays_plugin() or \
            not is_elf() or not is_crystal_binary():
            return ida_idaapi.PLUGIN_SKIP

        self.nn = ida_netnode.netnode(self.NODE_NAME, 0, True)
        self.naming_hook = None
        self.string_hook = None
        self.rettype_hook = None
        self.settype_hook = None
        self.set_cc_hook = None
        self.initalized_cache = False
        log("Plugin CrystalRE initializing")
        addon = ida_kernwin.addon_info_t()
        addon.id = "Nico-Posada.CrystalRE"
        addon.name = "CrystalRE"
        addon.producer = "Nico Posada"
        addon.url = "https://github.com/Nico-Posada/CrystalRE"
        addon.version = "1.1.0"
        ida_kernwin.register_addon(addon)
        self.run()
        return ida_idaapi.PLUGIN_KEEP            

    def run(self, arg: int = -1) -> None:
        if arg != -1:
            # stupid shortcut to make sure this only runs on startup and not via the dropdown.
            # maybe I'll add dropdown support someday, who knows
            return

        set_valid_chars()
        self.naming_hook = NamingHook()
        if not self.naming_hook.hook():
            warning("Unable to install naming hook, function names in decompilations might look odd.")
            self.naming_hook = None
        else:
            log("Naming hook installed")

        self.string_hook = StringCommenter()
        if not self.string_hook.hook():
            warning("Unable to install string commenter hook, string contents won't appear in decompiler.")
            self.string_hook = None
        else:
            log("String commenter hook installed")

        # register custom calling convention
        cc_id = register_cc()
        if cc_id != ida_typeinf.CM_CC_INVALID:
            log(f"CrystalCC registered with ID: {cc_id:#x}")
        else:
            warning("Failed to register CrystalCC")

        # register crystal type setter action (shift+y)
        self.settype_hook = register_type_action()

        # register force crystal cc action (shift+c)
        self.set_cc_hook = register_set_cc()

        binary_path = ida_nalt.get_input_file_path()

        # initialize symbol cache
        try:
            SymbolCache.init_cache(binary_path)
            self.initalized_cache = True
        except Exception as e:
            warning(f"Unable to initialize symbol cache: {e!r}.")
            self.initalized_cache = False
        
        # this hook is only relevant if we have symbols
        if self.initalized_cache:
            self.rettype_hook = ReturnTypeCommenter()
            if not self.rettype_hook.hook():
                warning("Unable to install return type commenter hook, return types won't appear in decompiler.")
                self.rettype_hook = None
            else:
                log("Return type commenter hook installed")

        # check if we've already initialized this idb
        if self.nn.altval(0) != 1:
            log("First time loading with CrystalRE, running full initialization")
            self.init_for_new_idb()
            self.nn.altset(0, 1)
        else:
            log("IDB already initialized, skipping string search and function renaming")

        self.initialized = True
    
    def init_for_new_idb(self):
        # type stuff
        apply_crystal_base_types()
        log("Initialized default crystal types.")

        # string stuff
        total = find_and_define_strings()
        log(f"Labeled {total} strings.")

        # function stuff
        if self.initalized_cache:
            set_function_names()
            fix_function_data()
            apply_known_functions()
        

    def term(self) -> None:
        if not getattr(self, "initialized", False):
            return

        log("terminating")
        self.naming_hook and self.naming_hook.unhook()
        self.string_hook and self.string_hook.unhook()
        self.rettype_hook and self.rettype_hook.unhook()

        unregister_cc()
        unregister_type_action(self.settype_hook)
        unregister_set_cc(self.set_cc_hook)

        self.naming_hook = None
        self.string_hook = None
        self.rettype_hook = None
        self.settype_hook = None
        self.set_cc_hook = None
        self.initialized = False

def PLUGIN_ENTRY():
    return CrystalRE()
