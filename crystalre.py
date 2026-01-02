import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_name
import ida_hexrays
import ida_netnode

from crystalre import *

class CrystalRE(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX

    # Required attributes - must be set by subclasses
    wanted_name: str = "CrystalRE"
    comment: str = "CrystalRE"
    help: str = "CrystalRE"
    
    NODE_NAME = "$ CrystalRE plugin"

    def init(self) -> int:
        self.initialized = False
        if not ida_hexrays.init_hexrays_plugin() or \
            not is_elf() or not is_crystal_binary():
            return ida_idaapi.PLUGIN_SKIP

        self.nn = ida_netnode.netnode(self.NODE_NAME, 0, True)
        self.naming_hook = None
        log("Plugin CrystalRE initializing")
        addon = ida_kernwin.addon_info_t()
        addon.id = "Nico-Posada.CrystalRE"
        addon.name = "CrystalRE"
        addon.producer = "Nico Posada"
        addon.url = "https://github.com/Nico-Posada/CrystalRE"
        addon.version = "0.0.1"
        ida_kernwin.register_addon(addon)
        self.run()
        return ida_idaapi.PLUGIN_KEEP            

    def run(self, arg: int = 0) -> None:
        set_valid_chars()
        self.naming_hook = NamingHook()
        if not self.naming_hook.hook():
            warning("Unable to install naming hook, function names in decompilations might look odd.")
            self.naming_hook = None
        else:
            log("Naming hook installed")

        binary_path = ida_nalt.get_input_file_path()

        # initialize symbol cache
        try:
            SymbolCache.init_cache(binary_path)
        except Exception as e:
            warning(f"Unable to initialize symbol cache: {e!r}. Skipping the rest of initialization.")
            return

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
        set_function_names()
        fix_function_data()
        

    def term(self) -> None:
        if not getattr(self, "initialized", False):
            return

        log("terminating")
        self.naming_hook and self.naming_hook.unhook()
        self.initialized = False

def PLUGIN_ENTRY():
    return CrystalRE()
