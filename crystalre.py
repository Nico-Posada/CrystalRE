from crystalre import *
import logging
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_name

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("crystalre")

class CrystalRE(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX

    # Required attributes - must be set by subclasses
    wanted_name: str = "CrystalRE"
    comment: str = "CrystalRE"
    help: str = "CrystalRE"

    def init(self) -> int:
        if not is_elf() or not is_crystal_binary():
            return ida_idaapi.PLUGIN_SKIP

        self.naming_hook = None
        log("Plugin CrystalRE initializing")
        addon = ida_kernwin.addon_info_t()
        addon.id = "Nico-Posada.CrystalRE"
        addon.name = "CrystalRE"
        addon.producer = "Nico Posada"
        addon.url = "https://github.com/Nico-Posada/CrystalRE"
        addon.version = "0.0.1"
        ida_kernwin.register_addon(addon)
        self.run(None)
        return ida_idaapi.PLUGIN_KEEP            

    def run(self, arg: int) -> None:
        setup_name_characters()
        apply_crystal_base_types()
        log("Initialized default crystal types.")
        total = find_and_define_strings()
        log(f"Labeled {total} strings.")
        self.naming_hook = install_naming_hook()
        log("Naming hook installed")
        
        binary_path = ida_nalt.get_input_file_path()

        # initialize symbol cache
        try:
            SymbolCache.init_cache(binary_path)
        except Exception as e:
            warning(f"Unable to initialize symbol cache: {e!r}. Skipping the rest of initialization.")
            return

        # get all parsed symbols
        symbols = SymbolCache.get_symbols()

        # apply names to functions
        for rva, parsed_sym in symbols.items():
            final_name = "*" # prefix to tell the name demangler this is a crystal func

            if parsed_sym.symbol_type == SymbolType.FUNCTION:
                func_info = parsed_sym.symbol_data

                # add self_type if present (owner is optional)
                if 'self_type' in func_info:
                    final_name += func_info['self_type'] + "::"

                # add function name (required)
                final_name += func_info['name']

            elif parsed_sym.symbol_type == SymbolType.PROC:
                proc_info = parsed_sym.symbol_data
                final_name += f"~{proc_info['symbol_string']}"

                # this part isn't standard but whatever
                if proc_info['proc_num']:
                    final_name += f"[{proc_info['proc_num']}]"

            # set the name in IDA
            ida_name.set_name(rva, final_name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_FORCE)
            # log(f"Set name {final_name} @ {rva:#x}")
        

    def term(self) -> None:
        log("terminating")
        if hasattr(self, "processor_hook"):
            remove_naming_hook(self.naming_hook)

def PLUGIN_ENTRY():
    return CrystalRE()
