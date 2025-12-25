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
        
        file_path = ida_nalt.get_input_file_path()
        try:
            data, file_type = determine_file(file_path)
            assert file_type == 1 # ELF
        except Exception as e:
            warning(f"Unable to load binary at {file_path!r}. Skipping the rest of the initialization.")
            return

        try:
            syms = parse_data(data)
        except Exception as e:
            msg = e.args[0]
            warning(f"{msg}. Skipping the rest of initialization.")
            return
        
        for sym in syms:
            # TODO: fix names that aren't function names too
            if sym.type != 'STT_FUNC':
                continue
            
            # all crystal symbols start with * or ~ (if anonymous proc)
            if sym.name.startswith("*"):
                parsed = parse_function(sym.name)
                if parsed is None:
                    warning(f"Failed to parse {sym.name}")
                    continue
                
                func_info = {k: v for k, v in parsed.items() if v}
                final_name = "*" # set the * to tell the name "demangler" that this is a crystal func
                if 'self_type' in func_info: # owner is optional, so check if it exists first
                    final_name += func_info['self_type'] + "::"
                final_name += func_info['name'] # name is required
            elif sym.name.startswith("~proc"):
                try:
                    symbol_string, proc_num = parse_proc(sym.name)
                except AssertionError as e:
                    warning(f"Got err {repr(e)} while parsing {sym.name!r}")
                    continue
                
                final_name = "*" # set the * to tell the name "demangler" that this is a crystal func
                final_name += f"~{symbol_string}"
                if proc_num:
                    final_name += f"[{proc_num}]" # not standard but whatever
            else:
                continue

            ida_name.set_name(sym.rva, final_name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_FORCE)
            log(f"Set name {final_name} @ {sym.rva:#x}")
        

    def term(self) -> None:
        log("terminating")
        if hasattr(self, "processor_hook"):
            remove_naming_hook(self.naming_hook)

def PLUGIN_ENTRY():
    return CrystalRE()
