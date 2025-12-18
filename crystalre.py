from crystalre import *
import logging
import ida_idaapi
import ida_kernwin

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("crystalre")

class CrystalRE(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX

    # Required attributes - must be set by subclasses
    wanted_name: str = "CrystalRE"
    comment: str = "CrystalRE"
    help: str = "CrystalRE"

    def init(self) -> int:
        if is_crystal_binary():
            logger.info("Plugin CrystalRE initializing")
            addon = ida_kernwin.addon_info_t()
            addon.id = "Nico-Posada.CrystalRE"
            addon.name = "CrystalRE"
            addon.producer = "Nico Posada"
            addon.url = "https://github.com/Nico-Posada/CrystalRE"
            addon.version = "0.0.1"
            ida_kernwin.register_addon(addon)
            return ida_idaapi.PLUGIN_KEEP
        else:
            return ida_idaapi.PLUGIN_SKIP

    def run(self, arg: int) -> None:
        logger.info("Plugin CrystalRE running")

    def term(self) -> None:
        logger.info("Plugin CrystalRE terminating")

def PLUGIN_ENTRY():
    return CrystalRE()
