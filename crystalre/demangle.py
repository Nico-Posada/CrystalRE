import ida_idp
import ida_name
from .log import log

class NamingHook(ida_idp.IDP_Hooks):
    def ev_demangle_name(self, name, disable_mask, demreq):
        # strip leading * from crystal function names
        if name and name.startswith("*"):
            # log(f"Got {name}, {disable_mask}, {demreq}")
            return [1, name[1:], 1]
        return 0

def install_naming_hook():
    hook = NamingHook()
    hook.hook()
    return hook

def remove_naming_hook(hook):
    if hook is not None:
        hook.unhook()

def setup_name_characters():
    # make crystal-specific characters valid in names
    special_chars = "<> ()!,=*~"
    for char in special_chars:
        ida_name.set_cp_validity(ida_name.UCDR_MANGLED, ord(char))
