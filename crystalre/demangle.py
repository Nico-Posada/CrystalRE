# The only way to show special characters in a function name without it defaulting to underscores
# is to set up an ev_demangle_name hook (i think), so this is what this file is for

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

def set_valid_chars():
    # make some crystal-specific characters valid in names
    special_chars = "~, !@#%^&*()-=<>/+|"
    for char in special_chars:
        ida_name.set_cp_validity(ida_name.UCDR_MANGLED, ord(char))
