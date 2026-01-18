import os
import json
import ida_name
import ida_typeinf
import ida_funcs
import idc

from .log import log, warning

def get_functions():
    # get path to cr_funcs.json relative to this file
    data_path = os.path.join(os.path.dirname(__file__), "data", "cr_funcs.json")

    try:
        with open(data_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        warning(f"Failed to load cr_funcs.json: {e}")
        return None

def apply_known_functions():
    funcs = get_functions()
    if funcs is None:
        return 0

    count = 0
    for func_name, prototype in funcs.items():
        # check if symbol exists in binary
        ea = ida_name.get_name_ea(idc.BADADDR, func_name)
        if ea == idc.BADADDR:
            continue

        # ensure function exists at address
        if not ida_funcs.get_func(ea):
            if not ida_funcs.add_func(ea):
                warning(f"Failed to create function at {ea:#x} for {func_name}")
                continue

        # parse the prototype
        tif = ida_typeinf.tinfo_t()
        if not ida_typeinf.parse_decl(tif, None, f"{prototype};", ida_typeinf.PT_SIL):
            warning(f"Failed to parse prototype for {func_name}: {prototype}")
            continue

        # apply type to function
        if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
            count += 1
        else:
            warning(f"Failed to apply type for {func_name} @ {ea:#x}")

    log(f"Applied prototypes to {count} known crystal functions")
    return count
