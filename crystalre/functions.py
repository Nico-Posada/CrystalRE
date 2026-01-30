import ida_funcs
import ida_typeinf
import ida_name
import idc
import ida_nalt
import ida_hexrays
import ida_auto

from .symbols import split_true_colons, SymbolCache, SymbolType
from .base_types import name_to_tif, is_numeric_type
from .log import log, info, warning, debug
from .cr_cc import get_cc_id

import re
# ex: Array(T), Hash::Entry(K, V)
GENERIC_METACLASS_PAT = re.compile(r"\b[TK]\b")

def set_function_names():
    # get all parsed symbols
        symbols = SymbolCache.get_symbols()

        # apply names to functions
        for rva, parsed_sym in symbols.items():
            final_name = "*" # prefix to tell the name demangler this is a crystal func

            if parsed_sym.symbol_type == SymbolType.FUNCTION:
                func_info = parsed_sym.symbol_data

                # add self_type if present (owner is optional)
                if 'self_type' in func_info:
                    final_name += func_info['self_type'] + ("::" if func_info.get("class_method?", True) else "#")

                # add function name (required)
                final_name += func_info['name']
                
                # not sure if I want to keep this, but i think it's better to keep the param types in the func name
                if "args" in func_info and func_info["args"]:
                    final_name += f"<{', '.join(func_info['args'])}>"

            elif parsed_sym.symbol_type == SymbolType.PROC:
                proc_info = parsed_sym.symbol_data
                final_name += f"~{proc_info['symbol_string']}"

                # this part isn't standard but whatever
                if proc_info['proc_num']:
                    final_name += f"[{proc_info['proc_num']}]"
            
            elif parsed_sym.symbol_type in (SymbolType.MATCH, SymbolType.OTHER):
                func_name = parsed_sym.orig_name
                # the function name is already fine so we can use the original name
                final_name += func_name 

            # set the name in IDA
            ida_name.set_name(rva, final_name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_FORCE)
            # log(f"Set name {final_name} @ {rva:#x}")

def create_functions():
    # pass 1: create functions at all symbol addresses
    funcs = SymbolCache.get_symbols()
    count = 0

    for rva in funcs.keys():
        if ida_funcs.get_func(rva):
            count += 1
            continue

        if ida_funcs.add_func(rva):
            count += 1
        else:
            warning(f"Failed to create function at {rva:#x}")

    log(f"Created/verified {count}/{len(funcs)} functions")
    return count

def set_function_types():
    # pass 2: set cc, return type, and args (bail if any type can't be resolved)
    funcs = SymbolCache.get_symbols()
    count = 0

    for rva, parsed_sym in funcs.items():
        data = parsed_sym.symbol_data
        args = data.get("args", [])
        return_type = data.get("return_type", "Nil")
        should_add_self = not data.get("class_method?", True)
        has_implicit_type_id = False

        # Nil args are literally nothing, they can be removed
        args = [arg for arg in args if arg != "Nil"]

        # for funcs that have a # in them, they pass the `this` variable as the first arg
        if should_add_self:
            args.insert(0, data.get("self_type", "Pointer(Void)"))

        # class methods with generic metaclass or virtual types get type id injected as first arg
        elif data.get("class_method?", False) and \
            (GENERIC_METACLASS_PAT.search(data.get("metaclass", "")) or data.get("self_type", "").endswith("+")):
            has_implicit_type_id = True
            args.insert(0, "UInt32")

        # validate return type
        if return_type in ("Nil", "NoReturn"):
            ret_tif = ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)
        else:
            ret_tif = name_to_tif(return_type, True)
            if ret_tif is None:
                continue

        # try to get tifs for all args - bail if any fail
        arg_tifs = []
        for i, arg_type in enumerate(args):
            arg_tif = name_to_tif(arg_type, True)
            if arg_tif is None:
                # edge case: allow unknown self type
                if i == 0 and should_add_self:
                    arg_tif = ida_typeinf.tinfo_t().get_stock(ida_typeinf.STI_PUNKNOWN)
                else:
                    break
            arg_tifs.append(arg_tif)

        if len(arg_tifs) != len(args):
            continue

        # build function type data
        ftd = ida_typeinf.func_type_data_t()
        ftd.set_cc(get_cc_id())
        ftd.rettype = ret_tif
        if return_type == "NoReturn":
            ftd.flags |= ida_typeinf.FTI_NORET

        for i, arg_tif in enumerate(arg_tifs):
            funcarg = ida_typeinf.funcarg_t()

            # set arg name
            if (parsed_sym.symbol_type == SymbolType.MATCH and len(args) == 1) or \
                has_implicit_type_id or \
                args[i].endswith(".class"):
                funcarg.name = "type_id"
            elif should_add_self and i == 0:
                funcarg.name = "self"
                # self args must be ptrs if they're large structs
                if not arg_tif.is_ptr() and not is_numeric_type(data.get("self_type", "")):
                    arg_tif.create_ptr(arg_tif)

            funcarg.type = arg_tif
            ftd.push_back(funcarg)

        # create and apply the tif
        new_tif = ida_typeinf.tinfo_t()
        if not new_tif.create_func(ftd):
            continue

        if ida_typeinf.apply_tinfo(rva, new_tif, ida_typeinf.TINFO_DEFINITE):
            count += 1

    log(f"Set function types for {count}/{len(funcs)} functions")
    return count

def fix_function_data():
    create_functions()
    set_function_types()