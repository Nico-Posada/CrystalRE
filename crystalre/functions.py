import ida_funcs
import ida_typeinf
import ida_name

from .symbols import split_true_colons, SymbolCache, SymbolType
from .base_types import name_to_tif
from .log import log, info, warning, debug

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

# Sets all the correct number of function params and sets the correct arg/ret val types if it exists in the idb
def fix_function_data():
    funcs = SymbolCache.get_symbols()
    count = 0

    info(f"Found {len(funcs)} functions to try to label.")
    for rva, parsed_sym in funcs.items():
        data = parsed_sym.symbol_data
        args = data.get("args", [])
        return_type = data.get("return_type", "Nil")
        should_add_self = not data.get("class_method?", True)
        
        # For the funcs that have a # in them, they pass the `this` variable as the first arg
        if should_add_self:
            args.insert(0, data.get("self_type", "Pointer(Void)"))
            # debug(f"Inserting self_type for {parsed_sym.orig_name!r} => {args}")

        # get the function
        func = ida_funcs.get_func(rva)
        if not func:
            # try to create function at this address
            if not ida_funcs.add_func(rva):
                warning(f"Failed to create function at {rva:#x}")
                continue
            func = ida_funcs.get_func(rva)
            if not func:
                warning(f"Failed to create function at {rva:#x} after adding it")
                continue

        # create function type data
        ftd = ida_typeinf.func_type_data_t()

        # set return type, but we need to handle Nil/NoReturn
        if return_type == "Nil":
            ftd.rettype = ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)
        elif return_type == "NoReturn":
            # set no return flag along with void return type
            ftd.flags |= ida_typeinf.FTI_NORET
            ftd.rettype = ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)
        else:
            # default to void if type not found in idb
            ret_tif = name_to_tif(return_type) or ida_typeinf.tinfo_t().get_stock(ida_typeinf.STI_PUNKNOWN)
            ftd.rettype = ret_tif

        # add arguments
        for i, arg_type in enumerate(args):
            funcarg = ida_typeinf.funcarg_t()
            # use auto generated names for everything but match funcs
            if parsed_sym.symbol_type == SymbolType.MATCH and len(args) == 1:
                funcarg.name = "type_id"
            elif should_add_self and i == 0:
                funcarg.name = "self"
            else:
                # leave as default names that ida/other plugin can set
                ...

            arg_tif = name_to_tif(arg_type) or ida_typeinf.tinfo_t().get_stock(ida_typeinf.STI_PVOID)
            funcarg.type = arg_tif
            ftd.push_back(funcarg)

        # create function type from data
        tif = ida_typeinf.tinfo_t()
        if not tif.create_func(ftd):
            warning(f"Failed to create function type for {parsed_sym.orig_name}")
            continue

        # im a bit iffy on using TINFO_DEFINITE here, but it's the only way to get IDA to respect the number of args we set
        if ida_typeinf.apply_tinfo(rva, tif, ida_typeinf.TINFO_DEFINITE):
            count += 1
            # info(f"Set type info for func @ {parsed_sym.rva:#x} ({parsed_sym.orig_name} => {args})")
        else:
            warning(f"Failed to apply function type for {parsed_sym.orig_name} @ {parsed_sym.rva:#x}")

    log(f"Fixed function arguments for {count} functions")
    return count