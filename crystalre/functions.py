import ida_funcs
import ida_typeinf
import ida_name
import idc
import ida_nalt
import ida_hexrays

from .symbols import split_true_colons, SymbolCache, SymbolType
from .base_types import name_to_tif, name_to_retloc, is_numeric_type
from .log import log, info, warning, debug

import re
GENERIC_METACLASS_PAT = re.compile(r"\bT\b")

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

# TODO: this was hacked together and i feel like this can be done way better 
def _try_set_retloc(return_type: str, ea: int, ret_type):
    tif = ida_typeinf.tinfo_t()
    fti = ida_typeinf.func_type_data_t()

    if ida_nalt.get_tinfo(tif, ea) and tif.is_func():
        if not tif.get_func_details(fti):
            return False

    # Set calling convention to __usercall (CM_CC_SPECIAL)
    # This tells IDA to use explicit arglocs for args and return
    fti.set_cc(ida_typeinf.CM_CC_SPECIAL)
    
    # set retloc if needed
    retloc = name_to_retloc(return_type)
    if retloc is None:
        return

    fti.rettype = ret_type
    fti.retloc = retloc
    fti.flags |= ida_typeinf.FTI_ARGLOCS | ida_typeinf.FTI_EXPLOCS

    new_tif = ida_typeinf.tinfo_t()
    if not new_tif.create_func(fti):
        return False

    if not ida_typeinf.apply_tinfo(ea, new_tif, ida_typeinf.TINFO_DEFINITE):
        return False

    ida_hexrays.mark_cfunc_dirty(ea, True) # Probably not needed?
    # log(f"Got to end for {ea:#x} @ {ea:#x}")
    return True

# Sets all the correct number of function params and sets the correct arg/ret val types if it exists in the idb
# TODO: If a binary contains dwarf data, IDA just assumes every function is of type `int __cdecl()` which makes decomps
# terrible to read, so we should detect if a function has that signature and remove it.
def fix_function_data():
    funcs = SymbolCache.get_symbols()
    count = 0

    info(f"Found {len(funcs)} functions to try to label.")
    for rva, parsed_sym in funcs.items():
        data = parsed_sym.symbol_data
        args = data.get("args", [])
        return_type = data.get("return_type", "Nil")
        should_add_self = not data.get("class_method?", True)
        has_implicit_type_id = False
        
        # Nil args are literally nothing, they can be removed
        args = [arg for arg in args if arg != "Nil"]
        
        # For the funcs that have a # in them, they pass the `this` variable as the first arg
        if should_add_self:
            args.insert(0, data.get("self_type", "Pointer(Void)"))
            # debug(f"Inserting self_type for {parsed_sym.orig_name!r} => {args}")
        
        # from the codegen, class methods that have a generic metaclass OR virtual types get this type id injected as the first arg
        elif data.get("class_method?", False) and \
            (GENERIC_METACLASS_PAT.search(data.get("metaclass", "")) or data.get("self_type", "").endswith("+")):
            has_implicit_type_id = True
            args.insert(0, "UInt32")

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

        # validate all types can be resolved before proceeding
        # check return type
        if return_type in ("Nil", "NoReturn"):
            ret_tif = ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)
        else:
            ret_tif = name_to_tif(return_type)
            if ret_tif is None:
                # skip this function if we can't resolve the return type
                # warning(f"Skipping {parsed_sym.orig_name} - unable to resolve return type {return_type!r}")
                continue

        # check all argument types
        arg_tifs = []
        for i, arg_type in enumerate(args):
            arg_tif = name_to_tif(arg_type)
            if arg_tif is None:
                # edge case we can allow
                if i > 0 or not should_add_self:
                    # skip this function if we can't resolve any argument type
                    break
                # stick to _UNKNOWN* rather than void* again
                arg_tif = ida_typeinf.tinfo_t().get_stock(ida_typeinf.STI_PUNKNOWN)
            arg_tifs.append(arg_tif)

        if len(arg_tifs) != len(args):
            # one or more arg types failed to resolve, skip this function
            continue

        # all types validated, now create function type data
        ftd = ida_typeinf.func_type_data_t()

        # set return type
        ftd.rettype = ret_tif
        if return_type == "NoReturn":
            ftd.flags |= ida_typeinf.FTI_NORET

        # add arguments
        for i, arg_tif in enumerate(arg_tifs):
            funcarg = ida_typeinf.funcarg_t()

            if parsed_sym.symbol_type == SymbolType.MATCH and len(args) == 1 or has_implicit_type_id:
                funcarg.name = "type_id"
            elif should_add_self and i == 0:
                funcarg.name = "self"
                # self args *MUST* be ptrs if they're large structs and not builtin numeric types
                arg_tif: ida_typeinf.tinfo_t
                if not arg_tif.is_ptr() and arg_tif.get_size() > 8 and \
                    not is_numeric_type(data.get("self_type", "")):
                    arg_tif.create_ptr(arg_tif)
            else:
                # leave as default names that ida/other plugins can set
                ...

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
            _try_set_retloc(return_type, rva, ret_tif)
            # info(f"Set type info for func @ {parsed_sym.rva:#x} ({parsed_sym.orig_name} => {args})")
        else:
            warning(f"Failed to apply function type for {parsed_sym.orig_name} @ {parsed_sym.rva:#x}")

    log(f"Fixed function arguments for {count} functions")
    return count