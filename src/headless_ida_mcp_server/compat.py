"""Capability-based IDAPython compatibility.

Adapted from ida-pro-mcp (Duncan Ogilvie and contributors), MIT.
Upstream provenance and modifications: docs/UPSTREAM.md and licenses/.
"""

from __future__ import annotations


class IDAError(RuntimeError):
    """An expected analysis error safe to report to the client."""


def function_name(modules, fn):
    if hasattr(fn, "get_name"):
        return fn.get_name() or ""
    return modules.ida_funcs.get_func_name(fn.start_ea) or ""


def prototype(modules, fn):
    if hasattr(fn, "get_prototype"):
        tif = fn.get_prototype()
        if tif is not None:
            return str(tif)
    tif = modules.ida_typeinf.tinfo_t()
    if modules.ida_nalt.get_tinfo(tif, fn.start_ea) and tif.is_func():
        return str(tif)
    return modules.idc.get_type(fn.start_ea)


def decompile(modules, address):
    hx = modules.ida_hexrays
    if hx is None or not hx.init_hexrays_plugin():
        raise IDAError("Hex-Rays is unavailable; use disassemble_function instead")
    fn = modules.ida_funcs.get_func(address)
    if fn is None:
        raise IDAError(f"No function at {address:#x}")
    error = hx.hexrays_failure_t()
    flags = getattr(hx, "DECOMP_WARNINGS", 0)
    if hasattr(hx, "decompile_function"):
        result = hx.decompile_function(fn.start_ea, error, flags)
    elif hasattr(hx, "decompile"):
        result = hx.decompile(fn.start_ea, error, flags)
    else:
        # decompile_func expects func_t, NOT an integer address.
        result = hx.decompile_func(fn, error, flags)
    if not result:
        if getattr(error, "code", None) == getattr(hx, "MERR_LICENSE", object()):
            raise IDAError("Decompiler license unavailable; use disassemble_function instead")
        raise IDAError(f"Decompilation failed at {address:#x}: {getattr(error, 'str', '')}")
    return result


def database_info(modules):
    info = modules.ida_ida
    if info is not None and hasattr(info, "inf_get_min_ea"):
        return (
            info.inf_get_min_ea(),
            info.inf_get_max_ea(),
            info.inf_get_procname(),
            64 if info.inf_is_64bit() else 32 if info.inf_is_32bit_exactly() else 16,
        )
    legacy = modules.idaapi.get_inf_structure()
    return (
        legacy.min_ea,
        legacy.max_ea,
        legacy.procname,
        64 if legacy.is_64bit() else 32 if legacy.is_32bit_exactly() else 16,
    )
