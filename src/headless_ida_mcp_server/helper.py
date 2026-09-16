"""Analysis operations executed INSIDE IDA, returning only JSON-compatible values.

Selected API compatibility and decompiler handling adapted from ida-pro-mcp,
MIT; see docs/UPSTREAM.md. No GUI state or global import monkey-patches.
"""

from __future__ import annotations

import importlib
import logging
from itertools import islice
from types import SimpleNamespace

from . import compat
from .compat import IDAError
from .models import (
    EntryPoint,
    Function,
    Import,
    Metadata,
    OperationResult,
    Page,
    Segment,
    String,
    TextLine,
    Xref,
)

logger = logging.getLogger(__name__)


def page(items, offset=0, limit=100):
    if not 0 <= offset <= 10_000_000 or not 1 <= limit <= 1000:
        raise IDAError("offset must be 0..10000000 and limit 1..1000")
    rows = list(islice(items, offset, offset + limit + 1))
    return {
        "data": rows[:limit],
        "offset": offset,
        "next_offset": offset + limit if len(rows) > limit else None,
    }


class IDA:
    """One instance per database, owned by the IDA process's main thread."""

    def __init__(self, modules=None):
        if modules is None:
            modules = SimpleNamespace()
            for name in (
                "idaapi",
                "idautils",
                "ida_entry",
                "ida_funcs",
                "ida_lines",
                "ida_nalt",
                "ida_name",
                "ida_typeinf",
                "idc",
                "ida_loader",
                "ida_segment",
                "ida_bytes",
            ):
                setattr(modules, name, importlib.import_module(name))
            for name in ("ida_hexrays", "ida_ida"):
                try:
                    setattr(modules, name, importlib.import_module(name))
                except ImportError:
                    setattr(modules, name, None)
        self.m = modules

    def _address(self, address):
        if (
            isinstance(address, bool)
            or not isinstance(address, int)
            or not 0 <= address < self.m.idaapi.BADADDR
        ):
            raise IDAError("Invalid address")
        return address

    def _function(self, address):
        fn = self.m.ida_funcs.get_func(self._address(address))
        if fn is None:
            raise IDAError(f"No function at {address:#x}")
        return fn

    def _row(self, fn, include_prototype=True):
        result = None
        if include_prototype:
            try:
                result = compat.prototype(self.m, fn)
            except Exception:
                logger.debug("Could not read function prototype", exc_info=True)
        return {
            "address": int(fn.start_ea),
            "end_address": int(fn.end_ea),
            "name": compat.function_name(self.m, fn),
            "prototype": result,
        }

    def get_function(self, address: int) -> Function:
        return self._row(self._function(address))

    def get_function_by_name(self, name: str) -> Function:
        address = self.m.ida_name.get_name_ea(self.m.idaapi.BADADDR, name)
        if address == self.m.idaapi.BADADDR:
            raise IDAError(f"No function named {name}")
        return self.get_function(address)

    def list_functions(
        self, offset=0, limit=100, query="", include_prototype=False
    ) -> Page[Function]:
        def rows():
            for address in self.m.idautils.Functions():
                fn = self.m.ida_funcs.get_func(address)
                if fn is not None:
                    row = self._row(fn, False)
                    if query.casefold() in row["name"].casefold():
                        yield row

        result = page(rows(), offset, limit)
        # Expensive type information is loaded only for returned rows, not skipped rows.
        if include_prototype:
            result["data"] = [self.get_function(row["address"]) for row in result["data"]]
        return result

    def get_metadata(self) -> Metadata:
        low, high, processor, bits = compat.database_info(self.m)
        hx = self.m.ida_hexrays
        return {
            "ida_version": self.m.idaapi.get_kernel_version(),
            "processor": processor,
            "bits": bits,
            "image_base": int(self.m.ida_nalt.get_imagebase()),
            "min_address": int(low),
            "max_address": int(high),
            "function_count": self.m.ida_funcs.get_func_qty(),
            "decompiler_available": bool(hx and hx.init_hexrays_plugin()),
        }

    def list_segments(self, offset=0, limit=100) -> Page[Segment]:
        def rows():
            for ea in self.m.idautils.Segments():
                seg = self.m.ida_segment.getseg(ea)
                if seg is not None:
                    yield {
                        "address": int(seg.start_ea),
                        "end_address": int(seg.end_ea),
                        "name": self.m.ida_segment.get_segm_name(seg),
                        "permissions": int(seg.perm),
                    }

        return page(rows(), offset, limit)

    def list_strings(self, offset=0, limit=100, query="") -> Page[String]:
        def rows():
            for item in self.m.idautils.Strings():
                text = str(item)
                if query.casefold() in text.casefold():
                    yield {
                        "address": int(item.ea),
                        "length": int(item.length),
                        "text": text[:4096],
                        "truncated": len(text) > 4096,
                    }

        return page(rows(), offset, limit)

    def list_imports(self, offset=0, limit=100, query="") -> Page[Import]:
        # IDA enumerates imports through callbacks, so stop after one lookahead row.
        if not 0 <= offset <= 10_000_000 or not 1 <= limit <= 1000:
            raise IDAError("Invalid pagination")
        rows = []
        matched = 0
        for index in range(self.m.ida_nalt.get_import_module_qty()):
            module = self.m.ida_nalt.get_import_module_name(index) or ""

            def collect(ea, name, ordinal):
                nonlocal matched
                name = name or f"ordinal_{ordinal}"
                if query.casefold() in name.casefold():
                    if matched >= offset:
                        rows.append(
                            {
                                "address": int(ea),
                                "name": name,
                                "module": module,
                                "ordinal": int(ordinal),
                            }
                        )
                    matched += 1
                return len(rows) <= limit

            self.m.ida_nalt.enum_import_names(index, collect)
            if len(rows) > limit:
                break
        return {
            "data": rows[:limit],
            "offset": offset,
            "next_offset": offset + limit if len(rows) > limit else None,
        }

    def get_entry_points(self, offset=0, limit=100) -> Page[EntryPoint]:
        def rows():
            entry = self.m.ida_entry
            for i in range(entry.get_entry_qty()):
                ordinal = entry.get_entry_ordinal(i)
                ea = entry.get_entry(ordinal)
                fn = self.m.ida_funcs.get_func(ea)
                yield {
                    "address": int(ea),
                    "ordinal": int(ordinal),
                    "name": entry.get_entry_name(ordinal) or "",
                    "function": self._row(fn, False) if fn is not None else None,
                }

        return page(rows(), offset, limit)

    def _xrefs(self, address, direction, offset, limit):
        self._address(address)
        source = self.m.idautils.XrefsTo if direction == "to" else self.m.idautils.XrefsFrom

        def rows():
            for ref in source(address, 0):
                ea = ref.frm if direction == "to" else ref.to
                fn = self.m.ida_funcs.get_func(ea)
                yield {
                    "address": int(ea),
                    "type": "code" if ref.iscode else "data",
                    "function": self._row(fn, False) if fn is not None else None,
                }

        return page(rows(), offset, limit)

    def get_xrefs_to(self, address: int, offset=0, limit=100) -> Page[Xref]:
        return self._xrefs(address, "to", offset, limit)

    def get_xrefs_from(self, address: int, offset=0, limit=100) -> Page[Xref]:
        return self._xrefs(address, "from", offset, limit)

    def decompile_function(self, address: int, offset=0, limit=100) -> Page[TextLine]:
        cfunc = compat.decompile(self.m, self._address(address))
        hx = self.m.ida_hexrays

        def rows():
            for index, sl in enumerate(cfunc.get_pseudocode()):
                ea = int(cfunc.entry_ea) if index == 0 else None
                head, item, tail = (hx.ctree_item_t() for _ in range(3))
                if cfunc.get_line_item(sl.line, 0, False, head, item, tail):
                    # Same conservative fallback as upstream: not every line maps to an address.
                    description = item.dstr() or ""
                    parts = description.split(": ", 1)
                    if len(parts) == 2:
                        try:
                            ea = int(parts[0], 16)
                        except ValueError:
                            pass
                text = self.m.ida_lines.tag_remove(sl.line)
                yield {
                    "line": index,
                    "address": ea,
                    "text": text[:16384],
                    "truncated": len(text) > 16384,
                }

        return page(rows(), offset, limit)

    def disassemble_function(self, address: int, offset=0, limit=100) -> Page[TextLine]:
        fn = self._function(address)

        def rows():
            for index, ea in enumerate(self.m.idautils.FuncItems(fn.start_ea)):
                text = self.m.idc.generate_disasm_line(ea, 0) or ""
                text = self.m.ida_lines.tag_remove(text)
                comment = self.m.ida_bytes.get_cmt(ea, False) or self.m.ida_bytes.get_cmt(ea, True)
                if comment:
                    text += f" ; {comment}"
                yield {
                    "line": index,
                    "address": int(ea),
                    "text": text[:16384],
                    "truncated": len(text) > 16384,
                }

        return page(rows(), offset, limit)

    def _dirty(self, address):
        hx = self.m.ida_hexrays
        if hx and hx.init_hexrays_plugin():
            hx.mark_cfunc_dirty(address, False)

    def refresh_decompiler_ctext(self, function_address: int) -> OperationResult:
        self._dirty(self._function(function_address).start_ea)
        return {"success": True, "message": "Decompiler cache invalidated"}

    def rename_function(self, function_address: int, new_name: str) -> OperationResult:
        fn = self._function(function_address)
        if not self.m.ida_name.set_name(fn.start_ea, new_name, self.m.ida_name.SN_CHECK):
            raise IDAError("Rename failed; check for an invalid or duplicate name")
        self._dirty(fn.start_ea)
        return {"success": True, "message": "Function renamed"}

    def rename_local_variable(
        self, function_address: int, old_name: str, new_name: str
    ) -> OperationResult:
        fn = self._function(function_address)
        compat.decompile(self.m, fn.start_ea)
        if not self.m.ida_hexrays.rename_lvar(fn.start_ea, old_name, new_name):
            raise IDAError("Local variable rename failed")
        self._dirty(fn.start_ea)
        return {"success": True, "message": "Local variable renamed"}

    def set_disassembly_comment(self, address: int, comment: str) -> OperationResult:
        self._address(address)
        if not self.m.ida_bytes.set_cmt(address, comment, False):
            raise IDAError("Failed to set disassembly comment")
        fn = self.m.ida_funcs.get_func(address)
        if fn is not None:
            self._dirty(fn.start_ea)
        return {"success": True, "message": "Disassembly comment set"}

    def set_decompiler_comment(self, address: int, comment: str) -> OperationResult:
        cfunc = compat.decompile(self.m, self._address(address))
        if address == cfunc.entry_ea:
            if not self.m.idc.set_func_cmt(address, comment, True):
                raise IDAError("Failed to set function comment")
            cfunc.refresh_func_ctext()
            return {"success": True, "message": "Function comment set"}
        eamap = cfunc.get_eamap()
        if address not in eamap or not eamap[address]:
            raise IDAError("No pseudocode statement maps to this address")
        hx = self.m.ida_hexrays
        location = hx.treeloc_t()
        location.ea = eamap[address][0].ea
        # Never delete all orphan comments: they may contain unrelated user annotations.
        location.itp = hx.ITP_SEMI
        old = cfunc.get_user_cmt(location, hx.RETRIEVE_ALWAYS)
        cfunc.set_user_cmt(location, comment)
        cfunc.refresh_func_ctext()
        if cfunc.has_orphan_cmts():
            cfunc.set_user_cmt(location, old or "")
            cfunc.refresh_func_ctext()
            raise IDAError("Comment location is ambiguous; previous comment preserved")
        cfunc.save_user_cmts()
        return {"success": True, "message": "Decompiler comment set"}

    def set_function_prototype(self, function_address: int, prototype: str) -> OperationResult:
        fn = self._function(function_address)
        ti = self.m.ida_typeinf
        tif = ti.tinfo_t()
        if not ti.parse_decl(tif, None, prototype, ti.PT_SIL) or not tif.is_func():
            raise IDAError("Declaration is not a valid function prototype")
        # PT_SIL is a parse flag, not an apply_tinfo flag.
        if not ti.apply_tinfo(fn.start_ea, tif, ti.TINFO_DEFINITE):
            raise IDAError("Failed to apply function prototype")
        self._dirty(fn.start_ea)
        return {"success": True, "message": "Function prototype updated"}

    def save_idb_file(self, save_path: str) -> OperationResult:
        if not self.m.ida_loader.save_database(save_path, 0):
            raise IDAError("IDA failed to save the database")
        return {"success": True, "message": "Database saved"}
