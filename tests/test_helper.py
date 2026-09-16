from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest

from headless_ida_mcp_server import compat
from headless_ida_mcp_server.compat import IDAError
from headless_ida_mcp_server.helper import IDA, page
from headless_ida_mcp_server.models import Function


@pytest.fixture
def modules():
    functions = {ea: NS(start_ea=ea, end_ea=ea + 8) for ea in [16, 32, 48, 64]}
    return NS(
        idaapi=NS(BADADDR=2**64 - 1, get_kernel_version=lambda: "9.0"),
        ida_funcs=NS(
            get_func=lambda ea: functions.get(ea),
            get_func_name=lambda ea: f"fn_{ea}",
            get_func_qty=lambda: len(functions),
        ),
        idautils=NS(Functions=lambda: iter(functions)),
        ida_typeinf=NS(tinfo_t=lambda: NS(is_func=lambda: True)),
        ida_nalt=NS(get_tinfo=lambda *args: False, get_imagebase=lambda: 16),
        idc=NS(get_type=Mock(return_value="int sample(void)")),
        ida_hexrays=None,
        ida_ida=NS(
            inf_get_min_ea=lambda: 16,
            inf_get_max_ea=lambda: 72,
            inf_get_procname=lambda: "metapc",
            inf_is_64bit=lambda: True,
        ),
    )


def test_function_contract(modules):
    row = IDA(modules).get_function(16)
    assert set(row) == set(Function.__annotations__)
    assert row["prototype"] == "int sample(void)"
    assert row["name"] == "fn_16"


def test_pagination_avoids_prototypes_for_skipped_rows(modules):
    api = IDA(modules)
    result = api.list_functions(offset=1, limit=1, include_prototype=True)
    assert [row["address"] for row in result["data"]] == [32]
    assert result["next_offset"] == 2
    assert modules.idc.get_type.call_count == 1
    assert api.list_functions(query="FN_48")["data"][0]["address"] == 48
    assert api.list_functions(offset=4)["data"] == []


def test_lazy_page():
    seen = []

    def items():
        for i in range(100000):
            seen.append(i)
            yield i

    assert page(items(), 2, 3) == {"data": [2, 3, 4], "offset": 2, "next_offset": 5}
    assert len(seen) == 6
    assert page(iter([1]), 0, 1)["next_offset"] is None
    with pytest.raises(IDAError):
        page(iter([]), 0, 0)


@pytest.mark.parametrize("version", ["new", "normal", "legacy"])
def test_decompile_api_dispatch(modules, version):
    function = modules.ida_funcs.get_func(16)
    target = Mock(return_value=object())
    hx = NS(init_hexrays_plugin=lambda: True, hexrays_failure_t=lambda: NS(), DECOMP_WARNINGS=1)
    setattr(
        hx,
        {"new": "decompile_function", "normal": "decompile", "legacy": "decompile_func"}[version],
        target,
    )
    modules.ida_hexrays = hx
    compat.decompile(modules, 16)
    first = target.call_args.args[0]
    assert first is function if version == "legacy" else first == 16


def test_missing_license(modules):
    hx = NS(
        init_hexrays_plugin=lambda: True,
        MERR_LICENSE=-42,
        hexrays_failure_t=lambda: NS(code=-42),
        decompile=lambda *args: None,
    )
    modules.ida_hexrays = hx
    with pytest.raises(IDAError, match="license"):
        compat.decompile(modules, 16)


def test_missing_hexrays_and_invalid_function(modules):
    api = IDA(modules)
    assert api.get_metadata()["decompiler_available"] is False
    with pytest.raises(IDAError, match="unavailable"):
        api.decompile_function(16)
    with pytest.raises(IDAError, match="No function"):
        api.get_function(9)
    with pytest.raises(IDAError, match="Invalid address"):
        api.get_function(-1)


def test_modern_prototype_and_name(modules):
    fn = NS(get_name=lambda: "modern", get_prototype=lambda: "void modern(void)")
    assert compat.function_name(modules, fn) == "modern"
    assert compat.prototype(modules, fn) == "void modern(void)"


def test_legacy_database_info(modules):
    modules.ida_ida = None
    modules.idaapi.get_inf_structure = lambda: NS(
        min_ea=1, max_ea=9, procname="x86", is_64bit=lambda: False, is_32bit_exactly=lambda: True
    )
    assert compat.database_info(modules) == (1, 9, "x86", 32)


def test_prototype_flags_and_invalidation(modules):
    modules.ida_typeinf.parse_decl = Mock(return_value=True)
    modules.ida_typeinf.apply_tinfo = Mock(return_value=True)
    modules.ida_typeinf.PT_SIL = 1
    modules.ida_typeinf.TINFO_DEFINITE = 8
    modules.ida_hexrays = NS(init_hexrays_plugin=lambda: True, mark_cfunc_dirty=Mock())
    IDA(modules).set_function_prototype(16, "int sample(void);")
    assert modules.ida_typeinf.apply_tinfo.call_args.args[-1] == 8
    modules.ida_hexrays.mark_cfunc_dirty.assert_called_once_with(16, False)


def test_save_failure_not_success(modules):
    modules.ida_loader = NS(save_database=lambda *args: False)
    with pytest.raises(IDAError, match="save"):
        IDA(modules).save_idb_file("/unused")


def test_imports_pagination_across_modules(modules):
    def enumerate_names(index, callback):
        for i in range(3):
            if not callback(index * 10 + i, f"name_{index}_{i}", i):
                break

    modules.ida_nalt.get_import_module_qty = lambda: 2
    modules.ida_nalt.get_import_module_name = lambda i: f"module_{i}"
    modules.ida_nalt.enum_import_names = enumerate_names
    result = IDA(modules).list_imports(offset=2, limit=2)
    assert [row["name"] for row in result["data"]] == ["name_0_2", "name_1_0"]
    assert result["next_offset"] == 4
    assert IDA(modules).list_imports(query="name_1_2")["next_offset"] is None


def test_strings_truncation_is_explicit(modules):
    class Text:
        ea = 16
        length = 5000

        def __str__(self):
            return "A" * self.length

    modules.idautils.Strings = lambda: [Text()]
    row = IDA(modules).list_strings()["data"][0]
    assert len(row["text"]) == 4096
    assert row["length"] == 5000
    assert row["truncated"] is True


def test_entry_points_do_not_drop_nonfunctions(modules):
    modules.ida_entry = NS(
        get_entry_qty=lambda: 1,
        get_entry_ordinal=lambda i: 1,
        get_entry=lambda ordinal: 1000,
        get_entry_name=lambda ordinal: "data_entry",
    )
    row = IDA(modules).get_entry_points()["data"][0]
    assert row["function"] is None
    assert row["name"] == "data_entry"


def test_xrefs_both_directions(modules):
    modules.idautils.XrefsTo = lambda *args: [NS(frm=32, to=16, iscode=True)]
    modules.idautils.XrefsFrom = lambda *args: [NS(frm=16, to=1000, iscode=False)]
    api = IDA(modules)
    assert api.get_xrefs_to(16)["data"][0]["function"]["address"] == 32
    assert api.get_xrefs_from(16)["data"][0] == {"address": 1000, "type": "data", "function": None}


def test_disassembly_missing_text_and_comments(modules):
    modules.idautils.FuncItems = lambda ea: [16, 17]
    modules.idc.generate_disasm_line = lambda ea, flags: "ret" if ea == 16 else None
    modules.ida_lines = NS(tag_remove=lambda text: text)
    modules.ida_bytes = NS(get_cmt=lambda ea, repeatable: "note" if repeatable else None)
    rows = IDA(modules).disassemble_function(16)["data"]
    assert rows[0]["text"] == "ret ; note"
    assert rows[1]["text"] == " ; note"
    assert rows[0]["truncated"] is False


def test_interior_comment_restores_previous_without_deleting_orphans(modules, monkeypatch):
    from headless_ida_mcp_server import compat

    cfunc = NS(
        entry_ea=16,
        get_eamap=lambda: {17: [NS(ea=17)]},
        get_user_cmt=lambda *args: "previous",
        set_user_cmt=Mock(),
        refresh_func_ctext=Mock(),
        has_orphan_cmts=lambda: True,
        save_user_cmts=Mock(),
    )
    monkeypatch.setattr(compat, "decompile", lambda *args: cfunc)
    modules.ida_hexrays = NS(treeloc_t=NS, ITP_SEMI=1, RETRIEVE_ALWAYS=0)
    with pytest.raises(IDAError, match="preserved"):
        IDA(modules).set_decompiler_comment(17, "new")
    assert cfunc.set_user_cmt.call_args_list[-1].args[-1] == "previous"
    cfunc.save_user_cmts.assert_not_called()
