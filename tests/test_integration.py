"""Opt in with IDA_TEST_EXECUTABLE and IDA_TEST_BINARY; never uses API keys/LLMs."""

import os

import pytest

from headless_ida_mcp_server.config import Settings
from headless_ida_mcp_server.sessions import SessionManager

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not (os.getenv("IDA_TEST_EXECUTABLE") and os.getenv("IDA_TEST_BINARY")),
        reason="Set IDA_TEST_EXECUTABLE and IDA_TEST_BINARY for live IDA tests",
    ),
]


async def test_real_ida_roundtrip(tmp_path):
    manager = SessionManager(
        Settings(ida_path=os.environ["IDA_TEST_EXECUTABLE"], read_only=False, startup_timeout=90)
    )
    try:
        session = await manager.open(os.environ["IDA_TEST_BINARY"])
        sid = session["session_id"]
        metadata = await manager.call(sid, "get_metadata")
        assert metadata["function_count"] > 0
        functions = await manager.call(sid, "list_functions", limit=2)
        assert 0 < len(functions["data"]) <= 2
        assert functions["next_offset"] is not None
        main = await manager.call(sid, "get_function_by_name", name="main")
        address = main["address"]
        assert (await manager.call(sid, "disassemble_function", address=address))["data"]
        for name in ["list_segments", "list_imports", "list_strings", "get_entry_points"]:
            assert (await manager.call(sid, name, limit=2))["data"]
        for name in ["get_xrefs_to", "get_xrefs_from"]:
            assert "data" in await manager.call(sid, name, address=address)
        if metadata["decompiler_available"]:
            assert (await manager.call(sid, "decompile_function", address=address))["data"]
            await manager.call(
                sid, "set_decompiler_comment", address=address, comment="MCP test entry comment"
            )
        await manager.call(
            sid, "set_disassembly_comment", address=address, comment="MCP test annotation"
        )
        await manager.call(
            sid, "set_function_prototype", function_address=address, prototype="int main(void);"
        )
        await manager.call(
            sid, "rename_function", function_address=address, new_name="mcp_test_main"
        )
        assert (await manager.call(sid, "get_function_by_name", name="mcp_test_main"))[
            "address"
        ] == address
        destination = tmp_path / "roundtrip.i64"
        assert (await manager.call(sid, "save_idb_file", save_path=str(destination)))["success"]
        assert destination.stat().st_size > 0
        await manager.close(sid)
        reopened = await manager.open(str(destination))
        fn = await manager.call(
            reopened["session_id"], "get_function_by_name", name="mcp_test_main"
        )
        assert fn["address"] == address
    finally:
        await manager.close_all()
    assert not manager.sessions


async def test_real_ida_mcp_output_schemas():
    from mcp.shared.memory import create_connected_server_and_client_session

    from headless_ida_mcp_server.server import create_server

    server = create_server(Settings(ida_path=os.environ["IDA_TEST_EXECUTABLE"]))
    async with create_connected_server_and_client_session(server) as client:
        opened = await client.call_tool("open_binary", {"path": os.environ["IDA_TEST_BINARY"]})
        assert not opened.isError
        sid = opened.structuredContent["session_id"]
        main = await client.call_tool("get_function_by_name", {"name": "main", "session_id": sid})
        assert not main.isError
        ea = main.structuredContent["address"]
        for name in [
            "get_metadata",
            "list_functions",
            "list_strings",
            "list_segments",
            "list_imports",
            "get_entry_points",
        ]:
            result = await client.call_tool(name, {"session_id": sid})
            assert not result.isError, (name, result)
            assert result.structuredContent is not None
        for name in ["disassemble_function", "get_xrefs_to", "get_xrefs_from"]:
            result = await client.call_tool(name, {"address": ea, "session_id": sid})
            assert not result.isError, (name, result)
        metadata = await client.call_tool("get_metadata", {"session_id": sid})
        if metadata.structuredContent["decompiler_available"]:
            result = await client.call_tool(
                "decompile_function", {"address": ea, "session_id": sid}
            )
            assert not result.isError, result
        assert not (await client.call_tool("close_binary", {"session_id": sid})).isError
