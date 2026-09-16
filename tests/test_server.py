import os
import sys
from datetime import timedelta

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.memory import create_connected_server_and_client_session

from headless_ida_mcp_server.config import Settings
from headless_ida_mcp_server.server import create_server
from headless_ida_mcp_server.sessions import SessionManager


async def test_protocol_schemas_and_errors():
    settings = Settings(host="127.0.0.2", port=9123)
    manager = SessionManager(settings)
    server = create_server(settings, manager)
    assert server.settings.host == "127.0.0.2"
    assert server.settings.port == 9123
    async with create_connected_server_and_client_session(server) as client:
        tools = (await client.list_tools()).tools
        assert all(t.outputSchema for t in tools)
        names = {t.name for t in tools}
        assert "decompile_checked" not in names
        assert "get_current_address" not in names
        assert "rename_function" not in names
        result = await client.call_tool("convert_number", {"text": "255"})
        assert not result.isError
        assert result.structuredContent["bytes"] == "ff"
        result = await client.call_tool("list_functions", {"limit": 0})
        assert result.isError
        result = await client.call_tool("get_function", {"address": 123})
        assert result.isError
        result = await client.call_tool("health", {})
        assert result.structuredContent["status"] == "ok"
    assert manager._closed


async def test_write_tools_opt_in():
    tools = await create_server(Settings(read_only=False)).list_tools()
    mapping = {t.name: t for t in tools}
    for name in ("rename_function", "save_idb_file", "set_function_prototype"):
        assert mapping[name].annotations.destructiveHint
        assert mapping[name].outputSchema


async def test_stdio_handshake(tmp_path):
    env = os.environ.copy()
    env.update(HOST="127.0.0.1", TRANSPORT="stdio")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_ida_mcp_server", "--env-file", str(tmp_path / "none")],
        env=env,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=10)) as client:
            await client.initialize()
            result = await client.call_tool("convert_number", {"text": "-129"})
            assert result.structuredContent["bytes"] == "7f ff"
            assert not result.isError
