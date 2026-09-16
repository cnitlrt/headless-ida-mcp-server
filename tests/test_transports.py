"""Real loopback HTTP/SSE transports plus connection-scoped database state."""

import asyncio
import socket
from contextlib import asynccontextmanager
from datetime import timedelta

import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.memory import create_connected_server_and_client_session

from headless_ida_mcp_server.config import Settings
from headless_ida_mcp_server.server import create_server


class MinimalBackend:
    instances = []

    def __init__(self, settings):
        self.closed = False
        self.instances.append(self)

    async def start(self, path):
        pass

    async def close(self):
        self.closed = True


@pytest.fixture
def fake_binary(tmp_path, monkeypatch):
    MinimalBackend.instances = []
    monkeypatch.setattr("headless_ida_mcp_server.sessions.IdaProcess", MinimalBackend)
    path = tmp_path / "fixture"
    path.write_bytes(b"fixture")
    return str(path)


async def check_isolation(connect, path):
    async with connect() as first:
        one = await first.call_tool("open_binary", {"path": path})
        assert not one.isError
        sid = one.structuredContent["session_id"]
        async with connect() as second:
            result = await second.call_tool("list_sessions", {})
            assert result.structuredContent["result"] == []
            result = await second.call_tool("close_binary", {"session_id": sid})
            assert result.isError
            two = await second.call_tool("open_binary", {"path": path})
            assert not two.isError
            result = await first.call_tool("open_binary", {"path": path})
            assert result.isError  # shared server-wide process quota
        assert MinimalBackend.instances[1].closed
        assert not MinimalBackend.instances[0].closed
        result = await first.call_tool("list_sessions", {})
        assert result.structuredContent["result"][0]["session_id"] == sid
    assert all(b.closed for b in MinimalBackend.instances)
    # A later client must not inherit a closed manager.
    async with connect() as third:
        assert not (await third.call_tool("open_binary", {"path": path})).isError
    assert all(b.closed for b in MinimalBackend.instances)


async def test_connection_scoped_lifespan(fake_binary):
    app = create_server(Settings(max_sessions=2))
    await check_isolation(lambda: create_connected_server_and_client_session(app), fake_binary)


@pytest.mark.parametrize("transport", ["sse", "streamable-http"])
async def test_network_transport(transport, fake_binary, monkeypatch):
    # sse-starlette 2.x keeps an event bound to the prior pytest event loop.
    # Production uses one loop; isolate this dependency's globals between tests.
    from sse_starlette.sse import AppStatus

    monkeypatch.setattr(AppStatus, "should_exit_event", None)
    monkeypatch.setattr(AppStatus, "should_exit", False)
    mcp = create_server(Settings(max_sessions=2))
    app = mcp.sse_app() if transport == "sse" else mcp.streamable_http_app()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.setblocking(False)
    port = listener.getsockname()[1]
    runner = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="on", ws="none"))
    task = asyncio.create_task(runner.serve(sockets=[listener]))

    @asynccontextmanager
    async def connect():
        url = f"http://127.0.0.1:{port}"
        transport_cm = (
            sse_client(url + "/sse") if transport == "sse" else streamable_http_client(url + "/mcp")
        )
        async with transport_cm as streams:
            async with ClientSession(
                streams[0], streams[1], read_timeout_seconds=timedelta(seconds=5)
            ) as client:
                await client.initialize()
                yield client
        # SSE cleanup is scheduled after the disconnect is observed server-side.
        await asyncio.sleep(0.05)

    try:
        async with asyncio.timeout(15):
            while not runner.started:
                if task.done():
                    await task
                await asyncio.sleep(0.01)
            await check_isolation(connect, fake_binary)
    finally:
        runner.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()
