"""Process lifecycle checks with a harmless stand-in executable, no IDA license."""

import asyncio
import json
import sys
import time
from types import SimpleNamespace as NS

import pytest

from headless_ida_mcp_server.backend import IdaProcess
from headless_ida_mcp_server.compat import IDAError
from headless_ida_mcp_server.config import Settings


@pytest.fixture
def executable(tmp_path):
    script = tmp_path / "fake idat"
    script.write_text("#!" + sys.executable + "\nimport time\ntime.sleep(30)\n")
    script.chmod(0o700)
    return script


async def test_start_timeout_reaps_process(executable, tmp_path):
    binary = tmp_path / "input; no shell $substitution"
    binary.write_bytes(b"hello")
    backend = IdaProcess(Settings(ida_path=str(executable), startup_timeout=0.15))
    with pytest.raises(TimeoutError):
        await backend.start(binary)
    assert backend.process is not None
    assert backend.process.returncode is not None
    assert not backend.directory.exists()
    await backend.close()  # idempotent


async def test_start_cancel_reaps_process(executable, tmp_path):
    binary = tmp_path / "sample"
    binary.write_bytes(b"hello")
    backend = IdaProcess(Settings(ida_path=str(executable)))
    task = asyncio.create_task(backend.start(binary))
    async with asyncio.timeout(2):
        while backend.process is None:
            await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert backend.process.returncode is not None
    assert not backend.directory.exists()


async def test_early_exit_surfaces_error(executable, tmp_path):
    executable.write_text(
        "#!" + sys.executable + '\nprint("fixture failure", flush=True)\nraise SystemExit(7)\n'
    )
    backend = IdaProcess(Settings(ida_path=str(executable)))
    binary = tmp_path / "sample"
    binary.write_bytes(b"hello")
    with pytest.raises(IDAError, match="fixture failure"):
        await backend.start(binary)
    assert backend.process.returncode == 7
    assert not backend.directory.exists()


async def test_rpc_lookup_does_not_block_event_loop():
    class Connection:
        @property
        def root(self):
            time.sleep(0.05)
            return NS(call=lambda *args: json.dumps({"result": 42}))

    backend = IdaProcess(Settings())
    backend.connection = Connection()
    backend.process = NS(returncode=None)
    task = asyncio.create_task(backend.call("get_metadata", {}))
    await asyncio.sleep(0.005)
    assert not task.done()
    assert await task == 42


async def test_export_never_overwrites(tmp_path):
    backend = IdaProcess(Settings())
    backend.directory = tmp_path
    (tmp_path / "export.i64").write_bytes(b"new database")

    async def call(*args):
        return {"success": True}

    backend.call = call
    destination = tmp_path / "existing.i64"
    destination.write_bytes(b"keep this")
    with pytest.raises(FileExistsError):
        await backend.export(destination)
    assert destination.read_bytes() == b"keep this"
    fresh = tmp_path / "fresh.i64"
    assert (await backend.export(fresh))["success"]
    assert fresh.read_bytes() == b"new database"


async def test_parent_exit_with_child_holding_stdout_is_reclaimed(executable, tmp_path):
    executable.write_text(
        "#!" + sys.executable + "\n"
        "import subprocess, sys, os, time\n"
        'subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])\n'
        'print("parent exited", flush=True)\n'
        "os._exit(7)\n"
    )
    binary = tmp_path / "sample"
    binary.write_bytes(b"hello")
    backend = IdaProcess(Settings(ida_path=str(executable), startup_timeout=3))
    async with asyncio.timeout(6):
        with pytest.raises(IDAError, match="parent exited"):
            await backend.start(binary)
    assert backend.process.returncode == 7
    assert not backend.directory.exists()
