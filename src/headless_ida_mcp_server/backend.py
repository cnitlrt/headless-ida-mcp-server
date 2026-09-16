"""Managed idat process, bounded startup/RPC, explicit cleanup and JSON batching."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
import signal
import site
import tempfile
from contextlib import suppress
from pathlib import Path

import rpyc

from .compat import IDAError
from .config import Settings
from .logger import logger


class IdaProcess:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.process = None
        self.connection = None
        self._remote_call = None
        self._temporary = None
        self.directory = None
        self._drain_task = None
        self._log_tail = b""
        self._token = secrets.token_urlsafe(32)
        self._closing = asyncio.Lock()
        self._group_id = None

    async def start(self, binary: Path):
        try:
            async with asyncio.timeout(self.settings.startup_timeout):
                await self._start(binary)
        except BaseException:
            await asyncio.shield(self.close())
            raise

    async def _start(self, binary: Path):
        executable = self.settings.executable()
        self._temporary = tempfile.TemporaryDirectory(prefix="ida-mcp-")
        self.directory = Path(self._temporary.name)
        # All IDA database sidecars are confined to this directory.
        target = self.directory / ("input" + binary.suffix)
        # Local bounded-size copy. Await the thread even on cancellation before cleanup.
        copy_task = asyncio.create_task(asyncio.to_thread(shutil.copyfile, binary, target))
        try:
            await asyncio.shield(copy_task)
        except asyncio.CancelledError:
            await copy_task
            raise
        config = self.directory / "bridge.json"
        ready = self.directory / "ready.json"
        config.write_text(
            json.dumps(
                {
                    "token": self._token,
                    "ready_path": str(ready),
                    "export_path": str(self.directory / "export.i64"),
                    "read_only": self.settings.read_only,
                }
            )
        )
        config.chmod(0o600)
        script = Path(__file__).with_name("ida_bridge.py").resolve()
        if any('"' in str(p) or "\n" in str(p) for p in (script, config)):
            raise ValueError("Unsupported quote/newline in installation path")
        args = [
            str(executable),
            "-A",
            f"-L{self.directory / 'ida.log'}",
            f'-S"{script}" "{config}"',
        ]
        if binary.suffix.lower() not in {".idb", ".i64"}:
            args.append(f"-o{self.directory / 'analysis.i64'}")
        args.append(str(target))
        env = os.environ.copy()
        # Only pure Python RPyC/plumbum and our bridge are needed by IDAPython.
        paths = [str(script.parent.parent), *site.getsitepackages()]
        if env.get("PYTHONPATH"):
            paths.append(env["PYTHONPATH"])
        env["PYTHONPATH"] = os.pathsep.join(paths)
        spawn = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *args,
                cwd=self.directory,
                env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=(os.name == "posix"),
            )
        )
        try:
            self.process = await asyncio.shield(spawn)
        except asyncio.CancelledError:
            self.process = await spawn
            self._group_id = self.process.pid if os.name == "posix" else None
            raise
        self._group_id = self.process.pid if os.name == "posix" else None
        self._drain_task = asyncio.create_task(self._drain())
        while not ready.exists():
            if self.process.returncode is not None:
                # A plugin's child might still hold stdout open after IDA exited.
                with suppress(TimeoutError):
                    await asyncio.wait_for(asyncio.shield(self._drain_task), 0.2)
                log = self.directory / "ida.log"
                detail = ""
                if log.exists():
                    with log.open("rb") as stream:
                        stream.seek(max(0, log.stat().st_size - 6000))
                        detail = stream.read(6000).decode(errors="replace")
                raise IDAError(
                    f"IDA exited during startup ({self.process.returncode}): "
                    + self._log_tail.decode(errors="replace")[-2000:]
                    + detail
                )
            await asyncio.sleep(0.05)
        port = json.loads(ready.read_text())["port"]
        connect = asyncio.create_task(
            asyncio.to_thread(
                rpyc.connect,
                "127.0.0.1",
                port,
                config={
                    "sync_request_timeout": self.settings.request_timeout,
                    "allow_public_attrs": False,
                    "allow_all_attrs": False,
                    "allow_pickle": False,
                },
            )
        )
        try:
            self.connection = await asyncio.shield(connect)
        except asyncio.CancelledError:
            # Establish ownership before teardown if cancellation races with connect().
            try:
                self.connection = await connect
            finally:
                raise
        await self.call("get_metadata", {})

    async def _drain(self):
        while chunk := await self.process.stdout.read(4096):
            self._log_tail = (self._log_tail + chunk)[-16384:]
            # Never forward IDA stdout to MCP stdout, which is reserved for JSON-RPC.
            logger.debug("IDA: %s", chunk.decode(errors="replace")[:512])

    async def call(self, operation: str, arguments: dict):
        if self.connection is None or self.process.returncode is not None:
            raise ConnectionError("IDA process is not running")
        payload = json.dumps(arguments)
        if len(payload) > 65536:
            raise ValueError("Request exceeds 64 KiB")
        connection = self.connection

        # root and exposed attribute lookup are RPCs too: keep them off the event loop.
        def invoke():
            if self._remote_call is None:
                self._remote_call = connection.root.call
            return self._remote_call(self._token, operation, payload)

        raw = await asyncio.to_thread(invoke)
        response = json.loads(raw)
        if "error" in response:
            raise IDAError(response["error"]["message"])
        return response["result"]

    async def export(self, destination: Path):
        await self.call("save_idb_file", {})
        source = self.directory / "export.i64"
        if not source.is_file():
            raise IDAError("IDA did not produce the requested database")

        # Exclusive create: no silent overwrite, including races with other sessions.
        # Keep the session lock and wait for the copy before removing its source.
        def copy():
            created = False
            try:
                with destination.open("xb") as output:
                    created = True
                    with source.open("rb") as data:
                        shutil.copyfileobj(data, output)
            except BaseException:
                if created:
                    destination.unlink(missing_ok=True)
                raise

        task = asyncio.create_task(asyncio.to_thread(copy))
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            await task
            raise
        return {"success": True, "message": f"Database saved to {destination}"}

    async def close(self):
        async with self._closing:
            # Terminate IDA first so a blocked RPC thread wakes before connection cleanup.
            group_id, self._group_id = self._group_id, None
            if self.process is not None and (
                self.process.returncode is None or group_id is not None
            ):
                try:
                    if group_id is not None:
                        os.killpg(group_id, signal.SIGTERM)
                    else:
                        self.process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(self.process.wait(), 3)
                except TimeoutError:
                    try:
                        if group_id is not None:
                            os.killpg(group_id, signal.SIGKILL)
                        else:
                            self.process.kill()
                    except ProcessLookupError:
                        pass
                    await self.process.wait()
                # The parent may exit before a child that ignored SIGTERM. Reclaim
                # the owned group even when process.wait() has already completed.
                if group_id is not None:
                    with suppress(ProcessLookupError):
                        os.killpg(group_id, signal.SIGKILL)
            if self.connection is not None:
                connection, self.connection = self.connection, None
                self._remote_call = None
                try:
                    await asyncio.wait_for(asyncio.to_thread(connection.close), 2)
                except Exception:
                    logger.debug("RPC close failed after process shutdown", exc_info=True)
            if self._drain_task is not None:
                with suppress(TimeoutError, asyncio.CancelledError):
                    await asyncio.wait_for(self._drain_task, 2)
                self._drain_task = None
            if self._temporary is not None:
                self._temporary.cleanup()
                self._temporary = None
