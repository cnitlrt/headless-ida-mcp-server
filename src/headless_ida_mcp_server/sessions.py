"""Database isolation within an MCP connection, with a server-wide process quota."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

import anyio

from .backend import IdaProcess
from .compat import IDAError
from .config import Settings
from .models import OperationResult, SessionInfo
from .protocol import READ_OPERATIONS, WRITE_OPERATIONS


@dataclass
class SessionBudget:
    """Shared by connection managers on the same asyncio loop."""

    limit: int
    used: int = 0

    def acquire(self):
        if self.used >= self.limit:
            raise IDAError("Session limit reached; close a binary first")
        self.used += 1

    def release(self):
        self.used -= 1


@dataclass
class Session:
    info: SessionInfo
    backend: IdaProcess
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_used: float = field(default_factory=time.monotonic)


async def cleanup(backend):
    # MCP/AnyIO cancellation must not interrupt resource reclamation.
    with anyio.CancelScope(shield=True):
        await asyncio.shield(backend.close())


class SessionManager:
    def __init__(
        self, settings: Settings, backend_factory=None, budget: SessionBudget | None = None
    ):
        self.settings = settings
        self.factory = backend_factory or IdaProcess
        self.budget = budget if budget is not None else SessionBudget(settings.max_sessions)
        self.sessions: dict[str, Session] = {}
        self._lifecycle = asyncio.Lock()
        self._closed = False

    async def open(self, path: str) -> SessionInfo:
        binary = self.settings.input_path(path)
        async with self._lifecycle:
            if self._closed:
                raise IDAError("Server is shutting down")
            self.budget.acquire()
            backend = None
            try:
                backend = self.factory(self.settings)
                await asyncio.wait_for(backend.start(binary), self.settings.startup_timeout)
            except BaseException:
                try:
                    if backend is not None:
                        await cleanup(backend)
                finally:
                    self.budget.release()
                raise
            info = {
                "session_id": uuid4().hex,
                "path": str(binary),
                "read_only": self.settings.read_only,
            }
            self.sessions[info["session_id"]] = Session(info, backend)
            return dict(info)

    def resolve(self, session_id: str | None) -> Session:
        if session_id is None:
            if len(self.sessions) != 1:
                raise IDAError(
                    "Pass session_id explicitly (no binary open or multiple sessions exist)"
                )
            return next(iter(self.sessions.values()))
        if session_id not in self.sessions:
            raise IDAError("Unknown or closed session_id")
        return self.sessions[session_id]

    async def _dispose(self, session):
        # Caller owns session.lock; timeout, close and shutdown cannot double-release the quota.
        if self.sessions.pop(session.info["session_id"], None) is not None:
            try:
                await cleanup(session.backend)
            finally:
                self.budget.release()

    async def call(self, session_id: str | None, operation: str, **arguments):
        if self._closed:
            raise IDAError("Server is shutting down")
        if operation not in READ_OPERATIONS | WRITE_OPERATIONS:
            raise IDAError("Unknown operation")
        if self.settings.read_only and operation in WRITE_OPERATIONS:
            raise IDAError("Write tools are disabled; set IDA_READ_ONLY=false to enable")
        destination = None
        if operation == "save_idb_file":
            destination = Path(arguments.pop("save_path")).expanduser().resolve()
            self.settings.check_root(destination)
            if destination.suffix.lower() != ".i64":
                raise IDAError("Save path must end in .i64 (64-bit IDA database format)")
            if not destination.parent.is_dir() or destination.exists():
                raise IDAError("Destination parent must exist and file must not already exist")
        session = self.resolve(session_id)
        await asyncio.wait_for(session.lock.acquire(), self.settings.request_timeout)
        try:
            if session.info["session_id"] not in self.sessions:
                raise IDAError("Session was closed while waiting")
            try:
                task = (
                    session.backend.export(destination)
                    if destination
                    else session.backend.call(operation, arguments)
                )
                return await asyncio.wait_for(task, self.settings.request_timeout)
            except (TimeoutError, asyncio.CancelledError, ConnectionError, EOFError, OSError):
                await self._dispose(session)
                raise
        finally:
            session.last_used = time.monotonic()
            session.lock.release()

    async def close(self, session_id: str) -> OperationResult:
        session = self.resolve(session_id)
        async with session.lock:
            await self._dispose(session)
        return {"success": True, "message": "Session closed; unsaved changes discarded"}

    async def close_all(self):
        async with self._lifecycle:
            self._closed = True

            async def close_session(session):
                async with session.lock:
                    await self._dispose(session)

            # Attempt every teardown even if one backend fails to close.
            results = await asyncio.gather(
                *(close_session(s) for s in list(self.sessions.values())), return_exceptions=True
            )
            for result in results:
                if isinstance(result, BaseException):
                    raise result

    def list(self) -> list[SessionInfo]:
        return [dict(session.info) for session in self.sessions.values()]

    async def expire_idle(self):
        if not self.settings.idle_timeout:
            return
        now = time.monotonic()
        for session in list(self.sessions.values()):
            if not session.lock.locked() and now - session.last_used >= self.settings.idle_timeout:
                async with session.lock:
                    await self._dispose(session)

    async def reap_idle(self):
        if not self.settings.idle_timeout:
            return
        while True:
            await asyncio.sleep(min(30, self.settings.idle_timeout))
            await self.expire_idle()
