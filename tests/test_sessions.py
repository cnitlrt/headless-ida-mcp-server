import asyncio

import pytest

from headless_ida_mcp_server.compat import IDAError
from headless_ida_mcp_server.config import Settings
from headless_ida_mcp_server.sessions import SessionManager


class FakeBackend:
    instances = []

    def __init__(self, settings):
        self.closed = False
        self.active = 0
        self.max_active = 0
        self.entered = asyncio.Event()
        self.delay = 0
        self.failure = None
        self.instances.append(self)

    async def start(self, binary):
        self.binary = binary

    async def call(self, operation, arguments):
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.entered.set()
        try:
            await asyncio.sleep(self.delay)
            if self.failure:
                raise self.failure
            return str(self.binary)
        finally:
            self.active -= 1

    async def close(self):
        self.closed = True


@pytest.fixture
def binary(tmp_path):
    path = tmp_path / "binary"
    path.write_bytes(b"fixture")
    return path


async def test_isolation_and_ambiguous_default(binary):
    manager = SessionManager(Settings(), FakeBackend)
    first = await manager.open(str(binary))
    second = await manager.open(str(binary))
    assert first["session_id"] != second["session_id"]
    assert (
        manager.resolve(first["session_id"]).backend
        is not manager.resolve(second["session_id"]).backend
    )
    with pytest.raises(IDAError, match="explicitly"):
        await manager.call(None, "get_metadata")
    backends = [s.backend for s in manager.sessions.values()]
    await manager.close_all()
    assert all(b.closed for b in backends)
    assert not manager.sessions
    with pytest.raises(IDAError, match="shutting down"):
        await manager.open(str(binary))


async def test_serial_calls_and_responsive_loop(binary):
    manager = SessionManager(Settings(), FakeBackend)
    info = await manager.open(str(binary))
    backend = manager.resolve(info["session_id"]).backend
    backend.delay = 0.03
    ticks = []

    async def heartbeat():
        for _ in range(5):
            await asyncio.sleep(0.005)
            ticks.append(1)

    await asyncio.gather(
        manager.call(None, "get_metadata"), manager.call(None, "get_metadata"), heartbeat()
    )
    assert backend.max_active == 1
    assert len(ticks) == 5
    await manager.close_all()


async def test_timeout_destroys_session(binary):
    manager = SessionManager(Settings(request_timeout=0.01), FakeBackend)
    info = await manager.open(str(binary))
    backend = manager.resolve(info["session_id"]).backend
    backend.delay = 1
    with pytest.raises(TimeoutError):
        await manager.call(None, "get_metadata")
    assert backend.closed
    assert not manager.sessions


async def test_cancel_active_destroys_session(binary):
    manager = SessionManager(Settings(), FakeBackend)
    info = await manager.open(str(binary))
    backend = manager.resolve(info["session_id"]).backend
    backend.delay = 100
    task = asyncio.create_task(manager.call(None, "get_metadata"))
    await backend.entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert backend.closed
    assert not manager.sessions


async def test_cancel_queued_leaves_active_session(binary):
    manager = SessionManager(Settings(), FakeBackend)
    info = await manager.open(str(binary))
    backend = manager.resolve(info["session_id"]).backend
    backend.delay = 0.03
    running = asyncio.create_task(manager.call(None, "get_metadata"))
    await backend.entered.wait()
    queued = asyncio.create_task(manager.call(None, "get_metadata"))
    await asyncio.sleep(0)
    queued.cancel()
    with pytest.raises(asyncio.CancelledError):
        await queued
    await running
    assert not backend.closed
    await manager.close_all()


async def test_limits_and_readonly(binary):
    manager = SessionManager(Settings(max_sessions=1), FakeBackend)
    info = await manager.open(str(binary))
    with pytest.raises(IDAError, match="limit"):
        await manager.open(str(binary))
    with pytest.raises(IDAError, match="disabled"):
        await manager.call(None, "rename_function", function_address=0, new_name="name")
    with pytest.raises(IDAError, match="Unknown operation"):
        await manager.call(None, "__class__")
    await manager.close(info["session_id"])
    with pytest.raises(IDAError, match="closed"):
        manager.resolve(info["session_id"])


async def test_domain_error_preserves_session(binary):
    manager = SessionManager(Settings(), FakeBackend)
    info = await manager.open(str(binary))
    backend = manager.resolve(info["session_id"]).backend
    backend.failure = IDAError("no function")
    with pytest.raises(IDAError):
        await manager.call(None, "get_function", address=0)
    assert not backend.closed
    await manager.close_all()


async def test_start_failure_cleanup(binary):
    class Failed(FakeBackend):
        async def start(self, path):
            raise IDAError("cannot start")

    manager = SessionManager(Settings(), Failed)
    with pytest.raises(IDAError):
        await manager.open(str(binary))
    assert Failed.instances[-1].closed
    assert not manager.sessions


async def test_constructor_failure_returns_quota(binary):
    def fail(settings):
        raise RuntimeError("fixture")

    manager = SessionManager(Settings(), fail)
    with pytest.raises(RuntimeError):
        await manager.open(str(binary))
    assert manager.budget.used == 0


async def test_startup_cancel_returns_quota(binary):
    entered = asyncio.Event()

    class SlowStart(FakeBackend):
        async def start(self, path):
            entered.set()
            await asyncio.sleep(30)

    manager = SessionManager(Settings(), SlowStart)
    task = asyncio.create_task(manager.open(str(binary)))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert manager.budget.used == 0
    assert SlowStart.instances[-1].closed


async def test_queue_timeout_does_not_close_session(binary):
    manager = SessionManager(Settings(request_timeout=0.01), FakeBackend)
    info = await manager.open(str(binary))
    session = manager.resolve(info["session_id"])
    await session.lock.acquire()
    try:
        with pytest.raises(TimeoutError):
            await manager.call(None, "get_metadata")
        assert not session.backend.closed
        assert manager.budget.used == 1
    finally:
        session.lock.release()
        await manager.close_all()
    assert manager.budget.used == 0


async def test_concurrent_close_and_timeout(binary):
    manager = SessionManager(Settings(request_timeout=0.01), FakeBackend)
    info = await manager.open(str(binary))
    backend = manager.resolve(info["session_id"]).backend
    backend.delay = 100
    call = asyncio.create_task(manager.call(None, "get_metadata"))
    await backend.entered.wait()
    close = asyncio.create_task(manager.close_all())
    with pytest.raises(TimeoutError):
        await call
    await close
    assert backend.closed
    assert manager.budget.used == 0


async def test_bad_exports_rejected_before_dispatch(binary, tmp_path):
    settings = Settings(read_only=False, allowed_roots=(tmp_path,))
    manager = SessionManager(settings, FakeBackend)
    await manager.open(str(binary))
    try:
        with pytest.raises(IDAError, match="already exist"):
            existing = tmp_path / "existing.i64"
            existing.write_bytes(b"existing")
            await manager.call(None, "save_idb_file", save_path=str(existing))
        with pytest.raises(IDAError, match="end in"):
            await manager.call(None, "save_idb_file", save_path=str(tmp_path / "bad.txt"))
        with pytest.raises(ValueError, match="outside"):
            await manager.call(
                None, "save_idb_file", save_path=str(tmp_path.parent / "outside.i64")
            )
    finally:
        await manager.close_all()


async def test_idle_reaper_respects_active_calls(binary):
    manager = SessionManager(Settings(idle_timeout=1), FakeBackend)
    info = await manager.open(str(binary))
    session = manager.resolve(info["session_id"])
    session.last_used -= 10
    await session.lock.acquire()
    await manager.expire_idle()
    assert not session.backend.closed
    session.lock.release()
    await manager.expire_idle()
    assert session.backend.closed
    assert manager.budget.used == 0
    assert not manager.sessions


async def test_idle_reaper_can_be_disabled(binary):
    manager = SessionManager(Settings(idle_timeout=0), FakeBackend)
    info = await manager.open(str(binary))
    manager.resolve(info["session_id"]).last_used = 0
    await manager.expire_idle()
    assert manager.sessions
    await manager.close_all()
