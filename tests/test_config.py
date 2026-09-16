import os
import subprocess
import sys

import pytest

from headless_ida_mcp_server.config import Settings


def test_import_without_config():
    env = os.environ.copy()
    env.pop("IDA_PATH", None)
    result = subprocess.run(
        [sys.executable, "-c", "import headless_ida_mcp_server.server"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_env_precedence(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text("PORT=9000\nHOST=127.0.0.1\nIDA_READ_ONLY=false\n")
    monkeypatch.setenv("PORT", "9001")
    monkeypatch.delenv("IDA_READ_ONLY", raising=False)
    settings = Settings.load(path)
    assert settings.port == 9001
    assert not settings.read_only
    assert "IDA_READ_ONLY" not in os.environ


@pytest.mark.parametrize(
    "args",
    [
        {"port": 0},
        {"port": 65536},
        {"host": "0.0.0.0"},
        {"host": "example.com"},
        {"transport": "http"},
        {"max_sessions": 0},
        {"request_timeout": 0},
    ],
)
def test_invalid_configuration(args):
    with pytest.raises(ValueError):
        Settings(**args)


def test_path_restrictions(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"1234")
    link = allowed / "link"
    link.symlink_to(outside)
    settings = Settings(allowed_roots=(allowed,))
    with pytest.raises(ValueError, match="outside"):
        settings.input_path(str(link))
    with pytest.raises(ValueError, match="regular"):
        settings.input_path(str(allowed))
    binary = allowed / "ok"
    binary.write_bytes(b"a")
    assert settings.input_path(str(binary)) == binary
    with pytest.raises(ValueError, match="exceeds"):
        Settings(max_file_bytes=1).input_path(str(outside))


def test_ida_path_required_only_when_opening():
    settings = Settings()
    with pytest.raises(ValueError, match="IDA_PATH"):
        settings.executable()


def test_cli_overrides_applied_before_validation(tmp_path):
    path = tmp_path / ".env"
    path.write_text("HOST=0.0.0.0\n")
    assert Settings.load(path, {"host": "127.0.0.1"}).host == "127.0.0.1"
