"""Validated configuration, loaded explicitly at application startup."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Literal

from dotenv import dotenv_values
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    ida_path: str = ""
    host: str = "127.0.0.1"
    port: int = Field(default=8888, ge=1, le=65535)
    transport: Literal["stdio", "sse", "streamable-http"] = "stdio"
    startup_timeout: float = Field(default=120, gt=0, le=3600)
    request_timeout: float = Field(default=60, gt=0, le=3600)
    idle_timeout: float = Field(default=900, ge=0, le=86400)
    max_sessions: int = Field(default=4, ge=1, le=32)
    max_file_bytes: int = Field(default=512 * 1024 * 1024, ge=1)
    read_only: bool = True
    allowed_roots: tuple[Path, ...] = ()

    @field_validator("host")
    @classmethod
    def loopback_only(cls, value: str) -> str:
        if value == "localhost":
            return value
        try:
            if ipaddress.ip_address(value).is_loopback:
                return value
        except ValueError:
            pass
        raise ValueError(
            "Only loopback HOST is supported; remote unauthenticated access is disabled"
        )

    @classmethod
    def load(cls, env_file: str | Path | None = ".env", overrides: dict | None = None) -> Settings:
        # Explicit location; no upward directory search or os.environ mutation.
        values = dict(dotenv_values(env_file)) if env_file and Path(env_file).is_file() else {}
        values.update(os.environ)
        fields = {
            "IDA_PATH": "ida_path",
            "HOST": "host",
            "PORT": "port",
            "TRANSPORT": "transport",
            "IDA_STARTUP_TIMEOUT": "startup_timeout",
            "IDA_REQUEST_TIMEOUT": "request_timeout",
            "IDA_IDLE_TIMEOUT": "idle_timeout",
            "IDA_MAX_SESSIONS": "max_sessions",
            "IDA_MAX_FILE_BYTES": "max_file_bytes",
            "IDA_READ_ONLY": "read_only",
        }
        data = {dest: values[key] for key, dest in fields.items() if values.get(key) is not None}
        roots = values.get("IDA_ALLOWED_ROOTS")
        if roots:
            data["allowed_roots"] = tuple(
                Path(p).expanduser().resolve() for p in roots.split(os.pathsep) if p
            )
        return cls.model_validate(data | (overrides or {}))

    def executable(self) -> Path:
        path = Path(self.ida_path).expanduser()
        if not self.ida_path or not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("IDA_PATH must name an executable idat/idat64 file")
        return path.resolve()

    def input_path(self, value: str) -> Path:
        path = Path(value).expanduser().resolve(strict=True)
        self.check_root(path)
        if not path.is_file():
            raise ValueError("Binary path must be a regular file")
        if path.stat().st_size > self.max_file_bytes:
            raise ValueError("Binary exceeds IDA_MAX_FILE_BYTES")
        return path

    def check_root(self, path: Path) -> None:
        if self.allowed_roots and not any(
            path.is_relative_to(root.resolve()) for root in self.allowed_roots
        ):
            raise ValueError("Path is outside IDA_ALLOWED_ROOTS")
