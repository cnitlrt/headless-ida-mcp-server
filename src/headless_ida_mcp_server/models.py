"""JSON contracts shared by MCP and IDAPython; no MCP/Pydantic imports."""

from __future__ import annotations

from typing import Generic, TypeVar

from typing_extensions import TypedDict

T = TypeVar("T")


class Page(TypedDict, Generic[T]):
    data: list[T]
    offset: int
    next_offset: int | None


class Function(TypedDict):
    address: int
    end_address: int
    name: str
    prototype: str | None


class Xref(TypedDict):
    address: int
    type: str
    function: Function | None


class ConvertedNumber(TypedDict):
    decimal: str
    hexadecimal: str
    bytes: str
    ascii: str | None
    binary: str


class TextLine(TypedDict):
    line: int
    address: int | None
    text: str
    truncated: bool


class Segment(TypedDict):
    address: int
    end_address: int
    name: str
    permissions: int


class Import(TypedDict):
    address: int
    name: str
    module: str
    ordinal: int


class String(TypedDict):
    address: int
    length: int
    text: str
    truncated: bool


class EntryPoint(TypedDict):
    address: int
    name: str
    ordinal: int
    function: Function | None


class Metadata(TypedDict):
    ida_version: str
    processor: str
    bits: int
    image_base: int
    min_address: int
    max_address: int
    function_count: int
    decompiler_available: bool


class OperationResult(TypedDict):
    success: bool
    message: str


class SessionInfo(TypedDict):
    session_id: str
    path: str
    read_only: bool


class Health(TypedDict):
    status: str
    sessions: int
    max_sessions: int
    read_only: bool
