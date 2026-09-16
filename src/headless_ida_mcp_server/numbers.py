"""Integer conversion independent of IDA and binary sessions."""

from __future__ import annotations

from typing import Literal

from .models import ConvertedNumber


def convert_number(
    text: str,
    size: int | None = None,
    signed: bool | None = None,
    byteorder: Literal["little", "big"] = "little",
) -> ConvertedNumber:
    if len(text) > 4096:
        raise ValueError("Number text exceeds 4096 characters")
    try:
        value = int(text, 0)
    except ValueError as exc:
        raise ValueError(f"Invalid integer: {text}") from exc
    if signed is None:
        signed = value < 0
    if value < 0 and not signed:
        raise ValueError("Unsigned conversion cannot represent a negative value")
    if size is None:
        bits = (~value).bit_length() + 1 if value < 0 else value.bit_length() + int(signed)
        size = max(1, (bits + 7) // 8)
    if not 1 <= size <= 4096:
        raise ValueError("size must be between 1 and 4096 bytes")
    try:
        data = value.to_bytes(size, byteorder, signed=signed)
    except OverflowError as exc:
        raise ValueError(f"Number does not fit in {size} bytes (signed={signed})") from exc
    printable = data.rstrip(b"\0")
    return {
        "decimal": str(value),
        "hexadecimal": hex(value),
        "bytes": data.hex(" "),
        "ascii": printable.decode("ascii") if all(32 <= b <= 126 for b in printable) else None,
        "binary": bin(value),
    }
