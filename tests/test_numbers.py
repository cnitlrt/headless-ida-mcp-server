import pytest

from headless_ida_mcp_server.numbers import convert_number


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("0", "00"),
        ("127", "7f"),
        ("128", "80"),
        ("255", "ff"),
        ("256", "00 01"),
        ("-1", "ff"),
        ("-128", "80"),
        ("-129", "7f ff"),
        ("-32768", "00 80"),
        ("-32769", "ff 7f ff"),
        ("0x4142", "42 41"),
        ("0b1000", "08"),
    ],
)
def test_auto_size(text, expected):
    assert convert_number(text)["bytes"] == expected


@pytest.mark.parametrize("value", [-65537, -32769, -129, -128, -1, 0, 127, 128, 255, 65535])
def test_round_trip(value):
    result = convert_number(str(value))
    assert int.from_bytes(bytes.fromhex(result["bytes"]), "little", signed=value < 0) == value


def test_explicit_semantics():
    assert convert_number("128", signed=True)["bytes"] == "80 00"
    assert convert_number("0x4142", byteorder="big")["ascii"] == "AB"
    assert convert_number("65", size=2)["bytes"] == "41 00"


@pytest.mark.parametrize(
    "args",
    [
        {"text": "nope"},
        {"text": "256", "size": 1},
        {"text": "-1", "signed": False},
        {"text": "128", "size": 1, "signed": True},
        {"text": "0", "size": 0},
        {"text": "1", "size": -1},
        {"text": "1", "size": 4097},
        {"text": "1" * 4097},
    ],
)
def test_reject_bad_conversion(args):
    with pytest.raises(ValueError):
        convert_number(**args)
