import struct
import uuid
from datetime import datetime
from decimal import Decimal

import pytest

from access_parser.utils import (
    TYPE_BINARY,
    TYPE_COMPLEX,
    TYPE_DATETIME,
    TYPE_FLOAT32,
    TYPE_FLOAT64,
    TYPE_GUID,
    TYPE_INT8,
    TYPE_INT16,
    TYPE_INT32,
    TYPE_MONEY,
    TYPE_NUMERIC,
    TYPE_OLE,
    TYPE_TEXT,
    categorize_pages,
    numeric_to_decimal,
    parse_type,
)


@pytest.mark.parametrize(
    ("data_type", "buffer", "expected"),
    [
        (TYPE_INT8, struct.pack("<b", -8), -8),
        (TYPE_INT16, struct.pack("<h", -1_024), -1_024),
        (TYPE_INT32, struct.pack("<i", 123_456), 123_456),
        (TYPE_COMPLEX, struct.pack("<i", -123_456), -123_456),
        (TYPE_FLOAT32, struct.pack("<f", 1.5), 1.5),
        (TYPE_FLOAT64, struct.pack("<d", -2.25), -2.25),
    ],
)
def test_parse_type_decodes_fixed_width_values(data_type: int, buffer: bytes, expected: float) -> None:
    assert parse_type(data_type, buffer) == expected


@pytest.mark.parametrize(
    ("stored_value", "expected"),
    [
        (123_456, Decimal("12.3456")),
        (0, Decimal("0.0000")),
        (-123_456, Decimal("-12.3456")),
    ],
)
def test_parse_type_decodes_money_exactly(stored_value: int, expected: Decimal) -> None:
    assert parse_type(TYPE_MONEY, struct.pack("<q", stored_value)) == expected


def test_parse_type_decodes_access_dates() -> None:
    assert parse_type(TYPE_DATETIME, struct.pack("<d", 0)) == datetime(1899, 12, 30)  # noqa: DTZ001
    assert parse_type(TYPE_DATETIME, struct.pack("<d", 1.5)) == datetime(1899, 12, 31, 12)  # noqa: DTZ001
    assert parse_type(TYPE_DATETIME, struct.pack("<d", -1.25)) == datetime(1899, 12, 29, 6)  # noqa: DTZ001


@pytest.mark.parametrize(
    ("buffer", "version", "expected"),
    [
        (b"caf\xc3\xa9", 3, "café"),
        (b"caf\xe9", 3, "café"),
        (b"a\x00b", 3, "ab"),
        ("café".encode("utf-16"), 4, "café"),
        ("café".encode("utf-16-le"), 4, "café"),
    ],
)
def test_parse_type_decodes_text(buffer: bytes, version: int, expected: str) -> None:
    assert parse_type(TYPE_TEXT, buffer, version=version) == expected


def test_parse_type_decodes_byte_fields_and_guid() -> None:
    guid = uuid.UUID("8bb9d14a-0f9f-c746-a827-0165678e8cbd")
    payload = bytes(range(32))

    assert parse_type(TYPE_BINARY, payload, length=5) == payload[:5]
    assert parse_type(TYPE_OLE, payload) == payload
    assert parse_type(TYPE_GUID, guid.bytes_le) == guid


@pytest.mark.parametrize(
    ("sign", "scale", "expected"),
    [
        (0, 6, Decimal("149.804168")),
        (0x80, 6, Decimal("-149.804168")),
        (0, 10, Decimal("0.0149804168")),
    ],
)
def test_numeric_to_decimal(sign: int, scale: int, expected: Decimal) -> None:
    numeric = struct.pack("<BIIII", sign, 0, 0, 0, 149_804_168)

    assert numeric_to_decimal(numeric, scale) == expected
    assert parse_type(TYPE_NUMERIC, numeric, scale=scale) == expected


def test_categorize_pages() -> None:
    table_page = b"\x02\x01aa"
    data_page = b"\x01\x01bb"
    other_page = b"other"

    table_defs, data_pages, all_pages = categorize_pages(table_page + data_page + other_page, page_size=4)

    assert table_defs == {0: table_page}
    assert data_pages == {4: data_page}
    assert all_pages == {0: table_page, 4: data_page, 8: b"othe", 12: b"r"}
