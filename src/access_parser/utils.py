"""Value decoding and page utilities for Access databases."""

import logging
import math
import os
import struct
import uuid
from datetime import datetime, timedelta
from decimal import Decimal

type ParsedValue = bool | bytes | datetime | Decimal | float | int | str | uuid.UUID | None
type PageMap = dict[int, bytes]

LOGGER = logging.getLogger("access_parser.utils")


TYPE_BOOLEAN = 1
TYPE_INT8 = 2
TYPE_INT16 = 3
TYPE_INT32 = 4
TYPE_MONEY = 5
TYPE_FLOAT32 = 6
TYPE_FLOAT64 = 7
TYPE_DATETIME = 8
TYPE_BINARY = 9
TYPE_TEXT = 10
TYPE_OLE = 11
TYPE_MEMO = 12
TYPE_GUID = 15
TYPE_NUMERIC = 16
TYPE_COMPLEX = 18

TABLE_PAGE_MAGIC = b"\x02\x01"
DATA_PAGE_MAGIC = b"\x01\x01"


ACCESS_EPOCH = datetime(1899, 12, 30)  # noqa: DTZ001 - Access stores timezone-naive dates.
CURRENCY_SCALE = 4
SECONDS_PER_DAY = 86_400

TYPE_TO_STRUCT_FORMAT = {
    TYPE_INT8: "b",
    TYPE_INT16: "h",
    TYPE_INT32: "i",
    TYPE_COMPLEX: "i",
    TYPE_FLOAT32: "f",
    TYPE_FLOAT64: "d",
}


def mdb_date_to_datetime(value: float) -> datetime:
    """Convert an OLE Automation date to a timezone-naive datetime."""
    fractional_days, whole_days = math.modf(value)
    return ACCESS_EPOCH + timedelta(days=int(whole_days), seconds=abs(fractional_days) * SECONDS_PER_DAY)


def numeric_to_decimal(buffer: bytes, scale: int) -> Decimal:
    """Decode Access's 17-byte exact numeric representation."""
    sign, word1, word2, word3, word4 = struct.unpack("<BIIII", buffer)
    coefficient = (word1 << 96) + (word2 << 64) + (word3 << 32) + word4
    value = Decimal(coefficient).scaleb(-scale)
    return -value if sign & 0x80 else value


def get_decoded_text(bytes_data: bytes) -> str:
    """Decode Jet 3 text as UTF-8 or Latin-1."""
    try:
        return bytes_data.decode("utf-8")
    except UnicodeDecodeError:
        return bytes_data.decode("latin1")


def _parse_money(buffer: bytes) -> Decimal:
    parsed = struct.unpack_from("<q", buffer)[0]
    return Decimal(parsed).scaleb(-CURRENCY_SCALE)


def _parse_text(buffer: bytes, version: int) -> str:
    if version <= 3:
        parsed = get_decoded_text(buffer)
    elif buffer.startswith((b"\xfe\xff", b"\xff\xfe")):
        parsed = get_decoded_text(buffer[2:])
    else:
        parsed = buffer.decode("utf-16", errors="ignore")

    if "\x00" in parsed:
        LOGGER.debug(f"Parsed string contains NUL (0x00) characters: {parsed}")
        return parsed.replace("\x00", "")
    return parsed


def parse_type(
    data_type: int,
    buffer: bytes,
    length: int | None = None,
    version: int = 3,
    scale: int = 0,
) -> ParsedValue:
    """Decode a field according to its Access type identifier."""
    if struct_format := TYPE_TO_STRUCT_FORMAT.get(data_type):
        return struct.unpack_from(struct_format, buffer)[0]
    if data_type == TYPE_MONEY:
        return _parse_money(buffer)
    if data_type == TYPE_DATETIME:
        return mdb_date_to_datetime(struct.unpack_from("<d", buffer)[0])
    if data_type == TYPE_BINARY:
        return buffer[:length]
    if data_type == TYPE_OLE:
        return buffer
    if data_type == TYPE_GUID:
        return uuid.UUID(bytes_le=buffer[:16])
    if data_type == TYPE_NUMERIC:
        return numeric_to_decimal(buffer[:17], scale)
    if data_type == TYPE_TEXT:
        return _parse_text(buffer, version)

    LOGGER.debug(f"parse_type - unsupported data type: {data_type}")
    return ""


def categorize_pages(db_data: bytes, page_size: int) -> tuple[PageMap, PageMap, PageMap]:
    """Split database bytes into table-definition, data, and complete page maps."""
    if len(db_data) % page_size:
        LOGGER.warning(f"DB is not full or PAGE_SIZE is wrong. page size: {page_size} DB length {len(db_data)}")
    pages = {i: db_data[i : i + page_size] for i in range(0, len(db_data), page_size)}
    data_pages: PageMap = {}
    table_defs: PageMap = {}
    for page, value in pages.items():
        if value.startswith(DATA_PAGE_MAGIC):
            data_pages[page] = value
        elif value.startswith(TABLE_PAGE_MAGIC):
            table_defs[page] = value
    return table_defs, data_pages, pages


def read_db_file(path: str | os.PathLike[str]) -> bytes:
    """Read a database file from disk."""
    if not os.path.isfile(path):
        LOGGER.error(f"File {path} not found")
        raise FileNotFoundError(f"File {path} not found")
    with open(path, "rb") as f:
        return f.read()
