import sqlite3
import struct
from collections import defaultdict
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import UUID

import pytest

from access_parser import AccessParser
from access_parser.access_parser import (
    AccessTable,
    ParsedTable,
    _get_primary_keys,  # pyright: ignore[reportPrivateUsage]
)
from access_parser.parsing_primitives import Column, RelativeMetadata, TableHeader
from access_parser.utils import TYPE_BINARY, TYPE_TEXT, ParsedValue

EXPECTED_CATALOG = {
    "MSysObjects": 2,
    "ClarotyTable": 18,
    "f_AF8292619150475ABBCC3E04860C1240_Data": 22,
    "MSysNameMap": 36,
    "MSysNavPaneGroupCategories": 44,
    "MSysNavPaneGroups": 47,
    "MSysNavPaneGroupToObjects": 51,
    "MSysNavPaneObjectIDs": 59,
}

TABLE_DIMENSIONS = [
    ("MSysObjects", 17, 26),
    ("ClarotyTable", 4, 2),
    ("f_AF8292619150475ABBCC3E04860C1240_Data", 8, 1),
    ("MSysNameMap", 5, 1),
    ("MSysNavPaneGroupCategories", 7, 3),
    ("MSysNavPaneGroups", 7, 9),
    ("MSysNavPaneGroupToObjects", 7, 11),
    ("MSysNavPaneObjectIDs", 3, 12),
]


@pytest.fixture(scope="module")
def database() -> AccessParser:
    return AccessParser(Path(__file__).parents[1] / "examples" / "test.mdb")


def test_reads_jet4_catalog(database: AccessParser) -> None:
    assert database.version == 4
    assert database.page_size == 4096
    assert database.catalog == EXPECTED_CATALOG


def test_parses_table_rows(database: AccessParser) -> None:
    assert database.parse_table("ClarotyTable") == {
        "ID": [1, 2],
        "Field1": ["test", "test2"],
        "Field2": ["Claroty", "Claroty"],
        "Field3": ["ICS!", None],
    }


@pytest.mark.parametrize(("table_name", "column_count", "row_count"), TABLE_DIMENSIONS)
def test_parses_all_discovered_tables(
    database: AccessParser,
    table_name: str,
    column_count: int,
    row_count: int,
) -> None:
    table = database.parse_table(table_name)

    assert len(table) == column_count
    assert {len(column) for column in table.values()} == {row_count}


def test_parses_schema_metadata(database: AccessParser) -> None:
    table = database.get_table("ClarotyTable")
    properties = database.extra_props["ClarotyTable"]

    assert table is not None
    assert properties is not None
    assert table.primary_keys == ["ID"]
    assert properties["Field3"]["ColumnOrder"] == 4


def test_primary_key_resolution_uses_stable_column_ids() -> None:
    columns = [
        cast("Column", SimpleNamespace(column_id=0, col_name_str="Other")),
        cast("Column", SimpleNamespace(column_id=5, col_name_str="PrimaryKey")),
    ]
    table_header = cast(
        "TableHeader",
        SimpleNamespace(
            all_indexes=[SimpleNamespace(idx_type=1, idx_col_num=0)],
            real_index_2=[SimpleNamespace(unk_struct=[SimpleNamespace(col_id=5), SimpleNamespace(col_id=0xFFFF)])],
        ),
    )

    assert _get_primary_keys(columns, table_header) == ["PrimaryKey"]


def test_parses_guid_and_binary_fields(database: AccessParser) -> None:
    name_map = database.parse_table("MSysNameMap")
    resources = database.parse_table("f_AF8292619150475ABBCC3E04860C1240_Data")
    name_map_data = name_map["NameMap"][0]
    file_data = resources["FileData"][0]

    assert name_map["GUID"] == [UUID("4ad1b98b-9f0f-46c7-a827-0165678e8cbd")]
    assert isinstance(name_map_data, bytes)
    assert len(name_map_data) == 342
    assert resources["FileName"] == ["Office Theme.thmx"]
    assert resources["FileTimeStamp"] == [None]
    assert isinstance(file_data, bytes)
    assert file_data.startswith(b"\x01\x00\x00\x00P\x0c\x00\x00x^")
    assert len(file_data) == 2794


def test_parses_access_dates_as_datetimes(database: AccessParser) -> None:
    objects = database.parse_table("MSysObjects")

    assert objects["DateCreate"][0] == datetime(2020, 7, 5, 14, 29, 3, 135_000)  # noqa: DTZ001


def test_prints_database(
    database: AccessParser,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(database, "catalog", {"ClarotyTable": 18})

    database.print_database()

    output = capsys.readouterr().out
    assert "TABLE NAME: ClarotyTable" in output
    assert "test2" in output


def test_rejects_missing_database(tmp_path: Path) -> None:
    missing_database = tmp_path / "missing.mdb"

    with pytest.raises(FileNotFoundError, match=r"missing\.mdb"):
        AccessParser(missing_database)


def test_rejects_invalid_database(tmp_path: Path) -> None:
    invalid_database = tmp_path / "invalid.mdb"
    invalid_database.write_bytes(b"not an Access database")

    with pytest.raises(ValueError, match="Failed to parse DB file header"):
        AccessParser(invalid_database)


def test_rejects_unknown_table(database: AccessParser) -> None:
    with pytest.raises(KeyError, match="Unknown table: MissingTable"):
        database.parse_table("MissingTable")


def test_runs_read_only_sql_queries(database: AccessParser) -> None:
    connection = database.to_sqlite(["ClarotyTable"])

    try:
        assert connection.execute(
            "SELECT Field1, Field3 FROM ClarotyTable WHERE ID > ?",
            (1,),
        ).fetchall() == [("test2", None)]
        assert connection.execute("SELECT name FROM sqlite_schema WHERE type = 'table'").fetchall() == [
            ("ClarotyTable",)
        ]
        assert connection.execute("PRAGMA query_only").fetchone() == (1,)
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute("DELETE FROM ClarotyTable")
    finally:
        connection.close()


def test_sqlite_export_preserves_blobs(database: AccessParser) -> None:
    connection = database.to_sqlite(["MSysNameMap"])

    try:
        value = connection.execute("SELECT GUID, NameMap FROM MSysNameMap").fetchone()
        assert value is not None
        assert value[0] == "4ad1b98b-9f0f-46c7-a827-0165678e8cbd"
        assert isinstance(value[1], bytes)
        assert len(value[1]) == 342
    finally:
        connection.close()


def test_sqlite_export_quotes_identifiers_and_keeps_empty_tables(monkeypatch: pytest.MonkeyPatch) -> None:
    parser = AccessParser.__new__(AccessParser)
    parser.catalog = {'select "table"': 1, "empty": 2}

    def parse_table(table_name: str) -> ParsedTable:
        if table_name == "empty":
            return defaultdict(list, {"value": []})
        return defaultdict(list, {'from "column"': [1]})

    monkeypatch.setattr(parser, "parse_table", parse_table)
    connection = parser.to_sqlite()

    try:
        assert connection.execute('SELECT "from ""column""" FROM "select ""table"""').fetchall() == [(1,)]
        assert connection.execute("SELECT COUNT(*) FROM empty").fetchone() == (0,)
    finally:
        connection.close()


def test_sqlite_export_normalizes_semantic_values(monkeypatch: pytest.MonkeyPatch) -> None:
    parser = AccessParser.__new__(AccessParser)
    parser.catalog = {"types": 1}

    def parse_table(_table_name: str) -> ParsedTable:
        return defaultdict(
            list,
            {
                "timestamp": [datetime(2020, 7, 5, 14, 29, 3, 135_000)],  # noqa: DTZ001
                "guid": [UUID("4ad1b98b-9f0f-46c7-a827-0165678e8cbd")],
                "amount": [Decimal("12.3400")],
            },
        )

    monkeypatch.setattr(parser, "parse_table", parse_table)
    connection = parser.to_sqlite()

    try:
        assert connection.execute("SELECT timestamp, guid, amount FROM types").fetchone() == (
            "2020-07-05 14:29:03.135000",
            "4ad1b98b-9f0f-46c7-a827-0165678e8cbd",
            "12.3400",
        )
    finally:
        connection.close()


def test_jet3_jump_table_offsets_are_independent_of_null_fields() -> None:
    record = bytearray(268)
    record[250:260] = b"a" * 10
    record[260:264] = b"b" * 4
    record[264:268] = b"c" * 4
    columns: dict[int, Column] = {
        index: cast(
            "Column",
            SimpleNamespace(type=TYPE_BINARY, column_id=index, col_name_str=f"column_{index}"),
        )
        for index in range(3)
    }
    metadata = cast(
        "RelativeMetadata",
        SimpleNamespace(
            variable_length_field_offsets=[250, 4, 8],
            variable_length_jump_table=[1],
            var_len_count=12,
        ),
    )
    table = AccessTable.__new__(AccessTable)
    table.version = 3
    table.parsed_table = defaultdict[str, list[ParsedValue]](list)

    table._parse_dynamic_length_data(  # pyright: ignore[reportPrivateUsage]
        bytes(record), metadata, columns, [True, False, True]
    )

    assert table.parsed_table == {
        "column_0": [b"a" * 10],
        "column_1": [None],
        "column_2": [b"c" * 4],
    }


@pytest.mark.parametrize("version", [3, 4])
@pytest.mark.parametrize("end_flags", [0, 0x4000, 0x8000, 0xC000])
@pytest.mark.parametrize("end_offset", [0x400, 0x401])
def test_overflow_record_masks_adjacent_row_flags(version: int, end_flags: int, end_offset: int) -> None:
    page_size = 2048 if version == 3 else 4096
    record = b"overflow row"
    start_offset = end_offset - len(record)
    page = bytearray(page_size)
    header = struct.pack("<2sHI", b"\x01\x01", 0, 1)
    if version > 3:
        header += b"\0" * 4
    header += struct.pack("<HHH", 2, end_offset | end_flags, start_offset | 0x8000)
    page[: len(header)] = header
    page[start_offset:end_offset] = record
    page[end_offset:] = b"x" * (page_size - end_offset)
    table = AccessTable.__new__(AccessTable)
    table.version = version
    table.page_size = page_size
    table._data_pages = {page_size: bytes(page)}  # pyright: ignore[reportPrivateUsage]

    assert table._get_overflow_record(0x101) == record  # pyright: ignore[reportPrivateUsage]


def test_parses_single_byte_jet3_lvprop_names() -> None:
    property_name = b"Description"
    column_name = b"Notes"
    value = b"hello"
    name_body = struct.pack("<H", len(property_name)) + property_name
    name_chunk = struct.pack("<IH", 6 + len(name_body), 128) + name_body
    property_data = struct.pack("<HBBHH", 8 + len(value), 0, TYPE_TEXT, 0, len(value)) + value
    value_body = struct.pack("<IH", 6 + len(column_name) + len(property_data), len(column_name))
    value_body += column_name + property_data
    value_chunk = struct.pack("<IH", 6 + len(value_body), 1) + value_body
    parser = AccessParser.__new__(AccessParser)
    parser.version = 3

    assert parser.parse_lvprop(b"KKD\0" + name_chunk + value_chunk) == {
        "Notes": {"Description": "hello"},
    }
