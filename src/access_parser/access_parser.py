"""Public Access database parser."""

import logging
import os
import sqlite3
import struct
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from decimal import Decimal
from typing import cast
from uuid import UUID

from construct import ConstructError
from tabulate import tabulate

from .parsing_primitives import (
    Column,
    RelativeMetadata,
    TableHeader,
    parse_access_header,
    parse_data_page_header,
    parse_lvprop as parse_lvprop_value,
    parse_memo,
    parse_relative_object_metadata_struct,
    parse_table_data,
    parse_table_head,
    parse_tdef_header,
)
from .utils import (
    TYPE_BOOLEAN,
    TYPE_MEMO,
    TYPE_NUMERIC,
    TYPE_OLE,
    TYPE_TEXT,
    PageMap,
    ParsedValue,
    categorize_pages,
    parse_type,
    read_db_file,
)

type ParsedTable = defaultdict[str, list[ParsedValue]]
type ColumnProperties = dict[str, ParsedValue]
type TableProperties = dict[str, ColumnProperties]
type ExtraProperties = dict[str, TableProperties | None]

# Page sizes
PAGE_SIZE_V3 = 0x800
PAGE_SIZE_V4 = 0x1000

# Versions
VERSION_3 = 0x00
VERSION_4 = 0x01
VERSION_5 = 0x02
VERSION_2010 = 0x03

ALL_VERSIONS = {VERSION_3: 3, VERSION_4: 4, VERSION_5: 5, VERSION_2010: 2010}
NEW_VERSIONS = [VERSION_4, VERSION_5, VERSION_2010]

SYSTEM_TABLE_FLAGS = [-0x80000000, -0x00000002, 0x80000000, 0x00000002]

LOGGER = logging.getLogger("access_parser")


def _quote_sqlite_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _to_sqlite_value(value: ParsedValue) -> bool | bytes | float | int | str | None:
    if isinstance(value, datetime):
        return value.isoformat(sep=" ", timespec="microseconds")
    if isinstance(value, (Decimal, UUID)):
        return str(value)
    return value


def _get_primary_keys(columns: list[Column], table_header: TableHeader) -> list[str]:
    columns_by_id = {column.column_id: column for column in columns}
    return [
        columns_by_id[index_column.col_id].col_name_str
        for index in table_header.all_indexes
        for index_column in table_header.real_index_2[index.idx_col_num].unk_struct
        if index.idx_type == 1 and index_column.col_id != 0xFFFF
    ]


class TableObj:
    """A table-definition page and its linked data pages."""

    def __init__(self, offset: int, val: bytes) -> None:
        """Initialize a table object."""
        self.value = val
        self.offset = offset
        self.linked_pages: list[bytes] = []


class AccessParser:
    """Parse tables from a Microsoft Access database file."""

    def __init__(self, db_path: str | os.PathLike[str]) -> None:
        """Read and index an Access database."""
        self.db_data = read_db_file(db_path)
        self.version: int
        self.page_size: int
        self._parse_file_header(self.db_data)
        self._table_defs, self._data_pages, self._all_pages = categorize_pages(self.db_data, self.page_size)
        self._tables_with_data = self._link_tables_to_data()
        self.catalog = self._parse_catalog()
        self.extra_props = self.parse_msys_table()

    def parse_msys_table(self) -> ExtraProperties:
        """Parse column metadata from MSysObjects."""
        msys_table = self.parse_table("MSysObjects")
        names = msys_table.get("Name")
        values = msys_table.get("LvProp")
        if not names or not values:
            return {}

        properties: ExtraProperties = {}
        for name, value in zip(names, values, strict=False):
            if isinstance(name, str) and isinstance(value, bytes):
                properties[name] = self.parse_lvprop(value)
        return properties

    def _parse_file_header(self, db_data: bytes) -> None:
        """Parse the basic file header and determine the Access DB version based on the parsing results.

        :param db_data: db file data.
        """
        try:
            head = parse_access_header(db_data)
        except ConstructError as error:
            # This is a very minimal parsing of the header. If we fail this probable is not a valid mdb file
            raise ValueError("Failed to parse DB file header. Check it is a valid access database") from error
        version = head.jet_version
        if version in NEW_VERSIONS:
            self.version = ALL_VERSIONS[version]
            self.page_size = PAGE_SIZE_V4

        else:
            if version != VERSION_3:
                LOGGER.error(f"Unknown database version {version} Trying to parse database as version 3")
            self.version = ALL_VERSIONS[VERSION_3]
            self.page_size = PAGE_SIZE_V3
        LOGGER.info(f"DataBase version {version}")

    def _link_tables_to_data(self) -> dict[int, TableObj]:
        """Link tables definitions to their data pages.

        :return: dict of {ofssets : PageObj}.
        """
        tables_with_data: dict[int, TableObj] = {}
        # Link table definitions to data
        # the offset of the table definition page / 0x800  ==  the owner of a Data page
        for data in self._data_pages.values():
            try:
                parsed_dp = parse_data_page_header(data, version=self.version)
            except ConstructError:
                LOGGER.error(f"Failed to parse data page {data}")
                continue
            page_offset = parsed_dp.owner * self.page_size
            if page_offset in self._table_defs:
                if page_offset not in tables_with_data:
                    tables_with_data[page_offset] = TableObj(page_offset, self._table_defs[page_offset])
                tables_with_data[page_offset].linked_pages.append(data)
        return tables_with_data

    def _parse_catalog(self) -> dict[str, int]:
        """Parse the catalog to get the DB tables and their offsets.

        :return: dict {table : offset}.
        """
        catalog_page = self._tables_with_data[2 * self.page_size]
        access_table = AccessTable(catalog_page, self.version, self.page_size, self._data_pages, self._table_defs)
        catalog = access_table.parse()
        names = cast("list[str]", catalog["Name"])
        ids = cast("list[int]", catalog["Id"])
        types = cast("list[int]", catalog["Type"])
        flags = cast("list[int]", catalog["Flags"])
        tables_mapping: dict[str, int] = {}
        for table_name, table_id, table_type, table_flags in zip(names, ids, types, flags, strict=True):
            # We need the MSysObjects table for metadata so exclude it from the system table filter.
            if table_name == "MSysObjects":
                tables_mapping[table_name] = table_id
            # Visible user tables are type 1
            if table_type == 1:
                # Don't parse system tables
                if table_flags not in SYSTEM_TABLE_FLAGS:
                    tables_mapping[table_name] = table_id
                else:
                    LOGGER.debug(f"Not parsing system table - {table_name}")
        return tables_mapping

    def get_table(self, table_name: str) -> AccessTable | None:
        """Return a parsed table definition, if it exists."""
        table_offset = self.catalog.get(table_name)
        if not table_offset:
            LOGGER.error(f"Could not find table {table_name} in DataBase")
            return
        table_offset = table_offset * self.page_size
        table = self._tables_with_data.get(table_offset)
        if not table:
            table_def = self._table_defs.get(table_offset)
            if table_def:
                table = TableObj(offset=table_offset, val=table_def)
                LOGGER.info(f"Table {table_name} has no data")
            else:
                LOGGER.error(f"Could not find table {table_name} offset {table_offset}")
                return

        # Try to get extra metadata for the table if it exists in the MSysObjects table
        props = self.extra_props.get(table_name) if table_name != "MSysObjects" else None

        return AccessTable(table, self.version, self.page_size, self._data_pages, self._table_defs, props)

    def parse_lvprop(self, lvprop_raw: bytes) -> TableProperties | None:
        """Parse table and column properties from an LVPROP value."""
        try:
            parsed = parse_lvprop_value(lvprop_raw, version=self.version)
        except ConstructError:
            return None
        if not parsed.chunks:
            return None
        table_names = [x.name for x in parsed.chunks[0].data.names]
        # Chunk type 0 does not have a column name, so we cannot link it to a column
        chunk_type_one = [x for x in parsed.chunks if x.chunk_type == 1]
        reconstructed_column_data: TableProperties = {}
        for chunk in chunk_type_one:
            if not chunk.data.column_name:
                LOGGER.error("Error while parsing MSysObjects table chunk.")
                continue
            data_values: ColumnProperties = {}
            for dv in chunk.data.data:
                val = parse_type(dv.type, dv.actual_data, version=self.version)
                try:
                    name = table_names[dv.name_index]
                    data_values[name] = val
                except IndexError:
                    LOGGER.error("Error while parsing MSysObjects table chunk.")
                    continue
            reconstructed_column_data[chunk.data.column_name] = data_values
        return reconstructed_column_data

    def parse_table(self, table_name: str) -> ParsedTable:
        """Parse a table from the db.

        tables names are in self.catalog
        :return defaultdict(list) with the parsed table -- table[column][row_index].
        """
        table = self.get_table(table_name)
        if table is None:
            raise KeyError(f"Unknown table: {table_name}")
        return table.parse()

    def to_sqlite(self, tables: Iterable[str] | None = None) -> sqlite3.Connection:
        """Copy tables into a query-only, in-memory SQLite database."""
        connection = sqlite3.connect(":memory:")
        table_names = self.catalog if tables is None else tables

        try:
            with connection:
                for table_name in table_names:
                    table = self.parse_table(table_name)
                    columns = list(table)
                    quoted_table = _quote_sqlite_identifier(table_name)
                    definitions = ", ".join(_quote_sqlite_identifier(column) for column in columns)
                    connection.execute(f"CREATE TABLE {quoted_table} ({definitions})")

                    if columns:
                        placeholders = ", ".join("?" for _ in columns)
                        rows = (
                            tuple(_to_sqlite_value(value) for value in row)
                            for row in zip(*(table[column] for column in columns), strict=True)
                        )
                        # Table names are quoted as SQLite identifiers above.
                        insert_sql = f"INSERT INTO {quoted_table} VALUES ({placeholders})"  # noqa: S608
                        connection.executemany(insert_sql, rows)

            connection.execute("PRAGMA query_only = ON")
        except Exception:
            connection.close()
            raise

        return connection

    def print_database(self) -> None:
        """Print data from all database tables."""
        table_names = self.catalog
        for table_name in table_names:
            table = self.parse_table(table_name)
            if not table:
                continue
            print(f"TABLE NAME: {table_name}\r\n")
            print(tabulate(table, headers="keys", disable_numparse=True))
            print("\r\n\r\n\r\n\r\n")


class AccessTable:
    """Decode rows using a parsed Access table definition."""

    def __init__(
        self,
        table: TableObj,
        version: int,
        page_size: int,
        data_pages: PageMap,
        table_defs: PageMap,
        props: TableProperties | None = None,
    ) -> None:
        """Initialize an Access table decoder."""
        self.version = version
        self.props = props
        self.page_size = page_size
        self._data_pages = data_pages
        self._table_defs = table_defs
        self.table = table
        self.parsed_table: ParsedTable = defaultdict(list)
        self.columns, self.primary_keys, self.table_header = self._get_table_columns()

    def create_empty_table(self) -> ParsedTable:
        """Create an empty result containing every table column."""
        parsed_table: ParsedTable = defaultdict(list)
        for column in self.columns.values():
            parsed_table[column.col_name_str] = []
        return parsed_table

    def parse(self) -> ParsedTable:
        """Parse (main table parsing function).

        We go through all of the data pages linked to the table, separate each
        data page to rows(records) and parse each record.
        :return defaultdict(list) with the parsed data -- table[column][row_index].
        """
        if not self.table.linked_pages:
            return self.create_empty_table()
        for data_chunk in self.table.linked_pages:
            original_data = data_chunk
            parsed_data = parse_data_page_header(original_data, version=self.version)

            last_offset: int | None = None
            for rec_offset in parsed_data.record_offsets:
                # Deleted row - Just skip it
                if rec_offset & 0x8000:
                    last_offset = rec_offset & 0xFFF
                    continue
                # Overflow page
                if rec_offset & 0x4000:
                    # overflow ptr is 4 bits flags, 12 bits ptr
                    rec_ptr_offset = rec_offset & 0xFFF
                    # update last pointer to pointer without flags
                    last_offset = rec_ptr_offset
                    # The ptr is the offset in the current data page. we get a 4 byte record_pointer from that
                    overflow_rec_ptr = original_data[rec_ptr_offset : rec_ptr_offset + 4]
                    overflow_rec_ptr = struct.unpack("<I", overflow_rec_ptr)[0]
                    record = self._get_overflow_record(overflow_rec_ptr)
                    if record:
                        self._parse_row(record)
                    continue
                # First record is actually the last one - from offset until the end of the data
                if not last_offset:
                    record = original_data[rec_offset:]
                else:
                    record = original_data[rec_offset:last_offset]
                last_offset = rec_offset
                if record:
                    self._parse_row(record)
        return self.parsed_table

    def _parse_row(self, record: bytes) -> None:
        """Parse record (row) of data.

        First parse all fixed-length data field and then parse the relative length data.
        :param record: the current row data
        :return:
        """
        original_record = record
        reverse_record = record[::-1]
        # Records contain null bitmaps for columns. The number of bitmaps is the number of columns / 8 rounded up
        null_table_len = (self.table_header.column_count + 7) // 8
        if null_table_len and null_table_len < len(original_record):
            null_bytes = record[-null_table_len:]
            # Turn bitmap to a list of True False values
            null_table = [(null_bytes[i // 8] & (1 << (i % 8))) != 0 for i in range(len(null_bytes) * 8)]
        else:
            LOGGER.error(f"Failed to parse null table column count {self.table_header.column_count}")
            return
        if self.version > 3:
            struct.unpack_from("h", record)[0]
            record = record[2:]
        else:
            struct.unpack_from("b", record)[0]
            record = record[1:]

        relative_records_column_map: dict[int, Column] = {}
        # Iterate columns
        for i, column in self.columns.items():
            # Fixed length columns are handled before variable length. If this is a variable length column add it to
            # mapping and continue
            if not column.column_flags.fixed_length:
                relative_records_column_map[i] = column
                continue

            self._parse_fixed_length_data(record, column, null_table)
        if relative_records_column_map:
            relative_records_column_map = dict(sorted(relative_records_column_map.items()))
            metadata = self._parse_dynamic_length_records_metadata(reverse_record, original_record, null_table_len)
            if not metadata:
                return
            if metadata.variable_length_field_offsets:
                self._parse_dynamic_length_data(original_record, metadata, relative_records_column_map, null_table)

    def _parse_fixed_length_data(
        self,
        original_record: bytes,
        column: Column,
        null_table: list[bool],
    ) -> None:
        """Parse fixed-length data from record.

        :param original_record: unmodified record
        :param column: column this data belongs to
        :param null_table: null table of the row.
        """
        column_name = column.col_name_str
        # The null table indicates null values in the row.
        # The only exception is BOOL fields which are encoded in the null table
        has_value = True
        if column.column_id > len(null_table):
            LOGGER.warning("Invalid null table. Bool values may be wrong, deleted values may be shown in the db.")
            if column.type == TYPE_BOOLEAN:
                has_value = None
        else:
            has_value = null_table[column.column_id]
        # Boolean fields are encoded in the null table
        if column.type == TYPE_BOOLEAN:
            parsed_type = has_value
        else:
            if not has_value:
                self.parsed_table[column_name].append(None)
                return
            if column.fixed_offset > len(original_record):
                LOGGER.error(f"Column offset is bigger than the length of the record {column.fixed_offset}")
                return
            record = original_record[column.fixed_offset :]
            scale = column.various.get("scale", 0)
            parsed_type = parse_type(
                column.type,
                record,
                version=self.version,
                scale=scale if isinstance(scale, int) else 0,
            )
        self.parsed_table[column_name].append(parsed_type)

    def _parse_dynamic_length_records_metadata(
        self,
        reverse_record: bytes,
        original_record: bytes,
        null_table_length: int,
    ) -> RelativeMetadata | None:
        """Parse the metadata of relative records.

        The metadata used to parse relative records is found at the end of the
        record so reverse_record is used for parsing from the bottom up.
        :param reverse_record: original record in reverse
        :param original_record: unmodified record
        :param null_table_length:
        :return: parsed relative record metadata.
        """
        if self.version > 3:
            reverse_record = reverse_record[null_table_length:]
            return parse_relative_object_metadata_struct(reverse_record, version=self.version)
        # Parse relative metadata.
        # Metadata is from the end of the record(reverse_record is used here)
        variable_length_jump_table_cnt = (len(original_record) - 1) // 256
        reverse_record = reverse_record[null_table_length:]
        try:
            relative_record_metadata = parse_relative_object_metadata_struct(
                reverse_record, variable_length_jump_table_cnt, self.version
            )
            # relative_record_metadata = RELATIVE_OBJS.parse(reverse_record)
            # we use this offset in original_record so we have to update the length with the null_tables
            relative_record_metadata.relative_metadata_end = (
                relative_record_metadata.relative_metadata_end + null_table_length
            )
        except ConstructError:
            relative_record_metadata = None
            LOGGER.error("Failed parsing record")

        if (
            relative_record_metadata
            and relative_record_metadata.variable_length_field_count != self.table_header.variable_columns
        ):
            # best effort - try to find variable column count in the record and parse from there
            # this is limited to the 10 first bytes to reduce false positives.
            # most of the time iv'e seen this there was an extra DWORD before the actual metadata
            metadata_start = reverse_record.find(bytes([self.table_header.variable_columns]))
            if metadata_start != -1 and metadata_start < 10:
                reverse_record = reverse_record[metadata_start:]
                try:
                    relative_record_metadata = parse_relative_object_metadata_struct(
                        reverse_record, variable_length_jump_table_cnt, self.version
                    )
                except ConstructError:
                    LOGGER.error(f"Failed to parse record metadata: {original_record}")
                relative_record_metadata.relative_metadata_end = (
                    relative_record_metadata.relative_metadata_end + metadata_start
                )
            else:
                LOGGER.warning(
                    f"Record did not parse correctly. Number of columns: {self.table_header.variable_columns}"
                    f" number of parsed columns: {relative_record_metadata.variable_length_field_count}"
                )
                return None
        return relative_record_metadata

    def _parse_dynamic_length_data(
        self,
        original_record: bytes,
        relative_record_metadata: RelativeMetadata,
        relative_records_column_map: dict[int, Column],
        null_table: list[bool],
    ) -> None:
        """Parse dynamic (non fixed length) records from row.

        :param original_record: full unmodified record
        :param relative_record_metadata: parsed record metadata
        :param relative_records_column_map: relative records colum mapping {index: column}
        :param null_table: list indicating which columns have null value.
        """
        relative_offsets = relative_record_metadata.variable_length_field_offsets
        jump_table = relative_record_metadata.variable_length_jump_table or []

        def absolute_offset(offset: int, index: int) -> int:
            if self.version != 3:
                return offset
            return offset + 0x100 * sum(jump_index <= index for jump_index in jump_table)

        for i, column_index in enumerate(relative_records_column_map):
            column = relative_records_column_map[column_index]
            col_name = column.col_name_str
            has_value = True
            if column.column_id > len(null_table):
                LOGGER.warning("Invalid null table. null values may be shown in the db.")
            else:
                has_value = null_table[column.column_id]
            if not has_value:
                self.parsed_table[col_name].append(None)
                continue

            rel_start = absolute_offset(relative_offsets[i], i)
            # If this is the last one use var_len_count as end offset
            if i + 1 == len(relative_offsets):
                rel_end = absolute_offset(relative_record_metadata.var_len_count, i + 1)
            else:
                rel_end = absolute_offset(relative_offsets[i + 1], i + 1)

            # if rel_start and rel_end are the same there is no data in this slot
            if rel_start == rel_end:
                self.parsed_table[col_name].append("")
                continue

            relative_obj_data = original_record[rel_start:rel_end]
            self.parsed_table[col_name].append(self._parse_variable_value(column, relative_obj_data))

    def _parse_variable_value(self, column: Column, data: bytes) -> ParsedValue:
        if column.type in {TYPE_MEMO, TYPE_OLE}:
            try:
                return self._parse_memo(data, return_raw=column.type == TYPE_OLE)
            except ConstructError:
                LOGGER.warning("Failed to parse memo or OLE field. Using data as bytes")
                return data
        if column.type != TYPE_NUMERIC:
            return parse_type(column.type, data, len(data), version=self.version)
        if len(data) != 17:
            LOGGER.warning(f"Relative numeric field has invalid length {len(data)}, expected 17")
            return data

        scale = column.various.get("scale", 6)
        return parse_type(
            column.type,
            data,
            len(data),
            version=self.version,
            scale=scale if isinstance(scale, int) else 6,
        )

    def _get_table_columns(self) -> tuple[dict[int, Column], list[str], TableHeader]:
        """Parse columns for a specific table."""
        try:
            table_header = parse_table_head(self.table.value, version=self.version)
            merged_data = self.table.value[table_header.tdef_header_end :]
            if table_header.TDEF_header.next_page_ptr:
                merged_data = merged_data + self._merge_table_data(table_header.TDEF_header.next_page_ptr)

            parsed_data = parse_table_data(
                merged_data,
                table_header.index_count,
                table_header.real_index_count,
                table_header.column_count,
                version=self.version,
            )

            # Merge Data back to table_header
            table_header.column = parsed_data.column
            table_header.column_names = parsed_data.column_names
            table_header.real_index_2 = parsed_data.real_index_2
            table_header.all_indexes = parsed_data.all_indexes
            table_header.index_names = parsed_data.index_names

        except ConstructError as error:
            LOGGER.error(f"Failed to parse table header {self.table.value}")
            raise ValueError("Failed to parse table header") from error
        col_names = table_header.column_names
        columns = table_header.column

        # Add names to columns metadata, so we can use only columns for parsing
        for i, c in enumerate(columns):
            c.col_name_str = col_names[i].col_name_str
            c.extra_props = None

        # column_index is more accurate(id is always incremented so it is wrong when a column is deleted).
        # Some tables like the catalog don't have index, so if indexes are 0 use id.

        # create a dict of index to column to make it easier to access. offset is used to make this zero based
        offset = min(x.column_index for x in columns)
        column_dict = {x.column_index - offset: x for x in columns}
        # If column index is not unique try best effort
        if len(column_dict) != len(columns):
            # create a dict of id to column to make it easier to access
            column_dict = {x.column_id: x for x in columns}

        # Add the extra properties relevant for the column
        if self.props:
            for col in column_dict.values():
                if col.col_name_str in self.props:
                    col.extra_props = self.props[col.col_name_str]

        primary_keys = _get_primary_keys(columns, table_header)

        if len(column_dict) != table_header.column_count:
            LOGGER.debug(f"expected {table_header.column_count} columns got {len(column_dict)}")
        return column_dict, primary_keys, table_header

    def _merge_table_data(self, first_page: int) -> bytes:
        """Merge data of tdef pages in case the data does not fit in one page.

        :param first_page: index of the next page
        :return: merged data from all linked table definitions.
        """
        table = self._table_defs[first_page * self.page_size]
        parsed_header = parse_tdef_header(table)
        data = table[parsed_header.header_end :]
        while parsed_header.next_page_ptr:
            table = self._table_defs[parsed_header.next_page_ptr * self.page_size]
            parsed_header = parse_tdef_header(table)
            data = data + table[parsed_header.header_end :]
        return data

    def _parse_memo(self, relative_obj_data: bytes, return_raw: bool = False) -> ParsedValue:
        LOGGER.debug(f"Parsing memo field {relative_obj_data}")
        parsed_memo = parse_memo(relative_obj_data)
        memo_type = TYPE_TEXT
        if parsed_memo.memo_length & 0x80000000:
            LOGGER.debug("memo data inline")
            inline_memo_length = parsed_memo.memo_length & 0x3FFFFFFF
            if len(relative_obj_data) < parsed_memo.memo_end + inline_memo_length:
                LOGGER.warning("Inline memo field has invalid length using full data")
                memo_data = relative_obj_data[parsed_memo.memo_end :]
            else:
                memo_data = relative_obj_data[parsed_memo.memo_end : parsed_memo.memo_end + inline_memo_length]

        elif parsed_memo.memo_length & 0x40000000:
            LOGGER.debug("LVAL type 1")
            memo_data = self._get_overflow_record(parsed_memo.record_pointer)
            if memo_data is None:
                return None
        else:
            LOGGER.debug("LVAL type 2")
            rec_data = self._get_overflow_record(parsed_memo.record_pointer)
            if rec_data is None:
                return None
            next_page = struct.unpack("I", rec_data[:4])[0]
            # LVAL2 has data over multiple pages. The first 4 bytes of the page are the next record, then that data.
            # Concat the data until we get a 0 next_page.
            memo_data = b""
            while next_page:
                memo_data += rec_data[4:]
                rec_data = self._get_overflow_record(next_page)
                if rec_data is None:
                    return None
                next_page = struct.unpack("I", rec_data[:4])[0]
            memo_data += rec_data[4:]
        if memo_data:
            if return_raw:
                return memo_data
            parsed_type = parse_type(memo_type, memo_data, len(memo_data), version=self.version)
            return parsed_type

        return None

    def _get_overflow_record(self, record_pointer: int) -> bytes | None:
        """Read the row addressed by an overflow record pointer.

        Strip flags from row boundaries before slicing the data page.

        :param record_pointer:
        :return: record.
        """
        record_offset = record_pointer & 0xFF
        page_num = record_pointer >> 8
        record_page = self._data_pages.get(page_num * self.page_size)
        if not record_page:
            LOGGER.warning(f"Could not find overflow record data page overflow pointer: {record_pointer}")
            return
        parsed_data = parse_data_page_header(record_page, version=self.version)
        if record_offset >= len(parsed_data.record_offsets):
            LOGGER.warning("Failed parsing overflow record offset")
            return
        start = parsed_data.record_offsets[record_offset]
        if start & 0x8000:
            start = start & 0xFFF
        else:
            LOGGER.debug(f"Overflow record flag is not present {start}")
        if record_offset == 0:
            record = record_page[start:]
        else:
            end = parsed_data.record_offsets[record_offset - 1] & 0xFFF
            record = record_page[start:end]
        return record
