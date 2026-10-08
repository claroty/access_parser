"""Binary structures used by the Access database parser."""

from collections.abc import Mapping
from typing import Protocol, cast

from construct import (
    Array,
    BitStruct,
    Bytes,
    Computed,
    Const,
    Construct,
    CString,
    Flag,
    GreedyBytes,
    GreedyRange,
    If,
    IfThenElse,
    Int8ub,
    Int8ul,
    Int16ub,
    Int16ul,
    Int32sl,
    Int32ul,
    PaddedString,
    Padding,
    Peek,
    Prefixed,
    Struct,
    Switch,
    Tell,
    this,
)

from .utils import ParsedValue


class AccessHeader(Protocol):
    """Parsed database header fields used by the parser."""

    jet_version: int


class TDefHeader(Protocol):
    """Parsed table-definition linkage header."""

    next_page_ptr: int
    header_end: int


class ColumnFlags(Protocol):
    """Column flags used while decoding rows."""

    fixed_length: bool


class Column(Protocol):
    """Parsed column definition used while decoding rows."""

    type: int
    column_id: int
    column_index: int
    fixed_offset: int
    column_flags: ColumnFlags
    various: Mapping[str, object]
    col_name_str: str
    extra_props: Mapping[str, ParsedValue] | None


class ColumnName(Protocol):
    """Parsed column name."""

    col_name_str: str


class IndexColumn(Protocol):
    """Column reference within an index."""

    col_id: int


class RealIndex(Protocol):
    """Parsed real-index definition."""

    unk_struct: list[IndexColumn]


class TableIndex(Protocol):
    """Parsed table index."""

    idx_col_num: int
    idx_type: int


class TableData(Protocol):
    """Parsed columns and indexes following a table header."""

    column: list[Column]
    column_names: list[ColumnName]
    real_index_2: list[RealIndex]
    all_indexes: list[TableIndex]
    index_names: list[object]


class TableHeader(TableData, Protocol):
    """Parsed table header and its attached column/index definitions."""

    TDEF_header: TDefHeader
    tdef_header_end: int
    number_of_rows: int
    variable_columns: int
    column_count: int
    index_count: int
    real_index_count: int


class DataPageHeader(Protocol):
    """Parsed data-page fields used by the parser."""

    owner: int
    record_offsets: list[int]


class RelativeMetadata(Protocol):
    """Offsets for variable-length fields in a record."""

    variable_length_field_count: int
    variable_length_jump_table: list[int] | None
    variable_length_field_offsets: list[int]
    var_len_count: int
    relative_metadata_end: int


class LvPropName(Protocol):
    """Name stored in an LVPROP name chunk."""

    name: str


class LvPropDatum(Protocol):
    """Value stored in an LVPROP data chunk."""

    type: int
    name_index: int
    actual_data: bytes


class LvPropChunkData(Protocol):
    """Payload of an LVPROP chunk."""

    names: list[LvPropName]
    column_name: str
    data: list[LvPropDatum]


class LvPropChunk(Protocol):
    """Parsed LVPROP chunk."""

    chunk_type: int
    data: LvPropChunkData


class LvProp(Protocol):
    """Parsed collection of LVPROP chunks."""

    chunks: list[LvPropChunk]


class Memo(Protocol):
    """Parsed memo field header."""

    memo_length: int
    record_pointer: int
    memo_end: int


def version_specific[ParsedT, BuildT](
    version: int,
    v3_subcon: Construct[ParsedT, BuildT],
    v4_subcon: Construct[ParsedT, BuildT],
) -> Construct[ParsedT, BuildT]:
    """There are some differences in the parsing structure between v3 and v4.

    Some fields are different length and some
    exist only in one of the versions. this returns the relevant parsing structure by version
    :param version: int 3 or 4
    :param v3_subcon: the parsing struct if version is 3
    :param v4_subcon: the parsing struct if version is 4.
    """
    return v3_subcon if version == 3 else v4_subcon


_ACCESS_HEADER = Struct(
    Const(b"\00\x01\x00\x00"),
    "jet_string" / CString("utf8"),
    "jet_version" / Int32ul,
    # RC4 encrypted with key 0x6b39dac7. Database metadata
    Padding(126),
)

_MEMO = Struct("memo_length" / Int32ul, "record_pointer" / Int32ul, "memo_unknown" / Int32ul, "memo_end" / Tell)

VERSION_3_FLAGS = BitStruct(
    "hyperlink" / Flag,
    "auto_GUID" / Flag,
    "unk_1" / Flag,
    "replication" / Flag,
    "unk_2" / Flag,
    "autonumber" / Flag,
    "can_be_null" / Flag,
    "fixed_length" / Flag,
)

VERSION_4_FLAGS = BitStruct(
    "hyperlink" / Flag,
    "auto_GUID" / Flag,
    "unk_1" / Flag,
    "replication" / Flag,
    "unk_2" / Flag,
    "autonumber" / Flag,
    "can_be_null" / Flag,
    "fixed_length" / Flag,
    "unk_3" / Flag,
    "unk_4" / Flag,
    "unk_5" / Flag,
    "modern_package_type" / Flag,
    "unk_6" / Flag,
    "unk_7" / Flag,
    "unk_8" / Flag,
    "compressed_unicode" / Flag,
)

_TDEF_HEADER = Struct(
    Const(b"\02\x01"),
    "peek_version" / Peek(Int16ul),
    "tdef_ver" / IfThenElse(this.peek_version == b"VC", Const(b"VC"), Int16ul),
    "next_page_ptr" / Int32ul,
    "header_end" / Tell,
)


def _make_lvprop_parser(encoding: str) -> Struct:
    chunk_names = Struct(
        "names"
        / GreedyRange(
            Struct(
                "name_length" / Int16ul,
                "name" / PaddedString(this.name_length, encoding),
            )
        ),
    )
    data = Struct(
        "data_length" / Int16ul,
        "ddl_flag" / Int8ul,
        "type" / Int8ul,
        "name_index" / Int16ul,
        "only_data_length" / Int16ul,
        "actual_data" / Bytes(this.only_data_length),
    )
    value = Struct(
        "val_length" / Int32ul,
        "name_length" / Int16ul,
        "column_name" / PaddedString(this.name_length, encoding),
        "data" / GreedyRange(data),
        "left" / GreedyBytes,
    )
    chunk = Struct(
        "length" / Int32ul,
        "chunk_type" / Int16ul,
        "data"
        / Prefixed(
            cast("Construct[int, int]", Computed(this.length - 6)),
            Switch(this.chunk_type, {128: chunk_names, 0: value, 1: value}, default=Bytes(this.length - 4)),
        ),
    )
    return Struct(
        # 'KKD\0' in Jet3 and 'MR2\0' in Jet 4.
        "magic" / Bytes(4),
        "chunks" / GreedyRange(chunk),
        "leftover" / GreedyBytes,
    )


_LVPROP_V3 = _make_lvprop_parser("utf8")
_LVPROP_V4 = _make_lvprop_parser("utf16")


def parse_access_header(buffer: bytes) -> AccessHeader:
    """Parse the database header."""
    return cast("AccessHeader", _ACCESS_HEADER.parse(buffer))


def parse_memo(buffer: bytes) -> Memo:
    """Parse a memo field header."""
    return cast("Memo", _MEMO.parse(buffer))


def parse_tdef_header(buffer: bytes) -> TDefHeader:
    """Parse a table-definition linkage header."""
    return cast("TDefHeader", _TDEF_HEADER.parse(buffer))


def parse_lvprop(buffer: bytes, version: int = 4) -> LvProp:
    """Parse an LVPROP metadata value."""
    parser = _LVPROP_V3 if version == 3 else _LVPROP_V4
    return cast("LvProp", parser.parse(buffer))


def parse_table_head(buffer: bytes, version: int = 3) -> TableHeader:
    """Parse a table-definition page header."""
    parser = Struct(
        "TDEF_header" / _TDEF_HEADER,
        # Table
        "table_definition_length" / Int32ul,
        "ver4_unknown" / If(version > 3, Int32ul),
        "number_of_rows" / Int32ul,
        "autonumber" / Int32ul,
        "autonumber_increment" / If(version > 3, Int32ul),
        "complex_autonumber" / If(version > 3, Int32ul),
        "ver4_unknown_1" / If(version > 3, Int32ul),
        "ver4_unknown_2" / If(version > 3, Int32ul),
        # 0x53 system table
        # 0x4e user table
        "table_type_flags" / Int8ul,
        "next_column_id" / Int16ul,
        "variable_columns" / Int16ul,
        "column_count" / Int16ul,
        "index_count" / Int32ul,
        "real_index_count" / Int32ul,
        "row_page_map" / Int32ul,
        "free_space_page_map" / Int32ul,
        "tdef_header_end" / Tell,
    )
    return cast("TableHeader", parser.parse(buffer))


def parse_table_data(
    buffer: bytes,
    index_count: int,
    real_index_count: int,
    column_count: int,
    version: int = 3,
) -> TableData:
    """Parse the columns and indexes following a table header."""
    REAL_INDEX = Struct("unk1" / Int32ul, "index_row_count" / Int32ul, "ver4_always_zero" / If(version > 3, Int32ul))

    VARIOUS_TEXT_V3 = Struct("LCID" / Int16ul, "code_page" / Int16ul, "various_text3_unknown" / Int16ul)

    VARIOUS_TEXT_V4 = Struct(
        "collation" / Int16ul, "various_text4_unknown" / Int8ul, "collation_version_number" / Int8ul
    )

    VARIOUS_TEXT = VARIOUS_TEXT_V3 if version == 3 else VARIOUS_TEXT_V4

    VARIOUS_DEC_V3 = Struct(
        "various_dec3_unknown" / Int16ul,
        "max_number_of_digits" / Int8ul,
        "number_of_decimal" / Int8ul,
        "various_dec3_unknown2" / Int16ul,
    )

    VARIOUS_DEC_V4 = Struct(
        "max_num_of_digits" / Int8ul, "num_of_decimal_digits" / Int8ul, "various_dec4_unknown" / Int16ul
    )

    VARIOUS_DEC = VARIOUS_DEC_V3 if version == 3 else VARIOUS_DEC_V4

    VARIOUS_NUMERIC_V3 = Struct("prec" / Int8ul, "scale" / Int8ul, "unknown" / Int32ul)
    VARIOUS_NUMERIC_V4 = Struct("prec" / Int8ul, "scale" / Int8ul, "unknown" / Int16ul)
    VARIOUS_NUMERIC = VARIOUS_NUMERIC_V3 if version == 3 else VARIOUS_NUMERIC_V4

    COLUMN = Struct(
        "type" / Int8ul,
        "ver4_unknown_3" / If(version > 3, Int32ul),
        "column_id" / Int16ul,
        "variable_column_number" / Int16ul,
        "column_index" / Int16ul,
        "various"
        / Switch(
            this.type,
            {
                9: VARIOUS_TEXT,
                10: VARIOUS_TEXT,
                11: VARIOUS_TEXT,
                12: VARIOUS_TEXT,
                16: VARIOUS_NUMERIC,
                1: VARIOUS_DEC,
                2: VARIOUS_DEC,
                3: VARIOUS_DEC,
                4: VARIOUS_DEC,
                5: VARIOUS_DEC,
                6: VARIOUS_DEC,
                7: VARIOUS_DEC,
                8: VARIOUS_DEC,
            },
            default=version_specific(version, Bytes(6), Bytes(4)),
        ),
        "column_flags" / version_specific(version, VERSION_3_FLAGS, VERSION_4_FLAGS),
        "ver4_unknown_4" / If(version > 3, Int32ul),
        "fixed_offset" / Int16ul,
        "length" / Int16ul,
    )

    COLUMN_NAMES = Struct(
        "col_name_len" / version_specific(version, Int8ul, Int16ul),
        "col_name_str"
        / version_specific(
            version,
            PaddedString(this.col_name_len, encoding="utf8"),
            PaddedString(this.col_name_len, encoding="utf16"),
        ),
    )

    REAL_INDEX2 = Struct(
        "unknown_b1" / If(version > 3, Int32ul),
        "unk_struct" / Array(10, Struct("col_id" / Int16ul, "idx_flags" / Int8ul)),
        "runk" / Int32ul,
        "first_index_page" / Int32ul,
        "flags" / Int8ul,
        "unknown_b3" / If(version > 3, Padding(9)),
    )

    ALL_INDEXES = Struct(
        "unknown_c1" / If(version > 3, Int32ul),
        "idx_num" / Int32ul,
        "idx_col_num" / Int32ul,
        "rel_tbl_type" / Int8ul,
        "rel_idx_num" / Int32sl,
        "rel_tbl_page" / Int32ul,
        "cascade_ups" / Int8ul,
        "cascade_dels" / Int8ul,
        "idx_type" / Int8ul,
        "unknown_c2" / If(version > 3, Int32ul),
    )

    INDEX_NAMES = Struct(
        "idx_name_len" / version_specific(version, Int8ul, Int16ul),
        "idx_name_str"
        / version_specific(
            version,
            PaddedString(this.idx_name_len, encoding="utf8"),
            PaddedString(this.idx_name_len, encoding="utf16"),
        ),
    )

    parser = Struct(
        "real_index" / Array(real_index_count, REAL_INDEX),
        "column" / Array(column_count, COLUMN),
        "column_names" / Array(column_count, COLUMN_NAMES),
        "real_index_2" / Array(real_index_count, REAL_INDEX2),
        "all_indexes" / Array(index_count, ALL_INDEXES),
        "index_names" / Array(index_count, INDEX_NAMES),
    )
    return cast("TableData", parser.parse(buffer))


def parse_data_page_header(buffer: bytes, version: int = 3) -> DataPageHeader:
    """Parse a data-page header and its record offsets."""
    parser = Struct(
        Const(b"\x01\x01"),
        "data_free_space" / Int16ul,
        "owner" / Int32ul,
        "ver4_unknown_dat1" / If(version > 3, Int32ul),
        "record_count" / Int16ul,
        "record_offsets" / Array(this.record_count, Int16ul),
    )
    return cast("DataPageHeader", parser.parse(buffer))


# buffer should be the record data in reverse
def parse_relative_object_metadata_struct(
    buffer: bytes,
    variable_jump_tables_cnt: int = 0,
    version: int = 3,
) -> RelativeMetadata:
    """Parse variable-length field offsets stored at the end of a record."""
    parser = Struct(
        "variable_length_field_count" / version_specific(version, Int8ub, Int16ub),
        "variable_length_jump_table" / If(version == 3, Array(variable_jump_tables_cnt, Int8ub)),
        # This currently supports up to 255 columns for versions > 3
        "variable_length_field_offsets"
        / version_specific(
            version,
            Array(this.variable_length_field_count, Int8ub),
            Array(this.variable_length_field_count & 0xFF, Int16ub),
        ),
        "var_len_count" / version_specific(version, Int8ub, Int16ub),
        "relative_metadata_end" / Tell,
    )
    return cast("RelativeMetadata", parser.parse(buffer))
