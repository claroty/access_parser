from construct import *
from construct import Int32ul,Int16ul,Int8ul,Int16ub,Int8ub,Int24ul,Int32sl #explicit imports to help intellisense

def version_specific(version, v3_subcon, v4_subcon):
    """
    There are some differences in the parsing structure between v3 and v4. Some fields are different length and some
    exist only in one of the versions. this returns the relevant parsing structure by version
    :param version: int 3 or 4
    :param v3_subcon: the parsing struct if version is 3
    :param v4_subcon: the parsing struct if version is 4
    """
    if version == 3:
        return v3_subcon
    else:
        return v4_subcon


ACCESSHEADER = Struct(
    Const(b'\00\x01\x00\x00'),
    "jet_string" / CString("utf8"),
    "jet_version" / Int32ul,
    # RC4 encrypted with key 0x6b39dac7. Database metadata
    Padding(126))

MEMO = Struct(
    "memo_length" / Int32ul,
    "record_pointer" / Int32ul,
    "memo_unknown" / Int32ul,
    "memo_end" / Tell)

VERSION_3_FLAGS = BitStruct(
    "hyperlink" / Flag,
    "auto_GUID" / Flag,
    "unk_1" / Flag,
    "replication" / Flag,
    "unk_2" / Flag,
    "autonumber" / Flag,
    "can_be_null" / Flag,
    "fixed_length" / Flag)

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
    'modern_package_type' / Flag,
    "unk_6" / Flag,
    "unk_7" / Flag,
    "unk_8" / Flag,
    "compressed_unicode" / Flag)

TDEF_HEADER = Struct(
    Const(b'\02\x01'),
    "peek_version" / Peek(Int16ul),
    "tdef_ver" / IfThenElse(lambda x: x.peek_version == b"VC", Const(b"VC"), Int16ul),
    "next_page_ptr" / Int32ul,
    "header_end" / Tell)

LVPROP_CHUNK_NAMES_INT = Struct(
    "name_length" / Int16ul,
    "name" / PaddedString(this.name_length, "utf16"),
)
LVPROP_CHUNK_NAMES = Struct(
    "names" / GreedyRange(LVPROP_CHUNK_NAMES_INT),
    # "leftover" / GreedyBytes
)
LVPROP_DATA = Struct(
    "data_length" / Int16ul,
    "ddl_flag" / Int8ul,
    "type" / Int8ul,
    "name_index" / Int16ul,
    "only_data_length" / Int16ul,
    "actual_data" / Bytes(this.only_data_length)
)
LVPROP_VALUE = Struct(
    "val_length" / Int32ul,
    "name_length" / Int16ul,
    "column_name" / PaddedString(this.name_length, "utf16"),
    "data" / GreedyRange(LVPROP_DATA),
    "left" / GreedyBytes
)

LVPROP_CHUNK = Struct(
    "length" / Int32ul,
    "chunk_type" / Int16ul,

    "data" / Prefixed(Computed(this.length - 6), Switch(this.chunk_type, {
        # 128: GreedyRange(LVPROP_CHUNK_NAMES)
        128: LVPROP_CHUNK_NAMES,
        0:LVPROP_VALUE,
        1: LVPROP_VALUE
    }, default=Bytes(this.length - 4)))
)
LVPROP = Struct(
    #'KKD\0' in Jet3 and 'MR2\0' in Jet 4.
    "magic" / Bytes(4),
    "chunks" / GreedyRange(LVPROP_CHUNK),
    "leftover" / GreedyBytes
)

def parse_table_head(buffer, version=3):
    return Struct(
        "TDEF_header" / TDEF_HEADER,
        # Table
        "table_definition_length" / Int32ul,
        "ver4_unknown" / If(lambda x: version > 3, Int32ul),
        "number_of_rows" / Int32ul,
        "autonumber" / Int32ul,
        "autonumber_increment" / If(lambda x: version > 3, Int32ul),
        "complex_autonumber" / If(lambda x: version > 3, Int32ul),
        "ver4_unknown_1" / If(lambda x: version > 3, Int32ul),
        "ver4_unknown_2" / If(lambda x: version > 3, Int32ul),
        # 0x53 system table
        # 0x4e user table
        "table_type_flags" / Int8ul,
        "next_column_id" / Int16ul,
        "variable_columns" / Int16ul,
        "column_count" / Int16ul,
        "index_count" / Int32ul,
        "real_index_count" / Int32ul,
        "row_page_map_row_number" / Int8ul,
        "row_page_map_page_number" / Int24ul,
        #"row_page_map" / Int32ul,
        "free_space_page_map_row_number" / Int8ul,
        "free_space_page_map_page_number" / Int24ul,
        #"free_space_page_map" / Int32ul,
        "tdef_header_end" / Tell).parse(buffer)


def parse_table_data(buffer, index_count, real_index_count, column_count, version=3):
    REAL_INDEX = Struct(
        "unk1" / Int32ul,
        "index_row_count" / Int32ul,
        "ver4_always_zero" /  If(lambda x: version > 3, Int32ul))

    VARIOUS_TEXT_V3 = Struct(
        "LCID" / Int16ul,
        "code_page" / Int16ul,
        "various_text3_unknown" / Int16ul)

    VARIOUS_TEXT_V4 = Struct(
        "collation" / Int16ul,
        "various_text4_unknown" / Int8ul,
        "collation_version_number" / Int8ul)

    VARIOUS_TEXT = VARIOUS_TEXT_V3 if version == 3 else VARIOUS_TEXT_V4

    VARIOUS_DEC_V3 = Struct(
        "various_dec3_unknown" / Int16ul,
        "max_number_of_digits" / Int8ul,
        "number_of_decimal" / Int8ul,
        "various_dec3_unknown2" / Int16ul)

    VARIOUS_DEC_V4 = Struct(
        "max_num_of_digits" / Int8ul,
        "num_of_decimal_digits" / Int8ul,
        "various_dec4_unknown" / Int16ul)

    VARIOUS_DEC = VARIOUS_DEC_V3 if version == 3 else VARIOUS_DEC_V4

    VARIOUS_NUMERIC_V3 = Struct("prec" / Int8ul, "scale" / Int8ul, "unknown" / Int32ul)
    VARIOUS_NUMERIC_V4 = Struct("prec" / Int8ul, "scale" / Int8ul, "unknown" / Int16ul)
    VARIOUS_NUMERIC = VARIOUS_NUMERIC_V3 if version == 3 else VARIOUS_NUMERIC_V4

    COLUMN = Struct(
        "type" / Int8ul,
        "ver4_unknown_3" /  If(lambda x: version > 3, Int32ul),
        "column_id" / Int16ul,
        "variable_column_number" / Int16ul,
        "column_index" / Int16ul,
        "various" / Switch(lambda ctx: ctx.type,
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

                           }, default=version_specific(version, Bytes(6), Bytes(4))),
        "column_flags" / version_specific(version, VERSION_3_FLAGS, VERSION_4_FLAGS),
        "ver4_unknown_4" / If(lambda x: version > 3, Int32ul),
        "fixed_offset" / Int16ul,
        "length" / Int16ul)

    COLUMN_NAMES = Struct(
        "col_name_len" / version_specific(version, Int8ul, Int16ul),
        "col_name_str" / version_specific(version,
                                          PaddedString(lambda x: x.col_name_len, encoding="utf8"),
                                          PaddedString(lambda x: x.col_name_len, encoding="utf16")),
    )

    REAL_INDEX2 = Struct(
        "unknown_b1" / If(lambda x: version > 3, Int32ul),
        "unk_struct" / Array(10, Struct("col_id" / Int16ul, "idx_flags" / Int8ul)),
        "runk" / Int32ul,
        "first_index_page" / Int32ul,
        "flags" / Int8ul,
        "unknown_b3" / If(lambda x: version > 3, Padding(9)))

    ALL_INDEXES = Struct(
        "unknown_c1" / If(lambda x: version > 3, Int32ul),
        "idx_num" / Int32ul,
        "idx_col_num" / Int32ul,
        "rel_tbl_type" / Int8ul,
        "rel_idx_num" / Int32sl,
        "rel_tbl_page" / Int32ul,
        "cascade_ups" / Int8ul,
        "cascade_dels" / Int8ul,
        "idx_type" / Int8ul,
        "unknown_c2" / If(lambda x: version > 3, Int32ul))

    INDEX_NAMES = Struct(
        "idx_name_len" / version_specific(version, Int8ul, Int16ul),
        "idx_name_str" / version_specific(version,
                                          PaddedString(lambda x: x.idx_name_len, encoding="utf8"),
                                          PaddedString(lambda x: x.idx_name_len, encoding="utf16")),
    )

    return Struct(
        "real_index" / Array(real_index_count, REAL_INDEX),
        "column" / Array(column_count, COLUMN),
        "column_names" / Array(column_count, COLUMN_NAMES),
        "real_index_2" / Array(real_index_count, REAL_INDEX2),
        "all_indexes" / Array(index_count, ALL_INDEXES),
        "index_names" /  Array(index_count, INDEX_NAMES)).parse(buffer)


def parse_data_page_header(buffer, version=3):
    return Struct(
        Const(b"\x01\x01"),
        "data_free_space" / Int16ul,
        "owner" / Int32ul,
        "ver4_unknown_dat1" / If(lambda x: version > 3, Int32ul),
        "record_count" / Int16ul,
        "record_offsets" / Array(lambda x: x.record_count, Int16ul)).parse(buffer)


# buffer should be the record data in reverse
def parse_relative_object_metadata_struct(buffer, variable_jump_tables_cnt=0, version=3):
    return Struct(
        "variable_length_field_count" / version_specific(version, Int8ub, Int16ub),
        "variable_length_jump_table" / If(lambda x: version == 3, Array(variable_jump_tables_cnt, Int8ub)),
        # This currently supports up to 255 columns for versions > 3
        "variable_length_field_offsets" / version_specific(version,
                                                           Array(lambda x: x.variable_length_field_count, Int8ub),
                                                           Array(lambda x: x.variable_length_field_count & 0xff,
                                                                 Int16ub)),
        "var_len_count" / version_specific(version, Int8ub, Int16ub),
        "relative_metadata_end" / Tell).parse(buffer)

#helper unpacking function
def parse_buffer_custom(buffer,position,type):
    '''Custom function to parse buffers using differet construct types
        ------
        Jackcess Mapping for type variable
        - get           = 'Int8ul'
        - getShort      = 'Int16ul'
        - getInt        = 'Int32ul'
        - get3ByteInt   = 'Int24ul'
        #Will add to this list as they come up
    '''
    type = globals()[type]

    parser = Struct("value" / type)
    buffer = buffer[position:]
    result = parser.parse(buffer)
    return result.value