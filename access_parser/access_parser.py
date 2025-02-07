import logging
import struct
from collections import defaultdict, OrderedDict

from construct import ConstructError
from tabulate import tabulate

from .parsing_primitives import parse_relative_object_metadata_struct, parse_table_head, parse_data_page_header, \
    ACCESSHEADER, MEMO, parse_table_data, TDEF_HEADER, LVPROP, parse_buffer_custom
from .utils import categorize_pages, parse_type, TYPE_MEMO, TYPE_TEXT, TYPE_BOOLEAN, read_db_file, numeric_to_string, \
    TYPE_96_BIT_17_BYTES, TYPE_OLE

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


class TableObj(object):
    def __init__(self, offset, val):
        self.value = val
        self.offset = offset
        self.linked_pages = []
        self.owned_pages = []
        self.free_space_pages = []


class AccessParser(object):
    def __init__(self, db_path):
        if isinstance(db_path, bytes):                  # allow to pass bytes object e.g. downloaded from cloud storage
            self.db_data = db_path
        else:
            self.db_data = read_db_file(db_path)
        self._parse_file_header(self.db_data)
        self._table_defs, self._data_pages, self._all_pages = categorize_pages(self.db_data, self.page_size)
        self._tables_with_data = self._link_tables_to_data()
        self.catalog = self._parse_catalog()
        self.extra_props = self.parse_msys_table()

    def parse_msys_table(self):
        """The MSysObjects contains extra metadata about tables and columns, like the Format of money field types """
        msys_table = self.parse_table("MSysObjects")
        if not msys_table:
            return None
        if not msys_table.get('Name') or not msys_table.get('LvProp'):
            return []
        table_to_lval_memo = {key: self.parse_lvprop(value) for key, value in zip(msys_table['Name'],
                                                                                  msys_table['LvProp']) if value}
        return table_to_lval_memo

    def _parse_file_header(self, db_data):
        """
        Parse the basic file header and determine the Access DB version based on the parsing results.
        :param db_data: db file data
        """
        try:
            head = ACCESSHEADER.parse(db_data)
        except ConstructError:
            # This is a very minimal parsing of the header. If we fail this probable is not a valid mdb file
            raise ValueError("Failed to parse DB file header. Check it is a valid access database")
        version = head.jet_version
        if version in NEW_VERSIONS:
            if version == VERSION_4:
                self.version = ALL_VERSIONS[VERSION_4]
            elif version == VERSION_5:
                self.version = ALL_VERSIONS[VERSION_5]
            elif version == VERSION_2010:
                self.version = ALL_VERSIONS[VERSION_2010]
            self.page_size = PAGE_SIZE_V4

        else:
            if not version == VERSION_3:
                LOGGER.error(f"Unknown database version {version} Trying to parse database as version 3")
            self.version = ALL_VERSIONS[VERSION_3]
            self.page_size = PAGE_SIZE_V3
        LOGGER.info(f"DataBase version {version}")

    def _link_tables_to_data(self):
        """
        Link tables definitions to their data pages
        :return: dict of {ofssets : PageObj}
        """
        tables_with_data = {}
        # Link table definitions to data
        # the offset of the table definition page / 0x800  ==  the owner of a Data page
        for offset, data in self._data_pages.items():
            try:
                parsed_dp = parse_data_page_header(data, version=self.version)
            except ConstructError:
                LOGGER.error(f"Failed to parse data page {data}")
                continue
            page_offset = parsed_dp.owner * self.page_size
            if page_offset in self._table_defs:
                table_page_value = self._table_defs.get(parsed_dp.owner * self.page_size)
                if page_offset not in tables_with_data:
                    tables_with_data[page_offset] = TableObj(page_offset, table_page_value)
                tables_with_data[page_offset].linked_pages.append(data)
        return tables_with_data

    def _parse_catalog(self):
        """
        Parse the catalog to get the DB tables and their offsets
        :return: dict {table : offset}
        """
        catalog_page = self._tables_with_data[2 * self.page_size]
        access_table = AccessTable(catalog_page, self.version, self.page_size, self._data_pages, self._table_defs, self._all_pages)
        catalog = access_table.parse()
        tables_mapping = {}
        for i, table_name in enumerate(catalog['Name']):
            # We need the MSysObjects table for metadata so exclude it from the system table filter.
            if table_name == "MSysObjects":
                tables_mapping[table_name] = catalog['Id'][i]
            # Visible user tables are type 1
            table_type = 1
            if catalog["Type"][i] == table_type:
                # Don't parse system tables
                if not catalog["Flags"][i] in SYSTEM_TABLE_FLAGS:
                    tables_mapping[table_name] = catalog['Id'][i]
                else:
                    LOGGER.debug(f"Not parsing system table - {table_name}")
        return tables_mapping

    def get_table(self, table_name):
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
        props = None
        if table_name != "MSysObjects" and table_name in self.extra_props:
            props = self.extra_props[table_name]

        return AccessTable(table, self.version, self.page_size, self._data_pages, self._table_defs, self._all_pages, props)

    def parse_lvprop(self, lvprop_raw):
        try:
            parsed = LVPROP.parse(lvprop_raw)
        except ConstructError:
            return None
        if not parsed.get("chunks"):
            return None
        table_names = [x.name for x in parsed.chunks[0].data.names]
        # Chunk type 0 does not have a column name, so we cannot link it to a column
        chunk_type_one = [x for x in parsed.chunks if x.chunk_type == 1]
        reconstructed_column_data = {}
        for chunk in chunk_type_one:
            if not chunk.data.column_name:
                LOGGER.error("Error while parsing MSysObjects table chunk.")
                continue
            data_values = {}
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

    def parse_table(self, table_name):
        """
        Parse a table from the db.
        tables names are in self.catalog
        :return defaultdict(list) with the parsed table -- table[column][row_index]
        """
        return self.get_table(table_name).parse()

    def print_database(self):
        """
        Print data from all database tables
        """
        table_names = self.catalog
        for table_name in table_names:
            table = self.parse_table(table_name)
            if not table:
                continue
            print(f'TABLE NAME: {table_name}\r\n')
            print(tabulate(table, headers="keys", disable_numparse=True))
            print('\r\n\r\n\r\n\r\n')


class AccessTable(object):
    def __init__(self, table, version, page_size, data_pages, table_defs, all_pages, props=None):
        self.version = version
        self.props = props
        self.page_size = page_size
        self._data_pages = data_pages
        self._table_defs = table_defs
        self._all_pages = all_pages
        self.table = table
        self.parsed_table = defaultdict(list)
        self.columns, self.primary_keys, self.table_header = self._get_table_columns()

    def create_empty_table(self):
        parsed_table = defaultdict(list)
        columns, *_ = self._get_table_columns()
        for i, column in columns.items():
            parsed_table[column.col_name_str] = [] #changed to blank array to align to expected type if data was present.
        return parsed_table

    def parse(self):
        """
        This is the main table parsing function. We go through all of the data pages linked to the table, separate each
        data page to rows(records) and parse each record.
        :return defaultdict(list) with the parsed data -- table[column][row_index]
        """
        if not self.table.owned_pages:
            return self.create_empty_table()
        for data_chunk in self.table.owned_pages:
            original_data = data_chunk
            parsed_data = parse_data_page_header(original_data, version=self.version)

            last_offset = None
            for rec_offset in parsed_data.record_offsets:
                # Deleted row - Just skip it
                if rec_offset & 0x8000:
                    last_offset = rec_offset & 0xfff
                    continue
                # Overflow page
                if rec_offset & 0x4000:
                    # overflow ptr is 4 bits flags, 12 bits ptr
                    rec_ptr_offset = rec_offset & 0xfff
                    # update last pointer to pointer without flags
                    last_offset = rec_ptr_offset
                    # The ptr is the offset in the current data page. we get a 4 byte record_pointer from that
                    overflow_rec_ptr = original_data[rec_ptr_offset:rec_ptr_offset + 4]
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
      
        ## fix final output order
        columns_sorted = OrderedDict(sorted(self.columns.items()))
        reordered_parsed_table = OrderedDict([(column.col_name_str,self.parsed_table[column.col_name_str]) for i, column in columns_sorted.items()])
        self.parsed_table = reordered_parsed_table
        return self.parsed_table

    def _parse_row(self, record):
        """
        parse record (row) of data. First parse all fixed-length data field and then parse the relative length data.
        :param record: the current row data
        :return:
        """
        original_record = record
        reverse_record = record[::-1]

        if self.version > 3:
            field_count = struct.unpack_from("h", record)[0]
            record = record[2:]
        else:
            field_count = struct.unpack_from("b", record)[0]
            record = record[1:]
        # Records contain null bitmaps for columns. The number of bitmaps is the number of columns / 8 rounded up

        null_table_len = (field_count + 7) // 8
        if null_table_len and null_table_len < len(original_record):
            null_table = record[-null_table_len:]
            # Turn bitmap to a list of True False values
            null_table = [((null_table[i // 8]) & (1 << (i % 8))) != 0 for i in range(len(null_table) * 8)]
        else:
            LOGGER.error(f"Failed to parse null table column count {field_count}")
            return

        relative_records_column_map = {}
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
            metadata = self._parse_dynamic_length_records_metadata(reverse_record, original_record,
                                                                   null_table_len)
            if not metadata:
                return
            if metadata.variable_length_field_offsets:
                self._parse_dynamic_length_data(original_record, metadata, relative_records_column_map, null_table)

    def _parse_fixed_length_data(self, original_record, column, null_table):
        """
        Parse fixed-length data from record
        :param original_record: unmodified record
        :param column: column this data belongs to
        :param null_table: null table of the row
        """
        column_name = column.col_name_str
        # The null table indicates null values in the row.
        # The only exception is BOOL fields which are encoded in the null table
        has_value = True
        if column.column_id > len(null_table):
            #new column added after row creation, not covered by null mask, in this case has_value = false
            has_value = False
            if column.type == TYPE_BOOLEAN:
                has_value = None
        else:
            has_value = null_table[column.column_id]
        # Boolean fields are encoded in the null table
        if column.type == TYPE_BOOLEAN:
            parsed_type = has_value
        else:
            if column.fixed_offset > len(original_record):
                LOGGER.error(f"Column offset is bigger than the length of the record {column.fixed_offset}")
                return
            record = original_record[column.fixed_offset:]
            parsed_type = parse_type(column.type, record, version=self.version, props=column.extra_props or None)
            if not has_value:
                self.parsed_table[column_name].append(None)
                return
        self.parsed_table[column_name].append(parsed_type)

    def _parse_dynamic_length_records_metadata(self, reverse_record, original_record, null_table_length):
        """
        parse the metadata of relative records. The metadata used to parse relative records is found at the end of the
        record so reverse_record is used for parsing from the bottom up.
        :param reverse_record: original record in reverse
        :param original_record: unmodified record
        :param null_table_length:
        :return: parsed relative record metadata
        """
        if self.version > 3:
            reverse_record = reverse_record[null_table_length:]
            return parse_relative_object_metadata_struct(reverse_record, version=self.version)
        # Parse relative metadata.
        # Metadata is from the end of the record(reverse_record is used here)
        variable_length_jump_table_cnt = (len(original_record) - 1) // 256
        reverse_record = reverse_record[null_table_length:]
        try:
            relative_record_metadata = parse_relative_object_metadata_struct(reverse_record,
                                                                             variable_length_jump_table_cnt,
                                                                             self.version)
            # relative_record_metadata = RELATIVE_OBJS.parse(reverse_record)
            # we use this offset in original_record so we have to update the length with the null_tables
            relative_record_metadata.relative_metadata_end = relative_record_metadata.relative_metadata_end + null_table_length
        except ConstructError:
            relative_record_metadata = None
            LOGGER.error("Failed parsing record")

        if relative_record_metadata and \
                relative_record_metadata.variable_length_field_count != self.table_header.variable_columns:

            # best effort - try to find variable column count in the record and parse from there
            # this is limited to the 10 first bytes to reduce false positives.
            # most of the time iv'e seen this there was an extra DWORD before the actual metadata
            metadata_start = reverse_record.find(bytes([self.table_header.variable_columns]))
            if metadata_start != -1 and metadata_start < 10:
                reverse_record = reverse_record[metadata_start:]
                try:
                    relative_record_metadata = parse_relative_object_metadata_struct(reverse_record,
                                                                                     variable_length_jump_table_cnt,
                                                                                     self.version)
                except ConstructError:
                    LOGGER.error(f"Failed to parse record metadata: {original_record}")
                relative_record_metadata.relative_metadata_end = relative_record_metadata.relative_metadata_end + \
                                                                 metadata_start
            else:
                LOGGER.warning(
                    f"Record did not parse correctly. Number of columns: {self.table_header.variable_columns}"
                    f" number of parsed columns: {relative_record_metadata.variable_length_field_count}")
                return None
        return relative_record_metadata

    def _parse_dynamic_length_data(self, original_record, relative_record_metadata,
                                   relative_records_column_map, null_table):
        """
        Parse dynamic (non fixed length) records from row
        :param original_record: full unmodified record
        :param relative_record_metadata: parsed record metadata
        :param relative_records_column_map: relative records colum mapping {index: column}
        :param null_table: list indicating which columns have null value
        """
        relative_offsets = relative_record_metadata.variable_length_field_offsets
        jump_table_addition = 0
        for i, column_index in enumerate(relative_records_column_map):
            column = relative_records_column_map[column_index]
            col_name = column.col_name_str
            has_value = True
            if column.column_id > len(null_table):
                #New column with no data so map to false
                has_value = False
            else:
                has_value = null_table[column.column_id]
            if not has_value:
                self.parsed_table[col_name].append(None)
                continue

            if self.version == 3:
                if column.variable_column_number in relative_record_metadata.variable_length_jump_table:
                    jump_table_addition += 0x100
            rel_start = relative_offsets[column.variable_column_number]
            # If this is the last one use var_len_count as end offset
            if column.variable_column_number + 1 == len(relative_offsets):
                rel_end = relative_record_metadata.var_len_count
            else:
                rel_end = relative_offsets[column.variable_column_number + 1]

            # if rel_start and rel_end are the same there is no data in this slot
            if rel_start == rel_end:
                self.parsed_table[col_name].append("")
                continue

            relative_obj_data = original_record[rel_start + jump_table_addition: rel_end + jump_table_addition]
            # Parse types that require column data here, call parse_type on all other types
            if column.type == TYPE_MEMO:
                try:
                    parsed_type = self._parse_memo(relative_obj_data)
                except ConstructError:
                    LOGGER.warning("Failed to parse memo field. Using data as bytes")
                    parsed_type = relative_obj_data
            elif column.type == TYPE_OLE:
                try:
                    parsed_type = self._parse_memo(relative_obj_data, return_raw=True)
                except ConstructError:
                    LOGGER.warning("Failed to parse OLE field. Using data as bytes")
                    parsed_type = relative_obj_data
            elif column.type == TYPE_96_BIT_17_BYTES:
                if len(relative_obj_data) != 17:
                    LOGGER.warning(f"Relative numeric field has invalid length {len(relative_obj_data)}, expected 17")
                    parsed_type = relative_obj_data
                else:
                    # Get scale or None
                    scale = column.get('various', {}).get('scale', 6)
                    parsed_type = numeric_to_string(relative_obj_data, scale)
            else:
                parsed_type = parse_type(column.type, relative_obj_data, len(relative_obj_data), version=self.version)
            self.parsed_table[col_name].append(parsed_type)


    def _get_usage_map(self,page_num,row_num):

        ##Need to define a version config
        OFFSET_ROW_START = 10 if self.version == 3 else 14
        SIZE_ROW_LOCATION = 2
        OFFSET_MASK = 0x1FFF
        OFFSET_USAGE_MAP_START = 5
        INVALID_PAGE_NUMBER = -1

        #get page containing usage map info
        table_buffer = self._data_pages[page_num*self.page_size]

        #prepare offsets to pick relevant info from table buffer
        row_start_offset = OFFSET_ROW_START + (SIZE_ROW_LOCATION * row_num)
        row_end_offset = OFFSET_ROW_START + (SIZE_ROW_LOCATION * (row_num - 1))

        #find row start
        row_start = parse_buffer_custom(table_buffer,row_start_offset,'Int16ul') & OFFSET_MASK

        #find row end
        row_end = self.page_size if row_num == 0 else parse_buffer_custom(table_buffer,row_end_offset,'Int16ul') & OFFSET_MASK

        #limit buffer
        table_buffer = table_buffer[:row_end]

        #map type
        map_type = parse_buffer_custom(table_buffer,row_start,'Int8ul')

        #offset start
        um_start_offset = row_start + OFFSET_USAGE_MAP_START

        ##inline handler processing

        max_inline_pages = (row_end - um_start_offset) * 8
        start_page = parse_buffer_custom(table_buffer,row_start+1,'Int32ul')
        end_page = start_page + max_inline_pages

        ##process page array
        filtered_buffer = table_buffer[um_start_offset:]
        filtered_buffer_size = len(filtered_buffer)
        page_numbers = []
        byteCount = 0
        
        while byteCount < filtered_buffer_size:
            b = filtered_buffer[byteCount:byteCount+1]
            if b != b'\x00':
                for i in range(8):
                    if ((int.from_bytes(b,'big') & (1 << i)) != 0):
                        pageNumberOffset = (byteCount * 8 + i)
                        pageNumber = (start_page + pageNumberOffset) if (pageNumberOffset >= 0) else INVALID_PAGE_NUMBER
                        if pageNumber < start_page or pageNumber > end_page:
                            #invalid page number 
                            break
                        page_numbers.append(pageNumber)
            byteCount += 1

        return page_numbers
        



    def _get_table_columns(self):
        """
        Parse columns for a specific table
        """
        try:
            table_header = parse_table_head(self.table.value, version=self.version)
            merged_data = self.table.value[table_header.tdef_header_end:]
            if table_header.TDEF_header.next_page_ptr:
                merged_data = merged_data + self._merge_table_data(table_header.TDEF_header.next_page_ptr)

            parsed_data = parse_table_data(
                merged_data,
                table_header.index_count,
                table_header.real_index_count,
                table_header.column_count,
                version=self.version,
            )


            #add usage maps from table referenced by table head
            #The catalog level linked pages array can be out of date following deletes. so use table header info to find accurate usage maps.
            self.table.owned_pages = [self._all_pages[pn * self.page_size] for pn in self._get_usage_map(table_header.row_page_map_page_number,table_header.row_page_map_row_number)]
            self.table.free_space_pages = [self._all_pages[pn * self.page_size] for pn in self._get_usage_map(table_header.free_space_page_map_page_number,table_header.free_space_page_map_row_number)]


            # Merge Data back to table_header
            table_header['index'] = parsed_data['real_index']
            table_header['column'] = parsed_data['column']
            table_header['column_names'] = parsed_data['column_names']
            table_header['real_index_2'] = parsed_data['real_index_2']
            table_header["all_indexes"] = parsed_data["all_indexes"]
            table_header["index_names"] = parsed_data["index_names"]

        except ConstructError:
            LOGGER.error(f"Failed to parse table header {self.table.value}")
            return
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
            for i, col in column_dict.items():
                if col.col_name_str in self.props:
                    col.extra_props = self.props[col.col_name_str]

        primary_keys = [
            column_dict[col.col_id].col_name_str
            for idx in table_header.all_indexes
            for col in table_header.real_index_2[idx.idx_col_num].unk_struct
            if idx.idx_type == 1 and col.col_id ^ 0xFFFF
        ]

        if len(column_dict) != table_header.column_count:
            LOGGER.debug(f"expected {table_header.column_count} columns got {len(column_dict)}")
        return column_dict, primary_keys, table_header

    def _merge_table_data(self, first_page):
        """
        Merege data of tdef pages in case the data does not fit in one page
        :param first_page: index of the next page
        :return: merged data from all linked table definitions
        """
        table = self._table_defs.get(first_page * self.page_size)
        parsed_header = TDEF_HEADER.parse(table)
        data = table[parsed_header.header_end:]
        while parsed_header.next_page_ptr:
            table = self._table_defs.get(parsed_header.next_page_ptr * self.page_size)
            parsed_header = TDEF_HEADER.parse(table)
            data = data + table[parsed_header.header_end:]
        return data

    def _parse_memo(self, relative_obj_data, return_raw=False):
        LOGGER.debug(f"Parsing memo field {relative_obj_data}")
        parsed_memo = MEMO.parse(relative_obj_data)
        memo_type = TYPE_TEXT
        if parsed_memo.memo_length & 0x80000000:
            LOGGER.debug("memo data inline")
            inline_memo_length = parsed_memo.memo_length & 0x3FFFFFFF
            if len(relative_obj_data) < parsed_memo.memo_end + inline_memo_length:
                LOGGER.warning("Inline memo field has invalid length using full data")
                memo_data = relative_obj_data[parsed_memo.memo_end:]
            else:
                memo_data = relative_obj_data[parsed_memo.memo_end:parsed_memo.memo_end + inline_memo_length]

        elif parsed_memo.memo_length & 0x40000000:
            LOGGER.debug("LVAL type 1")
            memo_data = self._get_overflow_record(parsed_memo.record_pointer)
        else:
            LOGGER.debug("LVAL type 2")
            rec_data = self._get_overflow_record(parsed_memo.record_pointer)
            next_page = struct.unpack("I", rec_data[:4])[0]
            # LVAL2 has data over multiple pages. The first 4 bytes of the page are the next record, then that data.
            # Concat the data until we get a 0 next_page.
            memo_data = b""
            while next_page:
                memo_data += rec_data[4:]
                rec_data = self._get_overflow_record(next_page)
                next_page = struct.unpack("I", rec_data[:4])[0]
            memo_data += rec_data[4:]
        if memo_data:
            if return_raw:
                return memo_data
            parsed_type = parse_type(memo_type, memo_data, len(memo_data), version=self.version)
            return parsed_type

    def _get_overflow_record(self, record_pointer):
        """
        Get the actual record from a record pointer
        :param record_pointer:
        :return: record
        """
        record_offset = record_pointer & 0xff
        page_num = record_pointer >> 8
        record_page = self._data_pages.get(page_num * self.page_size)
        if not record_page:
            LOGGER.warning(f"Could not find overflow record data page overflow pointer: {record_pointer}")
            return
        parsed_data = parse_data_page_header(record_page, version=self.version)
        if record_offset > len(parsed_data.record_offsets):
            LOGGER.warning("Failed parsing overflow record offset")
            return
        start = parsed_data.record_offsets[record_offset]
        if start & 0x8000:
            start = start & 0xfff
        else:
            LOGGER.debug(f"Overflow record flag is not present {start}")
        if record_offset == 0:
            record = record_page[start:]
        else:
            end = parsed_data.record_offsets[record_offset - 1]

            if end & 0x8000:# and (end & 0xff != 0): ##last byte check removed. stops valid end offsets from being parsed.
                end = end & 0xfff
            record = record_page[start: end]
        return record
