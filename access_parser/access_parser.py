import logging
import struct
from collections import defaultdict, OrderedDict

from construct import ConstructError
from tabulate import tabulate

from .parsing_primitives import parse_relative_object_metadata_struct, parse_table_head, parse_data_page_header, \
    ACCESSHEADER, MEMO, parse_table_data, TDEF_HEADER, LVPROP, parse_buffer_custom
from .utils import categorize_pages, parse_type, TYPE_MEMO, TYPE_TEXT, TYPE_BOOLEAN, read_db_file, numeric_to_string, \
    TYPE_96_BIT_17_BYTES, TYPE_OLE
from .jetformat import BaseFormat, Jet3Format, PageTypes


SYSTEM_TABLE_FLAGS = [-0x80000000, -0x00000002, 0x80000000, 0x00000002]

# top‐2‐bit mask and length mask (30 bits)
LONG_VALUE_TYPE_MASK    = 0xC0000000
LONG_VALUE_LENGTH_MASK  = ~LONG_VALUE_TYPE_MASK  & 0xFFFFFFFF

MAX_BYTE = 256

LOGGER = logging.getLogger("access_parser")


class TableObj(object):
    def __init__(self, offset, val):
        self.value = val
        self.offset = offset
        self.linked_pages = []
        self.owned_pages = {}
        self.free_space_pages = {}


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

    def _parse_file_header(self, db_data: bytes) -> None:
        """
        Inspect the first HEADER_LENGTH bytes of db_data,
        detect the correct Jet/ACE format, and set:
          - self.version      : full format helper
          - self.page_size    : pulled from the format
        """
        # grab exactly the bytes we need
        header_buf = db_data[:BaseFormat.HEADER_LENGTH]

        # 1) figure out which Format subclass applies
        try:
            fmt = BaseFormat.get_format_from_header(header_buf)
        except ValueError as ve:
            LOGGER.error(f"{ve}; defaulting to Jet3Format")
            fmt = Jet3Format()

        # 2) stash it on self for everything else to use
        self.version   = fmt
        self.page_size = fmt.page_size

        LOGGER.info(f"Detected Access format: Jet{self.version}, page_size={self.page_size}")

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

    def _clean_loc(self, x: int) -> int:
        """
        Strip off the high-bit flags (0x8000 = deleted, 0x4000 = overflow)
        to get the true 13-bit page offset.
        """
        return x & 0x1FFF


    def parse(self):
        """
        Main table parsing function. Iterates data pages, splits into rows, and streams parsed rows.
        :return: OrderedDict of parsed columns
        """
        if not self.table.owned_pages:
            return self.create_empty_table()

        for page_num, page_data in self.table.owned_pages.items():
            parsed_page = parse_data_page_header(page_data, version=self.version)
            # iterate each slot entry
            for row_num, raw_loc in enumerate(parsed_page.record_offsets):
                # skip deleted rows
                if raw_loc & 0x8000:
                    continue

                # overflow row
                if raw_loc & 0x4000:
                    start = self._clean_loc(raw_loc)
                    # read 4-byte overflow pointer
                    ptr = struct.unpack_from('<I', page_data, start)[0]
                    overflow_record = self._get_overflow_record(ptr)
                    if overflow_record is not None:
                        self._parse_row(overflow_record)
                    continue

                # normal row: compute cleaned start/end
                start = self._clean_loc(raw_loc)
                if row_num == 0:
                    end = self.page_size
                else:
                    end = self._clean_loc(parsed_page.record_offsets[row_num - 1])

                record = page_data[start:end]
                if record:
                    self._parse_row(record)

        # if all rows deleted
        if not self.parsed_table:
            return self.create_empty_table()

        # reorder columns in output
        columns_sorted = OrderedDict(sorted(self.columns.items(), key=lambda t: t[0]))
        reordered = OrderedDict(
            (col.col_name_str, self.parsed_table[col.col_name_str])
            for _, col in columns_sorted.items()
        )
        self.parsed_table = reordered
        return self.parsed_table



    def _get_usage_map(self,page_num,row_num):

        ##Need to define a version config
        OFFSET_MASK = 0x1FFF
        INVALID_PAGE_NUMBER = -1
        MAP_TYPE_INLINE = 0
        MAP_TYPE_REFERENCE = 1

        #get page containing usage map info
        table_buffer = self._all_pages[page_num*self.page_size]

        #prepare offsets to pick relevant info from table buffer
        row_start_offset = self.version.OFFSET_ROW_START + (self.version.SIZE_ROW_LOCATION * row_num)
        row_end_offset = self.version.OFFSET_ROW_START + (self.version.SIZE_ROW_LOCATION * (row_num - 1))

        #find row start
        row_start = parse_buffer_custom(table_buffer,row_start_offset,'Int16ul') & OFFSET_MASK

        #find row end
        row_end = self.page_size if row_num == 0 else parse_buffer_custom(table_buffer,row_end_offset,'Int16ul') & OFFSET_MASK

        #limit buffer
        table_buffer = table_buffer[:row_end]

        #map type
        map_type = parse_buffer_custom(table_buffer,row_start,'Int8ul')

        #offset start
        um_start_offset = row_start + self.version.OFFSET_USAGE_MAP_START

        if map_type == MAP_TYPE_INLINE:
            ##    Usage map whose map is written inline in the same page.  For Jet4, this
            ##    type of map can usually contains a maximum of 512 pages.  Free space maps
            ##    are always inline, used space maps may be inline or reference.  It has a
            ##    start page, which all page numbers in its map are calculated as starting
            ##    from.

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
        
        elif map_type == MAP_TYPE_REFERENCE:
            ##    Usage map whose map is written across one or more entire separate pages
            ##    of page type USAGE_MAP.  For Jet4, this type of map can contain 32736
            ##    pages per reference page, and a maximum of 17 reference map pages for a
            ##    total maximum of 556512 pages (2 GB).

            ##reference handler processing

            max_pages_per_usage_map_page = ((self.version.page_size - self.version.OFFSET_USAGE_MAP_PAGE_DATA) * 8)
            num_usage_pages = int((row_end - row_start - 1) / 4)
            um_start_offset = self.version.OFFSET_USAGE_MAP_START

            start_page = 0
            end_page = (num_usage_pages * max_pages_per_usage_map_page)

            # there is no "start page" for a reference usage map, so we get an
            # extra page reference on top of the number of page references that fit
            # in the table
            page_numbers = []
            for i in range(num_usage_pages):
                map_page_pointer_offset = row_start + self.version.OFFSET_REFERENCE_MAP_PAGE_NUMBERS + (i * 4)
                map_page_num = parse_buffer_custom(table_buffer,map_page_pointer_offset,'Int32ul')
                if map_page_num > 0:
                    map_page_buffer = self._all_pages[map_page_num*self.version.page_size]
                    page_type = map_page_buffer[0]
                    if page_type != PageTypes.USAGE_MAP:
                        LOGGER.error(f"Looking for usage map at page {map_page_num}, but page type is {page_type}")
                        return
                    filtered_buffer = map_page_buffer[self.version.OFFSET_USAGE_MAP_PAGE_DATA:]
                    
                    #Process map
                    buffer_start_page = (max_pages_per_usage_map_page * i)

                    filtered_buffer_size = len(filtered_buffer)
                    
                    byteCount = 0
                    
                    while byteCount < filtered_buffer_size:
                        b = filtered_buffer[byteCount:byteCount+1]
                        if b != b'\x00':
                            for i in range(8):
                                if ((int.from_bytes(b,'big') & (1 << i)) != 0):
                                    pageNumberOffset = (byteCount * 8 + i) + buffer_start_page
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
            owned_pages_map = self._get_usage_map(table_header.row_page_map_page_number,table_header.row_page_map_row_number)
            self.table.owned_pages = {pn: self._all_pages[pn * self.page_size] for pn in owned_pages_map}

            free_space_pages_map = self._get_usage_map(table_header.free_space_page_map_page_number,table_header.free_space_page_map_row_number)
            self.table.free_space_pages = {pn: self._all_pages[pn * self.page_size] for pn in free_space_pages_map}


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

        column_dict = OrderedDict(sorted(column_dict.items()))

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
            #adding a workaround until lval type 2 issue resolved.
            if rec_data:
                next_page = struct.unpack("I", rec_data[:4])[0]
                # LVAL2 has data over multiple pages. The first 4 bytes of the page are the next record, then that data.
                # Concat the data until we get a 0 next_page.
                memo_data = b""
                while next_page:
                    memo_data += rec_data[4:]
                    rec_data = self._get_overflow_record(next_page)
                    next_page = struct.unpack("I", rec_data[:4])[0]
                memo_data += rec_data[4:]
            else:
                memo_data = b""
        if memo_data:
            if return_raw:
                return memo_data
            parsed_type = parse_type(memo_type, memo_data, len(memo_data), version=self.version)
            return parsed_type

    def _get_overflow_record(self, record_pointer: int):
        slot_index = record_pointer & 0xFF
        page_num   = record_pointer >> 8
        page_data  = self._all_pages.get(page_num * self.page_size)
        if page_data is None:
            LOGGER.warning(f"Missing overflow page for pointer {record_pointer}")
            return None

        parsed_page = parse_data_page_header(page_data, version=self.version)
        raw_loc     = parsed_page.record_offsets[slot_index]

        # ─── SLICE OUT THE TRUE ROW ─────────────────────────────────────
        start = self._clean_loc(raw_loc)
        if slot_index == 0:
            end = self.page_size
        else:
            end = self._clean_loc(parsed_page.record_offsets[slot_index - 1])

        return page_data[start:end]


    # starting point for a iterating parser to enable outputs to be streamed to avoid memory overflows.
    def _parse_row(self, record):
        """
        Reads the row data from the given row buffer.  Leaves limit unchanged.
        :param record: the current row data
        :return:
        """

        original_record = record

        # Records contain null bitmaps for columns. The number of bitmaps is the number of columns / 8 rounded up
        null_table_len = (self.table_header.column_count + 7) // 8
        if null_table_len and null_table_len < len(original_record):
            null_table = record[-null_table_len:]
            # Turn bitmap to a list of True False values
            null_table = [((null_table[i // 8]) & (1 << (i % 8))) == 0 for i in range(len(null_table) * 8)]
        else:
            LOGGER.error(f"Failed to parse null table column count {self.table_header.column_count}")
            return


        if self.version.SIZE_ROW_VAR_COL_OFFSET != 2:

            jumpColOffsets = self._readJumpTableVarColOffsets(original_record,0,null_table_len)


        for i, column in self.columns.items():
            
            #get column name 
            column_name = column.col_name_str
            
            #Check nullmask
            isNull = True if column.column_id >= self.table_header.column_count else null_table[column.column_id]

            # Boolean fields are encoded in the null table
            if column.type == TYPE_BOOLEAN:
                self.parsed_table[column_name].append(isNull)
                continue

            # remaining columns marked as null in nullmask are recorded as None
            if isNull:
                self.parsed_table[column_name].append(None)
                continue

            # prep variables for column parsing
            rowStart = 0
            colDataPos = 0
            colDataLen = 0
            colDataType = column.type

            #if fixed length
            if column.column_flags.fixed_length:

                #identify fixed length variables
                dataStart = rowStart + self.version.OFFSET_COLUMN_FIXED_DATA_ROW_OFFSET
                colDataPos = dataStart + column.fixed_offset
                colDataLen = column.length
            
            #if variable length
            else:

                varDataStart = None
                varDataEnd = None

                if self.version.SIZE_ROW_VAR_COL_OFFSET == 2:

                    #read simple var length value
                    varColumnsOffsetPos = (len(original_record) - null_table_len - 4) - (column.variable_column_number * 2)

                    varDataStart = parse_buffer_custom(original_record,varColumnsOffsetPos,'Int16ul')
                    varDataEnd = parse_buffer_custom(original_record,varColumnsOffsetPos-2,'Int16ul')
                
                else:

                    #read jump-table based var length values
                    varDataStart = jumpColOffsets[column.variable_column_number]
                    varDataEnd = jumpColOffsets[column.variable_column_number + 1]

                #prepare variable length get
                colDataPos = rowStart + varDataStart
                colDataLen = varDataEnd - varDataStart

            if colDataLen <= 0:
                # empty string/zero‑length
                self.parsed_table[column_name].append("" if colDataType==TYPE_TEXT else b"")
                continue

            data = original_record[colDataPos:colDataPos+colDataLen]

            # dispatch on your column.type
            if colDataType in (TYPE_MEMO,TYPE_OLE):
                value = self._parse_memo(data, return_raw=(colDataType == TYPE_OLE))
            elif colDataType == TYPE_96_BIT_17_BYTES:
                scale = column.extra_props.get("scale", column.various.get("scale",6))
                value = numeric_to_string(data, scale)
            else:
                # fallback to gerneral parse_type
                value = parse_type(colDataType, data, colDataLen, version=self.version, props=column.extra_props or None)

            self.parsed_table[column_name].append(value)



    def _readJumpTableVarColOffsets(self, buffer, rowStart, nullMaskSize):

        # calculate offsets using jump-table info
        rowEnd = rowStart + len(buffer) -1
        numVarCols = buffer[rowEnd - nullMaskSize]

        varColOffsets = [0] * (numVarCols + 1)

        rowLen = rowEnd - rowStart + 1
        numJumps = (rowLen - 1) // MAX_BYTE
        colOffset = rowEnd - nullMaskSize - numJumps - 1

        # if last jump is a dummy value, ignore it
        if ((colOffset - rowStart - numVarCols) // MAX_BYTE) < numJumps:
            numJumps -= 1

        jumpsUsed = 0
        # Fill in each of the varColOffsets entries
        for i in range(numVarCols + 1):
            # Skip ahead in the jump table as long as the next jump byte equals i
            while (jumpsUsed < numJumps and
                buffer[rowEnd - nullMaskSize - jumpsUsed - 1] == i):
                jumps_used += 1

            # The low‐order part of the offset is at col_offset - i
            low = buffer[colOffset - i]
            # The high‐order is jumpsUsed * MAX_BYTE
            varColOffsets[i] = low + (jumpsUsed * MAX_BYTE)

        return varColOffsets