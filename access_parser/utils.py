import logging
import os
import struct
import uuid
import math
from datetime import datetime, timedelta

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
TYPE_96_bit_17_BYTES = 16
TYPE_COMPLEX = 18

TABLE_PAGE_MAGIC = b"\x02\x01"
DATA_PAGE_MAGIC = b"\x01\x01"


ACCESS_EPOCH = datetime(1899, 12, 30)

PERCENT_DEFAULT = '0.00%'
EURO_DEFAULT = '€0.00'
DOLLAR_DEFAULT = '$0.00'
GENERAL_NUMBER_DEFAULT = '0'
FIXED_AND_STANDARD_DEFAULT = '0.00'
SCIENTIFIC_DEFAULT = '0.00E+00'

FORMAT_PERCENT = "Percent"
FORMAT_DOLLAR = "$"
FORMAT_EURO = "€"
FORMAT_GENERAL_NUMBER = "General Number"
FORMAT_FIXED = "Fixed"
FORMAT_STANDARD = "Standard"
FORMAT_SCIENTIFIC = "Scientific"

FORMAT_TO_DEFAULT_VALUE = {
    FORMAT_DOLLAR: DOLLAR_DEFAULT,
    FORMAT_STANDARD: FIXED_AND_STANDARD_DEFAULT,
    FORMAT_FIXED: FIXED_AND_STANDARD_DEFAULT,
    FORMAT_PERCENT: PERCENT_DEFAULT,
    FORMAT_EURO: EURO_DEFAULT,
    FORMAT_GENERAL_NUMBER: GENERAL_NUMBER_DEFAULT,
    FORMAT_SCIENTIFIC: SCIENTIFIC_DEFAULT
}

# Character Encodings for Different Jet Versions
ENCODING_MAP = {
    3: "cp1252",  # Jet 3.x (Access 97 and earlier)
    4: "utf-16-le" # Jet 4.x+ (Access 2000 and newer)
}
TEXT_COMPRESSION_HEADER = b'\xff\xfe'

# https://stackoverflow.com/questions/45560782
def mdb_date_to_readable(double_time):
    try:
        dtime_bytes = struct.pack("q", double_time) 

        dtime_double = struct.unpack('<d', dtime_bytes)[0]
        dtime_frac, dtime_whole = math.modf(dtime_double)
        dtime = (ACCESS_EPOCH + timedelta(days=dtime_whole) + timedelta(days=dtime_frac))
        if dtime == ACCESS_EPOCH:
            return "(Empty Date)"
        return str(dtime)
    except OverflowError:
        return "(Invalid Date)"
    except struct.error:
        return "(Invalid Date)"


def numeric_to_string(bytes_num, scale=6):
    neg, num1, num2, num3, num4 = struct.unpack("<BIIII", bytes_num)
    full_number = (num1 << 96) + (num2 << 64) + (num3 << 32) + num4
    full_number = str(full_number)
    # If scale is 6 149804168 will be 149.804168 - 6 from the end.
    # If scale is bigger than the number ignore the scale(1498 will remain 1498)
    if len(full_number) > scale:
        dot_len = len(full_number) - scale
        full_number = full_number[:dot_len] + "." + full_number[dot_len:]
    # if number is smaller than scale then pad the number with relevant leading zeros.
    if len(full_number) <= scale:
        full_number = '0.' + ('0'*scale + full_number)[-scale:]
    numeric_string = "-" if neg else ""
    numeric_string += full_number
    return numeric_string

###Text type decoding functions
def decodeTextValue(data: bytes, version: int):
    """Decodes a compressed or uncompressed text value."""
    
    # Jet 3 does not support Unicode compression; decode directly
    if version == 3:
        return decodeUncompressedText(data, 0, len(data), version)
    
    # Check for Unicode compression header (Jet 4+ only)
    isCompressed = len(data) > 1 and data.startswith(TEXT_COMPRESSION_HEADER)
    
    if isCompressed:
        textBuf = ''
        dataStart = len(TEXT_COMPRESSION_HEADER)
        dataEnd = dataStart
        inCompressedMode = True

        # Process each segment in the compressed data
        while dataEnd < len(data):
            if data[dataEnd:dataEnd+1] == b'\x00':  # End of segment
                # Decode the current segment and toggle compression mode
                textBuf += decodeTextSegment(data, dataStart, dataEnd, inCompressedMode, version)
                inCompressedMode = not inCompressedMode
                dataStart = dataEnd + 1
            dataEnd += 1

        # Handle the last segment
        textBuf += decodeTextSegment(data, dataStart, dataEnd, inCompressedMode, version)
        return textBuf

    return decodeUncompressedText(data, 0, len(data), version)  


def decodeTextSegment(data: bytes, dataStart: int, dataEnd: int, inCompressedMode: bool,version: int):
    """
    Decodes a segment of a text value into the given buffer according to the
    given status of the segment (compressed/uncompressed).
    """
    if dataEnd <= dataStart:
        return ''  # No data in the segment

    if inCompressedMode:
        # Extract the relevant segment.
        segment = data[dataStart:dataEnd]
        # Create a new bytearray twice as long as the segment.
        expanded = bytearray(len(segment) * 2)
        # Using slice assignment: assign the original bytes to every even index.
        # The odd indices will remain 0, which is exactly the padding needed.
        expanded[::2] = segment
        # Convert the bytearray back to an immutable bytes object.
        data = bytes(expanded)
        dataStart = 0
        dataEnd = len(data)

    return decodeUncompressedText(data, dataStart, dataEnd, version)


def decodeUncompressedText(textBytes: bytes, dataStart: int, dataEnd: int, version: int, strict: bool = False) -> str:
    """
    Decodes uncompressed text based on database version.
    
    :param textBytes: The raw bytes of text.
    :param dataStart: Start index of the text segment.
    :param dataEnd: End index of the text segment.
    :param version: The database version to determine encoding.
    :param strict: Whether to raise an error on decoding failure. If False,
                   decoding errors are logged and replacement characters are used.
    :return: Decoded text string.
    """
    encoding = ENCODING_MAP.get(version, "utf-16-le")  # Default to utf-16-le for unknown versions
    bytesToDecode = textBytes[dataStart:dataEnd]
    
    try:
        return bytesToDecode.decode(encoding)
    except UnicodeDecodeError as e:
        message = (f"Decoding error: Data could not be decoded using {encoding}. "
                   f"Possible corruption or unexpected encoding in the data segment "
                   f"from {dataStart} to {dataEnd}.")
        if strict:
            raise ValueError(message) from e
        else:
            LOGGER.warning(message)
            # Return a best-effort result using replacement characters for undecodable bytes
            return bytesToDecode.decode(encoding, errors="replace")


def parse_money_type(parsed, prop_format):
    """
    Parse and format a money value according to the specified format.

    Args:
        parsed (int): The numerical value to be parsed.
        prop_format (str): The format string specifying the desired format.

    Returns:
        str: The parsed and formatted money value.
    """
    parsed = str(parsed)
    if prop_format == FORMAT_PERCENT:
        special_format = "{:.2f}%"
        dot_location = -2
    elif prop_format.startswith(FORMAT_DOLLAR):
        special_format = '${:,.2f}'
        dot_location = -4
    elif prop_format.startswith(FORMAT_EURO):
        special_format = '€{:,.2f}'
        dot_location = -4
    elif prop_format == FORMAT_GENERAL_NUMBER:
        special_format = '{:,.1f}'
        dot_location = -4
    elif prop_format == FORMAT_SCIENTIFIC:
        special_format = '{:.2e}'
        dot_location = -4
    elif prop_format in [FORMAT_FIXED, FORMAT_STANDARD]:
        dot_location = -4
        special_format = '{:,.2f}'
    else:
        LOGGER.warning(f"parse_money_type - unsupported format: {prop_format} value {parsed} may be wrong")
        return parsed

    money_float = parsed[:dot_location] + "." + parsed[dot_location:]
    if special_format:
        money_float = special_format.format(float(money_float))
    return money_float


def parse_type(data_type, buffer, length=None, version=3, props=None):
    parsed = ""
    # Bool or int8
    if data_type == TYPE_INT8:
        parsed = struct.unpack_from("b", buffer)[0]
    elif data_type == TYPE_INT16:
        parsed = struct.unpack_from("h", buffer)[0]
    elif data_type == TYPE_INT32 or data_type == TYPE_COMPLEX:
        parsed = struct.unpack_from("i", buffer)[0]
    elif data_type == TYPE_MONEY:
        parsed = struct.unpack_from("q", buffer)[0]
        if props and "Format" in props:
            prop_format = props['Format']
            if parsed == 0:
                parsed = [y for x, y in FORMAT_TO_DEFAULT_VALUE.items() if prop_format.startswith(x)]
                if not parsed:
                    LOGGER.warning(f"parse_type got unknown format while parsing money field {prop_format}")
                else:
                    parsed = parsed[0]
            else:
                parsed = parse_money_type(parsed, prop_format)
    elif data_type == TYPE_FLOAT32:
        parsed = struct.unpack_from("f", buffer)[0]
    elif data_type == TYPE_FLOAT64:
        parsed = struct.unpack_from("d", buffer)[0]
    elif data_type == TYPE_DATETIME:
        double_datetime = struct.unpack_from("q", buffer)[0]
        parsed = mdb_date_to_readable(double_datetime)
    elif data_type == TYPE_BINARY:
        parsed = buffer[:length]
        offset = length
    elif data_type == TYPE_OLE:
        parsed = buffer
    elif data_type == TYPE_GUID:
        parsed = buffer[:16]
        guid = uuid.UUID(parsed.hex())
        parsed = str(guid)
    elif data_type == TYPE_96_bit_17_BYTES:
        parsed = buffer[:17]
    elif data_type == TYPE_TEXT:
        parsed = decodeTextValue(buffer,version)
    else:
        LOGGER.debug(f"parse_type - unsupported data type: {data_type}")
    return parsed


def categorize_pages(db_data, page_size):
    if len(db_data) % page_size:
        LOGGER.warning(f"DB is not full or PAGE_SIZE is wrong. page size: {page_size} DB length {len(db_data)}")
    pages = {i: db_data[i:i + page_size] for i in range(0, len(db_data), page_size)}
    data_pages = {}
    table_defs = {}
    for page in pages:
        if pages[page].startswith(DATA_PAGE_MAGIC):
            data_pages[page] = pages[page]
        elif pages[page].startswith(TABLE_PAGE_MAGIC):
            table_defs[page] = pages[page]
    return table_defs, data_pages, pages


def read_db_file(path):
    if not os.path.isfile(path):
        LOGGER.error(f"File {path} not found")
        raise FileNotFoundError(f"File {path} not found")
    with open(path, "rb") as f:
        return f.read()
