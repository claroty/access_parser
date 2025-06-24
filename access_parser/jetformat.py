

import enum
import sys
import locale
from typing import ClassVar, Optional, Set, Type


class CodecType(enum.Enum):
    NONE    = enum.auto()
    JET     = enum.auto()
    MSISAM  = enum.auto()
    OFFICE  = enum.auto()


class DataType(enum.Enum):
    BOOLEAN         = enum.auto()
    BYTE            = enum.auto()
    INT             = enum.auto()
    LONG            = enum.auto()
    FLOAT           = enum.auto()
    DOUBLE          = enum.auto()
    GUID            = enum.auto()
    SHORT_DATE_TIME = enum.auto()
    MONEY           = enum.auto()
    NUMERIC         = enum.auto()
    TEXT            = enum.auto()
    MEMO            = enum.auto()
    BIG_INT         = enum.auto()
    EXT_DATE_TIME   = enum.auto()
    COMPLEX_TYPE    = enum.auto()

class PageTypes:
    INVALID         = 0
    DATA            = 1
    TABLE_DEF       = 2
    INDEX_NODE      = 3
    INDEX_LEAF      = 4
    USAGE_MAP       = 5


class BaseFormat:
    """
    Base class declaring every Jet-format constant as a class attribute.
    Subclasses simply override the ones that change.
    """

    # — Static JetFormat constants —
    MAX_RECORD_SIZE:      ClassVar[int]   = 1900
    TEXT_FIELD_UNIT_SIZE: ClassVar[int]   = 2
    TEXT_FIELD_MAX_LENGTH:ClassVar[int]   = 255 * TEXT_FIELD_UNIT_SIZE

    PROPERTY_MAP_TYPES:   ClassVar[list[bytes]] = [
        b"MR2\x00",   # access 2000+
        b"KKD\x00"    # access 97
    ]

    # the raw version byte in the header
    VERSION_CODE:       ClassVar[Optional[int]] = None
    # numeric mapping to enable compatibility
    VERSION_NUMBER:     ClassVar[Optional[int]] = None

    # — Identity & capabilities —
    name:                   ClassVar[str]           = "UNKNOWN"
    read_only:              ClassVar[bool]          = False
    indexes_supported:      ClassVar[bool]          = False
    codec_type:             ClassVar[CodecType]     = CodecType.NONE
    page_size:              ClassVar[int]           = 0
    max_database_size:      ClassVar[int]           = 0

    unsupported_data_types: ClassVar[Set[DataType]] = set()
    unsupported_calc_types: ClassVar[Set[DataType]] = set()

    # — Header parsing —
    OFFSET_VERSION:         ClassVar[int]           = 20
    HEADER_LENGTH:          ClassVar[int]           = 21
    OFFSET_ENGINE_NAME:     ClassVar[int]           = 0x04
    LENGTH_ENGINE_NAME:     ClassVar[int]           = 0x0F
    MSISAM_ENGINE:          ClassVar[bytes]         = b"MSISAM Database"

    BASE_HEADER_MASK:       ClassVar[bytes] = bytes([
        0xB5,0x6F,0x03,0x62,0x61,0x08,0xC2,0x55, 0xEB,0xA9,0x67,0x72,0x43,0x3F,0x00,0x9C,
        0x7A,0x9F,0x90,0xFF,0x80,0x9A,0x31,0xC5, 0x79,0xBA,0xED,0x30,0xBC,0xDF,0xCC,0x9D,
        0x63,0xD9,0xE4,0xC3,0x7B,0x42,0xFB,0x8A, 0xBC,0x4E,0x86,0xFB,0xEC,0x37,0x5D,0x44,
        0x9C,0xFA,0xC6,0x5E,0x28,0xE6,0x13,0xB6, 0x8A,0x60,0x54,0x94,0x7B,0x36,0xF5,0x72,
        0xDF,0xB1,0x77,0xF4,0x13,0x43,0xCF,0xAF, 0xB1,0x33,0x34,0x61,0x79,0x5B,0x92,0xB5,
        0x7C,0x2A,0x05,0xF1,0x7C,0x99,0x01,0x1B, 0x98,0xFD,0x12,0x4F,0x4A,0x94,0x6C,0x3E,
        0x60,0x26,0x5F,0x95,0xF8,0xD0,0x89,0x24, 0x85,0x67,0xC6,0x1F,0x27,0x44,0xD2,0xEE,
        0xCF,0x65,0xED,0xFF,0x07,0xC7,0x46,0xA1, 0x78,0x16,0x0C,0xED,0xE9,0x2D,0x62,0xD4
    ])

    # — All possible header‐level offsets & sizes (defaults) —
    OFFSET_MASKED_HEADER:         ClassVar[Optional[int]] = None
    HEADER_MASK:                  ClassVar[Optional[bytes]] = None
    OFFSET_HEADER_DATE:           ClassVar[Optional[int]] = None
    OFFSET_PASSWORD:              ClassVar[Optional[int]] = None
    SIZE_PASSWORD:                ClassVar[Optional[int]] = None
    OFFSET_SORT_ORDER:            ClassVar[Optional[int]] = None
    SIZE_SORT_ORDER:              ClassVar[Optional[int]] = None
    OFFSET_CODE_PAGE:             ClassVar[Optional[int]] = None
    OFFSET_ENCODING_KEY:          ClassVar[Optional[int]] = None

    # — All possible data‐page / table / index constants (defaults) —
    MAX_ROW_SIZE:                 ClassVar[Optional[int]] = None
    DATA_PAGE_INITIAL_FREE_SPACE: ClassVar[Optional[int]] = None

    OFFSET_NEXT_TABLE_DEF_PAGE:       ClassVar[Optional[int]] = None
    OFFSET_NUM_ROWS:                  ClassVar[Optional[int]] = None
    OFFSET_NEXT_AUTO_NUMBER:          ClassVar[Optional[int]] = None
    OFFSET_NEXT_COMPLEX_AUTO_NUMBER:  ClassVar[Optional[int]] = None

    OFFSET_TABLE_TYPE:            ClassVar[Optional[int]] = None
    OFFSET_MAX_COLS:              ClassVar[Optional[int]] = None
    OFFSET_NUM_VAR_COLS:          ClassVar[Optional[int]] = None
    OFFSET_NUM_COLS:              ClassVar[Optional[int]] = None

    OFFSET_NUM_INDEX_SLOTS:       ClassVar[Optional[int]] = None
    OFFSET_NUM_INDEXES:           ClassVar[Optional[int]] = None
    OFFSET_OWNED_PAGES:           ClassVar[Optional[int]] = None
    OFFSET_FREE_SPACE_PAGES:      ClassVar[Optional[int]] = None
    OFFSET_INDEX_DEF_BLOCK:       ClassVar[Optional[int]] = None

    SIZE_INDEX_COLUMN_BLOCK:      ClassVar[Optional[int]] = None
    SIZE_INDEX_INFO_BLOCK:        ClassVar[Optional[int]] = None

    OFFSET_COLUMN_TYPE:                   ClassVar[Optional[int]] = None
    OFFSET_COLUMN_NUMBER:                 ClassVar[Optional[int]] = None
    OFFSET_COLUMN_PRECISION:              ClassVar[Optional[int]] = None
    OFFSET_COLUMN_SCALE:                  ClassVar[Optional[int]] = None
    OFFSET_COLUMN_SORT_ORDER:             ClassVar[Optional[int]] = None
    OFFSET_COLUMN_CODE_PAGE:              ClassVar[Optional[int]] = None
    OFFSET_COLUMN_COMPLEX_ID:             ClassVar[Optional[int]] = None
    OFFSET_COLUMN_FLAGS:                  ClassVar[Optional[int]] = None
    OFFSET_COLUMN_EXT_FLAGS:              ClassVar[Optional[int]] = None
    OFFSET_COLUMN_LENGTH:                 ClassVar[Optional[int]] = None
    OFFSET_COLUMN_VARIABLE_TABLE_INDEX:   ClassVar[Optional[int]] = None
    OFFSET_COLUMN_FIXED_DATA_OFFSET:      ClassVar[Optional[int]] = None
    OFFSET_COLUMN_FIXED_DATA_ROW_OFFSET:  ClassVar[Optional[int]] = None

    OFFSET_TABLE_DEF_LOCATION:     ClassVar[Optional[int]] = None
    OFFSET_ROW_START:              ClassVar[Optional[int]] = None
    OFFSET_USAGE_MAP_START:        ClassVar[Optional[int]] = None
    OFFSET_USAGE_MAP_PAGE_DATA:    ClassVar[Optional[int]] = None
    OFFSET_REFERENCE_MAP_PAGE_NUMBERS: ClassVar[Optional[int]] = None

    OFFSET_FREE_SPACE:             ClassVar[Optional[int]] = None
    OFFSET_NUM_ROWS_ON_DATA_PAGE:  ClassVar[Optional[int]] = None
    MAX_NUM_ROWS_ON_DATA_PAGE:     ClassVar[Optional[int]] = None

    OFFSET_INDEX_COMPRESSED_BYTE_COUNT: ClassVar[Optional[int]] = None
    OFFSET_INDEX_ENTRY_MASK:            ClassVar[Optional[int]] = None
    OFFSET_PREV_INDEX_PAGE:             ClassVar[Optional[int]] = None
    OFFSET_NEXT_INDEX_PAGE:             ClassVar[Optional[int]] = None
    OFFSET_CHILD_TAIL_INDEX_PAGE:       ClassVar[Optional[int]] = None

    SIZE_INDEX_DEFINITION:         ClassVar[Optional[int]] = None
    SIZE_COLUMN_HEADER:            ClassVar[Optional[int]] = None
    SIZE_ROW_LOCATION:             ClassVar[Optional[int]] = None
    SIZE_LONG_VALUE_DEF:           ClassVar[Optional[int]] = None

    MAX_INLINE_LONG_VALUE_SIZE:    ClassVar[Optional[int]] = None
    MAX_LONG_VALUE_ROW_SIZE:       ClassVar[Optional[int]] = None
    MAX_COMPRESSED_UNICODE_SIZE:   ClassVar[Optional[int]] = None

    SIZE_TDEF_HEADER:              ClassVar[Optional[int]] = None
    SIZE_TDEF_TRAILER:             ClassVar[Optional[int]] = None
    SIZE_COLUMN_DEF_BLOCK:         ClassVar[Optional[int]] = None
    SIZE_INDEX_ENTRY_MASK:         ClassVar[Optional[int]] = None

    SKIP_BEFORE_INDEX_FLAGS:       ClassVar[Optional[int]] = None
    SKIP_AFTER_INDEX_FLAGS:        ClassVar[Optional[int]] = None
    SKIP_BEFORE_INDEX_SLOT:        ClassVar[Optional[int]] = None
    SKIP_AFTER_INDEX_SLOT:         ClassVar[Optional[int]] = None
    SKIP_BEFORE_INDEX:             ClassVar[Optional[int]] = None

    SIZE_NAME_LENGTH:              ClassVar[Optional[int]] = None
    SIZE_ROW_COLUMN_COUNT:         ClassVar[Optional[int]] = None
    SIZE_ROW_VAR_COL_OFFSET:       ClassVar[Optional[int]] = None

    USAGE_MAP_TABLE_BYTE_LENGTH:   ClassVar[Optional[int]] = None

    MAX_COLUMNS_PER_TABLE:         ClassVar[Optional[int]] = None
    MAX_INDEXES_PER_TABLE:         ClassVar[Optional[int]] = None
    MAX_TABLE_NAME_LENGTH:         ClassVar[Optional[int]] = None
    MAX_COLUMN_NAME_LENGTH:        ClassVar[Optional[int]] = None
    MAX_INDEX_NAME_LENGTH:         ClassVar[Optional[int]] = None

    LEGACY_NUMERIC_INDEXES:        ClassVar[Optional[bool]]   = None
    CHARSET:                       ClassVar[Optional[str]]    = None
    DEFAULT_SORT_ORDER:            ClassVar[Optional[str]]    = None
    PROPERTY_MAP_TYPE:             ClassVar[Optional[bytes]]  = None
    SIZE_TEXT_FIELD_UNIT:          ClassVar[Optional[int]]    = None

    ## compatibility functions to enable "version" to continue to be used as it was before:
    def __str__(self):
        """Return the VERSION_NUMBER when the object is converted to a string."""
        return str(self.VERSION_NUMBER)
    
    def __repr__(self):
        """Return a more detailed representation for debugging."""
        return f"{self.__class__.__name__}(version={self.VERSION_NUMBER})"
    
    def __eq__(self, other):
        """Enable direct comparison with numbers and other BaseFormat objects."""
        if isinstance(other, (int, float)):
            return self.VERSION_NUMBER == other
        elif isinstance(other, BaseFormat):
            return self.VERSION_NUMBER == other.VERSION_NUMBER
        return NotImplemented
    
    def __int__(self):
        """Allow conversion to integer."""
        return self.VERSION_NUMBER
    
    # Additional comparison methods for completeness
    def __lt__(self, other):
        if isinstance(other, (int, float)):
            return self.VERSION_NUMBER < other
        elif isinstance(other, BaseFormat):
            return self.VERSION_NUMBER < other.VERSION_NUMBER
        return NotImplemented
    
    def __gt__(self, other):
        if isinstance(other, (int, float)):
            return self.VERSION_NUMBER > other
        elif isinstance(other, BaseFormat):
            return self.VERSION_NUMBER > other.VERSION_NUMBER
        return NotImplemented
        
    def __le__(self, other):
        if isinstance(other, (int, float)):
            return self.VERSION_NUMBER <= other
        elif isinstance(other, BaseFormat):
            return self.VERSION_NUMBER <= other.VERSION_NUMBER
        return NotImplemented
        
    def __ge__(self, other):
        if isinstance(other, (int, float)):
            return self.VERSION_NUMBER >= other
        elif isinstance(other, BaseFormat):
            return self.VERSION_NUMBER >= other.VERSION_NUMBER
        return NotImplemented

    @classmethod
    def is_supported_data_type(cls, dt: DataType) -> bool:
        return dt not in cls.unsupported_data_types

    @classmethod
    def is_supported_calc_type(cls, dt: DataType) -> bool:
        return dt not in cls.unsupported_calc_types
    
    @classmethod
    def _all_subclasses(cls):
        """
        Recursively yield all subclasses of this class.
        """
        for sub in cls.__subclasses__():
            yield sub
            yield from sub._all_subclasses()

    @classmethod
    def get_format(cls, path: str) -> "BaseFormat":
        hdr = open(path, "rb").read(cls.HEADER_LENGTH)
        if len(hdr) < cls.HEADER_LENGTH:
            raise IOError(f"Not a Jet database: {path!r}")

        # 1) try the raw version byte first (Jet4+)
        raw_ver = hdr[cls.OFFSET_VERSION]
        for sub in cls._all_subclasses():
            if getattr(sub, "VERSION_CODE", None) == raw_ver:
                return sub()

        # 2) attempt unmask for Jet3 only
        masked_ver = raw_ver ^ cls.BASE_HEADER_MASK[cls.OFFSET_VERSION]
        from .jetformat import Jet3Format
        if masked_ver == Jet3Format.VERSION_CODE:
            return Jet3Format()

        # 3) fallback MSISAM by engine‐name
        eng = hdr[cls.OFFSET_ENGINE_NAME:
                  cls.OFFSET_ENGINE_NAME + cls.LENGTH_ENGINE_NAME]
        for sub in cls._all_subclasses():
            prefix = getattr(sub, "ENGINE_NAME_PREFIX", None)
            if prefix and eng.startswith(prefix):
                return sub()

        raise IOError(f"Unknown Jet version byte: raw=0x{raw_ver:02X}, masked=0x{masked_ver:02X}")

    
    @classmethod
    def get_format_from_header(cls, buf: bytes) -> "BaseFormat":
        if len(buf) < cls.HEADER_LENGTH:
            raise ValueError(f"Header buffer too small ({len(buf)} < {cls.HEADER_LENGTH})")

        raw_ver = buf[cls.OFFSET_VERSION]

        # 1) check raw byte → Jet4, Jet12, Jet14, Jet16, Jet17
        for sub in cls._all_subclasses():
            if getattr(sub, "VERSION_CODE", None) == raw_ver:
                return sub()

        # 2) if raw byte wasn’t a match, unmask *just* for Jet3 detection
        #    (only Jet3 files use this mask)
        masked_ver = raw_ver ^ cls.BASE_HEADER_MASK[cls.OFFSET_VERSION]
        from .jetformat import Jet3Format
        if masked_ver == Jet3Format.VERSION_CODE:
            return Jet3Format()

        # 3) fallback: MSISAM
        eng = buf[cls.OFFSET_ENGINE_NAME:cls.OFFSET_ENGINE_NAME + cls.LENGTH_ENGINE_NAME]
        for sub in cls._all_subclasses():
            prefix = getattr(sub, "ENGINE_NAME_PREFIX", None)
            if prefix and eng.startswith(prefix):
                return sub()

        raise ValueError(f"Unknown Jet version byte: raw=0x{raw_ver:02X}, masked=0x{masked_ver:02X}")


# ----------------------------------------------------------------------
# Jet3Format subclass: overrides *only* those attrs that Jet 3 needs
# ----------------------------------------------------------------------
class Jet3Format(BaseFormat):
    VERSION_CODE        = 0x00
    VERSION_NUMBER      = 3
    ENGINE_NAME_PREFIX  = None

    # identity & capabilities
    name                   = "3"
    read_only              = True                        
    indexes_supported      = True                        
    codec_type             = CodecType.JET               
    page_size              = 2048                        
    max_database_size      = 1 * 1024**3                 

    unsupported_data_types = {DataType.COMPLEX_TYPE}     
    unsupported_calc_types = set()                       

    # header‐level
    OFFSET_MASKED_HEADER         = 24                    
    HEADER_MASK                  = BaseFormat.BASE_HEADER_MASK[:-2] 
    OFFSET_HEADER_DATE           = -1                    
    OFFSET_PASSWORD              = 66                    
    SIZE_PASSWORD                = 20                    
    OFFSET_SORT_ORDER            = 58                    
    SIZE_SORT_ORDER              = 2                     
    OFFSET_CODE_PAGE             = 60                    
    OFFSET_ENCODING_KEY          = 62                    

    # page/table/index
    MAX_ROW_SIZE                       = 2012            
    DATA_PAGE_INITIAL_FREE_SPACE       = page_size - 14  

    OFFSET_NEXT_TABLE_DEF_PAGE         = 4               
    OFFSET_NUM_ROWS                    = 12              
    OFFSET_NEXT_AUTO_NUMBER            = 20              
    OFFSET_NEXT_COMPLEX_AUTO_NUMBER    = -1              

    OFFSET_TABLE_TYPE                  = 20              
    OFFSET_MAX_COLS                    = 21              
    OFFSET_NUM_VAR_COLS                = 23              
    OFFSET_NUM_COLS                    = 25              

    OFFSET_NUM_INDEX_SLOTS             = 27              
    OFFSET_NUM_INDEXES                 = 31              
    OFFSET_OWNED_PAGES                 = 35              
    OFFSET_FREE_SPACE_PAGES            = 39              
    OFFSET_INDEX_DEF_BLOCK             = 43              

    SIZE_INDEX_COLUMN_BLOCK            = 39              
    SIZE_INDEX_INFO_BLOCK              = 20              

    OFFSET_COLUMN_TYPE                 = 0               
    OFFSET_COLUMN_NUMBER               = 1               
    OFFSET_COLUMN_PRECISION            = 11              
    OFFSET_COLUMN_SCALE                = 12              
    OFFSET_COLUMN_SORT_ORDER           = 9               
    OFFSET_COLUMN_CODE_PAGE            = 11              
    OFFSET_COLUMN_COMPLEX_ID           = -1              
    OFFSET_COLUMN_FLAGS                = 13              
    OFFSET_COLUMN_EXT_FLAGS            = -1              
    OFFSET_COLUMN_LENGTH               = 16              
    OFFSET_COLUMN_VARIABLE_TABLE_INDEX = 3               
    OFFSET_COLUMN_FIXED_DATA_OFFSET    = 14              
    OFFSET_COLUMN_FIXED_DATA_ROW_OFFSET= 1               

    OFFSET_TABLE_DEF_LOCATION          = 4               
    OFFSET_ROW_START                   = 10              
    OFFSET_USAGE_MAP_START             = 5               
    OFFSET_USAGE_MAP_PAGE_DATA         = 4               
    OFFSET_REFERENCE_MAP_PAGE_NUMBERS  = 1               

    OFFSET_FREE_SPACE                  = 2               
    OFFSET_NUM_ROWS_ON_DATA_PAGE       = 8               
    MAX_NUM_ROWS_ON_DATA_PAGE          = 255             

    OFFSET_INDEX_COMPRESSED_BYTE_COUNT = 20              
    OFFSET_INDEX_ENTRY_MASK            = 22              
    OFFSET_PREV_INDEX_PAGE             = 8               
    OFFSET_NEXT_INDEX_PAGE             = 12              
    OFFSET_CHILD_TAIL_INDEX_PAGE       = 16              

    SIZE_INDEX_DEFINITION              = 8               
    SIZE_COLUMN_HEADER                 = 18              
    SIZE_ROW_LOCATION                  = 2               
    SIZE_LONG_VALUE_DEF                = 12              
    MAX_INLINE_LONG_VALUE_SIZE         = 64              
    MAX_LONG_VALUE_ROW_SIZE            = 2032            
    MAX_COMPRESSED_UNICODE_SIZE        = 1024            

    SIZE_TDEF_HEADER                   = 43              
    SIZE_TDEF_TRAILER                  = 2               
    SIZE_COLUMN_DEF_BLOCK              = 25              
    SIZE_INDEX_ENTRY_MASK              = 226             

    SKIP_BEFORE_INDEX_FLAGS            = 0               
    SKIP_AFTER_INDEX_FLAGS             = 0               
    SKIP_BEFORE_INDEX_SLOT             = 0               
    SKIP_AFTER_INDEX_SLOT              = 0               
    SKIP_BEFORE_INDEX                  = 0               

    SIZE_NAME_LENGTH                   = 1               
    SIZE_ROW_COLUMN_COUNT              = 1               
    SIZE_ROW_VAR_COL_OFFSET            = 1               

    USAGE_MAP_TABLE_BYTE_LENGTH        = 128             

    MAX_COLUMNS_PER_TABLE              = 255             
    MAX_INDEXES_PER_TABLE              = 32              
    MAX_TABLE_NAME_LENGTH              = 64              
    MAX_COLUMN_NAME_LENGTH             = 64              
    MAX_INDEX_NAME_LENGTH              = 64              

    LEGACY_NUMERIC_INDEXES             = True            
    CHARSET                            = 'cp1252'
    DEFAULT_SORT_ORDER                 = None            
    PROPERTY_MAP_TYPE                  = BaseFormat.PROPERTY_MAP_TYPES[1]  
    SIZE_TEXT_FIELD_UNIT               = 1               




class SortOrder(enum.Enum):
    """Placeholder for ColumnImpl.SortOrder"""
    GENERAL_SORT_ORDER      = enum.auto()
    GENERAL_97_SORT_ORDER   = enum.auto()
    GENERAL_LEGACY_SORT_ORDER = enum.auto()


# ----------------------------------------------------------------------
# Jet 4 (Access 2000/02/03 – Jet 4)
# ----------------------------------------------------------------------
class Jet4Format(BaseFormat):
    VERSION_CODE                            = 0x01
    VERSION_NUMBER                          = 4

    name                                    = "4"
    read_only                               = False
    indexes_supported                       = True
    codec_type                              = CodecType.JET
    page_size                               = 4096
    max_database_size                       = 2 * 1024**3            # 2 GB

    MAX_ROW_SIZE                            = 4060
    DATA_PAGE_INITIAL_FREE_SPACE            = page_size - 14

    OFFSET_MASKED_HEADER                    = 24
    HEADER_MASK                             = BaseFormat.BASE_HEADER_MASK
    OFFSET_HEADER_DATE                      = 114
    OFFSET_PASSWORD                         = 66
    SIZE_PASSWORD                           = 40
    OFFSET_SORT_ORDER                       = 110
    SIZE_SORT_ORDER                         = 4
    OFFSET_CODE_PAGE                        = 60
    OFFSET_ENCODING_KEY                     = 62

    OFFSET_NEXT_TABLE_DEF_PAGE              = 4
    OFFSET_NUM_ROWS                         = 16
    OFFSET_NEXT_AUTO_NUMBER                 = 20
    OFFSET_NEXT_COMPLEX_AUTO_NUMBER         = -1

    OFFSET_TABLE_TYPE                       = 40
    OFFSET_MAX_COLS                         = 41
    OFFSET_NUM_VAR_COLS                     = 43
    OFFSET_NUM_COLS                         = 45

    OFFSET_NUM_INDEX_SLOTS                  = 47
    OFFSET_NUM_INDEXES                      = 51
    OFFSET_OWNED_PAGES                      = 55
    OFFSET_FREE_SPACE_PAGES                 = 59
    OFFSET_INDEX_DEF_BLOCK                  = 63

    SIZE_INDEX_COLUMN_BLOCK                 = 52
    SIZE_INDEX_INFO_BLOCK                   = 28

    OFFSET_COLUMN_TYPE                      = 0
    OFFSET_COLUMN_NUMBER                    = 5
    OFFSET_COLUMN_PRECISION                 = 11
    OFFSET_COLUMN_SCALE                     = 12
    OFFSET_COLUMN_SORT_ORDER                = 11
    OFFSET_COLUMN_CODE_PAGE                 = -1
    OFFSET_COLUMN_COMPLEX_ID                = -1
    OFFSET_COLUMN_FLAGS                     = 15
    OFFSET_COLUMN_EXT_FLAGS                 = 16
    OFFSET_COLUMN_LENGTH                    = 23
    OFFSET_COLUMN_VARIABLE_TABLE_INDEX      = 7
    OFFSET_COLUMN_FIXED_DATA_OFFSET         = 21
    OFFSET_COLUMN_FIXED_DATA_ROW_OFFSET     = 2

    OFFSET_TABLE_DEF_LOCATION               = 4
    OFFSET_ROW_START                        = 14
    OFFSET_USAGE_MAP_START                  = 5
    OFFSET_USAGE_MAP_PAGE_DATA              = 4
    OFFSET_REFERENCE_MAP_PAGE_NUMBERS       = 1

    OFFSET_FREE_SPACE                       = 2
    OFFSET_NUM_ROWS_ON_DATA_PAGE            = 12
    MAX_NUM_ROWS_ON_DATA_PAGE               = 255

    OFFSET_INDEX_COMPRESSED_BYTE_COUNT      = 24
    OFFSET_INDEX_ENTRY_MASK                 = 27
    OFFSET_PREV_INDEX_PAGE                  = 12
    OFFSET_NEXT_INDEX_PAGE                  = 16
    OFFSET_CHILD_TAIL_INDEX_PAGE            = 20

    SIZE_INDEX_DEFINITION                   = 12
    SIZE_COLUMN_HEADER                      = 25
    SIZE_ROW_LOCATION                       = 2
    SIZE_LONG_VALUE_DEF                     = 12
    MAX_INLINE_LONG_VALUE_SIZE              = 64
    MAX_LONG_VALUE_ROW_SIZE                 = 4076
    MAX_COMPRESSED_UNICODE_SIZE             = 1024

    SIZE_TDEF_HEADER                        = 63
    SIZE_TDEF_TRAILER                       = 2
    SIZE_COLUMN_DEF_BLOCK                   = 25
    SIZE_INDEX_ENTRY_MASK                   = 453

    SKIP_BEFORE_INDEX_FLAGS                 = 4
    SKIP_AFTER_INDEX_FLAGS                  = 5
    SKIP_BEFORE_INDEX_SLOT                  = 4
    SKIP_AFTER_INDEX_SLOT                   = 4
    SKIP_BEFORE_INDEX                       = 4

    SIZE_NAME_LENGTH                        = 2
    SIZE_ROW_COLUMN_COUNT                   = 2
    SIZE_ROW_VAR_COL_OFFSET                 = 2

    USAGE_MAP_TABLE_BYTE_LENGTH             = 64

    MAX_COLUMNS_PER_TABLE                   = 255
    MAX_INDEXES_PER_TABLE                   = 32
    MAX_TABLE_NAME_LENGTH                   = 64
    MAX_COLUMN_NAME_LENGTH                  = 64
    MAX_INDEX_NAME_LENGTH                   = 64

    LEGACY_NUMERIC_INDEXES                  = True
    CHARSET                                 = "utf-16le"
    DEFAULT_SORT_ORDER                      = SortOrder.GENERAL_97_SORT_ORDER
    PROPERTY_MAP_TYPE                       = BaseFormat.PROPERTY_MAP_TYPES[1]
    SIZE_TEXT_FIELD_UNIT                    = 1

    # from V3_UNSUPP_TYPES: {COMPLEX_TYPE, BIG_INT, EXT_DATE_TIME}
    unsupported_data_types                  = {
        DataType.COMPLEX_TYPE,
        DataType.BIG_INT,
        DataType.EXT_DATE_TIME
    }
    unsupported_calc_types                  = set()  # no calculated types :contentReference[oaicite:2]{index=2}


# ----------------------------------------------------------------------
# Jet 12 (Access 2007 – ACE12) builds on Jet4
# ----------------------------------------------------------------------
class Jet12Format(Jet4Format):
    VERSION_CODE        = 0x02
    VERSION_NUMBER      = 5
    name                = "12"

    codec_type          = CodecType.OFFICE
    legacy_numeric_indexes = False

    # from V12_UNSUPP_TYPES = {BIG_INT, EXT_DATE_TIME}
    unsupported_data_types = {
        DataType.BIG_INT,
        DataType.EXT_DATE_TIME
    }

    # only these two offsets changed:
    offset_next_complex_auto_number = 28
    offset_column_complex_id        = 11

    # ACE 12 still doesn’t support complex type or calc types
    unsupported_calc_types = {
        dt for dt in DataType
    }  # no calculated types :contentReference[oaicite:3]{index=3}


# ----------------------------------------------------------------------
# Jet 14 (Access 2010 – ACE14) inherits from Jet12
# ----------------------------------------------------------------------
class Jet14Format(Jet12Format):
    VERSION_CODE        = 0x03
    VERSION_NUMBER      = 2010
    name                = "14"

    DEFAULT_SORT_ORDER  = SortOrder.GENERAL_SORT_ORDER
    PROPERTY_MAP_TYPE   = BaseFormat.PROPERTY_MAP_TYPES[0]

    # ACE 14 supports the V14_CALC_TYPES:
    _V14_CALC = {
        DataType.BOOLEAN, DataType.BYTE, DataType.INT, DataType.LONG,
        DataType.FLOAT, DataType.DOUBLE, DataType.GUID,
        DataType.SHORT_DATE_TIME, DataType.MONEY, DataType.NUMERIC,
        DataType.TEXT, DataType.MEMO
    }
    unsupported_calc_types = set(DataType) - _V14_CALC


# ----------------------------------------------------------------------
# Jet 16 (Access 2013 – ACE16) inherits from Jet14
# ----------------------------------------------------------------------
class Jet16Format(Jet14Format):
    VERSION_CODE        = 0x05
    VERSION_NUMBER      = 2013
    name                = "16"

    # from V16_UNSUPP_TYPES = {EXT_DATE_TIME}
    unsupported_data_types = {
        DataType.EXT_DATE_TIME
    }

    # ACE 16 adds BIG_INT calc support:
    _V16_CALC = Jet14Format._V14_CALC.union({ DataType.BIG_INT })
    unsupported_calc_types = set(DataType) - _V16_CALC


# ----------------------------------------------------------------------
# Jet 17 (Access 2016 – ACE17) inherits from Jet16
# ----------------------------------------------------------------------
class Jet17Format(Jet16Format):
    VERSION_CODE        = 0x06
    VERSION_NUMBER      = 2016
    name                = "17"

    # now supports everything
    unsupported_data_types = set()
    unsupported_calc_types = set()

    CHARSET              = "utf-16le"  # StandardCharsets.UTF_16LE
    DEFAULT_SORT_ORDER   = SortOrder.GENERAL_LEGACY_SORT_ORDER
    PROPERTY_MAP_TYPE    = BaseFormat.PROPERTY_MAP_TYPES[0]
    SIZE_TEXT_FIELD_UNIT = BaseFormat.TEXT_FIELD_UNIT_SIZE


# ----------------------------------------------------------------------
# MSISAM (Access 95) reuses Jet4 layout but overrides codec & engine‐name
# ----------------------------------------------------------------------
class MsisamFormat(Jet4Format):
    VERSION_CODE         = None
    ENGINE_NAME_PREFIX   = BaseFormat.MSISAM_ENGINE

    name                = "MSISAM"
    read_only           = True
    indexes_supported   = False
    codec_type          = CodecType.MSISAM
    page_size           = 512
    max_database_size   = 1 * 1024**2  # 1 MB

    # nothing at all is supported
    unsupported_data_types = set(DataType)
    unsupported_calc_types = set(DataType)