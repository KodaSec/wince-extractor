#! /usr/bin/env python3

"""

WinCE Extractor: Extract compressed files from Windows CE ROMs.

"""

from collections import defaultdict
from sortedcontainers import SortedDict
import ctypes
import os
import sys
import io
import argparse
import platform

if platform.architecture()[0] == "32bit":
    try:
        CECOMPRESS      = ctypes.cdll.LoadLibrary("DLLs\CECompress.dll")
        CECOMPRESS_V3   = ctypes.cdll.LoadLibrary("DLLs\CECompressV3.dll")
        CECOMPRESS_V4   = ctypes.cdll.LoadLibrary("DLLs\CECompressV4.dll")

        CEDecompressV3  = CECOMPRESS_V3.CEDecompress
        CEDecompressV4  = CECOMPRESS_V4.CEDecompress
        CEDecompressROM = CECOMPRESS.CEDecompressROM
    except Exception as e:
        perror(str(e))
        exit(1)
else:
    CEDecompress    = None
    CEDecompressROM = None

if os.name == 'nt':
    from ctypes import wintypes
    from ctypes.wintypes import CHAR
    # from ctypes.wintypes import BYTE # This gives a signed char, not an unsigned char like we need
    BYTE = ctypes.c_ubyte
    from ctypes.wintypes import WORD
    from ctypes.wintypes import DWORD
    from ctypes.wintypes import LONG
    from ctypes.wintypes import ULONG
    from ctypes.wintypes import USHORT
    from ctypes.wintypes import LPSTR
    from ctypes.wintypes import LPVOID
else:
    CHAR    = ctypes.c_char
    BYTE    = ctypes.c_ubyte
    WORD    = ctypes.c_ushort
    DWORD   = ctypes.c_ulong
    LONG    = ctypes.c_long
    ULONG   = ctypes.c_ulong
    USHORT  = ctypes.c_ushort
    LPSTR   = ctypes.POINTER(ctypes.c_char)
    LPVOID  = ctypes.c_void_p

_IMGOFSINCREMENT                    = 0x1000
_IMAGE_DOS_SIGNATURE                = 0x5A4D
_ROM_EXTRA                          = 9
_XIP_NAMELEN                        = 32
_PID_LENGTH                         = 10
_STD_EXTRA                          = 16
_E32OBJNAMEBYTES                    = 8
_IMAGE_FILE_RELOCS_STRIPPED         = 0x0001
_IMAGE_SCN_CNT_CODE                 = 0x00000020
_IMAGE_SCN_CNT_INITIALIZED_DATA     = 0x00000040
_IMAGE_SCN_CNT_UNINITIALIZED_DATA   = 0x00000080
_IMAGE_SCN_COMPRESSED               = 0x00002000
_ROM_SIGNATURE_OFFSET               = 64
_ROM_SIGNATURE                      = 0x43454345
_MAX_ROM                            = 32
_EXP = 0
_IMP = 1
_RES = 2
_EXC = 3
_SEC = 4
_FIX = 5
_DEB = 6
_IMD = 7
_MSP = 8
_TLS = 9
_CBK = 10
_RS1 = 11
_RS2 = 12
_RS3 = 13
_RS4 = 14
_RS5 = 15

_ST_TEXT    = 0
_ST_DATA    = 1
_ST_PDATA   = 2
_ST_RSRC    = 3
_ST_OTHER   = 4

_CECOMPRESS_ALLZEROS = 0
_CECOMPRESS_FAILED   = 0xffffffff
_CEDECOMPRESS_FAILED = 0xffffffff

def pointer_address(ptr, offset=0):
    """
    Calculates the new address from the given pointer
    and offset.

    Parameters:
    ptr (ctypes.pointer): The pointer to offset from
    offset (int): The number of objects that ptr points to to offset

    Returns:
    int: Address of the given ptr at the given offset
    """
    size = ctypes.sizeof(ptr._type_)
    return ctypes.addressof(ptr.contents) + (offset * size)

def convert_ptr_to_array(ptr, size, new_type=None):
    if type(ptr) is ctypes._SimpleCData:
        address = ctypes.addressof(ptr)
        if new_type is None:
            new_type = ptr._type_
    else:
        address = ptr
    return ctypes.cast(address, ctypes.POINTER(new_type * size)).contents

def perror(message):
    """
    Writes the given message to the stderr stream.

    Parameters:
    message (str): The message to print

    Returns:
    None
    """
    sys.stderr.write(message)
    sys.stderr.write(os.linesep)

class memory_block(object):
    """
    A block of memory with a start and end.
    The start and end may not be the start and end
    of the data it controls.
    """
    def __init__(self, length, start, end):
        """
        Contructs the memory_block

        Parameters:
        length (int): Length of the data
        start (int): Where to start into the data
        end (int): Where to end into the data

        Returns:
        None
        """
        self.data   = (BYTE * length)()
        self.start  = start
        self.end    = end

    def in_range(self, offset):
        """
        Checks if offset is between start and end

        Parameters:
        offset (int): The offset to check

        Returns:
        bool: True if offset is between start and end, False otherwise
        """
        return self.start <= offset and offset < self.end

    def __lt__(self, other):
        """
        Overrides the < operator to compare with either
        an integer or anther memory_block

        Parameters:
        other (int or memory_block): Another memory_block or integer

        Returns:
        bool: True if the given memory_block's start is after this one.
              True if the given integer it greater than the end.
        """
        if type(other) is memory_block:
            return self.start < other.start

        return self.end < other

    def __len__(self):
        """
        Overrides the len() method to give the length of the data

        Parameters:
        None

        Returns:
        int: The length of the data.
        """
        return len(self.data)

class memory_map_iterator(object):
    """
    An iterator to traverse through a memory_map. Based on the C++
    design and attempts to emulate using C++ iterators.
    """
    def __init__(self, **kwrds):
        """
        Constructs a memory_map_iterator.
        This constructor can be a copy constructor,
        or one that takes other parameters.

        Parameters:
        kwrds (map): A map of parameters that can be another memory_map_iterator
                     or arguments to construct this object.
                     Use 'copy' to copy a memory_map_iterator.
                     Use 'start', 'end', and 'data', for normal construction.

        Returns:
        None
        """
        if 'copy' in kwrds:
            self.m_block    = kwrds['copy'].m_block
            self.m_end      = kwrds['copy'].m_end
            self.data       = kwrds['copy'].data
            self.m_ofs      = kwrds['copy'].m_ofs
        elif 'start' in kwrds and 'end' in kwrds and 'data' in kwrds:
            self.m_block    = kwrds['start']
            self.m_end      = kwrds['end']
            self.data       = kwrds['data']
            self.m_ofs      = 0 if self.m_block == self.m_end else self.data[self.m_block].start

    def find_next(self):
        """
        Finds the index for the next block of data.

        Parameters:
        None

        Returns:
        None
        """
        while self.m_block != self.m_end and self.m_ofs >= self.data[self.m_block].end:
            self.m_block += 1
        
        if self.m_block == self.m_end:
            self.m_ofs = 0
        elif self.m_ofs < self.data[self.m_block].start:
            self.m_ofs = self.data[self.m_block].start

    def __next__(self):
        """
        Overrides the next() function.
        Increments the offset by one and finds the next block of data.

        Parameters:
        None

        Returns:
        memory_map_iterator: Itself
        """
        return self.__iadd__(1)

    def __iadd__(self, amount):
        """
        Overrides the += operator.
        Increments the offset by the given amount
        and finds the next block of data.

        Parameters:
        amount (int): Amount to increment

        Returns:
        memory_map_iterator: Itself
        """
        self.m_ofs += amount
        self.find_next()
        return self

    def __eq__(self, other):
        """
        Overrides the == operator.
        Checks if the given parameter is equal to this object

        Parameters:
        other (memory_map_iterator): Another memory_map_iterator

        Returns:
        bool: True if the other block and offset is equal to this one
        """
        return self.m_block == other.m_block and self.m_ofs == other.m_ofs

    def __ne__(self, other):
        """
        Overrides the != operator.
        Checks if the given parameter is not equal to this object.

        Parameters:
        other (memory_map_iterator): Another memory_map_iterator

        Returns:
        bool: True if the __eq__ method returns False
        """
        return not self.__eq__(other)

    def get_ptr(self):
        """
        Gets the memory address of the current block at an offset.

        Parameters:
        None

        Returns:
        int: Memory address of the given block at an offset or None if the current block is at the end
        """
        return None if self.m_block == self.m_end else ctypes.addressof(self.data[self.m_block].data) + (self.m_ofs - self.data[self.m_block].start)

    def _get_data(self, _type):
        """
        Helper method to get different types of information
        at the current call of get_ptr.

        Parameters:
        _type (type): A ctypes type that can be made a pointer of

        Returns:
        ctypes._SimpleCData: A ctypes simple data type
        """
        ptr = self.get_ptr()
        if not ptr:
            return None

        ptr = ctypes.cast(ptr, ctypes.POINTER(_type))
        return ptr.contents

    def get_byte(self):
        """
        Gets a byte at the current block address

        Parameters:
        None

        Returns:
        ctypes.c_ubyte: The byte at the current address
        """
        return self._get_data(BYTE)

    def get_word(self):
        """
        Gets a word at the current block address

        Parameters:
        None

        Returns:
        ctypes.c_ushort: The word at the current address
        """
        return self._get_data(WORD)
    
    def get_dword(self):
        """
        Gets a dword at the current block address

        Parameters:
        None

        Returns:
        ctypes.c_ulong: The dword at the current address
        """
        return self._get_data(DWORD)

class memory_map(object):
    """
    Loads and stores memory_blocks from a ROM file
    """
    def __init__(self):
        """
        Constructs a memory_map

        Parameters:
        None

        Returns:
        None
        """
        self.m_blocks = []

    def load_file(self, offset, filename, file_offset, length):
        """
        Loads a ROM file as a memory_block

        Parameters:
        offset (int): The offset to start into the memory_block
        filename (str): The name of the file
        file_offset (int): The offset into the file to start reading
        length (int): Length of the memory_block (amount to read)

        Returns:
        bool: True if reading the file was successful, False otherwise
        """
        try:
            with open(filename, mode="rb") as f:
                if length == 0:
                    f.seek(0, io.SEEK_END)
                    length = f.tell() - file_offset
                    if length == 0:
                        print("length not known")
                        return False
                
                try:
                    mb = memory_block(length=length, start=offset, end=offset + length)
                except MemoryError:
                    print("error allocating memory")
                    return False

                f.seek(file_offset, io.SEEK_SET)
                if f.readinto(mb.data) != len(mb):
                    perror("fread in load_file")
                    return False
                
        except Exception as e:
            perror(str(e))
            return False

        self.m_blocks.append(mb)
        self.m_blocks.sort()

        if g_verbose:
            print("block {} added buf={:08x} {:08x}".format(len(self.m_blocks), DWORD(ctypes.addressof(mb.data)).value, len(mb)))

        return True

    def get_ptr(self, offset):
        """
        Gets the memory address from current memory_blocks that are
        in the given offset.

        Parameters:
        offset (int): The offset into the memory_block

        Returns:
        int: A memory address, or None if the offset is not in any memory_blocks
        """
        for m_block in self.m_blocks:
            if m_block.in_range(offset):
                return ctypes.addressof(m_block.data) + (offset - m_block.start)

        perror("ERROR: could not find pointer for ofs {:08x}".format(offset))
        return None

    def _get_data(self, _type, offset):
        """
        Gets data at the given offset in the memory_blocks
        and interprets it as the given type

        Parameters:
        _type (type): The type to interpret the data as
        offset (int): The offset into a memory_block

        Returns:
        ctypes._SimpleCData: The interpreted data, or None if the offset is
                             not in the memory_blocks
        """
        ptr = self.get_ptr(offset)
        if ptr == 0:
            return None

        ptr = ctypes.cast(ptr, ctypes.POINTER(_type))
        if not ptr:
            return None
        return ptr.contents

    def get_byte(self, offset):
        """
        Gets a byte at the given offset

        Parameters:
        offset (int): The offset into the memory_blocks

        Returns:
        ctypes.c_ubyte: Byte at the given offset
        """
        return self._get_data(BYTE, offset)

    def get_dword(self, offset):
        """
        Gets a dword at the given offset

        Parameters:
        offset (int): The offset into the memory_blocks

        Returns:
        ctypes.c_ulong: Dword at the given offset
        """
        return self._get_data(DWORD, offset)

    def get_ofs(self, ptr):
        """
        Obtains an offset from the current memory_blocks near the given pointer

        Parameters:
        ptr (int): A memory address

        Returns:
        int: The found offset, or 0 if the offset cannot be found
        """
        for m_block in self.m_blocks:
            m_block_mem = ctypes.addressof(m_block.data)
            if m_block_mem <= ptr and ptr < m_block_mem + len(m_block):
                return (ptr - m_block_mem) + m_block.start
        
        perror("ERROR: could not find offset for ptr {:08x}".format(DWORD(ptr).value))
        return 0

    def first_address(self):
        """
        Finds the starting address of the first block

        Parameters:
        None

        Returns:
        int: A memory address
        """
        return self.m_blocks[0].start

    def last_address(self):
        """
        Finds the ending address of the last block

        Parameters:
        None

        Returns:
        int: A memory address
        """
        return self.m_blocks[-1].end

    def begin(self):
        """
        Creates a memory_map_iterator over the current memory_blocks

        Parameters:
        None

        Returns:
        memory_map_iterator: An iterator starting at 0 and ending at the number of memory_blocks
        """
        return memory_map_iterator(start=0, end=len(self.m_blocks), data=self.m_blocks)

    def end(self):
        """
        Creates a memory_map_iterator denoting an end-state memory_map_iterator

        Parameters:
        None

        Returns:
        memory_map_iterator: An iterator starting and ending at the number of memory_blocks
        """
        return memory_map_iterator(start=len(self.m_blocks), end=len(self.m_blocks), data=self.m_blocks)

class mem_region(object):
    """
    Denotes a region of memory that can be described as an entry as either a file
    or another significant entry.
    """
    def __init__(self, start, end):
        """
        Constructs a mem_region.

        Parameters:
        start (int): The starting address of the mem_region
        end (int): The ending address of the mem_region

        Returns:
        None
        """
        self.start          = start
        self.end            = end
        self.description    = ''
        self.length         = self.end - self.start

    def __lt__(self, other):
        """
        Overrides the < operator. Checks if the given mem_region's start or length is less than this one.

        Parameters:
        other (mem_region): The other mem_region to compare

        Returns:
        bool: True if this mem_region's start or length is less than the given one
        """
        return self.start < other.start or (self.start == other.start and self.length < other.length)

    def first_nonzero(self):
        """
        Finds the first non-zero byte in the region

        Parameters:
        None

        Returns:
        int: The first non-zero index or the end if not found
        """
        for i in range(self.start, self.end):
            if g_mem.get_byte(i).value != 0:
                return i

        return self.end

    def last_nonzero(self):
        """
        Finds the last non-zero byte in the region

        Parameters:
        None

        Returns:
        int: The last non-zero index or the index before the start
        """
        for i in range(self.end - 1, self.start - 1, -1):
            if g_mem.get_byte(i).value != 0:
                return i
        
        return self.start - 1

class mem_regions(object):
    """
    A collection of mem_regions and managing their descriptions and output.
    """
    def __init__(self):
        """
        Constructs a mem_regions

        Parameters:
        None

        Returns:
        None
        """
        self.m_list = []
    
    def mark_range(self, start, end, msg, *args):
        """
        Adds a description to a given range of memory

        Paramters:
        start (int): The start of the memory range
        end (int): The end of the memory range
        msg (str): The description format string of the memory range
        *args (list): A list of values for the format string
        
        Returns:
        mem_region: A mem_region with the given description and range
        """
        return self.mark_region(start, end-start, msg, *args)

    def mark_region(self, start, length, msg, *args):
        """
        Adds a description to a given range of memory

        Paramters:
        start (int): The start of the memory range
        length (int): The length of the memory range
        msg (str): The description format string of the memory range
        *args (list): A list of values for the format string
        
        Returns:
        mem_region: A mem_region with the given description and range
        """
        if start == 0:
            print("start=0")

        m = mem_region(start, start + length)
        m.description = msg.format(*args)

        self.m_list.append(m)

        return m

    def dump_memory_map(self):
        """
        Prints out all the descriptive information of the current memory regions

        Parameters:
        None

        Returns:
        None
        """
        self.m_list.sort()
        
        offset = g_mem.first_address()
        for i in self.m_list:
            if offset < i.start:
                m = mem_region(offset, i.start)
                if (i.start & 3) == 0 and i.start - offset < 4:
                    if g_verbose:
                        print("\t{:08x} - {:08x} L{:08x} alignment".format(m.start, m.end, m.length), end='')
                        if m.first_nonzero() != m.end:
                            byte_dump(m.start, m.end)
                else:
                    first_nz    = max(m.start, m.first_nonzero() & (~3))
                    last_nz     = min(m.end, (m.last_nonzero() & (~3)) + 4)
                    if first_nz == m.end:
                        print("\n{:08x} - {:08x} L{:08x} NUL".format(m.start, m.end, m.length), end='')
                    else:
                        if first_nz != m.start:
                            print("\n{:08x} - {:08x} L{:08x} NUL".format(m.start, first_nz, first_nz - m.start), end='')

                        print("\n{:08x} - {:08x} L{:08x} unknown".format(first_nz, last_nz, last_nz - first_nz), end='')

                        if last_nz - first_nz < 16:
                            byte_dump(first_nz, last_nz)
                        elif last_nz - first_nz < 64:
                            dword_dump(first_nz, last_nz)

                        if last_nz != m.end:
                            print("\n{:08x} - {:08x} L{:08x} NUL".format(last_nz, m.end, m.end - last_nz), end='')
            elif offset > i.start:
                print("\n!!! overlap of {} bytes".format(offset - i.start))
            
            print("\n{:08x} - {:08x} L{:08x} {}".format(i.start, i.end, i.length, i.description), end='')

            offset = i.end

        if offset < g_mem.last_address():
            print("\n{:08x} - {:08x} unknown".format(offset, g_mem.last_address()))

        print("")

class score_cmp(object):
    """
    A functor class that is used as a comparison function
    """
    def __init__(self, m_map):
        """
        Constructs a score_cmp

        Parameters:
        m_map (memory_map): The memory_map to compare values of

        Returns:
        None
        """
        self.m_map = m_map

    def __call__(self, a, b):
        """
        Overloads the () operator. Checks whether the given
        values as keys to the current memory_map is less than one
        another.

        Parameters:
        a (key type of m_map): First key to retrieve value
        b (key type of m_map): Second key to retrieve value

        Returns:
        bool: True if the first key's value is greater than the second key's
              value, False otherwise
        """
        return self.m_map[a] > self.m_map[b]

class file_type(object):
    """
    An enum-like class denoting a ROM's file type.
    """
    FT_BOOOFF   = 0
    FT_NBF      = 1
    FT_BIN      = 2

class filetime(ctypes.Structure):
    """
    A structure for holding a filetime instance in a ROM entry.
    """
    _fields_        = [("dwLowDateTime",    DWORD),
                       ("dwHighDateTime",   DWORD)]

class info(ctypes.Structure):
    """
    A structure for holding information about units
    in other structures.
    """
    _fields_        = [("rva",  ctypes.c_ulong),
                       ("size", ctypes.c_ulong)]

class e32_rom(ctypes.Structure):
    """
    A structure representing an e32_rom entry.
    """
    _fields_    = [("e32_objcnt",       ctypes.c_ushort),
                   ("e32_imageflags",   ctypes.c_ushort),
                   ("e32_entryrva",     ctypes.c_ulong),
                   ("e32_vbase",        ctypes.c_ulong),
                   ("e32_subsysmajor",  ctypes.c_ushort),
                   ("e32_subsysminor",  ctypes.c_ushort),
                   ("e32_stackmax",     ctypes.c_ulong),
                   ("e32_vsize",        ctypes.c_ulong),
                   ("e32_sect14rva",    ctypes.c_ulong),
                   ("e32_sect14size",   ctypes.c_ulong),
                   ("e32_unit",         info * _ROM_EXTRA),
                   ("e32_subsys",       ctypes.c_ushort)]

class o32_rom(ctypes.Structure):
    """
    A structure representing an o32_rom entry.
    """
    _fields_    = [("o32_vsize",    ctypes.c_ulong),
                   ("o32_rva",      ctypes.c_ulong),
                   ("o32_psize",    ctypes.c_ulong),
                   ("o32_dataptr",  ctypes.c_ulong),
                   ("o32_realaddr", ctypes.c_ulong),
                   ("o32_flags",    ctypes.c_ulong)]

class romhdr(ctypes.Structure):
    """
    A structure representing a romhdr entry.
    """
    _fields_    = [("dllfirst",         ULONG),
                   ("dlllast",          ULONG),
                   ("physfirst",        ULONG),
                   ("physlast",         ULONG),
                   ("nummods",          ULONG),
                   ("ulRAMStart",       ULONG),
                   ("ulRAMFree",        ULONG),
                   ("ulRAMEnd",         ULONG),
                   ("ulCopyEntries",    ULONG),
                   ("ulCopyOffset",     ULONG),
                   ("ulProfileLen",     ULONG),
                   ("ulProfileOffset",  ULONG),
                   ("numfiles",         ULONG),
                   ("ulKernelFlags",    ULONG),
                   ("ulFSRamPercent",   ULONG),
                   ("ulDrivglobstart",  ULONG),
                   ("ulDrivgloblen",    ULONG),
                   ("usCPUType",        USHORT),
                   ("usMiscFlags",      USHORT),
                   ("pExtensions",      DWORD), # Originally void*, but Python makes pointers 8 bytes
                                                # and it needs to be a 4 byte pointer.
                   ("ulTrackingStart",  ULONG),
                   ("ulTrackingLen",    ULONG)]

class toc_entry(ctypes.Structure):
    """
    A structure representing a TOC entry.
    """
    _fields_    = [("dwFileAttributes", DWORD),
                    ("ftTime",          filetime),
                    ("nFileSize",       DWORD),
                    ("lpszFileName",    DWORD), # Originally void*, but Python makes pointers 8 bytes
                                                # and it needs to be a 4 byte pointer.
                    ("ulE32Offset",     ULONG),
                    ("ulO32Offset",     ULONG),
                    ("ulLoadOffset",    ULONG)]

class file_entry(ctypes.Structure):
    """
    A structure representing a file entry.
    """
    _fields_    = [("dwFileAttributes", DWORD),
                   ("ftTime",           filetime),
                   ("nRealFileSize",    DWORD),
                   ("nCompFileSize",    DWORD),
                   ("lpszFileName",     DWORD), # Originally void*, but Python makes pointers 8 bytes
                                                # and it needs to be a 4 byte pointer.
                   ("ulLoadOffset",     ULONG)]

class copy_entry(ctypes.Structure):
    """
    A structure representing a copy entry.
    """
    _fields_    = [("ulSource",     ULONG),
                   ("ulDest",       ULONG),
                   ("ulCopyLen",    ULONG),
                   ("ulDestLen",    ULONG)]

class xipchain_entry(ctypes.Structure):
    """
    A structure representing a xipchain entry.
    """
    _fields_    = [("pvAddr",       LPVOID),
                   ("dwLength",     DWORD),
                   ("dwMaxLength",  DWORD),
                   ("usOrder",      USHORT),
                   ("usFlags",      USHORT),
                   ("dwVersion",    DWORD),
                   ("szName",       CHAR * _XIP_NAMELEN),
                   ("dwAlgoFlags",  DWORD),
                   ("dwKeyLen",     DWORD),
                   ("byPublicKey",  BYTE * 596)]

class xipchain_info(ctypes.Structure):
    """
    A structure holding information about a xipchain entry.
    """
    _fields_    = [("cXIPs",            DWORD),
                   ("xipEntryStart",    xipchain_entry)]

class rom_pid(ctypes.Structure):
    """
    A structure for holding information about extension entries.
    """
    class _rom_pid_anon_union(ctypes.Union):
        """
        Information about a rom pid sharing space with an array of DWORDs.
        """
        class _rom_pid_union_struct(ctypes.Structure):
            """
            Information about a rom pid.
            """
            _fields_    = [("name",     ctypes.c_char * (_PID_LENGTH - 4) * ctypes.sizeof(DWORD)),
                           ("type",     DWORD),
                           ("pdata",    DWORD),
                        #    ("pdata",    ctypes.c_void_p),
                           ("length",   DWORD),
                           ("reserved", DWORD)]

        _fields_    = [("dwPID",    DWORD * _PID_LENGTH),
                       ("s",        _rom_pid_union_struct)]

    _anonymous_ = ('u')
    _fields_    = [('u',        _rom_pid_anon_union),
                   ('pNextExt', DWORD)]
                #    ('pNextExt', ctypes.c_void_p)]

class image_dos_header(ctypes.Structure):
    """
    A structure representing the header of DOS images.
    """
    _fields_    = [("e_magic",      WORD),
                   ("e_cblp",       WORD),
                   ("e_cp",         WORD),
                   ("e_crlc",       WORD),
                   ("e_cparhdr",    WORD),
                   ("e_minalloc",   WORD),
                   ("e_maxalloc",   WORD),
                   ("e_ss",         WORD),
                   ("e_sp",         WORD),
                   ("e_csum",       WORD),
                   ("e_ip",         WORD),
                   ("e_cs",         WORD),
                   ("e_lfarlc",     WORD),
                   ("e_ovno",       WORD),
                   ("e_res",        WORD * 4),
                   ("e_oemid",      WORD),
                   ("e_oeminfo",    WORD),
                   ("e_res2",       WORD * 10),
                   ("e_lfanew",     LONG)]

class e32_exe(ctypes.Structure):
    """
    A structure representing a e32_exe entry.
    """
    _fields_    = [("e32_magic",        ctypes.c_ubyte * 4),
                   ("e32_cpu",          ctypes.c_ushort),
                   ("e32_objcnt",       ctypes.c_ushort),
                   ("e32_timestamp",    ctypes.c_ulong),
                   ("e32_symtaboff",    ctypes.c_ulong),
                   ("e32_symcount",     ctypes.c_ulong),
                   ("e32_opthdrsize",   ctypes.c_ushort),
                   ("e32_imageflags",   ctypes.c_ushort),
                   ("e32_coffmagic",    ctypes.c_ushort),
                   ("e32_linkmajor",    ctypes.c_ubyte),
                   ("e32_linkminor",    ctypes.c_ubyte),
                   ("e32_codesize",     ctypes.c_ulong),
                   ("e32_initdsize",    ctypes.c_ulong),
                   ("e32_uninitdsize",  ctypes.c_ulong),
                   ("e32_entryrva",     ctypes.c_ulong),
                   ("e32_codebase",     ctypes.c_ulong),
                   ("e32_database",     ctypes.c_ulong),
                   ("e32_vbase",        ctypes.c_ulong),
                   ("e32_objalign",     ctypes.c_ulong),
                   ("e32_filealign",    ctypes.c_ulong),
                   ("e32_osmajor",      ctypes.c_ushort),
                   ("e32_osminor",      ctypes.c_ushort),
                   ("e32_usermajor",    ctypes.c_ushort),
                   ("e32_userminor",    ctypes.c_ushort),
                   ("e32_subsysmajor",  ctypes.c_ushort),
                   ("e32_subsysminor",  ctypes.c_ushort),
                   ("e32_res1",         ctypes.c_ulong),
                   ("e32_vsize",        ctypes.c_ulong),
                   ("e32_hdrsize",      ctypes.c_ulong),
                   ("e32_filechksum",   ctypes.c_ulong),
                   ("e32_subsys",       ctypes.c_ushort),
                   ("e32_dllflags",     ctypes.c_ushort),
                   ("e32_stackmax",     ctypes.c_ulong),
                   ("e32_stackinit",    ctypes.c_ulong),
                   ("e32_heapmax",      ctypes.c_ulong),
                   ("e32_heapinit",     ctypes.c_ulong),
                   ("e32_res2",         ctypes.c_ulong),
                   ("e32_hdrextra",     ctypes.c_ulong),
                   ("e32_unit",         info * _STD_EXTRA)]

class o32_obj(ctypes.Structure):
    """
    A structure for representing an o32_obj entry.
    """
    _fields_    = [("o32_name",     ctypes.c_ubyte * _E32OBJNAMEBYTES),
                   ("o32_vsize",    ctypes.c_ulong),
                   ("o32_rva",      ctypes.c_ulong),
                   ("o32_psize",    ctypes.c_ulong),
                   ("o32_dataptr",  ctypes.c_ulong),
                   ("o32_realaddr", ctypes.c_ulong),
                   ("o32_access",   ctypes.c_ulong),
                   ("o32_temp3",    ctypes.c_ulong),
                   ("o32_flags",    ctypes.c_ulong)]

class B000FFHeader(ctypes.Structure):
    """
    A structure holding the header of a B000FF file.
    """
    _fields_    = [("signature",        ctypes.c_char * 7),
                   ("imgstart",         DWORD),
                   ("imglength",        DWORD),
                   ("blockstart",       DWORD),
                   ("blocklength",      DWORD),
                   ("blockchecksum",    DWORD),
                   ("data",             BYTE * 1)]

def byte_dump(start, end):
    """
    Prints out all the bytes from start to end in the current memory_map.

    Parameters:
    start (int): The starting offset
    end (int): The ending offset

    Returns:
    None
    """
    for ofs in range(start, end):
        print(" {:02x}".format(g_mem.get_byte(ofs).value), end='')

def dword_dump_as_string(start, end):
    """
    Dumps all the dwords from start to end into a string.

    Parameters:
    start (int): The starting offset
    end (int): The ending offset
    """
    s = ""

    for ofs in range(start, end & ~3, 4):
        s += " {:08x}".format(g_mem.get_dword(ofs).value)

    return s

def dword_dump(start, end):
    """
    Prints out all the dwords from start to end.

    Parameters:
    start (int): The starting offset
    end (int): The ending offset
    """
    if (start & 3) != 0:
        byte_dump(start, min(end, (start & (~3)) + 4))
        start = min(end, (start & (~3)) + 4)

    for ofs in range(start, end & (~3), 4):
        print(" {:08x}".format(g_mem.get_dword(ofs).value))

    if (end & 3) != 0:
        byte_dump(end & (~3), end)

def write_blanks(f, n_blanks):
    """
    Extends the current file by n_blanks amount of bytes from the current position.

    Parameters:
    f (file): File to extend
    n_blanks (int): Number of bytes to extend by

    Returns:
    None
    """
    f.seek(n_blanks, io.SEEK_CUR)

def write_alignment(f, page_size):
    """
    Writes blanks to the given file to fill the current page size gap.

    Parameters:
    f (file): File to write to
    page_size (int): A page size

    Returns:
    None
    """
    cur_ofs = f.tell()
    if cur_ofs % page_size != 0:
        write_blanks(f, page_size - (cur_ofs % page_size))

def write_dummy_mz_header(f):
    """
    Writes a image DOS header to the given file.

    Parameters:
    f (file): File to write to

    Returns:
    None
    """
    dos = image_dos_header()

    dos.e_magic     = _IMAGE_DOS_SIGNATURE
    dos.e_cblp      = 0x90
    dos.e_cp        = 3
    dos.e_cparhdr   = 0x4
    dos.e_maxalloc  = 0xffff
    dos.e_sp        = 0xb8
    dos.e_lfarlc    = 0x40
    dos.e_lfanew    = 0xc0

    doscode = bytes([0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
            0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
            0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
            0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

    f.write(dos)
    f.write(doscode)
    write_blanks(f, 0x40)

def find_first_segment(o32, objcnt, segtypeflag):
    """
    Finds the first o32 that matches the given segment type flags.

    Parameters:
    o32 (LP_o32_rom): A o32 pointer to o32 objects
    objcnt (int): The amount of o32 objects
    segtypeflag (int): The current flags to check

    Returns:
    int: The o32 rva of the o32 object that matches the given flag,
         otherwise 0
    """
    for i in range(objcnt):
        if (o32[i].o32_flags & segtypeflag) != 0:
            return o32[i].o32_rva
    
    return 0

def calc_segment_size_sum(o32, objcnt, segtypeflag):
    """
    Sums up all the o32 objects' vsize that match the segment type flags.

    Parameters:
    o32 (LP_o32_rom): A o32 pointer to o32 objects
    objcnt (int): The amount of o32 objects

    Returns:
    int: Sum of vsizes
    """
    size = 0
    for i in range(objcnt):
        if (o32[i].o32_flags & segtypeflag) != 0:
            size += o32[i].o32_vsize

    return size

def filetime_to_time_t(pft):
    """
    Converts filetime structure to time_t value.

    Parameters:
    pft (filetime): filetime structure
    
    Returns:
    int: time_t value
    """
    t = pft.dwHighDateTime
    t <<= 32
    t |= pft.dwLowDateTime
    t //= 10000000
    t -= 11644473600

    return t

def write_e32_header(f, rom, e32, t, o32):
    """
    Writes an e32 object to the file.

    Parameters:
    f (file): File to write to
    rom (LP_romhdr): Pointer to a romhdr structure
    e32 (LP_e32_rom): Pointer to an e32_rom structure
    t (LP_toc_entry): Pointer to a toc_entry structure
    o32 (LP_o32_rom): Pointer to an o32_rom structure

    Returns:
    None
    """
    pe32 = e32_exe()

    pe32.e32_magic[0]       = ord('P')
    pe32.e32_magic[1]       = ord('E')
    pe32.e32_cpu            = rom.contents.usCPUType
    pe32.e32_objcnt         = e32.contents.e32_objcnt
    pe32.e32_timestamp      = filetime_to_time_t(t.contents.ftTime)
    pe32.e32_symtaboff      = 0
    pe32.e32_symcount       = 0
    pe32.e32_opthdrsize     = 0xe0
    pe32.e32_imageflags     = e32.contents.e32_imageflags | _IMAGE_FILE_RELOCS_STRIPPED
    pe32.e32_coffmagic      = 0x10b
    pe32.e32_linkmajor      = 6
    pe32.e32_linkminor      = 1
    pe32.e32_codesize       = calc_segment_size_sum(o32, e32.contents.e32_objcnt, _IMAGE_SCN_CNT_CODE)
    pe32.e32_initdsize      = calc_segment_size_sum(o32, e32.contents.e32_objcnt, _IMAGE_SCN_CNT_INITIALIZED_DATA)
    pe32.e32_uninitdsize    = calc_segment_size_sum(o32, e32.contents.e32_objcnt, _IMAGE_SCN_CNT_UNINITIALIZED_DATA)
    pe32.e32_entryrva       = e32.contents.e32_entryrva
    pe32.e32_codebase       = find_first_segment(o32, e32.contents.e32_objcnt, _IMAGE_SCN_CNT_CODE)
    pe32.e32_database       = find_first_segment(o32, e32.contents.e32_objcnt, _IMAGE_SCN_CNT_INITIALIZED_DATA)
    pe32.e32_vbase          = e32.contents.e32_vbase
    pe32.e32_objalign       = 0x1000
    pe32.e32_filealign      = 0x200
    pe32.e32_osmajor        = 4
    pe32.e32_osminor        = 0
    pe32.e32_subsysmajor    = e32.contents.e32_subsysmajor
    pe32.e32_subsysminor    = e32.contents.e32_subsysminor
    pe32.e32_vsize          = e32.contents.e32_vsize
    pe32.e32_filechksum     = 0
    pe32.e32_subsys         = e32.contents.e32_subsys
    pe32.e32_stackmax       = e32.contents.e32_stackmax
    pe32.e32_stackinit      = 0x1000
    pe32.e32_heapmax        = 0x100000
    pe32.e32_heapinit       = 0x1000
    pe32.e32_hdrextra       = _STD_EXTRA

    pe32.e32_unit[_EXP]         = e32.contents.e32_unit[_EXP]
    pe32.e32_unit[_IMP]         = e32.contents.e32_unit[_IMP]
    pe32.e32_unit[_RES]         = e32.contents.e32_unit[_RES]
    pe32.e32_unit[_EXC]         = e32.contents.e32_unit[_EXC]
    pe32.e32_unit[_SEC]         = e32.contents.e32_unit[_SEC]
    pe32.e32_unit[_IMD]         = e32.contents.e32_unit[_IMD]
    pe32.e32_unit[_MSP]         = e32.contents.e32_unit[_MSP]
    pe32.e32_unit[_RS4].rva     = e32.contents.e32_sect14rva
    pe32.e32_unit[_RS4].size    = e32.contents.e32_sect14size

    f.write(pe32)

def write_o32_header(f, e32, o32):
    """
    Writes an o32 object to the file.

    Parameters:
    f (file): File to write to
    e32 (LP_e32_rom): Pointer to an e32_rom structure
    o32 (LP_o32_rom): Pointer to an o32_rom structure

    Returns:
    int: An o32_obj rva
    """
    po32 = o32_obj()

    if e32.contents.e32_unit[_RES].rva == o32.contents.o32_rva and e32.contents.e32_units[_RES].size == o32.contents.o32_vsize:
        seg_type = _ST_RSRC
    elif e32.contents.e32_unit[_EXC].rva == o32.contents.o32_rva and e32.contents.e32_unit[_EXC].size == o32.contents.o32_vsize:
        seg_type = _ST_PDATA
    elif (o32.contents.o32_flags & _IMAGE_SCN_CNT_CODE) != 0:
        seg_type = _ST_TEXT
    elif (o32.contents.o32_flags & _IMAGE_SCN_CNT_INITIALIZED_DATA) != 0:
        seg_type = _ST_DATA
    elif (o32.contents.o32_flags & _IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0:
        seg_type = _ST_PDATA
    else:
        seg_type = _ST_OTHER

    if g_segmentNameUsage[seg_type] != 0:
        po32.o32_name[:] = "{}{}".format(g_segmentNames[seg_type], g_segmentNameUsage[seg_type]).encode('ascii')[:_E32OBJNAMEBYTES].ljust(_E32OBJNAMEBYTES, '\0'.encode('ascii'))
    else:
        po32.o32_name[:] = g_segmentNames[seg_type].encode('ascii')[:_E32OBJNAMEBYTES].ljust(_E32OBJNAMEBYTES, '\0'.encode('ascii'))

    g_segmentNameUsage[seg_type] += 1

    po32.o32_vsize      = o32.contents.o32_vsize
    po32.o32_rva        = o32.contents.o32_rva if g_iswince3rom else o32.contents.o32_realaddr - e32.contents.e32_vbase
    po32.o32_psize      = 0
    po32.o32_dataptr    = 0
    po32.o32_realaddr   = 0
    po32.o32_access     = 0
    po32.o32_temp3      = 0
    po32.o32_flags      = o32.contents.o32_flags & (~_IMAGE_SCN_COMPRESSED)

    f.write(po32)

    return po32.o32_rva

def write_uncompressed_data(f, dataptr, datasize, bCompressed, maxUncompressedSize):
    """
    Uses the CEDecompress Windows library function to decompress the ROM data and write
    out its files.

    Parameters:
    f (file): File to write to
    dataptr (int): Address of an o32_rom object
    datasize (int): Size of the o32_rom object
    bCompressed (bool): Whether the contents are compressed and need to be decompressed first
    maxUncompressedSize (int): The amount of data to uncompress

    Returns:
    int: How many bytes were written
    """
    buf = ctypes.cast(g_mem.get_ptr(dataptr), ctypes.POINTER(BYTE))
    if not buf:
        return 0

    buflen = datasize
    if g_iswince3rom and datasize == maxUncompressedSize:
        # bug in wince3,  compressed flag set, while data is not compressed.
        pass
    elif bCompressed:
        dcbuf   = (BYTE * (maxUncompressedSize + 4096))()
        buflen  = cedecompress(buf, datasize, dcbuf, maxUncompressedSize, 0, 1, 4096) # CALL TO EXTERNAL LIBRARY

        if buflen != _CEDECOMPRESS_FAILED:
            buf = dcbuf
        else:
            print("error decompressing {:08x}L{:08x}", dataptr, datasize)
            buflen      = datasize
            bCompressed = False

    if type(buf) is int:
        # Converting buf from an int to an array at the given address
        buf = convert_ptr_to_array(buf, maxUncompressedSize + 4096)

    nWritten = f.write(bytes(buf[:buflen]))
    if nWritten != buflen:
        perror("fwrite")
        print("error writing uncompressed data")

    return nWritten

def uncompress_and_write(start, end, filename, regnr, bCompressed, size, realofs):
    """
    Uncompresses the current ROM and writes its entry as the given filename.

    Parameters:
    start (int): The start of the data
    end (int): The end of the data
    filename (str): The name of the file
    regnr (int): ???
    bCompressed (bool): Whether the contents are compressed and need to be decompressed first
    size (int): The file size
    realofs (int): The offset into the file

    Returns:
    None
    """
    buf = g_mem.get_ptr(start)
    if not buf:
        return

    buflen = end - start
    if g_iswince3rom and buflen == size:
        # bug in wince3,  compressed flag set, while data is not compressed.
        pass
    elif bCompressed:
        # dcbuf   = bytearray(size + 4096)
        dcbuf   = (BYTE * (size + 4096))()
        buflen  = cedecompress(buf, buflen, dcbuf, size, 0, 1, 4096) # CALL TO EXTERNAL LIBRARY

        if buflen != _CEDECOMPRESS_FAILED:
            buf = dcbuf
        else:
            print("error decompressing {}".format(filename))
            buflen      = end - start
            bCompressed = False

    if regnr < 0:
        fn = os.path.join(g_output_directory, filename)
    else:
        fn = os.path.join(g_output_directory, filename) + "-{}-{:08x}".format(regnr, realofs)

    if type(buf) is int:
        # Converting buf from an int to an array at the given address
        # buf = ctypes.cast(buf, ctypes.POINTER(BYTE * (size + 4096))).contents
        buf = convert_ptr_to_array(buf, size + 4096, new_type=BYTE)

    with open(fn, "w+b") as f:
        nWritten = f.write(bytes(buf[:buflen]))
        if nWritten != buflen:
            print("error writing {} bytes - wrote {}".format(buflen, nWritten))
            perror(fn)

def is_object_contains_section(o32, inf):
    """
    If the current o32_rom object's rva is in the given e32_unit's rva.

    Parameters:
    o32 (o32_rom): o32_rom structure
    inf (info): info structure

    Returns:
    bool: True if the rva is in range, False otherwise
    """
    return o32.o32_rva <= inf.rva and inf.rva + inf.size < o32.o32_rva + o32.o32_vsize

def create_original_file(rom, t, filename, e32, o32):
    """
    Extracts and creates a file from the given ROM.

    Parameters:
    rom (LP_romhdr): A pointer to a romhdr structure
    t (LP_toc_entry): A pointer to a toc_entry structure
    filename (str): The name to give the new file
    e32 (LP_e32_rom): A pointer to an e32_rom structure
    o32 (LP_o32_rom): A pointer to an o32_rom structure

    Returns:
    None
    """
    fn = os.path.join(g_output_directory, filename)
    with open(fn, "w+b") as f:
        write_dummy_mz_header(f)
        dwE32Ofs = f.tell()
        write_e32_header(f, rom, e32, t, o32)

        o32_ofs_list    = []
        data_ofs_list   = []
        data_len_list   = []
        rva_map         = SortedDict()

        ctypes.memset(g_segmentNameUsage, 0, ctypes.sizeof(g_segmentNameUsage))
        for i in range(e32.contents.e32_objcnt):
            o32_ofs_list.append(f.tell())
            rva = write_o32_header(f, e32, ctypes.cast(pointer_address(o32, i), ctypes.POINTER(o32_rom)))
            if rva != o32[i].o32_rva:
                print("NOTE: section at {:08x} iso {:08x} for {}".format(rva, o32[i].o32_rva, filename))

            rva_map[o32[i].o32_rva] = (rva, o32[i].o32_vsize)
        
        write_alignment(f, 0x200)

        dwHeaderSize = f.tell()

        for i in range(e32.contents.e32_objcnt):
            data_ofs_list.append(f.tell())
            data_len = write_uncompressed_data(f, 
                o32[i].o32_dataptr, min(o32[i].o32_vsize, o32[i].o32_psize), 
                (o32[i].o32_flags & _IMAGE_SCN_COMPRESSED) != 0, o32[i].o32_vsize)
            
            data_len_list.append(data_len)
            write_alignment(f, 0x200)

        dwTotalFileSize = f.tell()

        for i in range(e32.contents.e32_objcnt):
            f.seek(o32_ofs_list[i] + 16, io.SEEK_SET)
            f.write(data_len_list[i].to_bytes(ctypes.sizeof(DWORD), sys.byteorder))
            f.write(data_ofs_list[i].to_bytes(ctypes.sizeof(DWORD), sys.byteorder))

            if b_use_negative_rva and is_object_contains_section(o32[i], e32.contents.e32_unit[_IMP]):
                f.seek(data_ofs_list[i] + e32.contents.e32_unit[_IMP].rva - o32[i].o32_rva + 0x10, io.SEEK_SET)
                while True:
                    imp_addr = DWORD()
                    f.readinto(imp_addr)
                    if imp_addr.value == 0:
                        break

                    s = rva_map.bisect_right(imp_addr.value)
                    if s != 0 and s != len(rva_map):
                        s -= 1
                        key, value = rva_map.peekitem(s)
                        if imp_addr.value < key + value[1]:
                            imp_addr.value -= key - value[0]
                            f.seek(-4, io.SEEK_CUR)
                            f.write(imp_addr)
                            f.seek(0x10, io.SEEK_CUR)
                        else:
                            print("!!! {:08x} after {:08x} but not before {:08x}".format(imp_addr.value, key, key + value[1]))

        f.seek(dwE32Ofs + 0x54, io.SEEK_SET) # ofs to e32_hdrsize
        f.write(dwHeaderSize.to_bytes(ctypes.sizeof(DWORD), sys.byteorder))
        f.seek(dwTotalFileSize, io.SEEK_SET)

        # (previous) TODO: set fileattributes + datetime.

def dump_xip_chain_entry(xipnr, xip):
    """
    Documents information about a xipchain entry.

    Parameters:
    xipnr (int): Current xip_chain entry number
    xip (LP_xipchain_entry): A pointer to an xipchain_entry structure

    Returns:
    None
    """
    g_regions.mark_region(g_mem.get_ofs(ctypes.addressof(xip)), ctypes.sizeof(xipchain_entry), "xip{} : {}", xipnr, xip.szName.contents)
    g_regions.mark_region(DWORD(xip.pvAddr).value, 0, "start xip{} : {}", xipnr, xip.szName.contents)

    if g_verbose:
        g_regions.mark_region(DWORD(xip.pvAddr).value + xip.dwLength, 0, "end xip{} : {}", xipnr, xip.szName.contents)

def dump_xip_chain(dwXipOffset):
    """
    Documents information about xipchain entries.

    Parameters:
    dwXipOffset (int): Offset of the xip chain

    Returns:
    None
    """
    xipchain = ctypes.cast(g_mem.get_ptr(), ctypes.POINTER(xipchain_info))        
    if not xipchain:
        return

    if xipchain.cXIPs > _MAX_ROM:
        print("ERROR - invalid xipchain")
        return

    g_regions.mark_region(dwXipOffset, ctypes.sizeof(DWORD), "xipchain head")

    xip = ctypes.cast(ctypes.addressof(xipchain.contents.xipEntryStart), ctypes.POINTER(xipchain_entry))

    for i in range(xipchain.cXIPs):
        dump_xip_chain_entry(i, ctypes.cast(ctypes.addressof(xip[i]), ctypes.POINTER(xipchain_entry)))

def extension_already_processed(dwOffset):
    """
    Checks if the given extension has already been processed.

    Parameters:
    dwOffset (int): Offset of an extension

    Returns:
    bool: True if it has already been processed, False otherwise
    """
    return dwOffset in g_extensions_processed

def record_extension_processed(dwOffset):
    """
    Records that the given extension has been processed.

    Parameters:
    dwOffset (int): Offset of an extension

    Returns:
    None
    """
    g_extensions_processed.add(dwOffset)

def dump_extensions(dwPidOffset):
    """
    Document information about extensions.

    Parameters:
    dwPidOffset: The offset of the start of the extensions

    Returns:
    None
    """
    if extension_already_processed(dwPidOffset):
        return

    record_extension_processed(dwPidOffset)

    pid = ctypes.cast(g_mem.get_ptr(dwPidOffset), ctypes.POINTER(rom_pid))
    if not pid:
        return

    if pid.contents.pNextExt is None:
        return

    dwPidOffset = pid.contents.pNextExt
    pid = ctypes.cast(g_mem.get_ptr(dwPidOffset), ctypes.POINTER(rom_pid))
    while pid:
        g_regions.mark_region(dwPidOffset, ctypes.sizeof(rom_pid), "rom extension entry {}", pid.contents.s.name)
        g_regions.mark_region(pid.s.pdata.value, pid.s.length, "rom extension data {}", pid.contents.s.name)

        dwPidOffset = pid.contents.pNextExt
        pid = ctypes.cast(g_mem.get_ptr(dwPidOffset), ctypes.POINTER(rom_pid))

def dump_module_toc_entry(rom, modnr, ofs):
    """
    Documents information about a toc_entry.

    Parameters:
    rom (LP_romhdr): A pointer to a romhdr structure
    modnr (int): Current mod number
    ofs (int): Starting offset of the toc entries

    Returns:
    None
    """
    t = ctypes.cast(g_mem.get_ptr(ofs), ctypes.POINTER(toc_entry))
    if not t:
        print("invalid modtoc ofs {:08x}".format(ofs))
        return

    if t.contents.lpszFileName is None:
        return

    filename_ptr = g_mem.get_ptr(DWORD(t.contents.lpszFileName).value)
    if not filename_ptr:
        return

    filename = ctypes.string_at(filename_ptr).decode('ascii', 'ignore')
    if filename =='\0':
        return

    g_regions.mark_region(ofs, ctypes.sizeof(toc_entry), "modent {:3} {:08x} {:08x}{:08x} {:8} {:08x} {}",
        modnr, t.contents.dwFileAttributes, t.contents.ftTime.dwHighDateTime, t.contents.ftTime.dwLowDateTime,
        t.contents.nFileSize, t.contents.ulLoadOffset, filename)

    g_regions.mark_region(DWORD(t.contents.lpszFileName).value, len(filename) + 1, "modname {}", filename)

    e32 = ctypes.cast(g_mem.get_ptr(DWORD(t.contents.ulE32Offset).value), ctypes.POINTER(e32_rom))
    if not e32:
        return

    if b_wm2005_rom:
        print("Note: removing {:08x} from e32 struct for {}".format(ctypes.cast(e32.contents.e32_unit, ctypes.POINTER(DWORD)).contents, filename))
        ctypes.memmove(ctypes.cast(e32.contents.e32_unit, ctypes.POINTER(BYTE)), ctypes.cast(e32.contents.e32_unit, ctypes.POINTER(BYTE)) + 4, _ROM_EXTRA * ctypes.sizeof(info) + ctypes.sizeof(DWORD))

    m = g_regions.mark_region(DWORD(t.contents.ulE32Offset).value, ctypes.sizeof(e32_rom) + (4 if b_wm2005_rom else 0),
        "e32 struct {} objs, img={:04x} entrypt={:08x} base={:08x} v{}.{} tp{} {}", e32.contents.e32_objcnt,
        e32.contents.e32_imageflags, e32.contents.e32_entryrva, e32.contents.e32_vbase,
        e32.contents.e32_subsysmajor, e32.contents.e32_subsysminor, e32.contents.e32_subsys, filename)

    o32 = ctypes.cast(g_mem.get_ptr(DWORD(t.contents.ulO32Offset).value), ctypes.POINTER(o32_rom))
    if not o32:
        return

    if g_verbose:
        m.description += dword_dump_as_string(t.contents.ulE32Offset, t.contents.ulE32Offset + ctypes.sizeof(e32_rom) + (4 if b_wm2005_rom else 0))

    m = g_regions.mark_region(DWORD(t.contents.ulO32Offset).value, e32.contents.e32_objcnt * ctypes.sizeof(o32_rom),
        "o32 struct {}", filename)

    for i in range(e32.contents.e32_objcnt):
        m = g_regions.mark_region(o32[i].o32_dataptr if o32[i].o32_dataptr != 0 else ofs, min(o32[i].o32_vsize, o32[i].o32_psize),
            "o32 region_{} rva={:08x} vsize={:08x} real={:08x} psize={:08x} f={:08x} for {}", i, o32[i].o32_rva,
            o32[i].o32_vsize, o32[i].o32_realaddr, o32[i].o32_psize, o32[i].o32_flags, filename)

    if g_output_directory is not None and cedecompress is not None:
        create_original_file(rom, t, filename, e32, o32)

def dump_file_toc_entry(filenr, ofs):
    """
    Documents information about a file_entry and will attempt to extract it if needed.

    Parameters:
    filenr (int): Current file number
    ofs (int): Offset of the file_entry

    Returns:
    None
    """
    t = ctypes.cast(g_mem.get_ptr(ofs), ctypes.POINTER(file_entry))
    if not t:
        print("invalid filetoc ofs {:08x}".format(ofs))
        return

    if t.contents.lpszFileName is None:
        return

    filename_ptr = g_mem.get_ptr(DWORD(t.contents.lpszFileName).value)
    if not filename_ptr:
        return

    filename = ctypes.string_at(filename_ptr).decode('ascii', 'ignore')
    if filename =='\0':
        return

    g_regions.mark_region(ofs, ctypes.sizeof(file_entry), "filent {:3} {:08x} {:08x}{:08x} {:8} {:8} {:08x} {}",
        filenr, t.contents.dwFileAttributes, t.contents.ftTime.dwHighDateTime, t.contents.ftTime.dwLowDateTime,
        t.contents.nRealFileSize, t.contents.nCompFileSize, t.contents.ulLoadOffset, filename)

    g_regions.mark_region(DWORD(t.contents.lpszFileName).value, len(filename) + 1, "filename {}", filename)

    m = g_regions.mark_region(DWORD(t.contents.ulLoadOffset).value, t.contents.nCompFileSize, "filedata {}", filename)

    if g_output_directory is not None and cedecompress is not None:
        uncompress_and_write(m.start, m.end, filename, -1, t.contents.nCompFileSize != t.contents.nRealFileSize,
            t.contents.nRealFileSize, t.contents.ulLoadOffset)

def dump_romhdr(romnr, ofs):
    """
    Documents information about the current ROM, such as toc and file entries. Also
    extracts file information if needed.

    Paramters:
    romnr (int): Current rom number
    ofs (int): Offset of a romhdr

    Returns:
    None
    """
    r = ctypes.cast(g_mem.get_ptr(ofs), ctypes.POINTER(romhdr))
    if not r:
        print("invalid romhdr ofs {:08x}", ofs)
        return

    m = g_regions.mark_region(ofs, ctypes.sizeof(romhdr), "rom_{:02} header: dlls={:08x}-{:08x} phys={:08x}-{:08x}, {} modules, {} files, {} copyentries ext={:08x}  ram={:08x}-{:08x} cputype={:08x}",
        romnr, r.contents.dllfirst, r.contents.dlllast, r.contents.physfirst, r.contents.physlast,
        r.contents.nummods, r.contents.numfiles, r.contents.ulCopyEntries, r.contents.pExtensions,
        r.contents.ulRAMStart, r.contents.ulRAMEnd, r.contents.usCPUType)

    if g_verbose:
        m.description += dword_dump_as_string(ofs, ofs + ctypes.sizeof(romhdr))

    g_regions.mark_region(r.contents.physfirst, 0, "rom_{:02} start", romnr)
    g_regions.mark_region(r.contents.physlast, 0, "rom_{0:02} end", romnr)

    if r.contents.pExtensions != 0:
        dump_extensions(r.contents.pExtensions)

    tm = ctypes.cast(pointer_address(r, 1), ctypes.POINTER(toc_entry))
    for i in range(r.contents.nummods):
        dump_module_toc_entry(r, i, g_mem.get_ofs(pointer_address(tm, i)))

    tf = ctypes.cast(pointer_address(tm, r.contents.nummods), ctypes.POINTER(file_entry))
    for i in range(r.contents.numfiles):
        dump_file_toc_entry(i, g_mem.get_ofs(pointer_address(tf, i)))

    if r.contents.ulCopyEntries != 0:
        cp = ctypes.cast(g_mem.get_ptr(r.contents.ulCopyOffset), ctypes.POINTER(copy_entry))
        if not cp:
            return

        m = g_regions.mark_region(r.contents.ulCopyOffset, ctypes.sizeof(copy_entry) * r.contents.ulCopyEntries,
            "rom_{:02} copy to ram: ", romnr)

        for i in range(r.contents.ulCopyEntries):
            m.description += " {:08x}L{:06x} -> {:08x}L{:06x}".format(cp.contents.ulSource, cp.contents.ulCopyLen, cp.contents.ulDest, cp.contents.ulDestLen)

def find_xip_region():
    """
    ???
    """
    pos = []
    i   = g_mem.begin()
    end = g_mem.end()

    while i != end:
        if i.get_dword().value == 0x31415252:
            pos.append(i.m_ofs - 0x48)
        i += 4

    posscore    = defaultdict()
    start       = 0

    for po in pos:
        if start == 0 or po != start + 0x290:
            start = po
        
        posscore[start] += 1

    pos.sort(key=score_cmp(posscore))

    for key, value in posscore.items():
        if key % 0x1000 != 0:
            continue
        
        nxips = g_mem.get_dword(key).value

        if nxips >= value:
            return key

    return 0

def scan_rom():
    """
    Scans the current ROM file and dumps out information about it.

    Parameters:
    None

    Returns:
    None
    """
    romhdrs = set()
    romnr   = 0
    for rom_ofs in range((g_mem.first_address() + _IMGOFSINCREMENT - 1) &~ (_IMGOFSINCREMENT - 1), g_mem.last_address(), _IMGOFSINCREMENT):
        rom = ctypes.cast(g_mem.get_ptr(rom_ofs), ctypes.POINTER(DWORD))
        if not rom:
            continue

        if rom[_ROM_SIGNATURE_OFFSET // ctypes.sizeof(DWORD)] == _ROM_SIGNATURE:
            if rom[0] == 0xea0003fe:
                g_regions.mark_region(rom_ofs, 4, "JUMP to kernel start")

            if b_wm2005_rom:
                g_regions.mark_region(g_mem.get_ofs(pointer_address(rom, 16)), 12, "'ECEC' -> {:08x} {:08x}", rom[17], rom[18])
            else:
                g_regions.mark_region(g_mem.get_ofs(pointer_address(rom, 16)), 8, "'ECEC' -> {:08x}", rom[17])

            if rom[17] not in romhdrs:
                dump_romhdr(romnr, rom[17])
                romnr += 1
                romhdrs.add(rom[17])

def parse_region_spec(spec):
    """
    ???
    """
    pos_colon       = spec.find(':')
    pos_2ndcolon    = spec.find(':', pos_colon + 1)
    pos_dash        = spec.find('-')

    if pos_colon == -1 or (pos_2ndcolon == -1 and pos_dash == -1):
        return  (False, 0, 0, '')
    
    if pos_dash == -1:
        start       = int(spec[0:pos_colon])
        length      = int(spec[pos_colon+1:pos_2ndcolon - pos_colon - 1])
        description = spec[:pos_2ndcolon + 1]
        return (True, start, length, description)
    if pos_dash < pos_colon:
        start       = int(spec[0:pos_dash])
        end         = int(spec[pos_dash + 1:pos_colon - pos_dash - 1])
        length      = end - start
        description = spec[:pos_colon + 1]
        return (True, start, length, description)

    return (False, 0, 0, '')

def get_file_size(f):
    """
    Gets the size of a file.

    Parameters:
    f (file): File to grab size from

    Returns:
    int: File size
    """
    return os.path.getsize(f.name)

def is_NBF_header(hdr):
    """
    Scans the given string and determines if it is part of an NBF header.

    Parameters:
    hdr (str): A header string

    Returns:
    bool: True if the header is a NBF header, False otherwise
    """
    return hdr[10] == '-' and hdr[15] == '-' and hdr[19] == '-'

def determine_file_type(f):
    """
    Determines the file type of a ROM.

    Parameters:
    f (file): Input file

    Returns:
    tuple(bool, int, int, file_type): A tuple consisting of:
                                      1. If successfully determined file type
                                      2. File start
                                      3. File length
                                      4. File type
    """
    buf = bytearray(32)
    f.seek(0, io.SEEK_SET)
    if f.readinto(buf) != len(buf):
        perror("fread")
        return False

    header = "".join(chr(x) for x in buf)

    if header[:6] == "B000FF":
        hdr     = B000FFHeader()
        buf.write(hdr)
        _file_type  = file_type.FT_BOOOFF
        start       = 7 + 5 * 4
        length      = hdr.blocklength

        return (not (hdr.imglength != hdr.blocklength or hdr.imgstart != hdr.blockstart), start, length, _file_type)

    file_size = get_file_size(f)
    if is_NBF_header(header):
        _file_type  = file_type.FT_NBF
        start       = 0x20
        length      = file_size - start
    else:
        _file_type  = file_type.FT_BIN
        start       = 0
        length      = file_size

    return (True, start, length, _file_type)

def read_dword(f, offset):
    """
    Extract a dword at the given offset from the file.

    Parameters:
    f (file): File to read from
    offset (int): Offset into the file to start reading

    Returns:
    tuple(bool, int): A tuple consisting of:
                      1. If reading was successful
                      2. The value of the dword
    """
    f.seek(offset, io.SEEK_SET)
    dword   = DWORD()
    success = f.readinto(dword) == ctypes.sizeof(DWORD)
    return (success, dword.value)

def determine_image_offset(f):
    """
    Determines the offset of the image.

    Parameters:
    f (file): The file to read from

    Returns:
    tuple(bool, int, int): A tuple consisting of:
                           1. If determining offset was successful
                           2. Image start
                           3. Image length
    """
    success, image_start, image_length, _ = determine_file_type(f)
    if success:
        success, dword = read_dword(f, image_start + 0x40)
        if success and dword == _ROM_SIGNATURE:
            return (True, image_start, image_length)

    f.seek(0, io.SEEK_SET)
    buf         = bytearray(65536 + 4)
    buf_view    = memoryview(buf)
    ofs         = 0

    while True:
        nRead = f.readinto(buf_view[4:])
        if nRead == 0:
            break
        for p in range(nRead + 4):
            dword = int.from_bytes(buf_view[p:p+ctypes.sizeof(DWORD)], sys.byteorder)
            if dword == _ROM_SIGNATURE:
                image_start     = ofs + (p - 4) - 0x40
                image_length    = get_file_size(f) - image_start
                return (True, image_start, image_length)
        
        buf_view[0:4] = buf_view[nRead:nRead+4]
        ofs += nRead

    return (False, image_start, image_length)

def determine_load_offset(f, image_start, image_length):
    """
    Determines the load offset of the file.

    Paramters:
    f (file): File to read from
    image_start (int): Start of the image
    image_length (int): Length of the image

    Returns:
    tuple(bool, int): A tuple consisting of:
                      1. If successful in finding load offset
                      2. The load offset
    """
    _max        = -1
    max_base    = 0
    res         = False
    offset      = 0
    bases       = defaultdict(int)

    for img_ofs in range(0, image_length - _IMGOFSINCREMENT, _IMGOFSINCREMENT):
        success, sig = read_dword(f, image_start + img_ofs + 64)
        if not success:
            return (False, offset)

        if sig != _ROM_SIGNATURE:
            continue

        success, romhdr = read_dword(f, image_start + img_ofs + 68)
        if not success:
            return (False, offset)

        for img_base in range((romhdr + image_start - image_length) & (~0xfff), romhdr + image_start, 0x1000):
            success, phys_first = read_dword(f, romhdr + image_start - img_base + 8)
            if not success:
                continue

            if phys_first == img_ofs + img_base:
                print("img {:08x} : hdr={:08x} base={:08x}  commandlineoffset={:08x}".format(img_ofs, romhdr, img_base, img_base - image_start))
                bases[img_base] += 1
                if bases[img_base] > _max:
                    _max        = bases[img_base]
                    max_base    = img_base

    if _max > 0:
        offset  = max_base - image_start
        res     = True

    return (res, offset)

if __name__ == '__main__':
    g_mem                   = memory_map()
    g_regions               = mem_regions()
    g_segmentNameUsage      = (DWORD * 5)()
    g_segmentNames          = [".text", ".data", ".pdata", ".rsrc", ".other"]
    g_extensions_processed  = set()

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', metavar='dirpath', help='save found files/modules to this path')
    parser.add_argument('-v', action='store_true', help='verbose : print alignment, struct contents')
    parser.add_argument('-q', action='store_true', help="quiet : don't print anything")
    parser.add_argument('-n', action='store_false', help="don't use negative rva fix")
    parser.add_argument('-u', metavar='<ofs>L<len>:desc', action='append', default=[], help='add user defined memory regions to complete image')
    parser.add_argument('-x', metavar='<offset>', type=int, default=0, help='process XIP chain at offset')
    parser.add_argument('-i', metavar='<offset>', type=int, default=0, help='specifiy image start offset')
    parser.add_argument('-3', action='store_true', help='use wince3.x decompression')
    parser.add_argument('-4', action='store_true', help='use wince4.x decompression [ default ]')
    parser.add_argument('-5', action='store_true', help='use wince4.x decompress, and e32rom for wm2005')
    parser.add_argument('image_files', metavar='imagefile [offset]', nargs='+')

    args = parser.parse_args()

    g_output_directory  = args.d
    g_verbose           = args.v
    b_quiet             = args.q
    b_use_negative_rva  = args.n
    user_regions        = args.u
    dwXipOffset         = args.x
    image_start         = args.i
    bHaveImageStart     = args.i != 0
    cedecompress        = CEDecompress if vars(args)['3'] else CEDecompressROM
    b_wm2005_rom        = vars(args)['5']
    g_iswince3rom       = vars(args)['3']
    image_length        = 0

    image_switch = True

    if g_output_directory is not None and cedecompress is None:
        perror("Cannot decompress and extract files when not using 32-bit Python.")
        exit(1)

    for token in args.image_files:
        if image_switch:
            if os.path.exists(token):
                image_file = token
            else:
                perror("{} : No such file or directory".format(token))
                exit(1)
        else:
            try:
                load_offset = int(token)
                if not g_mem.load_file(load_offset, image_file, 0, 0):
                    exit(1)
            except ValueError:
                exit(1)

        image_switch = not image_switch

    if len(args.image_files) % 2 != 0:
        with open(image_file, 'rb') as f:
            if bHaveImageStart:
                image_length = get_file_size(f)
            else:
                success, image_start, image_length = determine_image_offset(f)
                if not success:
                    print("unable to determine image start offset")
                    exit(1)
            
            success, load_offset = determine_load_offset(f, image_start, image_length)
            if not success:
                print("unable to determine loading offset for {}".format(image_file))
                exit(1)

            if not g_mem.load_file(load_offset, image_file, 0, 0):
                exit(1)

    scan_rom()

    if dwXipOffset != 0:
        dump_xip_chain(dwXipOffset)
    
    for user_region in user_regions:
        success, start, length, description = parse_region_spec(user_region, start, length, description)

        if success:
            g_regions.mark_region(start, length, "{}", description)


    if not b_quiet:
        g_regions.dump_memory_map()
