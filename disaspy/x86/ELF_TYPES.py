import sys
# project
from disaspy.x86.Utils import *

"""
class p_type_e:
    PT_NULL = 0x0
    PT_LOAD = 0x1
    PT_DYNAMIC = 0x2
    PT_INTERP = 0x3
    PT_NOTE = 0x4
    PT_SHLIB = 0x5
    PT_PHDR = 0x6
    PT_LOOS = 0x60000000
    PT_HIOS = 0x6FFFFFFF
    PT_LOPROC = 0x70000000
    PT_HIPROC = 0x7FFFFFFF
    GNU_EH_FRAME = 0x6474e550
    GNU_STACK = 0x6474e551
    GNU_RELRO = 0x6474e552
"""
class p_type:
    PT_NULL = 0
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_NOTE = 4
    PT_SHLIB = 5
    PT_PHDR = 6
    PT_TLS = 7
    PT_NUM = 8
    PT_LOOS = 0x60000000
    PT_GNU_EH_FRAME = 0x6474E550
    PT_GNU_STACK = 0x6474E551
    PT_GNU_RELRO = 0x6474E552
    PT_LOSUNW = 0x6FFFFFFA
    PT_SUNWBSS = 0x6FFFFFFA
    PT_SUNWSTACK = 0x6FFFFFFB
    PT_HISUNW = 0x6FFFFFFF
    PT_HIOS = 0x6FFFFFFF
    PT_LOPROC = 0x70000000
    PT_HIPROC = 0x7FFFFFFF
    PT_ARM_EXIDX = PT_LOPROC + 1

# This function and class is directly taken from 
## github.com/terminaldweller/delf
## These were further looked into for behavior using
## The elf manpages and the glibc source code
class PH_DYN_TAG_TYPE:
    DT_NULL  = 0
    DT_NEEDED  = 1
    DT_PLTRELSZ = 2
    DT_PLTGOT  = 3
    DT_HASH  = 4
    DT_STRTAB  = 5
    DT_SYMTAB  = 6
    DT_RELA  = 7
    DT_RELASZ  = 8
    DT_RELAENT  = 9
    DT_STRSZ  = 10
    DT_SYMENT  = 11
    DT_INIT = 12
    DT_FINI = 13
    DT_SONAME = 14
    DT_RPATH = 15
    DT_SYMBOLIC = 16
    DT_REL = 17
    DT_RELSZ = 18
    DT_RELENT = 19
    DT_PLTREL = 20
    DT_DEBUG = 21
    DT_TEXTREL = 22
    DT_JMPREL = 23
    DT_LOPROC = 0x70000000
    DT_HIPROC = 0x7FFFFFFF
    DT_BIND_NOW = 24
    DT_INIT_ARRAY = 25
    DT_FINI_ARRAY = 26
    DT_INIT_ARRAYSZ = 27
    DT_FINI_ARRAYSZ = 28
    DT_RUNPATH = 29
    DT_FLAGS = 30
    DT_ENCODING = 32
    DT_PREINIT_ARRAY = 32
    DT_PREINIT_ARRAYSZ = 33
    DT_NUM = 34
    DT_LOOS = 0x6000000d
    DT_HIOS = 0x6ffff000
    DT_PROC_NUM = 0x0
    DT_MIPS_NUM = 0x0
    DT_VALRNGLO = 0x6ffffd00
    DT_GNU_PRELINKED = 0x6ffffdf5
    DT_GNU_CONFLICTSZ = 0x6ffffdf6
    DT_GNU_LIBLISTSZ  = 0x6ffffdf7
    DT_CHECKSUM = 0x6ffffdf8
    DT_PLTPADSZ = 0x6ffffdf9
    DT_MOVEENT = 0x6ffffdfa
    DT_MOVESZ = 0x6ffffdfb
    DT_FEATURE_1 = 0x6ffffdfc
    DT_POSFLAG_1 = 0x6ffffdfd
    DT_SYMINSZ = 0x6ffffdfe
    DT_SYMINENT = 0x6ffffdff
    DT_VALRNGHI = 0x6ffffdff
    DT_VALNUM  = 12
    DT_ADDRRNGLO = 0x6ffffe00
    DT_GNU_HASH = 0x6ffffef5
    DT_TLSDESC_PLT = 0x6ffffef6
    DT_TLSDESC_GOT = 0x6ffffef7
    DT_GNU_CONFLICT = 0x6ffffef8
    DT_GNU_LIBLIST = 0x6ffffef9
    DT_CONFIG = 0x6ffffefa
    DT_DEPAUDIT = 0x6ffffefb
    DT_AUDIT = 0x6ffffefc
    DT_PLTPAD = 0x6ffffefd
    DT_MOVETAB = 0x6ffffefe
    DT_SYMINFO = 0x6ffffeff
    DT_ADDRRNGHI = 0x6ffffeff
    DT_ADDRNUM = 11
    DT_VERSYM = 0x6ffffff0
    DT_RELACOUNT = 0x6ffffff9
    DT_RELCOUNT = 0x6ffffffa
    DT_FLAGS_1 = 0x6ffffffb
    DT_VERDEF = 0x6ffffffc
    DT_VERDEFNUM = 0x6ffffffd
    DT_VERNEED = 0x6ffffffe
    DT_VERNEEDNUM = 0x6fffffff
    DT_VERSIONTAGNUM = 16
    DT_AUXILIARY = 0x7ffffffd
    DT_FILTER = 0x7fffffff
    DT_EXTRANUM = 3

def get_program_header_dynamic_entries_d_tag_type(value):
    if value == PH_DYN_TAG_TYPE.DT_NULL: return "DT_NULL"
    elif value == PH_DYN_TAG_TYPE.DT_NEEDED: return "DT_NEEDED"
    elif value == PH_DYN_TAG_TYPE.DT_PLTRELSZ: return "DT_PLTRELSZ"
    elif value == PH_DYN_TAG_TYPE.DT_PLTGOT: return "DT_PLTGOT"
    elif value == PH_DYN_TAG_TYPE.DT_HASH: return "DT_HASH"
    elif value == PH_DYN_TAG_TYPE.DT_STRTAB: return "DT_STRTAB"
    elif value == PH_DYN_TAG_TYPE.DT_SYMTAB: return "DT_SYMTAB"
    elif value == PH_DYN_TAG_TYPE.DT_RELA: return "DT_RELA"
    elif value == PH_DYN_TAG_TYPE.DT_RELASZ: return "DT_RELASZ"
    elif value == PH_DYN_TAG_TYPE.DT_RELAENT: return "DT_RELAENT"
    elif value == PH_DYN_TAG_TYPE.DT_STRSZ: return "DT_STRSZ"
    elif value == PH_DYN_TAG_TYPE.DT_SYMENT: return "DT_SYMENT"
    elif value == PH_DYN_TAG_TYPE.DT_INIT: return "DT_INIT"
    elif value == PH_DYN_TAG_TYPE.DT_FINI: return "DT_FINI"
    elif value == PH_DYN_TAG_TYPE.DT_SONAME: return "DT_SONAME"
    elif value == PH_DYN_TAG_TYPE.DT_RPATH: return "DT_RPATH"
    elif value == PH_DYN_TAG_TYPE.DT_SYMBOLIC: return "DT_SYMBOLIC"
    elif value == PH_DYN_TAG_TYPE.DT_REL: return "DT_REL"
    elif value == PH_DYN_TAG_TYPE.DT_RELSZ: return "DT_RELSZ"
    elif value == PH_DYN_TAG_TYPE.DT_RELENT: return "DT_RELENT"
    elif value == PH_DYN_TAG_TYPE.DT_PLTREL: return "DT_PLTREL"
    elif value == PH_DYN_TAG_TYPE.DT_DEBUG: return "DT_DEBUG"
    elif value == PH_DYN_TAG_TYPE.DT_TEXTREL: return "DT_TEXTREL"
    elif value == PH_DYN_TAG_TYPE.DT_JMPREL: return "DT_JMPREL"
    elif value == PH_DYN_TAG_TYPE.DT_LOPROC: return "DT_LOPROC"
    elif value == PH_DYN_TAG_TYPE.DT_HIPROC: return "DT_HIPROC"
    elif value == PH_DYN_TAG_TYPE.DT_BIND_NOW: return "DT_BIND_NOW"
    elif value == PH_DYN_TAG_TYPE.DT_INIT_ARRAY: return "DT_INIT_ARRAY"
    elif value == PH_DYN_TAG_TYPE.DT_FINI_ARRAY: return "DT_FINI_ARRAY"
    elif value == PH_DYN_TAG_TYPE.DT_INIT_ARRAYSZ: return "DT_INIT_ARRAYSZ"
    elif value == PH_DYN_TAG_TYPE.DT_FINI_ARRAYSZ: return "DT_FINI_ARRAYSZ"
    elif value == PH_DYN_TAG_TYPE.DT_RUNPATH: return "DT_RUNPATH"
    elif value == PH_DYN_TAG_TYPE.DT_FLAGS: return "DT_FLAGS"
    elif value == PH_DYN_TAG_TYPE.DT_ENCODING: return "DT_ENCODING"
    elif value == PH_DYN_TAG_TYPE.DT_PREINIT_ARRAY: return "DT_PREINIT_ARRAY"
    elif value == PH_DYN_TAG_TYPE.DT_PREINIT_ARRAYSZ: return "DT_PREINIT_ARRAYSZ"
    elif value == PH_DYN_TAG_TYPE.DT_NUM: return "DT_NUM"
    elif value == PH_DYN_TAG_TYPE.DT_LOOS: return "DT_LOOS"
    elif value == PH_DYN_TAG_TYPE.DT_HIOS: return "DT_HIOS"
    #elif value == PH_DYN_TAG_TYPE.DT_PROC_NUM: return "DT_PROC_NUM"
    #elif value == PH_DYN_TAG_TYPE.DT_MIPS_NUM: return "DT_MIPS_NUM"
    elif value == PH_DYN_TAG_TYPE.DT_VALRNGLO: return "DT_VALRNGLO"
    elif value == PH_DYN_TAG_TYPE.DT_GNU_PRELINKED: return "DT_GNU_PRELINKED"
    elif value == PH_DYN_TAG_TYPE.DT_GNU_CONFLICTSZ: return "DT_GNU_CONFLICTSZ"
    elif value == PH_DYN_TAG_TYPE.DT_GNU_LIBLISTSZ: return "DT_GNU_LIBLISTSZ"
    elif value == PH_DYN_TAG_TYPE.DT_CHECKSUM: return "DT_CHECKSUM"
    elif value == PH_DYN_TAG_TYPE.DT_PLTPADSZ: return "DT_PLTPADSZ"
    elif value == PH_DYN_TAG_TYPE.DT_MOVEENT: return "DT_MOVEENT"
    elif value == PH_DYN_TAG_TYPE.DT_MOVESZ: return "DT_MOVESZ"
    elif value == PH_DYN_TAG_TYPE.DT_FEATURE_1: return "DT_FEATURE_1"
    elif value == PH_DYN_TAG_TYPE.DT_POSFLAG_1: return "DT_POSFLAG_1"
    elif value == PH_DYN_TAG_TYPE.DT_SYMINSZ: return "DT_SYMINSZ"
    elif value == PH_DYN_TAG_TYPE.DT_SYMINENT: return "DT_SYMINENT"
    elif value == PH_DYN_TAG_TYPE.DT_VALRNGHI: return "DT_VALRNGHI"
    #DT_VALNUM  = 12
    elif value == PH_DYN_TAG_TYPE.DT_ADDRRNGLO: return "DT_ADDRRNGLO"
    elif value == PH_DYN_TAG_TYPE.DT_GNU_HASH: return "DT_GNU_HASH"
    elif value == PH_DYN_TAG_TYPE.DT_TLSDESC_PLT: return "DT_TLSDESC_PLT"
    elif value == PH_DYN_TAG_TYPE.DT_TLSDESC_GOT: return "DT_TLSDESC_GOT"
    elif value == PH_DYN_TAG_TYPE.DT_GNU_CONFLICT: return "DT_GNU_CONFLICT"
    elif value == PH_DYN_TAG_TYPE.DT_GNU_LIBLIST: return "DT_GNU_LIBLIST"
    elif value == PH_DYN_TAG_TYPE.DT_CONFIG: return "DT_CONFIG"
    elif value == PH_DYN_TAG_TYPE.DT_DEPAUDIT: return "DT_DEPAUDIT"
    elif value == PH_DYN_TAG_TYPE.DT_AUDIT: return "DT_AUDIT"
    elif value == PH_DYN_TAG_TYPE.DT_PLTPAD: return "DT_PLTPAD"
    elif value == PH_DYN_TAG_TYPE.DT_MOVETAB: return "DT_MOVETAB"
    elif value == PH_DYN_TAG_TYPE.DT_SYMINFO: return "DT_SYMINFO"
    elif value == PH_DYN_TAG_TYPE.DT_ADDRRNGHI: return "DT_ADDRRNGHI"
    #DT_ADDRNUM = 11
    elif value == PH_DYN_TAG_TYPE.DT_VERSYM: return "DT_VERSYM"
    elif value == PH_DYN_TAG_TYPE.DT_RELACOUNT: return "DT_RELACOUNT"
    elif value == PH_DYN_TAG_TYPE.DT_RELCOUNT: return "DT_RELCOUNT"
    elif value == PH_DYN_TAG_TYPE.DT_FLAGS_1: return "DT_FLAGS_1"
    elif value == PH_DYN_TAG_TYPE.DT_VERDEF: return "DT_VERDEF"
    elif value == PH_DYN_TAG_TYPE.DT_VERDEFNUM: return "DT_VERDEFNUM"
    elif value == PH_DYN_TAG_TYPE.DT_VERNEED: return "DT_VERNEED"
    elif value == PH_DYN_TAG_TYPE.DT_VERNEEDNUM: return "DT_VERNEEDNUM"
    elif value == PH_DYN_TAG_TYPE.DT_VERSIONTAGNUM: return "DT_VERSIONTAGNUM"
    elif value == PH_DYN_TAG_TYPE.DT_AUXILIARY: return "DT_AUXILIARY"
    elif value == PH_DYN_TAG_TYPE.DT_FILTER: return "DT_FILTER"
    #DT_EXTRANUM = 3
    else: return str(value)

class program_header_dynamic_entry:
    def __init__(self, d_tag, d_un):
        self.d_tag = d_tag
        self.d_un = d_un
