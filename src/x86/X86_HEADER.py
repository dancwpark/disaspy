from capstone import *
from capstone.x86 import *
import code
import signal
import sys

class FILE_HEADER:
    def __init__(self, ei_mag, ei_class, ei_data, 
                 ei_version, ei_osabi, ei_abiversion,
                 ei_pad, e_type, e_machine, e_version,
                 e_entry, e_phoff, e_shoff, e_flags,
                 e_ehsize, e_phentsize, e_phnum,
                 e_shentsize, e_shnum, e_shstrndx)
        """
        Arguments are fields of the ELF header.
        Read more at: 
                   https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
        """
        self.ei_mag = ei_mag
        self.ei_class = ei_class
        self.ei_data = ei_data
        self.ei_version = ei_version
        self.ei_osabi = ei_osabi
        self.ei_abiversion = ei_abiversion
        self.ei_pad = ei_pad
        self.e_type = e_type
        self.e_machine = e_machine
        self.e_version = e_version
        self.e_entry = e_entry
        self.e_phoff = e_phoff
        self.e_shoff = e_shoff
        self.e_flags = e_flags
        self.e_ehsize = e_ehsize
        self.e_phentsize = e_phentsize
        self.e_phnum = e_phnum
        self.e_shentsize = e_shentsize
        self.e_shnum = e_shnum
        self.e_shstrndx = e_shstrndx


class PROGRAM_HEADER:
    def __init__(self, p_type, p_flags64, p_offset,
                 p_vaddr, p_paddr, p_filesz,
                 p_memsz, p_flags32, p_align):
        self.p_type = p_type
        self.p_flags64 = p_flags64
        self.p_offset = p_offest
        self.p_vaddr = p_vaddr
        self.p_paddr = p_paddr
        self.p_filesz = p_filesz
        self.p_memsz = p_memsz
        self.p_flags32 = p_flags32
        self.p_align = p_align


class SECTION_HEADER:
    def __init__(self, sh_name, sh_type, sh_flags,
                 sh_addr, sh_offset, sh_size,
                 sh_link, sh_info, sh_addralign,
                 sh_entsize):
        self.sh_name = sh_name
        self.sh_type = sh_type
        self.sh_flags = sh_flags
        self.sh_addr = sh_addr
        self.sh_offset = sh_offset
        self.sh_size = sh_size
        self.sh_link = sh_link
        self.sh_info = sh_info
        self.sh_addralign = sh_addralign
        self.sh_entsize = sh_entsize

