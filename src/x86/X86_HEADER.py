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
        pass


class PROGRAM_HEADER:
    def __init__():
        pass


class SECTION_HEADER:
    def __init__():
        pass

