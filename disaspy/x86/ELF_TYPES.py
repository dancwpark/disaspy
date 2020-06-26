from capstone import *
from capstone.x86 import *
import code
import signal
import sys
# project
from disaspy.x86.Utils import *
from disaspy.x86.X86_HEADER import *

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

class program_header_dynamic_entry:
    def __init__(self, d_tag, d_un):
        self.d_tag = d_tag;
        self.d_un = d_un