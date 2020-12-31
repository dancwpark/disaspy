#!/usr/bin/python3

import code
import signal
import capstone
from disaspy.x86.ELF import ELF
from disaspy.x86.Utils import *
from disaspy.x86.ELF_TYPES import *
from disaspy.x86.X86_HEADER import *

def main():
    print("disassembling 'tests/elf/hello':.text")
    binary = 'tests/elf/hello'
    print(ELF)
    elf = ELF(openObj_r(binary))
    elf.initialize(64) # maybe have this be part of the ELF?
                       # Can put openObj_r and initialize into ELF.init 
    # Time to disass
    for section in elf.section_header:
        name = elf.read_section_name(byte2int(section.sh_name))
        if name == '.text':
            if byte2int(section.sh_flags) & 0x4 != 0x04:
                print("ERROR!")
                break
            elf.obj.seek(byte2int(section.sh_offset))
            code = elf.obj.read(byte2int(section.sh_size))
            # capstone stuff
            capstone_obj = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            for i in capstone_obj.disasm(bytes(code), 0x0):
                print(hex(i.address).ljust(7), i.mnemonic.ljust(7), i.op_str)

    print()
    print('---------------------------------------------------------')
    print("You can check the correctness using objdump!")
    print("Ubuntu: objdump -M intel -d tests/elf/hello")
    print("MacOS: objdump -x86-asm-syntax=intel -d tests/elf/hello")
    print('---------------------------------------------------------')
    print("You might want to use `less`")


if __name__ == "__main__":
    main()
