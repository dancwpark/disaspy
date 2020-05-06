#!/usr/bin/python3

import code
import signal
import capstone
from disaspy.x86.ELF import ELF
from disaspy.x86.Utils import *

def main():
    binary = 'tests/elf/hello'
    print(ELF)
    elf = ELF(openObj_r(binary))
    elf.initialize(64) # maybe have this be part of the ELF?



if __name__ == "__main__":
    main()
