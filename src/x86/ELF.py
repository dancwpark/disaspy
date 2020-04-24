from capstone import *
from capstone.x86 import *
import code
import signal
import sys
# project
import utils
import X86_HEADER


class ELF(object):
    def __init__(self, obj):
        """
        obj: path to:
                      Executable
                      Shared Object
                      Object
             to be loaded.
        obj: Should have been opened with utils.openObj_r(path)
        """
        self.obj = obj
        # Seek to beginning
        self.obj.seek(0, 0)
        self.header = X86_HEADER.FILE_HEADER(0,0,0,0,0,0,
                                             0,0,0,0,0,0,
                                             0,0,0,0,0,0,
                                             0,0)
        self.program_header = []
        self.section_header = []
        self.size = int()
