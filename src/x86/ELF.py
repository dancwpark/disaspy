from capstone import *
from capstone.x86 import *
import code
import signal
import sys
# project
import utils



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
        self.header
