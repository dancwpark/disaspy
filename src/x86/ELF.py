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
        self.string_tb_e = []
        self.string_tb_e_dyn = []
        self.symbol_table_e = []
        self.data_section = []
        self.text_section = []
        self.dlpath = str()
        self.ph_dyn_ent = []
        self.dyn_section = []
        self.dyn_section_ends = []
        self.rela_dyn = []
        self.rela_dyn_ents = []
        self.rela_plt = []
        self.rela_plt_ents = []
        self.rodata = []
        self.plt = []
        self.got = []
        self.got_plt = []
        self.plt_got = []
        self.plt_ents = []
        self.plt_got_ents = []
        self.got_ents = []
        self.got_plt_ents = []

    def initialize(self, size):
        assert type(size) is int
        self.size = size
        self.read_header(size)
        # Get program header offset to load program header
        self.obj.seek(utils.byte2int(self.header.e_phoff))
        #phnum = utils.byte2int(self.header.e_phnum)
        for i in range(0, (utils.byte2int(self.header.e_phnum)):
            self.read_program_header(size)
        pass


    def read_header(self, size):
        """ 
        Parse the header from the file: self.obj
        """
        assert type(size) is int
        self.header.ei_mag = self.obj.read(4)
        self.header.ei_class = self.obj.read(1)
        self.header.ei_data = self.obj.read(1)
        self.header.ei_version = self.obj.read(1)
        self.header.ei_osabi = self.obj.read(1)
        self.header.ei_abiversion = self.obj.read(1)
        self.header.ei_pad = self.obj.read(7)
        self.header.e_type = self.obj.read(2)
        self.header.e_machine = self.obj.read(2)
        self.header.e_version = self.obj.read(4)
        # e_entry, e_phoff, e_shoff depend on size: 32 vs 64
        if size is 32:
            self.header.e_entry = self.obj.read(4)
            self.header.e_phoff = self.obj.read(4)
            self.header.e_shoff = self.obj.read(4)
        elif size is 64:
            self.header.e_entry = self.obj.read(8)
            self.header.e_phoff = self.obj.read(8)
            self.header.e_shoff = self.obj.read(8)
        self.header.e_flags = self.obj.read(4)
        self.header.e_ehsize = self.obj.read(2)
        self.header.e_phentsize = self.obj.read(2)
        self.header.e_phnum = self.obj.read(2)
        self.header.e_shentsize = self.obj.read(2)
        self.header.e_shnum = self.obj.read(2)
        self.header.e_shstrndx = self.obj.read(2)


    def read_program_header(self, size):
        pass
