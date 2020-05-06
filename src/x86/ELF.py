from capstone import *
from capstone.x86 import *
import code
import signal
import sys
# project
from utils import *
from X86_HEADER import *

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
        self.header = FILE_HEADER(0,0,0,0,0,0,
                                             0,0,0,0,0,0,
                                             0,0,0,0,0,0,
                                             0,0)
        self.program_header = []
        self.section_header = []
        self.size = int()
        self.string_tb = []
        self.string_tb_dyn = []
        self.symbol_table = []
        self.data_section = []
        self.text_section = []
        self.dlpath = str()
        self.ph_dyn_entries = []
        self.dyn_section = []
        self.dyn_section_entries = []
        self.rela_dyn = []
        self.rela_dyn_entries = []
        self.rela_plt = []
        self.rela_plt_entries = []
        self.rodata = []
        self.plt = []
        self.got = []
        self.got_plt = []
        self.plt_got = []
        self.plt_ents = []
        self.plt_got_entries = []
        self.got_ents = []
        self.got_plt_entries = []

    def initialize(self, size):
        assert type(size) is int
        self.size = size
        self.read_header(size)
        
        # Read in program header
        self.obj.seek(byte2int(self.header.e_phoff))
        #phnum = utils.byte2int(self.header.e_phnum)
        for i in range(0, (byte2int(self.header.e_phnum))):
            self.read_program_header(size)

        # Read in section header
        self.obj.seek(byte2int(self.header.e_shoff))
        #shnum = utils.byte2int(self.header.e_shoff)
        shnum = byte2int(self.header.e_shnum)
        for i in range(0, shnum):
            self.read_section_header(size)

            s_type = byte2int(self.section_header[i].sh_type)
            if s_type is SH_TYPE.SHT_SYMTAB:
                self.obj.seek(byte2int(
                    self.section_header[i].sh_offset), 0)
                symbol_tbl = self.obj.read(
                        byte2int(self.section_header[i].sh_size))
                offset = 0
                for j in range (0, (int(
                    byte2int(self.section_header[i].sh_size) / 24))):
                    self.read_symtab_entry(symbol_tbl[offset:offset+24],
                        self.string_tb)
                    offset += 24
            elif s_type is SH_TYPE.SHT_DYNSYM:
                self.obj.seek(byte2int(
                    self.section_header[i].sh_offset), 0)
                symbol_tbl = self.obj.read(
                        byte2int(self.section_header[i].sh_size))
                offset = 0
                for j in range(0, (int(
                    byte2int(self.section_header[i].sh_size) / 24))):
                    self.read_symtab_entry(symbol_tbl[offset:offset+24],
                            self.string_tb_dyn)
                    offset += 24
        pass
       
        self.pop_data_section()
        # TODO: the below funcs need to be written
        self.pop_text_section()
        self.get_program_header_dynamic_entries(".dynamic", 
                self.dynamic_section_entries)
        self.pop_rela(".rela.plt", self.rela_plt, self.rela_plt_entries)
        self.pop_rela(".rela.dyn", self.rela_dyn, self.rela_dyn_entries)



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
        tmp = PROGRAM_HEADER(0,0,0,0,0,0,0,0,0)
        tmp.p_type = self.obj.read(4)
        if size is 32:
            tmp.offset = self.obj.read(4)
            tmp.p_vaddr = self.obj.read(4)
            tmp.p_paddr = self.obj.read(4)
            tmp.p_filesz = self.obj.read(4)
            tmp.p_memsz = self.obj.read(4)
            tmp.p_flags32 = self.obj.read(4)
            tmp.p_align = self.obj.read(4)
        elif size is 64:
            tmp.p_flags = self.obj.read(4)
            tmp.p_offset = self.obj.read(8)
            tmp.p_vaddr = self.obj.read(8)
            tmp.p_paddr = self.obj.read(8)
            tmp.p_filesz = self.obj.read(8)
            tmp.p_memsz = self.obj.read(8)
            tmp.p_align = self.obj.read(8)
        self.program_header.append(tmp)


    def read_section_header(self, size):
        tmp = SECTION_HEADER(0,0,0,0,0,0,0,0,0,0)
        tmp.sh_name = self.obj.read(4)
        tmpl.sh_type = self.obj.read(4)
        if size is 32:
            tmp.sh_flags = self.obj.read(4)
            tmp.sh_addr = self.obj.read(4)
            tmp.sh_offset = self.obj.read(4)
            tmp.sh_size = self.obj.read(4)
            tmp.sh_link = self.obj.read(4)
            tmp.sh_info = self.obj.read(4)
            tmp.sh_addralign = self.obj.read(4)
            tmp.sh_entsize = self.obj.read(4)
        elif size is 64:
            tmp.sh_flags = self.obj.read(8)
            tmp.sh_addr = self.obj.read(8)
            tmp.sh_offset = self.obj.read(8)
            tmp.sh_size = self.obj.read(8)
            tmp.sh_link = self.obj.read(4)
            tmp.sh_info = self.obj.read(4)
            tmp.sh_addralign = self.obj.read(8)
            tmp.sh_entsize = self.obj.read(8)
        self.section_header.append(tmp)

    def read_symtab_entry(self, symtab, entries):
        tmp = SYMTAB_ENTRY64(0,0,0,0,0,0,0,0)
        tmp.st_name = symtab[0:4]
        tmp.st_info = symtabl[4:5]
        tmp.st_other = symtab[5:6]
        tmp.st_shndx = symtab[6:8]
        tmp.st_value = symtab[8:16]
        tmp.st_size = symtab[16:24]
        tmp.st_bind = byte2int(tmp.st_info) >> 4
        tmp.st_type = byte2int(tmp.st_info) & 0x0f

    def read_section_name(self, index):
        shstrtab_ndx = byte2int(self.header.e_shstrndx)
        name = ""
        self.obj.seek(byte2int(self.section_header[shstrtab_ndx].sh_offset),
                0)
        strs = self.obj.readd(byte2int(
            self.section_header[shstrtab_ndx].sh_size))
        c = strs[index]
        while chr(c) != '\0':
            index += 1
            name += chr(c)
            c = strs[index]
        return name

    def pop_data_section(self):
        for section in self.section_header:
            name = self.read_section_name(byte2int(section.sh_name))
            if name == '.data':
                self.obj.seek(byte2int(section.sh_offset))
                self.data_section = self.obj.read(byte2int(section.sh_name))



    def pop_text_section(self):
        for section in self.section_header:
            name = self.read_section_name(byte2int(section.sh_name))
            if name == '.text':
                self.obj.seek(byte2int(section.sh_offsett))
                self.text_section = self.obj.read(byte2int(section.sh_size))




