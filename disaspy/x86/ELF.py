import code
import signal
import sys
# project
from disaspy.x86.Utils import *
from disaspy.x86.X86_HEADER import *
from disaspy.x86.ELF_TYPES import *

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
       
        self.pop_data_section()
        self.pop_text_section()
        # Debug stuff
        # print(str(self.text_section.hex()))
        # print(type(self.text_section))
        # print("Got here")
        # input()
        # end Debug stuff
        self.get_program_header_dynamic_entries()
        self.pop_dynamic_entries(".dynamic", 
                self.dyn_section_entries)
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
        if size == 32:
            self.header.e_entry = self.obj.read(4)
            self.header.e_phoff = self.obj.read(4)
            self.header.e_shoff = self.obj.read(4)
        elif size == 64:
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
        if size == 32:
            tmp.offset = self.obj.read(4)
            tmp.p_vaddr = self.obj.read(4)
            tmp.p_paddr = self.obj.read(4)
            tmp.p_filesz = self.obj.read(4)
            tmp.p_memsz = self.obj.read(4)
            tmp.p_flags32 = self.obj.read(4)
            tmp.p_align = self.obj.read(4)
        elif size == 64:
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
        tmp.sh_type = self.obj.read(4)
        if size == 32:
            tmp.sh_flags = self.obj.read(4)
            tmp.sh_addr = self.obj.read(4)
            tmp.sh_offset = self.obj.read(4)
            tmp.sh_size = self.obj.read(4)
            tmp.sh_link = self.obj.read(4)
            tmp.sh_info = self.obj.read(4)
            tmp.sh_addralign = self.obj.read(4)
            tmp.sh_entsize = self.obj.read(4)
        elif size == 64:
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
        tmp.st_info = symtab[4:5]
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
        strs = self.obj.read(byte2int(
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
                self.obj.seek(byte2int(section.sh_offset))
                self.text_section = self.obj.read(byte2int(section.sh_size))

    def get_program_header_dynamic_entries(self):
        size = 0
        for program_header in self.program_header:
            if byte2int(program_header.p_type) == p_type.PT_DYNAMIC:
                self.obj.seek(byte2int(program_header.p_offset), 0)
                size = byte2int(program_header.p_filesz)
                program_header_dyn = self.obj.read(size)
        for i in range(int(size/8)):
             d_tag = byte2int(program_header_dyn[8*i:8*i+4])
             d_un = byte2int(program_header_dyn[8*i + 4 : 8*i + 8])
             self.ph_dyn_entries.append(program_header_dynamic_entry(d_tag, d_un))


    def pop_dynamic_entries(self, section_name, pop_target):
        for section in self.section_header:
            name = self.read_section_name(byte2int(section.sh_name))
            if name == section_name:
                self.obj.seek(byte2int(section.sh_offset))
                self.dyn_section = self.obj.read(byte2int(section.sh_size))
        sec_length = int(len(self.dyn_section))
        tmp = {}
        if self.size == 64: 
            jump_value = 8
        elif self.size == 32:
            jump_value = 4
        else:
            jump_value = 8
            print("self.size is not 32/64. Setting default jump value to 8")
        for offset in range(0, sec_length, jump_value*2):
            d_tag_type = byte2int(self.dyn_section[offset:offset+jump_value])
            tmp["dtag"] = d_tag_type
            value = byte2int(self.dyn_section[offset+jump_value:offset+2*jump_value])
            tmp["value"] = value
            tag_type_str = get_program_header_dynamic_entries_d_tag_type(d_tag_type)
            tmp["tag_type_str"] = tag_type_str
            # tag_type_str = ""
            pop_target.append(tmp)
            # tmp = {}

    def pop_rela(self, section_name, section_content, pop_target):
        size = int()
        entsize = int()
        tmp = {}
        step = int()
        if self.size == 64:
            step = 8
        elif self.size == 32:
            step = 4
        for section in self.section_header:
            name = self.read_section_name(byte2int(section.sh_name))
            if name == section_name:
                self.obj.seek(byte2int(section.sh_offset))
                section_content = self.obj.read(byte2int(section.sh_size))
                size = byte2int(section.sh_size)
                entsize = byte2int(section.sh_entsize)
        if entsize != 0:
            for i in range(0, int(size/entsize)):
                tmp["r_offset"] = byte2int(section_content[i*entsize:i*entsize+step])
                tmp["r_info"] = byte2int(section_content[i*entsize+step:i*entsize+(step*2)])
                tmp["r_append"] = byte2int(section_content[i*entsize+(step*2):i*entsize+(step*3)], sign=True)
                pop_target.append(tmp)
                tmp = {}


