from elftools.elf.elffile import ELFFile
from elftools.elf.constants import E_FLAGS, SH_FLAGS
from elftools.elf.enums import ENUM_E_TYPE, ENUM_E_MACHINE
import os


class ELFParser :

    def __init__(self, BinaryPath : str):
        
        if not os.path.isfile(BinaryPath) : 
            raise FileNotFoundError('No such a file directory')
        
        self.BinaryPath = BinaryPath
        try:
            self._file = open(BinaryPath, "rb")
            self.elffile = ELFFile(self._file)
        except Exception as e:
            raise ValueError(f"Failed to parse ELF file: {e}")
        

    def getHeader(self):
        
        h = self.elffile.header                  
        e_ident = h['e_ident']
        print(" ELF Header :")
        print(f"    File                                : {self.BinaryPath}")
        print(f"    Class                               : {e_ident['EI_CLASS']} ({'ELF32' if e_ident['EI_CLASS']=='ELFCLASS32' else 'ELF64'})")
        print(f"    Data encoding                       : {e_ident['EI_DATA']} ({'little' if e_ident['EI_DATA']=='ELFDATA2LSB' else 'big'} endian)")
        print(f"    OS/ABI                              : {e_ident['EI_OSABI']}")
        print(f"    ABI Version                         : {e_ident['EI_ABIVERSION']}")
        print(f"    Type                                : {h['e_type']}")
        print(f"    Machine                             : {h['e_machine']}")
        print(f"    Version                             : {h['e_version']}")
        print(f"    Entry point                         : {hex(h['e_entry'])}")
        print(f"    Program header off                  : {h['e_phoff']} ")
        print(f"    Section header off                  : {h['e_shoff']} ")
        print(f"    Flags                               : {h['e_flags']}")
        print(f"    Header size                         : {h['e_ehsize']} bytes")
        print(f"    Program headers size                : {h['e_phentsize']} bytes")
        print(f"    Number of program headers           : {h['e_phnum']} ")
        print(f"    Section header table entry size     : {h['e_shentsize']} bytes")
        print(f"    Section header table entry count    : {h['e_shnum']} ")
        print(f"    Section header table entry index    : {h['e_shstrndx']}")
        print(f"    Number of sections in the file      : {self.elffile.num_sections()}")

    def getSectionHeaderInformations(self, section: str):

        if not isinstance(section, str):
            raise TypeError("section name must be a string")
        
        if section[0]!='.' : section = f".{section}"

        sec = self.elffile.get_section_by_name(section)

        if sec is None:
            raise ValueError(f"Section not found: {section}")

        header = {
            "name": sec.name,
            "type": sec["sh_type"],
            "flags": sec["sh_flags"],
            "addr": sec["sh_addr"],
            "offset": sec["sh_offset"],
            "size": sec["sh_size"],
            "link": sec["sh_link"],
            "info": sec["sh_info"],
            "addralign": sec["sh_addralign"],
            "entsize": sec["sh_entsize"],
        }
        
        return header

    def _print_dic(self, dic : dict) :

        for key, value in dic.items():
            if isinstance(value, int):
                print(f"    {key:<12}    : 0x{value:x}")
            else:
                print(f"    {key:<12}    : {value}") 

    def close(self) :
        if self._file :
            self._file.close()
            self._file = None


