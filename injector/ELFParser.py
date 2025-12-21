from elftools.elf.elffile import ELFFile
from elftools.elf.elffile import Section
from elftools.elf.constants import E_FLAGS, SH_FLAGS
from elftools.elf.enums import ENUM_E_TYPE, ENUM_E_MACHINE
from capstone import *
import os

STT_FUNC = 'STT_FUNC'

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

        """
        gets the header section information for a given @section 
        """

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


    def _findFunction(self,functionName) :

        """
        makes sure that a given function name exits 

        """
        symtab = self.elffile.get_section_by_name('.symtab')
        
        if symtab is None :
            raise ModuleNotFoundError(' .symtab section not found')
        
    
        for symbol in symtab.iter_symbols():
            name = symbol.name 

            if name == functionName and symbol.entry['st_info']['type'] == STT_FUNC:
                return symbol

        return None

    def getFunctionInformation(self, functionName : str) -> dict : 
        
        """
        list the informations about a given function like the virtual address and the name of bytes
        of the function
        """
        symbol = self._findFunction(functionName)

        if not  symbol :
            raise ModuleNotFoundError(f'"{functionName}" does not exists ') 
                
        infos = {
                "SectionIndx" : symbol['st_shndx'],
                "SymbolAddr" : symbol['st_value'],
                "SizeBytes"      : symbol['st_size']
        }
        
        return infos 

    def _getFunction(self, functionName) -> dict :
        
        """return the dic centaining bytes of a given name function, vritual address and actual address of the function"""

        text_sec= self.getSectionHeaderInformations('.text')
        functionInfo = self.getFunctionInformation(functionName)

        text_addr_in_file = text_sec["offset"] - 1
        text_size = text_sec["size"]
        text_addr_vrt = text_sec["addr"]
        function_vrt_addr = functionInfo['SymbolAddr']
        function_size = functionInfo["SizeBytes"]
        function_addr_in_file =  text_addr_in_file + (function_vrt_addr - text_addr_vrt)

        if function_addr_in_file < text_addr_in_file or  function_addr_in_file >  text_size + text_addr_in_file  :
            raise ValueError(f"Function '{functionName}' not found or is not a function symbol")

        self._file.seek(function_addr_in_file)

        final = {
                'code' : self._file.read(function_size),    # code of the function in row bytes
                'faddr' : function_addr_in_file,            # address of the function in the file
                'vaddr' : function_vrt_addr                 # virtual address of the function 
        }

        return final
    
    def _disasm_function(self, functionName: str):
        """
        disassemble a Thumb function from Cortex-M ELF.
        """
        code_bytes = self._getFunction(functionName)
        func_info = self.getFunctionInformation(functionName)
        vaddr = func_info['SymbolAddr']        
        size = func_info['SizeBytes']

        if vaddr == 0:
            raise ValueError(f"{functionName} has address 0 ")

        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_V8)
        md.detail = False

        print(f"\n{'='*60}")
        print(f"{functionName} @ 0x{vaddr:08x}  ({size} bytes)")
        print(f"{'Address':<10} {'Bytes':<12} {'Instruction':<30}")
        print('-' * 60)

        consumed = 0
        for inst in md.disasm(code_bytes, vaddr):
            bytes_hex = " ".join(f"{b:02x}" for b in inst.bytes)
            print(f"0x{inst.address:08x}:  {bytes_hex:<12}  {inst.mnemonic} {inst.op_str}")
            consumed += inst.size

        if consumed < len(code_bytes):
            print(f"[!] {len(code_bytes) - consumed} trailing bytes (padding?):")
            tail = code_bytes[consumed:]
            hex_tail = tail.hex()
            for i in range(0, len(hex_tail), 32):
                print(" " * 20 + hex_tail[i:i+32])
        
    def _coutNumberOfInstruction(self, funcName :str ) :

        func = self._getFunction(funcName)
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_V8)
        md.detail = False
        nmInst =  0
        for _ in md.disasm(func['code'], func['vaddr']):
            nmInst+=1
        
        return nmInst

    def replaceInstructionInFunc(self, functionName: str, replacement: dict, index ):
        """
        for a given dict {size : instruction} we try to inject the instruction at @index in the given function
        we raise an error at any failure  
        """
        func = self._getFunction(functionName)
        code_bytes = func['code']
        paddr = func['faddr']
        vaddr = func['vaddr']

        if vaddr == 0:
            raise ValueError(f"{functionName} has address 0 ")

        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_V8)
        md.detail = False

        if self._file.closed or 'b+' not in self._file.mode:
                self._file.close()
                self._file = open(self.BinaryPath, 'rb+')
        
        current_index = 0
        current_byte_offset = 0
        for inst in md.disasm(code_bytes, vaddr):
            if current_index == index:   
                repl_inst = replacement[inst.size]
                if repl_inst is None : 
                    raise ValueError(f"No replacement defined for {inst.size}-byte instruction")
                if len(repl_inst) != inst.size:
                    raise ValueError(f"Replacement size mismatch: need {inst.size}, got {len(repl_inst)}")
        

                self._file.seek(paddr + current_byte_offset)
                self._file.write(repl_inst)
                self._file.flush()
                self._file.seek(0)
                return True
            current_index+=1
            current_byte_offset+= inst.size

        raise IndexError(f"Instruction index {index} out of range in {functionName}")

    def close(self) :
        if self._file :
            self._file.close()
            self._file = None


