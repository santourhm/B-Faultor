from ELFParser import ELFParser
import shutil
from pathlib import Path
import math as m
import itertools

NOPS = {
            2: b'\x00\xbf',                    
            4: b'\xaf\xf3\x00\x80'  #0xF3AF8000
        }

class FaultInjector :


    def __init__(self, elf : ELFParser):
        
        self.elf = elf
        self.dst = 'faulted'
        
    def InjectSkipInstruction(self, funName: str, N : int):
        
        src = Path(self.elf.BinaryPath)
        dst_dir = Path(self.dst)
        dst_dir.mkdir(parents=True, exist_ok=True)
        
    
        nmInst = self.elf._coutNumberOfInstruction(funName)

        if nmInst <= N : 
            raise ValueError('The number of the faults is more than the number of instructions in the given section') 

        indices = list(range(nmInst))

        func = self.elf._getFunction(funName)
        fault_sets = list(itertools.combinations(indices, N))
        for i, fault_set in enumerate(fault_sets):
            dst = dst_dir / f"{i}_{src.name}"
            shutil.copyfile(src, dst)
    
            for idx in fault_set:
                faulted_elf = ELFParser(dst)
                faulted_elf.replaceInstructionInFuncByCode(func,NOPS,idx)
            faulted_elf.close()    
    
    def BitFlipInSymbol(self, symbol : str, section : str, idx : int, bitIndex : int) :
        """
        for a symbol in a specifc section (eg, .rodata), we flip a bit  at the address 
        @symbol + idx , the index of the bit to flip is specifed at @bitIndex
        """

        symbl = self._findSymbol(symbol)

        if not symbol : 
            raise ValueError(f'{symbol} not found')
        
        """ if not symbol.entry['st_info'] 
        sec = self.elf.elffile.get_section_by_name(section) """


       


