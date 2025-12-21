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

        fault_sets = list(itertools.combinations(indices, N))
        for i, fault_set in enumerate(fault_sets):
            dst = dst_dir / f"{i}_{src.name}"
            shutil.copyfile(src, dst)
    
            for idx in fault_set:
                faulted_elf = ELFParser(dst)
                faulted_elf.replaceInstructionInFunc(funName,NOPS,idx)
            faulted_elf.close()    



       


