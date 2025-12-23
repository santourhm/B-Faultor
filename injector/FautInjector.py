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
        
    def InjectInstructionOverAll(self, funName: str, inst : dict ,N : int):
        
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
                faulted_elf.replaceInstructionInFuncByCode(func,inst,idx)
            faulted_elf.close()    
    
    def BitFlipInSymbol(self, symbol: str, idx: int, bitIndex: int):
        """
        Flip one bit at (symbol + idx), bit position bitIndex (0..7)
        """

        symbl = self.elf._findSymbol(symbol)
        if not symbl:
            raise ValueError(f"symbol '{symbol}' not found")

        if symbl['st_info']['type'] != 'STT_OBJECT':
            raise ValueError(f"symbol '{symbol}' is not an object")

        size_sym = symbl['st_size']
        if idx < 0 or idx >= size_sym:
            raise IndexError(f"index {idx} outside symbol '{symbol}'")

        if bitIndex < 0 or bitIndex > 7:
            raise ValueError("bitIndex must be in [0, 7]")

        sec_idx = symbl['st_shndx']
        sec = self.elf.elffile.get_section(sec_idx)

        file = self.elf._file
        print(f'name :{sec['sh_name']}')
        file_offset = (
            sec['sh_offset']
            + (symbl['st_value'] - sec['sh_addr'])
            + idx
        )

        file.seek(file_offset)
        old_byte = file.read(1)
        if len(old_byte) != 1:
            raise IOError("failed to read byte")

        old_val = old_byte[0]

        new_val = old_val ^ (1 << bitIndex)
        
        file.seek(file_offset)
        file.write(bytes([new_val]))

        """file.seek(file_offset)
        data = file.read(10) 
        print(" ".join(f"{b:02x}" for b in data))"""
        print(
            f"0x{old_val:02x} -> 0x{new_val:02x} "
            f"(bit {bitIndex} flipped)"
        )




       


