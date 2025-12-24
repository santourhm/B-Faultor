import argparse
from ELFParser import ELFParser
from FautInjector import FaultInjector

NOPS = {
    2: b'\x00\xbf',
    4: b'\xaf\xf3\x00\x80'
}

def main():
    parser = argparse.ArgumentParser(
        description="ELF fault injection tool"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Inspect ELF structures"
    )

    inspect_parser.add_argument(
        "binary",
        type=str,
        help="Path to the ELF binary"
    )

    inspect_parser.add_argument(
        "--header",
        action="store_true",
        help="Print ELF header"
    )


    bitflip_parser = subparsers.add_parser(
        "bitflip",
        help="bitflip"
    )

    bitflip_parser.add_argument(
        "binary",
        type=str,
        help="Path to the ELF binary"
    )

    bitflip_parser.add_argument(
        "--symbol",
        required=True,
        help="Target symbol name"
    )


    bitflip_parser.add_argument(
        "--idx",
        type=int,
        required=True,
        help="Byte index inside the symbol"
    )

    bitflip_parser.add_argument(
        "--bit",
        type=int,
        required=True,
        help="Bit index to flip (0–7)"
    )


    nop_parser = subparsers.add_parser(
        "nop",
        help="nop opcode injection"
    )

    nop_parser.add_argument(
        "binary",
        type=str,
        help="Path to the ELF binary"
    )

    nop_parser.add_argument(
        "--func",
        required=True,
        help="name of the function to fault (see , --symbol list)"
    )

    nop_parser.add_argument(
        "--N",
        type=int,
        required=True,
        help="Number of injected faults (NB ; N < N_Of_Instructions)"
    )


    args = parser.parse_args()
    elf_parser = None

    try:
        elf_parser = ELFParser(args.binary)

        if args.command == "inspect":
            if args.header:
                elf_parser.getHeader()

        elif args.command == "bitflip":
            injector = FaultInjector(elf_parser)
            if args.symbol  != None and args.bit != None and args.idx  != None : 
                injector.BitFlipInSymbol(
                    symbol=args.symbol,
                    idx=args.idx,
                    bitIndex=args.bit
                )
        elif args.command == 'nop'   : 
             injector = FaultInjector(elf_parser)
             if args.func!=None  and args.N !=None: 
                injector.InjectInstructionOverAll(
                    funName=args.func,
                    inst=NOPS,
                    N=args.N
                    )
                
    except Exception as e:
        print(f"[!] Error: {e}")

    finally:
        if elf_parser:
            elf_parser.close()

if __name__ == "__main__":
    main()
