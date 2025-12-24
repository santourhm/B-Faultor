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

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("binary")
    inspect.add_argument("--header", action="store_true")

    bitflip = subparsers.add_parser("bitflip")
    bitflip.add_argument("binary")
    bitflip.add_argument("--symbol", required=True)
    bitflip.add_argument("--idx", type=int, required=True)
    bitflip.add_argument("--bit", type=int, required=True)

    nop = subparsers.add_parser("nop")
    nop.add_argument("binary")
    nop.add_argument("--func", required=True)

    nop_sub = nop.add_subparsers(dest="mode", required=True)

    nop_all = nop_sub.add_parser("all")
    nop_all.add_argument(
        "--N",
        type=int,
        required=True,
        help="Number of instructions to replace by NOP"
    )

    nop_at = nop_sub.add_parser("at")
    nop_at.add_argument(
        "--index",
        type=int,
        required=True,
        help="Instruction index to replace by NOP"
    )

    args = parser.parse_args()
    elf_parser = None

    try:
        elf_parser = ELFParser(args.binary)
        injector = FaultInjector(elf_parser)

        if args.command == "inspect":
            if args.header:
                elf_parser.getHeader()

        elif args.command == "bitflip":
            injector.BitFlipInSymbol(
                args.symbol,
                args.idx,
                args.bit
            )

        elif args.command == "nop":
            if args.mode == "all":
                injector.InjectInstructionOverAll(
                    funName=args.func,
                    inst=NOPS,
                    N=args.N
                )
            elif args.mode == "at":
                injector.InjectInstructionAtIndex(
                    args.func,
                    NOPS,
                    args.index
                )

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        if elf_parser :
            elf_parser.close()

if __name__ == "__main__":
    main()
