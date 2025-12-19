import argparse
from ELFParser import ELFParser

def main():
    parser = argparse.ArgumentParser(
        description="Simple ELF parser for fault injection experiments"
    )

    parser.add_argument(
        "binary",
        type=str,
        help="Path to the ELF binary"
    )


    parser.add_argument(
        "header",
        type=str,
        help="Header of the binary file"
    )

    # Optional argument example (future feature)
    parser.add_argument(
        "--bit-flip",
        type=int,
        default=0,
        help="Number of bits to flip (default: 0)"
    )

    args = parser.parse_args()

    try:
        elf_parser = ELFParser(args.binary)
        if args.header :
            elf_parser.getHeader()
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
