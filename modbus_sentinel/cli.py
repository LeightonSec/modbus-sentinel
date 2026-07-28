"""modbus-sentinel CLI.

argparse only; the dependency surface is locked at scapy + stdlib (DECISIONS.md
D3), and a plain-print CLI keeps Gate 4's terminal-sanitization story simple:
nothing emits ANSI except us, so anything escape-like in output came from a
packet and must already be hex-escaped.
"""

import argparse
import sys

from modbus_sentinel import __version__

_ETHICAL_WARNING = (
    "For authorised use only. Analyse only captures you own or have explicit\n"
    "written permission to analyse.\n"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="modbus-sentinel",
        description=(
            "State-based anomaly detector for Modbus TCP pcaps. "
            "Flags behavior inconsistent with a device's own observed baseline."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"modbus-sentinel {__version__}"
    )
    parser.add_argument("pcap", nargs="?", help="Modbus TCP pcap file to analyse")
    parser.add_argument(
        "--baseline-until",
        metavar="TIMESTAMP|PACKETS",
        help=(
            "end of the baseline period (D6: user-supplied, never auto-split); "
            "the baseline period is assumed clean"
        ),
    )
    parser.add_argument(
        "--json", action="store_true", help="machine-readable report output"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.pcap is None:
        parser.print_help()
        return 2
    print(_ETHICAL_WARNING, file=sys.stderr)
    # Gate 1 (ingestion) in progress; see DESIGN.md gate structure.
    print("modbus-sentinel: analysis pipeline not yet implemented (Gate 1 in progress).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
