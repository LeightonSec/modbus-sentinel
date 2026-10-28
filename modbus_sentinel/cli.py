"""modbus-sentinel CLI (Gate 4 minimum).

argparse only; the dependency surface is locked at scapy + stdlib (DECISIONS.md
D3). Pipeline: ingest_pcap, split at --baseline-until (D6, D12), validate every
record (a malformed one is rejected, reported and skipped, so one hostile
packet cannot stop the run: B1), build_baseline, detect, report. Every line of
the text report passes through report.safe_text and packet snippets are hex
dumps, so nothing packet-derived reaches the terminal raw (DESIGN.md Gate 4).

Exit codes: 0 ran with no findings; 1 ran with at least one finding; 2 usage or
input error (bad --baseline-until, unreadable pcap, no baseline transactions).
Devices with no baseline, rejected records and parse anomalies are reported but
do not change the exit code (B2).
"""

import argparse
import sys

from scapy.error import Scapy_Exception

from modbus_sentinel import __version__
from modbus_sentinel.baseline import build_baseline, parse_until, split_records, validate_record
from modbus_sentinel.detect import detect
from modbus_sentinel.ingest import TransactionRecord, ingest_pcap
from modbus_sentinel.report import RejectedRecord, dumps_json, render_text, safe_text, to_json

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
    parser.add_argument("pcap", help="Modbus TCP pcap file to analyse")
    parser.add_argument(
        "--baseline-until",
        required=True,
        metavar="TIMESTAMP",
        help=(
            "end of the baseline period, exclusive (D6, D12): epoch seconds or ISO 8601 "
            "with an offset, e.g. 2026-07-06T08:00:00Z. The baseline period is assumed clean."
        ),
    )
    parser.add_argument(
        "--json", action="store_true", help="machine-readable report output"
    )
    return parser


def _error(message: str) -> int:
    print(f"error: {safe_text(message)}", file=sys.stderr)
    return 2


def _partition(
    records: list[TransactionRecord],
) -> tuple[list[TransactionRecord], list[RejectedRecord]]:
    """B1: malformed records are set aside and reported, never analysed."""
    kept: list[TransactionRecord] = []
    rejected: list[RejectedRecord] = []
    for r in records:
        try:
            validate_record(r)
        except ValueError as exc:
            rejected.append(
                RejectedRecord(r.request_ts, r.server_ip, r.unit_id, r.function_code, str(exc))
            )
        else:
            kept.append(r)
    return kept, rejected


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(_ETHICAL_WARNING, file=sys.stderr)
    try:
        until = parse_until(args.baseline_until)
    except ValueError as exc:
        return _error(str(exc))
    try:
        ingest = ingest_pcap(args.pcap)
    except (OSError, Scapy_Exception) as exc:
        return _error(f"cannot read {args.pcap}: {exc}")
    base_recs, det_recs = split_records(ingest.records, until)
    base_recs, rejected_base = _partition(base_recs)
    det_recs, rejected_det = _partition(det_recs)
    if not base_recs:
        return _error("no transactions before --baseline-until; nothing to learn")
    baseline = build_baseline(base_recs, until)
    detection = detect(baseline, det_recs)
    rejected = rejected_base + rejected_det
    if args.json:
        print(dumps_json(to_json(args.pcap, ingest, baseline, detection, rejected)))
    else:
        print(render_text(args.pcap, ingest, baseline, detection, rejected), end="")
    return 1 if detection.findings else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
