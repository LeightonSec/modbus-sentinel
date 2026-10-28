"""Gate 4 minimum report: human-readable text and --json (DESIGN.md Gate 4).

What happened is kept separate from why it was flagged. Every line of the text
report passes through safe_text before it is joined, so no packet-derived
character reaches the terminal unescaped, even if a later change interpolates
packet data; packet snippets are also shown only as hex dumps. The JSON form
gets its escaping from the encoder (ensure_ascii=True, and JSON always escapes
control characters in strings), and snippets are hex strings there too.

Coverage gaps are stated, never silent: classes 3 and 4, unanswered requests,
function codes outside the supported set, unparsed streams, devices with no
baseline, and records rejected as malformed (D12, D2, D10, B1).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from modbus_sentinel.baseline import _FC_NAME, _TABLE_LABEL, Baseline, _iso, _plural
from modbus_sentinel.baseline import to_dict as baseline_to_dict
from modbus_sentinel.detect import CLASS_NAMES, DetectionResult, Finding
from modbus_sentinel.ingest import IngestResult

REPORT_SCHEMA_VERSION = 1
ANOMALY_DETAIL_CAP = 20  # B5: the text report lists the first 20; --json lists all
_NOT_IMPLEMENTED = {3: "polling-interval break", 4: "off-hours activity"}


@dataclass(frozen=True)
class RejectedRecord:
    """A record that failed validate_record: reported, not analysed (B1)."""

    request_ts: float
    server_ip: str
    unit_id: int
    function_code: int
    reason: str


def hexdump(b: bytes) -> str:
    """Packet bytes as spaced hex, never decoded as text."""
    return b.hex(" ") if b else "(none)"


def safe_text(s: str) -> str:
    """Printable ASCII passes; a backslash is doubled so escapes stay
    unambiguous; every other character becomes \\xNN, \\uNNNN or \\UNNNNNNNN."""
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif 0x20 <= o <= 0x7E:
            out.append(ch)
        elif o <= 0xFF:
            out.append(f"\\x{o:02x}")
        elif o <= 0xFFFF:
            out.append(f"\\u{o:04x}")
        else:
            out.append(f"\\U{o:08x}")
    return "".join(out)


def _ts(ts: float | None) -> str:
    """ISO 8601 UTC with milliseconds (B9); never raises."""
    if ts is None:
        return "unknown time"
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return f"epoch {ts}"
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _fcs(fcs: Iterable[int]) -> str:
    return ", ".join(f"{fc:02d}" for fc in fcs) or "none"


def _addresses(start: int, end: int) -> str:
    return str(start) if start == end else f"{start}-{end}"


def coverage_gaps(ingest: IngestResult, detection: DetectionResult) -> list[str]:
    counts = ingest.anomaly_counts()
    not_implemented = ", ".join(
        f"{c} ({_NOT_IMPLEMENTED[c]})" for c in detection.classes_not_implemented
    )
    unparsed = counts.get("unattributed_stream", 0) + counts.get("direction_conflict", 0)
    return [
        f"classes not implemented: {not_implemented}",
        "unanswered or superseded requests are not analysed: "
        f"{counts.get('orphan_request', 0)} orphan requests counted",
        "function codes outside the supported set (including FC 08 and FC 43) are counted, "
        f"not attributed to a device: {counts.get('unknown_function_code', 0)}",
        f"streams not parsed (direction unknown or conflicting): {unparsed}",
    ]


def _what(f: Finding) -> str:
    w = f.what
    text = (
        f"{_ts(w.request_ts)} {w.server_ip} unit {w.unit_id} FC {w.function_code:02d} "
        f"{_FC_NAME[w.function_code]}, {_TABLE_LABEL[w.table]} "
        f"{_addresses(w.start_address, w.end_address)}"
    )
    if w.value is not None:
        text += f", value {w.value}"
    if w.exception_code is not None:
        text += f", device answered with exception code {w.exception_code}"
    return text


def render_text(
    path: str,
    ingest: IngestResult,
    baseline: Baseline,
    detection: DetectionResult,
    rejected: Sequence[RejectedRecord] = (),
) -> str:
    lines = [
        "modbus-sentinel report",
        f"  pcap: {path}",
        "  clock: capture clock, UTC (not device clock). Addresses are 0-based wire addresses.",
        f"  baseline period: transactions requested before {_iso(baseline.until)}; "
        "assumed clean, so anything in it is learned as normal.",
        "  wording: findings are anomalous, not attack; each class is a heuristic, not proof of malice.",
        "",
        "ingest",
        f"  packets: {ingest.packets_total} ({ingest.packets_non_tcp} non-TCP), "
        f"paired transactions: {len(ingest.records)}",
        f"  retransmissions deduplicated: {ingest.retransmitted_segments} segments, "
        f"{ingest.retransmitted_bytes} bytes",
    ]
    counts = ingest.anomaly_counts()
    if not counts:
        lines.append("  parse and pairing anomalies: none")
    else:
        lines.append(f"  parse and pairing anomalies: {len(ingest.anomalies)}")
        lines.extend(f"    {kind}: {n}" for kind, n in sorted(counts.items()))
        shown = ingest.anomalies[:ANOMALY_DETAIL_CAP]
        lines.append(f"  listed: first {len(shown)} of {len(ingest.anomalies)}")
        for a in shown:
            lines.append(
                f"    - {_ts(a.timestamp)} {a.kind} on {a.stream}: {a.detail}; "
                f"bytes: {hexdump(a.snippet)}"
            )
        if len(ingest.anomalies) > len(shown):
            lines.append(f"    and {len(ingest.anomalies) - len(shown)} more (all are in --json)")
    lines += [
        "",
        "baseline",
        f"  {_plural(baseline.transactions, 'transaction')} in the baseline period, "
        f"{_plural(len(baseline.devices), 'device')} (full baseline in --json)",
    ]
    for d in baseline.devices:
        lines.append(
            f"  device {d.server_ip} unit {d.unit_id}: {_plural(d.transactions, 'transaction')}, "
            f"{_plural(d.exceptions, 'exception response')}, function codes {_fcs(d.function_codes)}"
        )
    lines += [
        "",
        "detection",
        "  classes run: " + ", ".join(f"{c} {CLASS_NAMES[c]}" for c in detection.classes_run),
        f"  transactions analysed: {detection.records_analysed}",
    ]
    if not detection.records_analysed:
        lines.append("  no transactions after --baseline-until; nothing analysed")
    lines.append(f"  findings: {len(detection.findings) or 'none'}")
    for i, f in enumerate(detection.findings, start=1):
        lines += ["", f"  finding {i} of {len(detection.findings)}", f"    what happened: {_what(f)}"]
        lines.extend(
            f"    why flagged:   class {r.anomaly_class} {r.name}: {r.explanation}" for r in f.why
        )
    if detection.unbaselined:
        lines += ["", "not analysed: no baseline for these devices"]
        for u in detection.unbaselined:
            lines.append(
                f"  device {u.server_ip} unit {u.unit_id}: {_plural(u.transactions, 'transaction')} "
                f"({_plural(u.writes, 'write')}), function codes {_fcs(u.function_codes)}, "
                f"seen {_ts(u.first_ts)} to {_ts(u.last_ts)}"
            )
    if rejected:
        lines += ["", "rejected: malformed, not analysed"]
        for r in rejected:
            lines.append(
                f"  {_ts(r.request_ts)} {r.server_ip} unit {r.unit_id} FC {r.function_code:02d}: {r.reason}"
            )
    lines += ["", "coverage gaps"]
    lines.extend(f"  {g}" for g in coverage_gaps(ingest, detection))
    return "\n".join(safe_text(line) for line in lines) + "\n"


def to_json(
    path: str,
    ingest: IngestResult,
    baseline: Baseline,
    detection: DetectionResult,
    rejected: Sequence[RejectedRecord] = (),
) -> dict:
    """Everything in the text report, uncapped, plus the full baseline."""
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "pcap": path,
        "notes": {
            "clock": "capture clock, UTC (not device clock)",
            "addresses": "0-based wire addresses",
            "baseline": "assumed clean; anything in it is learned as normal",
            "wording": "anomalous, not attack; each class is a heuristic, not proof of malice",
        },
        "ingest": {
            "packets_total": ingest.packets_total,
            "packets_non_tcp": ingest.packets_non_tcp,
            "transactions": len(ingest.records),
            "retransmitted_segments": ingest.retransmitted_segments,
            "retransmitted_bytes": ingest.retransmitted_bytes,
            "anomaly_counts": ingest.anomaly_counts(),
            "anomalies": [
                {
                    "kind": a.kind,
                    "detail": a.detail,
                    "stream": a.stream,
                    "timestamp": a.timestamp,
                    "snippet_hex": a.snippet.hex(),
                }
                for a in ingest.anomalies
            ],
        },
        "baseline": baseline_to_dict(baseline),
        "detection": {
            "until": detection.until,
            "records_analysed": detection.records_analysed,
            "classes_run": list(detection.classes_run),
            "classes_not_implemented": list(detection.classes_not_implemented),
            "findings": [
                {"what": asdict(f.what), "why": [asdict(r) for r in f.why]}
                for f in detection.findings
            ],
            "unbaselined": [asdict(u) for u in detection.unbaselined],
        },
        "rejected": [asdict(r) for r in rejected],
        "coverage_gaps": coverage_gaps(ingest, detection),
    }


def dumps_json(report: dict) -> str:
    """ensure_ascii escapes non-ASCII; JSON escapes control characters (R4)."""
    return json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2)
