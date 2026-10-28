"""Gate 4 report tests: text and JSON (DESIGN.md Gate 4, B5 to B9).

Fixtures are hand-built (IngestResult, records through the real baseline and
detect code) so hostile bytes can be placed exactly where a packet could put
them. The sanitisation tests are the DESIGN.md Gate 4 requirement: packet
bytes never reach the terminal raw.
"""

import json

from pcap_builder import SERVER
from record_builder import rec

from modbus_sentinel.baseline import build_baseline, to_dict
from modbus_sentinel.detect import detect
from modbus_sentinel.ingest import IngestAnomaly, IngestResult
from modbus_sentinel.report import (
    ANOMALY_DETAIL_CAP,
    RejectedRecord,
    dumps_json,
    hexdump,
    render_text,
    safe_text,
    to_json,
)

T0 = 1783324800.0  # 2026-07-06T08:00:00Z
UNTIL = T0 + 120  # 2026-07-06T08:02:00Z
AT = T0 + 150.3  # 2026-07-06T08:02:30.300Z
PATH = "capture.pcap"
OTHER_IP = "192.168.1.21"
STREAM = "192.168.1.10:49152<->192.168.1.20:502"


def base_records():
    """Unit 1: holding read 100-109, holding written 40; FC set {03, 06}."""
    return [rec(T0, fc=3, start=100, qty=10), rec(T0 + 1, fc=6, start=40)]


def anomaly(kind="malformed_pdu", detail="fc 3 request with 2 data bytes (want 4)", stream=STREAM,
            ts=T0 + 5, snippet=b"\x03\x00"):
    return IngestAnomaly(kind=kind, detail=detail, stream=stream, timestamp=ts, snippet=snippet)


def build(anomalies=(), det=(), base=None):
    base = base_records() if base is None else base
    b = build_baseline(base, UNTIL)
    d = detect(b, list(det))
    ingest = IngestResult(
        records=list(base) + list(det),
        anomalies=list(anomalies),
        packets_total=100,
        packets_non_tcp=1,
        retransmitted_segments=2,
        retransmitted_bytes=24,
    )
    return ingest, b, d


def render(anomalies=(), det=(), base=None, rejected=(), path=PATH) -> str:
    ingest, b, d = build(anomalies, det, base)
    return render_text(path, ingest, b, d, rejected)


def report_json(anomalies=(), det=(), base=None, rejected=()) -> str:
    ingest, b, d = build(anomalies, det, base)
    return dumps_json(to_json(PATH, ingest, b, d, rejected))


def test_header_states_clock_baseline_and_wording() -> None:
    out = render()
    assert "capture clock, UTC (not device clock)" in out
    assert "0-based wire addresses" in out
    assert "transactions requested before 2026-07-06T08:02:00Z" in out
    assert "assumed clean" in out
    assert "anomalous, not attack" in out
    assert "pcap: capture.pcap" in out


def test_what_happened_separate_from_why() -> None:
    out = render(det=[rec(AT, fc=6, start=105)])
    lines = out.splitlines()
    (what,) = [ln for ln in lines if ln.startswith("    what happened:")]
    whys = [ln for ln in lines if ln.startswith("    why flagged:")]
    assert "2026-07-06T08:02:30.300Z 192.168.1.20 unit 1 FC 06 write single register" in what
    assert "holding registers 105" in what
    assert "anomalous" not in what  # facts only
    assert len(whys) == 1
    assert "class 1 unscheduled write: anomalous" in whys[0]
    assert "  findings: 1" in out


def test_snippet_ansi_and_control_bytes_hex_escaped() -> None:
    out = render(anomalies=[anomaly(snippet=b"\x1b[31mX\x07\x00\x9b")])
    assert "bytes: 1b 5b 33 31 6d 58 07 00 9b" in out
    for raw in ("\x1b", "\x07", "\x00", "\x9b"):
        assert raw not in out


def test_detail_stream_and_path_escaped_at_sink() -> None:
    out = render(anomalies=[anomaly(detail="a\x1b[2Jb", stream="x\rY")], path="cap\x1b.pcap")
    assert r"a\x1b[2Jb" in out
    assert r"x\x0dY" in out
    assert r"pcap: cap\x1b.pcap" in out
    assert "\x1b" not in out and "\r" not in out


def test_every_output_char_printable_ascii() -> None:
    out = render(
        anomalies=[anomaly(detail="\x1b]0;title\x07", stream="s\x00", snippet=bytes(range(256))[:16])],
        det=[rec(AT, fc=6, start=105), rec(AT + 1, fc=16, start=900, qty=2, exc=2), rec(AT + 2, ip=OTHER_IP)],
        rejected=[RejectedRecord(AT + 3, SERVER, 1, 3, "address range \x1b 65530-65539")],
        path="p" + chr(0xE9) + chr(0x1F600) + ".pcap",
    )
    assert all(0x20 <= ord(c) <= 0x7E or c == "\n" for c in out)


def test_backslash_doubled_so_escapes_are_unambiguous() -> None:
    out = render(anomalies=[anomaly(detail="\\x1b")])  # a literal backslash, not ESC
    assert r"\\x1b" in out


def test_coverage_gaps_stated() -> None:
    anomalies = [
        anomaly(kind="orphan_request"),
        anomaly(kind="orphan_request"),
        anomaly(kind="unknown_function_code"),
        anomaly(kind="unattributed_stream"),
        anomaly(kind="direction_conflict"),
    ]
    out = render(anomalies=anomalies)
    assert "classes not implemented: 3 (polling-interval break), 4 (off-hours activity)" in out
    assert "unanswered or superseded requests are not analysed: 2 orphan requests counted" in out
    assert "(including FC 08 and FC 43) are counted, not attributed to a device: 1" in out
    assert "streams not parsed (direction unknown or conflicting): 2" in out


def test_unbaselined_device_listed_not_analysed() -> None:
    out = render(det=[rec(AT, ip=OTHER_IP)])
    assert "not analysed: no baseline for these devices" in out
    assert "device 192.168.1.21 unit 1: 1 transaction (0 writes), function codes 03" in out
    assert "  findings: none" in out


def test_no_findings_says_so() -> None:
    out = render(det=[rec(AT, fc=6, start=40)])  # holding 40 was written in baseline
    assert "  findings: none" in out
    assert "finding 1" not in out


def test_empty_detection_period_stated() -> None:
    out = render(det=[])
    assert "  transactions analysed: 0" in out
    assert "no transactions after --baseline-until; nothing analysed" in out


def test_anomaly_listing_capped_counts_complete() -> None:
    out = render(anomalies=[anomaly() for _ in range(25)])
    assert "  parse and pairing anomalies: 25" in out
    assert "    malformed_pdu: 25" in out
    assert f"  listed: first {ANOMALY_DETAIL_CAP} of 25" in out
    assert sum(1 for ln in out.splitlines() if ln.startswith("    - ")) == ANOMALY_DETAIL_CAP
    assert "    and 5 more (all are in --json)" in out


def test_no_anomalies_says_none() -> None:
    assert "  parse and pairing anomalies: none" in render()


def test_rejected_records_section() -> None:
    reason = "192.168.1.20 unit 1 FC 03: address range 65530-65539 exceeds 65535 (malformed Modbus address)"
    out = render(rejected=[RejectedRecord(AT, SERVER, 1, 3, reason)])
    assert "rejected: malformed, not analysed" in out
    assert "2026-07-06T08:02:30.300Z 192.168.1.20 unit 1 FC 03: " + reason in out


def test_what_happened_range_and_exception() -> None:
    out = render(det=[rec(AT, fc=16, start=100, qty=4, exc=2)])
    (what,) = [ln for ln in out.splitlines() if ln.startswith("    what happened:")]
    assert "holding registers 100-103" in what
    assert "device answered with exception code 2" in what


def test_baseline_device_line_with_no_function_codes() -> None:
    out = render(base=[rec(T0, fc=1, start=0, qty=8, exc=1)])
    assert "device 192.168.1.20 unit 1: 1 transaction, 1 exception response, function codes none" in out


def test_anomaly_time_unknown_and_out_of_range() -> None:
    out = render(anomalies=[anomaly(ts=None), anomaly(ts=1e12)])
    assert "    - unknown time malformed_pdu" in out
    assert "    - epoch 1000000000000.0 malformed_pdu" in out


def test_json_parses_and_has_sections() -> None:
    data = json.loads(report_json(det=[rec(AT, fc=6, start=105)]))
    assert set(data) == {
        "schema_version", "pcap", "notes", "ingest", "baseline", "detection", "rejected", "coverage_gaps",
    }
    assert data["schema_version"] == 1
    assert data["notes"]["wording"].startswith("anomalous, not attack")
    (f,) = data["detection"]["findings"]
    assert f["what"]["start_address"] == 105
    assert [r["anomaly_class"] for r in f["why"]] == [1]
    assert data["detection"]["classes_not_implemented"] == [3, 4]


def test_json_baseline_equals_to_dict() -> None:
    ingest, b, d = build()
    data = json.loads(dumps_json(to_json(PATH, ingest, b, d)))
    assert data["baseline"] == json.loads(json.dumps(to_dict(b)))


def test_json_escapes_control_chars() -> None:
    raw = report_json(anomalies=[anomaly(detail="a\x1bb", snippet=b"\x1b[")])
    assert "\x1b" not in raw
    assert "a\\u001bb" in raw
    data = json.loads(raw)
    assert data["ingest"]["anomalies"][0]["snippet_hex"] == "1b5b"
    assert data["ingest"]["anomalies"][0]["detail"] == "a\x1bb"  # lossless after decoding


def test_json_lists_all_anomalies_uncapped() -> None:
    data = json.loads(report_json(anomalies=[anomaly() for _ in range(25)]))
    assert len(data["ingest"]["anomalies"]) == 25
    assert data["ingest"]["anomaly_counts"] == {"malformed_pdu": 25}


def test_json_rejected_and_unbaselined() -> None:
    data = json.loads(
        report_json(
            det=[rec(AT, ip=OTHER_IP)],
            rejected=[RejectedRecord(AT, SERVER, 1, 3, "address range 65530-65539")],
        )
    )
    assert data["rejected"][0]["reason"] == "address range 65530-65539"
    assert data["detection"]["unbaselined"][0]["server_ip"] == OTHER_IP


def test_hexdump_and_safe_text_units() -> None:
    assert hexdump(b"") == "(none)"
    assert hexdump(b"\x00\xff") == "00 ff"
    assert safe_text("plain ASCII 123 !~") == "plain ASCII 123 !~"
    assert safe_text("\x7f") == "\\x7f"
    assert safe_text(chr(0xE9)) == "\\xe9"
    assert safe_text(chr(0x2014)) == "\\u2014"
    assert safe_text(chr(0x1F600)) == "\\U0001f600"
    assert safe_text("\\") == "\\\\"
