"""Gate 3 detection tests, first cut: classes 1, 2 and 5 (D7, D12).

The Gate 3 pass criteria run on synthetic pcaps through the real ingest_pcap:
one generator (family_pcap) builds a baseline period and a detection period
with the same devices, rates and timing, so the clean pcap and every injected
variant come from the same capture family (DESIGN.md Gate 3). Hand-built
records cover the exact address and class rules.
"""

import random
from pathlib import Path

import pytest
from family_builder import T0, UNTIL, Event, family_events, fc08, fc43_req, fc43_resp
from pcap_builder import (
    SERVER,
    Conn,
    exc_resp,
    read_req,
    read_resp,
    write_multi_req,
    write_multi_resp,
    write_single_req,
)
from record_builder import rec
from scapy.utils import wrpcap

from modbus_sentinel.baseline import COILS, HOLDING, build_baseline, split_records
from modbus_sentinel.detect import (
    CLASSES_NOT_IMPLEMENTED,
    CLASSES_RUN,
    DetectionResult,
    detect,
)
from modbus_sentinel.ingest import IngestResult, ingest_pcap

OTHER_IP = "192.168.1.21"


def family_pcap(tmp_path: Path, inject: list[Event] | None = None) -> IngestResult:
    events = sorted(family_events() + (inject or []), key=lambda e: e[0])
    c = Conn(t0=T0 - 1)
    for tid, (t, req, resp) in enumerate(events, start=1):
        c.send(req(tid), at=t)
        if resp is not None:
            c.recv(resp(tid), at=t + 0.05)
    path = tmp_path / "family.pcap"
    wrpcap(str(path), c.pkts)
    return ingest_pcap(str(path))


def run_family(tmp_path: Path, inject: list[Event] | None = None) -> tuple[IngestResult, DetectionResult]:
    result = family_pcap(tmp_path, inject)
    base_recs, det_recs = split_records(result.records, UNTIL)
    return result, detect(build_baseline(base_recs, UNTIL), det_recs)


def small_baseline():
    """Unit 1: holding read 100-109, holding written 40 and 300-301, coils read
    0-15, coil 3 and coils 500-501 written. FC set {01, 03, 05, 06, 15, 16}."""
    return build_baseline(
        [
            rec(T0, fc=3, start=100, qty=10),
            rec(T0 + 1, fc=6, start=40),
            rec(T0 + 2, fc=1, start=0, qty=16),
            rec(T0 + 3, fc=5, start=3),
            rec(T0 + 4, fc=16, start=300, qty=2),
            rec(T0 + 5, fc=15, start=500, qty=2),
        ],
        UNTIL,
    )


AT = UNTIL + 10  # a detection-period time for hand-built records


# --- Gate 3 pass criteria (DESIGN.md Gate 3) ----------------------------------------


def test_gate3_injected_unscheduled_write_flagged(tmp_path: Path) -> None:
    """DESIGN.md: "on a synthetic pcap with an injected unscheduled write, the
    tool flags it"."""
    inject = [(T0 + 150.3, lambda t: write_single_req(t, 1, 105, 7), lambda t: write_single_req(t, 1, 105, 7))]
    _, res = run_family(tmp_path, inject)
    (f,) = res.findings
    assert f.classes == (1,)
    assert f.what.function_code == 6 and f.what.table == HOLDING
    assert (f.what.start_address, f.what.end_address, f.what.value) == (105, 105, 7)
    assert f.what.request_ts == pytest.approx(T0 + 150.3, abs=1e-5)
    assert f.what.exception_code is None
    assert f.why[0].addresses == ((105, 105),)


def test_gate3_clean_same_family_zero_findings(tmp_path: Path) -> None:
    """DESIGN.md: "On a clean pcap with no injected anomaly, zero false
    positives ... The clean pcap comes from the same capture family as the
    baseline pcap"."""
    result, res = run_family(tmp_path)
    assert result.anomalies == []
    assert res.findings == ()
    assert res.unbaselined == ()
    assert res.records_analysed > 0


# --- classes 1 and 2 (D7, per-table per D12) ------------------------------------------


def test_unknown_register_write_is_class_2(tmp_path: Path) -> None:
    inject = [(T0 + 150.3, lambda t: write_single_req(t, 1, 900, 7), lambda t: write_single_req(t, 1, 900, 7))]
    _, res = run_family(tmp_path, inject)
    (f,) = res.findings
    assert f.classes == (2,)
    assert f.why[0].addresses == ((900, 900),)


def test_write_to_baseline_written_register_not_flagged() -> None:
    res = detect(small_baseline(), [rec(AT, fc=6, start=40)])
    assert res.findings == ()
    assert res.records_analysed == 1


@pytest.mark.parametrize(
    "fc,start,qty,expected",
    [
        (6, 105, 1, (1,)),  # read-only single register
        (6, 900, 1, (2,)),  # unknown single register
        (16, 100, 4, (1,)),  # all read-only range
        (16, 108, 4, (2,)),  # 108-109 read-only, 110-111 unknown
        (15, 14, 4, (2,)),  # coils 14-15 read-only, 16-17 unknown
    ],
)
def test_classes_1_and_2_never_together(fc: int, start: int, qty: int, expected: tuple) -> None:
    (f,) = detect(small_baseline(), [rec(AT, fc=fc, start=start, qty=qty)]).findings
    assert f.classes == expected
    assert not {1, 2} <= set(f.classes)


def test_new_fc_and_read_only_register_one_finding_classes_1_and_5(tmp_path: Path) -> None:
    inject = [
        (
            T0 + 150.3,
            lambda t: write_multi_req(t, 1, 16, 105, (7,)),
            lambda t: write_multi_resp(t, 1, 16, 105, 1),
        )
    ]
    _, res = run_family(tmp_path, inject)
    (f,) = res.findings  # one finding, not two (D12)
    assert f.classes == (1, 5)
    assert f.what.function_code == 16


def test_new_fc_and_unknown_register_classes_2_and_5() -> None:
    base = build_baseline([rec(T0, fc=3, start=100, qty=10)], UNTIL)
    (f,) = detect(base, [rec(AT, fc=6, start=900)]).findings
    assert f.classes == (2, 5)


def test_new_read_fc_is_class_5_only(tmp_path: Path) -> None:
    inject = [(T0 + 150.3, lambda t: read_req(t, 1, 2, 0, 8), lambda t: read_resp(t, 1, 2, 1))]
    _, res = run_family(tmp_path, inject)
    (f,) = res.findings
    assert f.classes == (5,)
    assert f.why[0].addresses == ()


def test_table_confusion_input_read_then_holding_write_is_class_2(tmp_path: Path) -> None:
    """Baseline reads input register 50 (FC 04) and writes holding 40 (FC 06 is
    known). A write to holding 50 is class 2: input 50 is a different register
    (D12). Address 50, not 40, because the family legitimately writes holding 40."""
    inject = [(T0 + 150.3, lambda t: write_single_req(t, 1, 50, 7), lambda t: write_single_req(t, 1, 50, 7))]
    _, res = run_family(tmp_path, inject)
    (f,) = res.findings
    assert f.classes == (2,)


def test_coil_and_holding_tables_separate() -> None:
    (f,) = detect(small_baseline(), [rec(AT, fc=6, start=3)]).findings  # coil 3 was written
    assert f.classes == (2,)
    assert f.what.table == HOLDING


def test_range_write_mixed_unknown_and_read_only_is_class_2() -> None:
    (f,) = detect(small_baseline(), [rec(AT, fc=15, start=0, qty=21)]).findings
    assert f.classes == (2,)
    assert f.what.table == COILS
    (reason,) = f.why
    assert reason.addresses == ((16, 20),)
    assert "coils 16-20 never read or written" in reason.explanation
    assert "coils 0-2, 4-15 only ever read" in reason.explanation  # D1: no fact dropped


def test_range_write_all_read_only_is_class_1() -> None:
    (f,) = detect(small_baseline(), [rec(AT, fc=16, start=100, qty=4)]).findings
    assert f.classes == (1,)
    assert f.why[0].addresses == ((100, 103),)


# --- exceptions (D3, A3) -------------------------------------------------------------


def test_exception_answered_write_still_flagged(tmp_path: Path) -> None:
    inject = [(T0 + 150.3, lambda t: write_single_req(t, 1, 900, 7), lambda t: exc_resp(t, 1, 6, 2))]
    _, res = run_family(tmp_path, inject)
    (f,) = res.findings
    assert f.classes == (2,)
    assert f.what.exception_code == 2
    assert "the device answered with exception code 2" in f.why[0].explanation


def test_fc_with_only_baseline_exceptions_is_new() -> None:
    base = build_baseline([rec(T0, fc=1, start=0, qty=8, exc=1), rec(T0 + 1, fc=3)], UNTIL)
    (f,) = detect(base, [rec(AT, fc=1, start=0, qty=8)]).findings
    assert f.classes == (5,)


# --- devices not in the baseline (D2) ---------------------------------------------------


def test_unseen_unit_listed_not_flagged(tmp_path: Path) -> None:
    inject = [
        (T0 + 150.3, lambda t: read_req(t, 3, 3, 100, 10), lambda t: read_resp(t, 3, 3, 10)),
        (T0 + 160.3, lambda t: read_req(t, 3, 3, 100, 10), lambda t: read_resp(t, 3, 3, 10)),
        (T0 + 170.3, lambda t: write_single_req(t, 3, 40, 1), lambda t: write_single_req(t, 3, 40, 1)),
    ]
    _, res = run_family(tmp_path, inject)
    assert res.findings == ()
    (u,) = res.unbaselined
    assert (u.server_ip, u.unit_id) == (SERVER, 3)
    assert (u.transactions, u.writes, u.function_codes) == (3, 1, (3, 6))
    assert u.first_ts == pytest.approx(T0 + 150.3, abs=1e-5)
    assert u.last_ts == pytest.approx(T0 + 170.3, abs=1e-5)


def test_unseen_ip_listed_not_flagged() -> None:
    res = detect(small_baseline(), [rec(AT, fc=6, start=900, ip=OTHER_IP)])
    assert res.findings == ()
    assert [(u.server_ip, u.unit_id) for u in res.unbaselined] == [(OTHER_IP, 1)]


# --- validation (D4) -------------------------------------------------------------------


def test_detect_rejects_record_before_until() -> None:
    with pytest.raises(ValueError, match="before the baseline end"):
        detect(small_baseline(), [rec(UNTIL - 1)])


def test_detect_rejects_address_past_65535() -> None:
    with pytest.raises(ValueError, match="address range 65530-65539 exceeds 65535"):
        detect(small_baseline(), [rec(AT, fc=16, start=65530, qty=10)])


def test_detect_rejects_unsupported_fc() -> None:
    with pytest.raises(ValueError, match="unsupported function code 07"):
        detect(small_baseline(), [rec(AT, fc=7)])


# --- D12 pin: unanswered writes are invisible ------------------------------------------------


def test_unanswered_write_produces_no_finding(tmp_path: Path) -> None:
    inject = [(T0 + 150.3, lambda t: write_single_req(t, 1, 900, 7), None)]
    result, res = run_family(tmp_path, inject)
    assert result.anomaly_counts() == {"orphan_request": 1}
    assert res.findings == ()  # declared v0.1 limit (D12)


# --- result shape ---------------------------------------------------------------------------


def test_findings_ordered_and_deterministic() -> None:
    recs = [
        rec(AT + 3, fc=6, start=900),
        rec(AT + 1, fc=6, start=105),
        rec(AT + 2, fc=2, start=0, qty=8),
        rec(AT + 4, fc=6, start=40),
    ]
    shuffled = recs[:]
    random.Random(0).shuffle(shuffled)
    res = detect(small_baseline(), recs)
    assert detect(small_baseline(), shuffled) == res
    assert [f.what.request_ts for f in res.findings] == [AT + 1, AT + 2, AT + 3]


def test_explanations_say_anomalous_never_attack() -> None:
    recs = [
        rec(AT + 1, fc=6, start=105),  # class 1
        rec(AT + 2, fc=6, start=900, exc=2),  # class 2, exception note
        rec(AT + 3, fc=2, start=0, qty=8),  # class 5
    ]
    findings = detect(small_baseline(), recs).findings
    assert sorted(c for f in findings for c in f.classes) == [1, 2, 5]
    for f in findings:
        for reason in f.why:
            assert "anomalous" in reason.explanation
            assert "attack" not in reason.explanation.lower()


def test_classes_not_implemented_reported() -> None:
    res = detect(small_baseline(), [])
    assert res.classes_run == CLASSES_RUN == (1, 2, 5)
    assert res.classes_not_implemented == CLASSES_NOT_IMPLEMENTED == (3, 4)


def test_empty_detection_period() -> None:
    res = detect(small_baseline(), [])
    assert res.findings == () and res.unbaselined == ()
    assert res.records_analysed == 0
    assert res.until == UNTIL


# --- D13: FC 08 and FC 43 (address-less, class 5 only) ---------------------------


def test_fc08_on_known_device_is_class_5_only(tmp_path: Path) -> None:
    inject = [(T0 + 150.3, lambda t: fc08(t, 1, 0x0001), lambda t: fc08(t, 1, 0x0001))]
    _, res = run_family(tmp_path, inject)
    (f,) = res.findings
    assert f.classes == (5,)
    assert f.what.function_code == 8 and f.what.subfunction == 0x0001
    assert (f.what.table, f.what.start_address, f.what.end_address) == (None, None, None)


def test_fc43_on_known_device_is_class_5_only(tmp_path: Path) -> None:
    inject = [(T0 + 150.3, lambda t: fc43_req(t, 1), lambda t: fc43_resp(t, 1))]
    _, res = run_family(tmp_path, inject)
    (f,) = res.findings
    assert f.classes == (5,)
    assert f.what.function_code == 43 and f.what.subfunction == 0x0E
    assert (f.what.table, f.what.start_address, f.what.end_address) == (None, None, None)


def test_fc08_already_in_baseline_not_flagged() -> None:
    base = build_baseline([rec(T0, fc=3), rec(T0 + 1, fc=8, subfunction=0x0000)], UNTIL)
    res = detect(base, [rec(AT, fc=8, subfunction=0x000A)])
    assert res.findings == ()
    assert res.records_analysed == 1


def test_fc08_exception_answered_still_class_5() -> None:
    (f,) = detect(small_baseline(), [rec(AT, fc=8, subfunction=0x0001, exc=1)]).findings
    assert f.classes == (5,)
    assert f.what.exception_code == 1
    assert "the device answered with exception code 1" in f.why[0].explanation


def test_addressless_never_classes_1_or_2() -> None:
    cases = [(8, 0x0000, None), (8, 0x0004, 1), (43, 0x0E, None), (43, 0x0E, 2)]
    recs = [rec(AT + i, fc=fc, subfunction=sub, exc=exc) for i, (fc, sub, exc) in enumerate(cases)]
    findings = detect(small_baseline(), recs).findings
    assert len(findings) == 4
    assert all(f.classes == (5,) for f in findings)


def test_same_timestamp_addressless_and_addressed_sort_without_error() -> None:
    """Address-less findings (start_address None) and addressed ones at the SAME
    timestamp on the same device. The sort key uses -1 for a missing start, so no
    comparison pits None against an int; order is by function code, then start."""
    recs = [
        rec(AT, fc=43, subfunction=0x0E),
        rec(AT, fc=6, start=900),
        rec(AT, fc=8, subfunction=0x0001),
        rec(AT, fc=6, start=105),
        rec(AT, fc=8, subfunction=0x0002),
    ]
    findings = detect(small_baseline(), recs).findings
    assert [(f.what.function_code, f.what.start_address) for f in findings] == [
        (6, 105),
        (6, 900),
        (8, None),
        (8, None),
        (43, None),
    ]
