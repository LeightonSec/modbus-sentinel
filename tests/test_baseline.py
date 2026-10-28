"""Gate 2 baseline tests (D1, D5, D6, D8, D12).

Two kinds of fixture: hand-built TransactionRecords for exact timing (poll
statistics, the 72 h window), and synthetic pcaps through the real ingest_pcap
for the D12 rules end to end (per-table sets, exceptions, device keying). The
golden render is generated from the real code and reviewed once by a human:
it is the evidence for "readable without reading code".
"""

import json
import random
from pathlib import Path

import pytest
from pcap_builder import (
    CLIENT,
    SERVER,
    Conn,
    exc_resp,
    frame,
    read_req,
    read_resp,
    write_multi_req,
    write_multi_resp,
    write_single_req,
)
from record_builder import rec
from scapy.utils import wrpcap

from modbus_sentinel.baseline import (
    COILS,
    DISCRETE_INPUTS,
    HOLDING,
    INPUT,
    build_baseline,
    from_dict,
    parse_until,
    render_text,
    split_records,
    to_dict,
)
from modbus_sentinel.ingest import IngestResult, TransactionRecord, ingest_pcap

T0 = 1783324800.0  # 2026-07-06T08:00:00Z
MIDNIGHT = 1783296000.0  # 2026-07-06T00:00:00Z
DAY = 86400.0
HOUR = 3600.0
FAR_UNTIL = T0 + 10 * 365 * DAY  # after every fixture timestamp, inside datetime's range
GOLDEN = Path(__file__).parent / "golden_baseline.txt"
GOLDEN_UNTIL = T0 + 60


def ingest(tmp_path: Path, *conns: Conn) -> IngestResult:
    pkts = [p for c in conns for p in c.pkts]
    path = tmp_path / "fixture.pcap"
    wrpcap(str(path), pkts)
    return ingest_pcap(str(path))


def baseline_of(tmp_path: Path, *conns: Conn):
    result = ingest(tmp_path, *conns)
    assert result.anomalies == []  # fixtures must pair cleanly
    return build_baseline(result.records, FAR_UNTIL)


def golden_records() -> list[TransactionRecord]:
    """Two units on one IP, 60 s of traffic: the golden render fixture."""
    r = [rec(T0 + 2 * i, fc=3, start=100, qty=10) for i in range(30)]
    r += [rec(T0 + 1 + 5 * i, fc=3, start=200, qty=2) for i in range(11)]
    r += [rec(T0 + t, fc=6, start=40) for t in (10, 30, 50)]
    r.append(rec(T0 + 59, fc=3, start=500, qty=1, exc=2))
    r += [rec(T0 + 2 + 5 * i, fc=4, start=0, qty=4, unit=2) for i in range(12)]
    r += [rec(T0 + 3 + 6 * i, fc=1, start=0, qty=16, unit=2) for i in range(9)]
    r.append(rec(T0 + 20, fc=5, start=3, unit=2))
    return r


def day_records(days: int, hours: list[int]) -> list[TransactionRecord]:
    return [rec(MIDNIGHT + d * DAY + h * HOUR) for d in range(days) for h in hours]


# --- parse_until (D12: timestamp only) ----------------------------------------


def test_parse_until_epoch_seconds() -> None:
    assert parse_until("1783324800") == T0
    assert parse_until("1783324800.5") == T0 + 0.5


def test_parse_until_iso_with_offset() -> None:
    assert parse_until("2026-07-06T08:00:00Z") == T0
    assert parse_until("2026-07-06T10:00:00+02:00") == T0


def test_parse_until_rejects_naive() -> None:
    with pytest.raises(ValueError, match="no UTC offset"):
        parse_until("2026-07-06T08:00:00")


@pytest.mark.parametrize("bad", ["yesterday", "-5", "1e9", ""])
def test_parse_until_rejects_garbage(bad: str) -> None:
    with pytest.raises(ValueError, match="is not a timestamp"):
        parse_until(bad)


# --- split (A1, A2) -------------------------------------------------------------


def test_split_boundary_is_exclusive() -> None:
    until = T0 + 10
    before, at = rec(until - 0.001), rec(until)
    baseline, detection = split_records([at, before], until)
    assert [r.request_ts for r in baseline] == [until - 0.001]
    assert [r.request_ts for r in detection] == [until]


def test_split_sorts_by_request_ts() -> None:
    recs = [rec(T0 + 3), rec(T0 + 1), rec(T0 + 2)]
    baseline, detection = split_records(recs, T0 + 100)
    assert [r.request_ts for r in baseline] == [T0 + 1, T0 + 2, T0 + 3]
    assert detection == []


# --- per-table address sets (D12) -------------------------------------------------


def test_per_table_separation(tmp_path: Path) -> None:
    c = Conn()
    c.send(read_req(1, fc=4, addr=40, qty=1))
    c.recv(read_resp(1, fc=4, qty=1))
    c.send(read_req(2, fc=3, addr=100, qty=10))
    c.recv(read_resp(2, fc=3, qty=10))
    c.send(write_single_req(3, addr=40, value=7))
    c.recv(write_single_req(3, addr=40, value=7))
    (d,) = baseline_of(tmp_path, c).devices
    assert 40 in d.tables[INPUT].read
    assert 40 not in d.tables[HOLDING].read  # input register 40 is not holding register 40
    assert 40 in d.tables[HOLDING].write
    assert d.tables[HOLDING].read.ranges == ((100, 109),)
    assert d.tables[INPUT].write.ranges == ()


def test_coil_and_discrete_tables(tmp_path: Path) -> None:
    c = Conn()
    c.send(read_req(1, fc=1, addr=0, qty=16))
    c.recv(read_resp(1, fc=1, qty=1))
    c.send(read_req(2, fc=2, addr=8, qty=8))
    c.recv(read_resp(2, fc=2, qty=1))
    c.send(write_multi_req(3, fc=15, addr=3, values=(1, 0, 1)))
    c.recv(write_multi_resp(3, fc=15, addr=3, qty=3))
    (d,) = baseline_of(tmp_path, c).devices
    assert d.tables[COILS].read.ranges == ((0, 15),)
    assert d.tables[COILS].write.ranges == ((3, 5),)
    assert d.tables[DISCRETE_INPUTS].read.ranges == ((8, 15),)
    assert d.tables[HOLDING].read.ranges == ()


def test_fc05_single_coil_write(tmp_path: Path) -> None:
    fc05 = b"\x05" + (3).to_bytes(2, "big") + b"\xff\x00"  # coil 3 ON
    c = Conn()
    c.send(frame(1, 1, fc05))
    c.recv(frame(1, 1, fc05))  # FC 05 response echoes the request
    (d,) = baseline_of(tmp_path, c).devices
    assert d.function_codes == (5,)
    assert d.tables[COILS].write.ranges == ((3, 3),)
    assert d.tables[HOLDING].write.ranges == ()


def test_fc16_range_expansion(tmp_path: Path) -> None:
    c = Conn()
    c.send(write_multi_req(1, fc=16, addr=10, values=(1, 2, 3, 4)))
    c.recv(write_multi_resp(1, fc=16, addr=10, qty=4))
    (d,) = baseline_of(tmp_path, c).devices
    assert d.tables[HOLDING].write.ranges == ((10, 13),)
    assert len(d.tables[HOLDING].write) == 4
    assert 9 not in d.tables[HOLDING].write and 14 not in d.tables[HOLDING].write


def test_build_rejects_address_past_65535() -> None:
    with pytest.raises(ValueError, match="address range 65530-65539 exceeds 65535"):
        build_baseline([rec(T0, fc=3, start=65530, qty=10)], FAR_UNTIL)


def test_build_rejects_unsupported_fc() -> None:
    with pytest.raises(ValueError, match="unsupported function code 08"):
        build_baseline([rec(T0, fc=8)], FAR_UNTIL)


def test_build_rejects_record_not_before_until() -> None:
    with pytest.raises(ValueError, match="not before the baseline end"):
        build_baseline([rec(T0)], T0)


# --- exceptions (D12, A3) -----------------------------------------------------------


def test_exception_excluded_from_sets(tmp_path: Path) -> None:
    c = Conn()
    c.send(read_req(1, fc=3, addr=100, qty=10))
    c.recv(read_resp(1, fc=3, qty=10))
    c.send(read_req(2, fc=3, addr=500, qty=1))
    c.recv(exc_resp(2, fc=3, code=2))  # illegal data address
    (d,) = baseline_of(tmp_path, c).devices
    assert 500 not in d.tables[HOLDING].read
    assert d.tables[HOLDING].read.ranges == ((100, 109),)
    assert d.transactions == 2
    assert d.exceptions == 1


def test_exception_write_excluded_from_write_set(tmp_path: Path) -> None:
    c = Conn()
    c.send(write_single_req(1, addr=40, value=7))
    c.recv(exc_resp(1, fc=6, code=2))
    (d,) = baseline_of(tmp_path, c).devices
    assert 40 not in d.tables[HOLDING].write
    assert d.tables[HOLDING].write.ranges == ()


def test_exception_only_fc_not_in_fc_set(tmp_path: Path) -> None:
    c = Conn()
    c.send(read_req(1, fc=1, addr=0, qty=8))
    c.recv(exc_resp(1, fc=1, code=1))  # illegal function
    b = baseline_of(tmp_path, c)
    (d,) = b.devices
    assert d.function_codes == ()
    assert d.exceptions == 1
    assert "function codes: none (every transaction was an exception response)" in render_text(b)


# --- device identity (D1) -------------------------------------------------------------


def test_two_units_one_ip(tmp_path: Path) -> None:
    c = Conn()
    c.send(read_req(1, unit=1, addr=100))
    c.recv(read_resp(1, unit=1))
    c.send(read_req(2, unit=2, addr=200))
    c.recv(read_resp(2, unit=2))
    b = baseline_of(tmp_path, c)
    assert [d.key for d in b.devices] == [(SERVER, 1), (SERVER, 2)]
    u1, u2 = b.device((SERVER, 1)), b.device((SERVER, 2))
    assert 100 in u1.tables[HOLDING].read and 200 not in u1.tables[HOLDING].read
    assert 200 in u2.tables[HOLDING].read and 100 not in u2.tables[HOLDING].read
    assert b.device((SERVER, 3)) is None


def test_same_unit_two_ips(tmp_path: Path) -> None:
    other = "192.168.1.21"
    a = Conn()
    a.send(read_req(1, addr=100))
    a.recv(read_resp(1))
    b_conn = Conn(client=(CLIENT, 49153), server=(other, 502))
    b_conn.send(read_req(1, addr=300))
    b_conn.recv(read_resp(1))
    b = baseline_of(tmp_path, a, b_conn)
    assert [d.key for d in b.devices] == [(SERVER, 1), (other, 1)]
    assert 300 not in b.device((SERVER, 1)).tables[HOLDING].read


# --- poll groups (D5) -------------------------------------------------------------------


def test_poll_group_armable_at_10() -> None:
    (d,) = build_baseline([rec(T0 + i) for i in range(10)], FAR_UNTIL).devices
    (g,) = d.poll_groups
    assert g.requests == 10 and g.armable
    assert g.median_interval_s == 1.0 and g.mad_s == 0.0


def test_poll_group_not_armable_at_9() -> None:
    b = build_baseline([rec(T0 + i) for i in range(9)], FAR_UNTIL)
    (g,) = b.devices[0].poll_groups
    assert g.requests == 9 and not g.armable
    assert "insufficient baseline data (n=9), interval not monitored" in render_text(b)


def test_poll_group_median_mad_values() -> None:
    offsets = [0.0, 0.9, 1.9, 3.0, 4.0, 7.0]  # intervals 0.9, 1.0, 1.1, 1.0, 3.0
    (d,) = build_baseline([rec(T0 + o) for o in offsets], FAR_UNTIL).devices
    (g,) = d.poll_groups
    # abs tolerance: offsets on a ~1.78e9 epoch carry ~2.4e-7 float spacing
    assert g.median_interval_s == pytest.approx(1.0, abs=1e-6)
    assert g.mad_s == pytest.approx(0.1, abs=1e-6)


def test_poll_group_single_request() -> None:
    (d,) = build_baseline([rec(T0)], FAR_UNTIL).devices
    (g,) = d.poll_groups
    assert g.requests == 1 and not g.armable
    assert g.median_interval_s is None and g.mad_s is None


def test_poll_groups_keyed_fc_addr_qty() -> None:
    recs = [rec(T0, qty=10), rec(T0 + 1, qty=5), rec(T0 + 2, qty=10), rec(T0 + 3, fc=4, qty=10)]
    (d,) = build_baseline(recs, FAR_UNTIL).devices
    keys = [(g.function_code, g.start_address, g.quantity, g.requests) for g in d.poll_groups]
    assert keys == [(3, 100, 5, 1), (3, 100, 10, 2), (4, 100, 10, 1)]


# --- operational window (D8, UTC per D12) -------------------------------------------------


def test_window_armable_day_shift() -> None:
    b = build_baseline(day_records(4, list(range(8, 19))), FAR_UNTIL)
    w = b.devices[0].window
    assert w.armable
    assert w.start_s == 8 * HOUR and w.length_s == 10 * HOUR
    assert w.span_s == 3 * DAY + 10 * HOUR
    assert "08:00:00 to 18:00:00 UTC, armable under D8" in render_text(b)


def test_window_wraps_midnight() -> None:
    hours = [0, 1, 2, 3, 4, 5, 6, 22, 23]
    w = build_baseline(day_records(4, hours), FAR_UNTIL).devices[0].window
    assert w.armable
    assert w.start_s == 22 * HOUR and w.length_s == 8 * HOUR


def test_window_short_span_reason() -> None:
    w = build_baseline(day_records(2, list(range(8, 19))), FAR_UNTIL).devices[0].window
    assert not w.armable
    assert w.reason == "not armable, baseline spans 34.0 h; D8 needs 72 h"


def test_window_too_wide_reason() -> None:
    w = build_baseline(day_records(4, list(range(0, 23))), FAR_UNTIL).devices[0].window
    assert not w.armable
    assert w.length_s == 22 * HOUR
    assert "D8 allows at most 20 h" in w.reason


def test_window_one_stray_record_widens() -> None:
    recs = day_records(4, list(range(8, 19))) + [rec(MIDNIGHT + DAY + 3 * HOUR)]
    w = build_baseline(recs, FAR_UNTIL).devices[0].window
    assert w.start_s == 3 * HOUR and w.length_s == 15 * HOUR  # 100% containment
    assert w.armable


# --- serialization ------------------------------------------------------------------------


def test_to_dict_json_round_trip() -> None:
    b = build_baseline(golden_records(), GOLDEN_UNTIL)
    text = json.dumps(to_dict(b), sort_keys=True)
    assert from_dict(json.loads(text)) == b
    assert json.dumps(to_dict(build_baseline(golden_records(), GOLDEN_UNTIL)), sort_keys=True) == text


def test_from_dict_rejects_schema() -> None:
    data = to_dict(build_baseline([rec(T0)], FAR_UNTIL))
    data["schema_version"] = 2
    with pytest.raises(ValueError, match="schema_version 2"):
        from_dict(data)


# --- whole-baseline behaviour ----------------------------------------------------------------


def test_empty_baseline() -> None:
    b = build_baseline([], T0)
    assert b.devices == () and b.transactions == 0
    assert "no transactions in the baseline period" in render_text(b)


def test_render_until_outside_datetime_range_falls_back() -> None:
    b = build_baseline([rec(T0)], 1e12)  # year ~33658: datetime cannot format it
    text = render_text(b)
    assert "transactions requested before epoch 1000000000000.0" in text


def test_deterministic_and_order_independent() -> None:
    recs = golden_records()
    shuffled = recs[:]
    random.Random(0).shuffle(shuffled)
    assert build_baseline(shuffled, GOLDEN_UNTIL) == build_baseline(recs, GOLDEN_UNTIL)


def test_render_text_golden() -> None:
    rendered = render_text(build_baseline(golden_records(), GOLDEN_UNTIL))
    assert rendered == GOLDEN.read_text(encoding="utf-8")
