"""Per-device baseline (Gate 2): what "normal" looked like in the baseline period.

Built from the TransactionRecords of the user-designated baseline period (D6,
D12) and keyed by (server IP, unit ID) (D1). Address sets are kept per Modbus
table, and exception responses add nothing to the address sets or the FC set
(D12). Poll groups (D5) and the operational window (D8) are recorded with
whether they would arm; classes 3 and 4 do not run yet (D12), so this module
describes the baseline and detects nothing.

A record whose address range runs past 65535 is malformed Modbus and is
rejected with a ValueError naming the range (D12 ruling on A12), never stored.
"""

from __future__ import annotations

import bisect
import ipaddress
import re
import statistics
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

from modbus_sentinel.ingest import TransactionRecord

POLL_ARM_FLOOR = 10  # D5: a poll group arms at >= 10 baseline requests
WINDOW_MIN_SPAN_S = 72 * 3600  # D8
WINDOW_MAX_S = 20 * 3600  # D8
SCHEMA_VERSION = 1
MAX_ADDRESS = 0xFFFF
_DAY = 86400.0

COILS = "coils"
DISCRETE_INPUTS = "discrete_inputs"
HOLDING = "holding_registers"
INPUT = "input_registers"
TABLES = (COILS, DISCRETE_INPUTS, HOLDING, INPUT)
READ_TABLE = {1: COILS, 2: DISCRETE_INPUTS, 3: HOLDING, 4: INPUT}  # D12
WRITE_TABLE = {5: COILS, 15: COILS, 6: HOLDING, 16: HOLDING}  # D12
_READ_ONLY = frozenset({DISCRETE_INPUTS, INPUT})
_TABLE_LABEL = {
    COILS: "coils",
    DISCRETE_INPUTS: "discrete inputs",
    HOLDING: "holding registers",
    INPUT: "input registers",
}
_FC_NAME = {
    1: "read coils",
    2: "read discrete inputs",
    3: "read holding registers",
    4: "read input registers",
    5: "write single coil",
    6: "write single register",
    15: "write multiple coils",
    16: "write multiple registers",
}

DeviceKey = tuple[str, int]  # (server IP, unit ID), D1

_EPOCH_RE = re.compile(r"\d+(\.\d+)?")
_UNTIL_FORMS = "epoch seconds (e.g. 1783324800) or ISO 8601 with an offset (e.g. 2026-07-06T08:00:00Z)"


@dataclass(frozen=True)
class AddressSet:
    """Sorted, merged, inclusive address ranges."""

    ranges: tuple[tuple[int, int], ...] = ()

    @classmethod
    def from_ranges(cls, ranges: Iterable[tuple[int, int]]) -> AddressSet:
        merged: list[list[int]] = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        return cls(tuple((s, e) for s, e in merged))

    def __contains__(self, addr: int) -> bool:
        i = bisect.bisect_right([s for s, _ in self.ranges], addr) - 1
        return i >= 0 and addr <= self.ranges[i][1]

    def __len__(self) -> int:
        return sum(e - s + 1 for s, e in self.ranges)

    def render(self) -> str:
        if not self.ranges:
            return "none"
        return ", ".join(str(s) if s == e else f"{s}-{e}" for s, e in self.ranges)


@dataclass(frozen=True)
class TableSets:
    read: AddressSet
    write: AddressSet  # always empty for the read-only tables


@dataclass(frozen=True)
class PollGroup:
    function_code: int
    start_address: int
    quantity: int  # 1 for FC 05/06
    requests: int  # D5 "observations"
    median_interval_s: float | None  # None when requests < 2
    mad_s: float | None  # raw median absolute deviation, unscaled
    armable: bool  # requests >= POLL_ARM_FLOOR


@dataclass(frozen=True)
class OperationalWindow:
    armable: bool
    reason: str
    span_s: float  # this device's first to last baseline request
    start_s: float  # window start, seconds of day, UTC (D12)
    length_s: float


@dataclass(frozen=True)
class DeviceBaseline:
    server_ip: str
    unit_id: int
    transactions: int  # paired records in the baseline, exceptions included
    exceptions: int  # of which exception responses
    first_ts: float
    last_ts: float
    function_codes: tuple[int, ...]  # exception-only FCs excluded (D12)
    tables: Mapping[str, TableSets]  # all four tables always present
    poll_groups: tuple[PollGroup, ...]
    window: OperationalWindow

    @property
    def key(self) -> DeviceKey:
        return (self.server_ip, self.unit_id)


@dataclass(frozen=True)
class Baseline:
    until: float  # exclusive upper bound on request_ts, epoch seconds
    transactions: int
    devices: tuple[DeviceBaseline, ...]

    def device(self, key: DeviceKey) -> DeviceBaseline | None:
        for d in self.devices:
            if d.key == key:
                return d
        return None


def parse_until(text: str) -> float:
    """--baseline-until value to epoch seconds (D12: timestamp only)."""
    s = text.strip()
    if _EPOCH_RE.fullmatch(s):
        return float(s)
    # Python 3.10 fromisoformat rejects a trailing Z; map it to +00:00 first.
    iso = s[:-1] + "+00:00" if s.endswith(("Z", "z")) else s
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        raise ValueError(f"--baseline-until {text!r} is not a timestamp; use {_UNTIL_FORMS}") from None
    if dt.tzinfo is None:
        raise ValueError(f"--baseline-until {text!r} has no UTC offset; use {_UNTIL_FORMS}")
    return dt.timestamp()


def split_records(
    records: Iterable[TransactionRecord], until: float
) -> tuple[list[TransactionRecord], list[TransactionRecord]]:
    """Sort by request_ts; baseline is request_ts < until, detection the rest."""
    ordered = sorted(records, key=lambda r: r.request_ts)
    return (
        [r for r in ordered if r.request_ts < until],
        [r for r in ordered if r.request_ts >= until],
    )


def record_range(r: TransactionRecord) -> tuple[int, int]:
    """Inclusive address range a request covers (D12); FC 05/06 cover one."""
    qty = 1 if r.function_code in (5, 6) else r.quantity
    return r.start_address, r.start_address + qty - 1


def _where(r: TransactionRecord) -> str:
    return f"{r.server_ip} unit {r.unit_id} FC {r.function_code:02d}"


def validate_record(r: TransactionRecord) -> None:
    """Shared by baseline and detection: supported FCs only (D12), and an
    address range past 65535 is malformed Modbus and raises (A12)."""
    if r.function_code not in READ_TABLE and r.function_code not in WRITE_TABLE:
        raise ValueError(f"{_where(r)}: unsupported function code {r.function_code:02d}")
    start, end = record_range(r)
    if end > MAX_ADDRESS:
        raise ValueError(f"{_where(r)}: address range {start}-{end} exceeds 65535 (malformed Modbus address)")


def _check_record(r: TransactionRecord, until: float) -> None:
    validate_record(r)
    if r.request_ts >= until:
        raise ValueError(f"{_where(r)}: request at {r.request_ts} is not before the baseline end {until}")


def _poll_groups(recs: list[TransactionRecord]) -> tuple[PollGroup, ...]:
    groups: dict[tuple[int, int, int], list[float]] = {}
    for r in recs:
        start, end = record_range(r)
        groups.setdefault((r.function_code, start, end - start + 1), []).append(r.request_ts)
    out = []
    for (fc, start, qty), times in sorted(groups.items()):
        intervals = [b - a for a, b in zip(times, times[1:])]
        median = mad = None
        if intervals:
            median = statistics.median(intervals)
            mad = statistics.median(abs(x - median) for x in intervals)
        out.append(PollGroup(fc, start, qty, len(times), median, mad, len(times) >= POLL_ARM_FLOOR))
    return tuple(out)


def _duration(seconds: float) -> str:
    if seconds < 3600:
        return f"{seconds:.0f} s"
    return f"{seconds / 3600:.1f} h"


def _window(recs: list[TransactionRecord]) -> OperationalWindow:
    """D8: smallest contiguous time-of-day interval (mod 24 h, UTC) holding
    every baseline request, found by removing the largest circular gap."""
    span = recs[-1].request_ts - recs[0].request_ts
    tod = sorted({r.request_ts % _DAY for r in recs})
    best_gap, best_i = -1.0, 0
    for i, t in enumerate(tod):
        nxt = tod[i + 1] if i + 1 < len(tod) else tod[0] + _DAY
        if nxt - t > best_gap:
            best_gap, best_i = nxt - t, i
    start = tod[(best_i + 1) % len(tod)]
    length = _DAY - best_gap
    if span < WINDOW_MIN_SPAN_S:
        armable, reason = False, f"not armable, baseline spans {_duration(span)}; D8 needs 72 h"
    elif length > WINDOW_MAX_S:
        armable, reason = False, f"not armable, window covers {length / 3600:.1f} h of 24; D8 allows at most 20 h"
    else:
        armable = True
        reason = f"armable under D8: baseline spans {span / 3600:.1f} h, window covers {length / 3600:.1f} h of 24"
    return OperationalWindow(armable, reason, span, start, length)


def _build_device(key: DeviceKey, recs: list[TransactionRecord]) -> DeviceBaseline:
    normal = [r for r in recs if not r.is_exception]  # D12: exceptions stay out
    ranges: dict[str, tuple[list[tuple[int, int]], list[tuple[int, int]]]] = {
        t: ([], []) for t in TABLES
    }
    for r in normal:
        if r.function_code in WRITE_TABLE:
            ranges[WRITE_TABLE[r.function_code]][1].append(record_range(r))
        else:
            ranges[READ_TABLE[r.function_code]][0].append(record_range(r))
    tables = {
        t: TableSets(AddressSet.from_ranges(rd), AddressSet.from_ranges(wr))
        for t, (rd, wr) in ranges.items()
    }
    return DeviceBaseline(
        server_ip=key[0],
        unit_id=key[1],
        transactions=len(recs),
        exceptions=len(recs) - len(normal),
        first_ts=recs[0].request_ts,
        last_ts=recs[-1].request_ts,
        function_codes=tuple(sorted({r.function_code for r in normal})),
        tables=tables,
        poll_groups=_poll_groups(recs),
        window=_window(recs),
    )


def _device_order(key: DeviceKey) -> tuple:
    addr = ipaddress.ip_address(key[0])
    return (addr.version, addr, key[1])


def build_baseline(records: Sequence[TransactionRecord], until: float) -> Baseline:
    """Baseline from baseline-period records only (see split_records)."""
    by_device: dict[DeviceKey, list[TransactionRecord]] = {}
    for r in sorted(records, key=lambda r: r.request_ts):
        _check_record(r, until)
        by_device.setdefault((r.server_ip, r.unit_id), []).append(r)
    devices = tuple(
        _build_device(k, by_device[k]) for k in sorted(by_device, key=_device_order)
    )
    return Baseline(until=until, transactions=len(records), devices=devices)


def to_dict(b: Baseline) -> dict:
    """JSON-safe dict; timestamps stay epoch floats so the round trip is exact."""
    return {
        "schema_version": SCHEMA_VERSION,
        "until": b.until,
        "transactions": b.transactions,
        "devices": [
            {
                "server_ip": d.server_ip,
                "unit_id": d.unit_id,
                "transactions": d.transactions,
                "exceptions": d.exceptions,
                "first_ts": d.first_ts,
                "last_ts": d.last_ts,
                "function_codes": list(d.function_codes),
                "tables": {
                    t: {
                        "read": [list(r) for r in d.tables[t].read.ranges],
                        "write": [list(r) for r in d.tables[t].write.ranges],
                    }
                    for t in TABLES
                },
                "poll_groups": [
                    {
                        "function_code": g.function_code,
                        "start_address": g.start_address,
                        "quantity": g.quantity,
                        "requests": g.requests,
                        "median_interval_s": g.median_interval_s,
                        "mad_s": g.mad_s,
                        "armable": g.armable,
                    }
                    for g in d.poll_groups
                ],
                "window": {
                    "armable": d.window.armable,
                    "reason": d.window.reason,
                    "span_s": d.window.span_s,
                    "start_s": d.window.start_s,
                    "length_s": d.window.length_s,
                },
            }
            for d in b.devices
        ],
    }


def _ranges(items: list) -> AddressSet:
    return AddressSet(tuple((int(s), int(e)) for s, e in items))


def from_dict(data: dict) -> Baseline:
    """Inverse of to_dict."""
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"baseline schema_version {data.get('schema_version')!r} is not {SCHEMA_VERSION}"
        )
    devices = []
    for d in data["devices"]:
        w = d["window"]
        devices.append(
            DeviceBaseline(
                server_ip=d["server_ip"],
                unit_id=d["unit_id"],
                transactions=d["transactions"],
                exceptions=d["exceptions"],
                first_ts=d["first_ts"],
                last_ts=d["last_ts"],
                function_codes=tuple(d["function_codes"]),
                tables={
                    t: TableSets(_ranges(d["tables"][t]["read"]), _ranges(d["tables"][t]["write"]))
                    for t in TABLES
                },
                poll_groups=tuple(
                    PollGroup(
                        g["function_code"],
                        g["start_address"],
                        g["quantity"],
                        g["requests"],
                        g["median_interval_s"],
                        g["mad_s"],
                        g["armable"],
                    )
                    for g in d["poll_groups"]
                ),
                window=OperationalWindow(
                    w["armable"], w["reason"], w["span_s"], w["start_s"], w["length_s"]
                ),
            )
        )
    return Baseline(until=data["until"], transactions=data["transactions"], devices=tuple(devices))


def _iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return f"epoch {ts}"  # outside datetime's range: show the raw value, never raise


def _time_of_day(seconds: float) -> str:
    s = int(seconds % _DAY)
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _render_device(d: DeviceBaseline) -> list[str]:
    lines = [f"device {d.server_ip} unit {d.unit_id}"]
    if d.exceptions:
        exc = f"of which {_plural(d.exceptions, 'exception response')} (kept out of the address sets)"
    else:
        exc = "no exception responses"
    lines.append(f"  transactions: {d.transactions}, {exc}")
    lines.append(
        f"  seen: {_iso(d.first_ts)} to {_iso(d.last_ts)} ({_duration(d.last_ts - d.first_ts)})"
    )
    if d.function_codes:
        fcs = ", ".join(f"{fc:02d} {_FC_NAME[fc]}" for fc in d.function_codes)
    else:
        fcs = "none (every transaction was an exception response)"
    lines.append(f"  function codes: {fcs}")
    lines.append("  address sets:")
    for t in TABLES:
        sets = d.tables[t]
        if t in _READ_ONLY:
            lines.append(f"    {_TABLE_LABEL[t]:<18} read: {sets.read.render()}")
        else:
            lines.append(
                f"    {_TABLE_LABEL[t]:<18} read: {sets.read.render():<22} written: {sets.write.render()}"
            )
    lines.append("  poll groups (class 3 not implemented; band width N not decided):")
    for g in d.poll_groups:
        head = f"FC {g.function_code:02d} addr {g.start_address} qty {g.quantity}"
        if g.armable:
            tail = f"median {g.median_interval_s:.3f} s  MAD {g.mad_s:.3f} s  armable"
        else:
            tail = f"insufficient baseline data (n={g.requests}), interval not monitored"
        lines.append(f"    {head:<22} {_plural(g.requests, 'request'):<12} {tail}")
    w = d.window
    if w.armable:
        text = (
            f"{_time_of_day(w.start_s)} to {_time_of_day(w.start_s + w.length_s)} UTC, {w.reason}"
        )
    else:
        text = w.reason
    lines.append(f"  operational window (class 4 not implemented): {text}")
    return lines


def render_text(b: Baseline) -> str:
    """Human-readable baseline: what "normal" means per device, no code needed."""
    lines = [
        "modbus-sentinel baseline (Gate 2)",
        f"  baseline period: transactions requested before {_iso(b.until)}",
        "  clock: capture clock, UTC. Addresses are 0-based wire addresses.",
        "  assumption: the baseline period is clean; anything in it is learned as normal.",
    ]
    if not b.devices:
        lines.append("  no transactions in the baseline period; nothing is learned as normal.")
        return "\n".join(lines) + "\n"
    lines.append(f"  {_plural(b.transactions, 'transaction')}, {_plural(len(b.devices), 'device')}")
    for d in b.devices:
        lines.append("")
        lines.extend(_render_device(d))
    return "\n".join(lines) + "\n"
