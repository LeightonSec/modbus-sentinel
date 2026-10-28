"""Detection first cut (Gate 3): classes 1, 2 and 5 (D7, D12).

Each post-baseline TransactionRecord is checked against its device's baseline,
keyed by (server IP, unit ID) (D1). A transaction produces at most one Finding,
and that finding lists every class it matched; classes 1 and 2 are never both
(D7, D12). What happened (facts from the record) is kept separate from why it
was flagged (one Reason per class), per DESIGN.md Gate 4.

Rulings this module implements (commit 3 plan, approved):
- Writes are judged per address against the target table's sets only (D12):
  written in baseline = normal, read but never written = class 1, never read or
  written = class 2. A multi-address write with any never-seen address is class
  2, otherwise class 1 if any address was only read; the reason names both
  kinds of address, so no fact is dropped (D1).
- A device absent from the baseline is not run through the classes; it is
  reported as an UnbaselinedDevice coverage gap instead (D2).
- An exception-answered transaction is judged like any other: the attempt is
  the behaviour, and the finding records the exception code (D3).
- A malformed record (unsupported FC, address past 65535) or one from before
  the baseline end raises ValueError (D4). Whether a hostile packet should stop
  the run this way is a CLI / Gate 4 decision.
Classes 3 and 4 are not implemented (D12) and are named as such in the result.
Every value here is an integer or a string built from integers: no raw packet
bytes reach a Finding.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace

from modbus_sentinel.baseline import (
    _FC_NAME,
    _TABLE_LABEL,
    READ_TABLE,
    WRITE_TABLE,
    AddressSet,
    Baseline,
    DeviceBaseline,
    DeviceKey,
    _device_order,
    record_range,
    validate_record,
)
from modbus_sentinel.ingest import TransactionRecord

CLASS_NAMES = {1: "unscheduled write", 2: "write to unknown register", 5: "never-seen function code"}
CLASSES_RUN = (1, 2, 5)
CLASSES_NOT_IMPLEMENTED = (3, 4)  # D12: named, never silently absent


@dataclass(frozen=True)
class WhatHappened:
    """Facts from the record, no judgement."""

    request_ts: float
    server_ip: str
    unit_id: int
    function_code: int
    table: str
    start_address: int
    end_address: int  # equal to start_address for FC 05/06
    value: int | None  # FC 05/06 written value, else None
    exception_code: int | None  # set when the device answered with an exception


@dataclass(frozen=True)
class Reason:
    """Why flagged: one per matched class."""

    anomaly_class: int
    name: str
    explanation: str  # plain English; says "anomalous", never "attack"
    addresses: tuple[tuple[int, int], ...]  # triggering addresses; () for class 5


@dataclass(frozen=True)
class Finding:
    what: WhatHappened
    why: tuple[Reason, ...]  # sorted by class; never both 1 and 2 (D7)

    @property
    def classes(self) -> tuple[int, ...]:
        return tuple(r.anomaly_class for r in self.why)


@dataclass(frozen=True)
class UnbaselinedDevice:
    """A device seen only after the baseline: not analysed, reported (D2)."""

    server_ip: str
    unit_id: int
    transactions: int
    writes: int
    function_codes: tuple[int, ...]  # every FC attempted, exceptions included
    first_ts: float
    last_ts: float


@dataclass(frozen=True)
class DetectionResult:
    until: float
    records_analysed: int
    findings: tuple[Finding, ...]
    unbaselined: tuple[UnbaselinedDevice, ...]
    classes_run: tuple[int, ...] = CLASSES_RUN
    classes_not_implemented: tuple[int, ...] = CLASSES_NOT_IMPLEMENTED


def _ranges(addrs: list[int]) -> tuple[tuple[int, int], ...]:
    return AddressSet.from_ranges((a, a) for a in addrs).ranges


def _write_reason(r: TransactionRecord, dev: DeviceBaseline) -> Reason | None:
    table = WRITE_TABLE[r.function_code]
    sets = dev.tables[table]
    start, end = record_range(r)
    read_only: list[int] = []
    unknown: list[int] = []
    for a in range(start, end + 1):
        if a in sets.write:
            continue  # written in the baseline: normal
        if a in sets.read:
            read_only.append(a)
        else:
            unknown.append(a)
    label = _TABLE_LABEL[table]
    if unknown:
        text = f"anomalous: {label} {AddressSet(_ranges(unknown)).render()} never read or written in the baseline"
        if read_only:
            text += f"; {label} {AddressSet(_ranges(read_only)).render()} only ever read"
        return Reason(2, CLASS_NAMES[2], text, _ranges(unknown))
    if read_only:
        text = (
            f"anomalous: {label} {AddressSet(_ranges(read_only)).render()} "
            "only ever read in the baseline, never written"
        )
        return Reason(1, CLASS_NAMES[1], text, _ranges(read_only))
    return None


def _evaluate(r: TransactionRecord, dev: DeviceBaseline) -> Finding | None:
    reasons: list[Reason] = []
    if r.function_code in WRITE_TABLE:
        w = _write_reason(r, dev)
        if w is not None:
            reasons.append(w)
    if r.function_code not in dev.function_codes:
        fc = r.function_code
        text = (
            f"anomalous: function code {fc:02d} ({_FC_NAME[fc]}) was never used "
            "successfully with this device in the baseline"
        )
        reasons.append(Reason(5, CLASS_NAMES[5], text, ()))
    if not reasons:
        return None
    if r.is_exception:
        note = f"; the device answered with exception code {r.exception_code}"
        reasons = [replace(x, explanation=x.explanation + note) for x in reasons]
    reasons.sort(key=lambda x: x.anomaly_class)
    start, end = record_range(r)
    table = WRITE_TABLE.get(r.function_code) or READ_TABLE[r.function_code]
    what = WhatHappened(
        request_ts=r.request_ts,
        server_ip=r.server_ip,
        unit_id=r.unit_id,
        function_code=r.function_code,
        table=table,
        start_address=start,
        end_address=end,
        value=r.value,
        exception_code=r.exception_code,
    )
    return Finding(what, tuple(reasons))


def _unbaselined(key: DeviceKey, recs: list[TransactionRecord]) -> UnbaselinedDevice:
    return UnbaselinedDevice(
        server_ip=key[0],
        unit_id=key[1],
        transactions=len(recs),
        writes=sum(1 for r in recs if r.function_code in WRITE_TABLE),
        function_codes=tuple(sorted({r.function_code for r in recs})),
        first_ts=recs[0].request_ts,
        last_ts=recs[-1].request_ts,
    )


def detect(baseline: Baseline, records: Iterable[TransactionRecord]) -> DetectionResult:
    """Run classes 1, 2 and 5 over post-baseline records (see split_records)."""
    ordered = sorted(records, key=lambda r: r.request_ts)
    findings: list[Finding] = []
    unseen: dict[DeviceKey, list[TransactionRecord]] = {}
    for r in ordered:
        validate_record(r)
        if r.request_ts < baseline.until:
            raise ValueError(
                f"{r.server_ip} unit {r.unit_id} FC {r.function_code:02d}: request at "
                f"{r.request_ts} is before the baseline end {baseline.until}; detection "
                "takes post-baseline records only"
            )
        key = (r.server_ip, r.unit_id)
        dev = baseline.device(key)
        if dev is None:
            unseen.setdefault(key, []).append(r)
            continue
        finding = _evaluate(r, dev)
        if finding is not None:
            findings.append(finding)
    findings.sort(
        key=lambda f: (
            f.what.request_ts,
            _device_order((f.what.server_ip, f.what.unit_id)),
            f.what.function_code,
            f.what.start_address,
        )
    )
    unbaselined = tuple(
        _unbaselined(k, unseen[k]) for k in sorted(unseen, key=_device_order)
    )
    return DetectionResult(
        until=baseline.until,
        records_analysed=len(ordered),
        findings=tuple(findings),
        unbaselined=unbaselined,
    )
