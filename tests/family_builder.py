"""Shared synthetic capture family for detection and CLI tests.

Moved unchanged from tests/test_detect.py (constants, fc05, _every,
family_events), so the Gate 3 pass-criteria pcaps and the CLI pcaps come from
one generator: same devices, rates and timing, i.e. the same capture family
(DESIGN.md Gate 3). write_family_pcap is new: it writes the family, plus any
injected events, to a pcap file for tests that need a path (the CLI). All
packet data is synthetic.
"""

from collections.abc import Callable
from pathlib import Path

from pcap_builder import Conn, frame, read_req, read_resp, write_single_req
from scapy.utils import wrpcap

T0 = 1783324800.0  # 2026-07-06T08:00:00Z
UNTIL = T0 + 120  # baseline period: T0 to T0 + 120 s
END = T0 + 240  # detection period: T0 + 120 s to T0 + 240 s

Builder = Callable[[int], bytes]
Event = tuple[float, Builder, Builder | None]


def fc05(tid: int, unit: int, addr: int) -> bytes:
    return frame(tid, unit, b"\x05" + addr.to_bytes(2, "big") + b"\xff\x00")


def fc08(tid: int, unit: int, subfunction: int = 0x0000) -> bytes:
    """FC 08 diagnostics, sub-function plus one data word; the echo is identical."""
    return frame(tid, unit, b"\x08" + subfunction.to_bytes(2, "big") + b"\x00\x00")


def fc43_req(tid: int, unit: int) -> bytes:
    """FC 43 / MEI 0x0E read device id request: read code 1, object id 0."""
    return frame(tid, unit, b"\x2b\x0e\x01\x00")


def fc43_resp(tid: int, unit: int) -> bytes:
    """FC 43 / MEI 0x0E response with one object; the value is discarded (D13)."""
    return frame(tid, unit, b"\x2b\x0e\x01\x01\x00\x00\x01" + b"\x00\x04ACME")


def _every(period: float, offset: float, req: Builder, resp: Builder) -> list[Event]:
    out = []
    i = 0
    while T0 + offset + i * period < END:
        out.append((T0 + offset + i * period, req, resp))
        i += 1
    return out


def family_events() -> list[Event]:
    """Device A (unit 1) and device B (unit 2) on one IP, same pattern in both
    periods. Fractional offsets keep every request at least 0.1 s apart."""
    ev: list[Event] = []
    ev += _every(2, 0.0, lambda t: read_req(t, 1, 3, 100, 10), lambda t: read_resp(t, 1, 3, 10))
    ev += _every(5, 0.5, lambda t: read_req(t, 1, 3, 200, 2), lambda t: read_resp(t, 1, 3, 2))
    ev += _every(10, 0.7, lambda t: read_req(t, 1, 4, 50, 1), lambda t: read_resp(t, 1, 4, 1))
    ev += _every(30, 0.9, lambda t: write_single_req(t, 1, 40, 7), lambda t: write_single_req(t, 1, 40, 7))
    ev += _every(3, 0.2, lambda t: read_req(t, 2, 1, 0, 16), lambda t: read_resp(t, 2, 1, 1))
    ev += _every(30, 0.4, lambda t: fc05(t, 2, 3), lambda t: fc05(t, 2, 3))
    return ev


def write_family_pcap(path: Path, inject: list[Event] | None = None) -> Path:
    """Write the family plus injected events to path; returns path."""
    events = sorted(family_events() + (inject or []), key=lambda e: e[0])
    c = Conn(t0=T0 - 1)
    for tid, (t, req, resp) in enumerate(events, start=1):
        c.send(req(tid), at=t)
        if resp is not None:
            c.recv(resp(tid), at=t + 0.05)
    wrpcap(str(path), c.pkts)
    return path
