"""Write a small synthetic Modbus TCP capture for trying modbus-sentinel.

All packet data is synthetic and built here; nothing is captured. Addresses are
from the 192.0.2.0/24 documentation range, MAC addresses are fixed locally
administered values, and every timestamp is fixed, so each run writes the same
file. scapy is the only dependency; nothing is imported from tests/.

Contents: one client (192.0.2.10) and one server (192.0.2.20, port 502, unit 1)
on one TCP connection, from 2026-07-06T08:00:00Z for four minutes:

- every 5 s the client reads holding registers 100-109 (FC 3);
- every 30 s it writes 7 to holding register 40 (FC 6);
- at 08:02:30Z, planted: an FC 6 write of 500 to holding register 105;
- at 08:02:50Z, planted: an FC 8 diagnostics request, sub-function 0x0001.

Every request gets a normal response. Use the cutoff 2026-07-06T08:02:00Z
(epoch 1783324920): the first two minutes become the baseline and the last two
are checked against it.

    python -m scripts.make_demo_pcap demo.pcap
    modbus-sentinel demo.pcap --baseline-until 2026-07-06T08:02:00Z
"""

import argparse
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

CLIENT = ("192.0.2.10", 49152)
SERVER = ("192.0.2.20", 502)
MAC = {CLIENT: "02:00:00:00:00:0a", SERVER: "02:00:00:00:00:14"}
UNIT = 1
T0 = 1783324800.0  # 2026-07-06T08:00:00Z
END = T0 + 240
RESPONSE_DELAY = 0.05


def frame(tid: int, pdu: bytes) -> bytes:
    """MBAP header (transaction id, protocol 0, length, unit) plus the PDU."""
    return tid.to_bytes(2, "big") + b"\x00\x00" + (len(pdu) + 1).to_bytes(2, "big") + bytes([UNIT]) + pdu


def read_holding(start: int, quantity: int) -> tuple[bytes, bytes]:
    request = bytes([3]) + start.to_bytes(2, "big") + quantity.to_bytes(2, "big")
    data = b"\x00\x00" * quantity
    return request, bytes([3, len(data)]) + data


def write_register(address: int, value: int) -> tuple[bytes, bytes]:
    pdu = bytes([6]) + address.to_bytes(2, "big") + value.to_bytes(2, "big")
    return pdu, pdu  # the FC 6 response echoes the request


def diagnostics(subfunction: int) -> tuple[bytes, bytes]:
    pdu = bytes([8]) + subfunction.to_bytes(2, "big") + b"\x00\x00"
    return pdu, pdu  # echoed, as for the query-data sub-functions


def events() -> list[tuple[float, bytes, bytes]]:
    """(request time, request PDU, response PDU), sorted by time."""
    out = []
    i = 0
    while T0 + 0.2 + 5 * i < END:
        out.append((T0 + 0.2 + 5 * i, *read_holding(100, 10)))
        i += 1
    i = 0
    while T0 + 1.0 + 30 * i < END:
        out.append((T0 + 1.0 + 30 * i, *write_register(40, 7)))
        i += 1
    out.append((T0 + 150.3, *write_register(105, 500)))  # planted, after the cutoff
    out.append((T0 + 170.3, *diagnostics(0x0001)))  # planted, after the cutoff
    return sorted(out, key=lambda e: e[0])


class Connection:
    """One TCP connection with consistent sequence numbers."""

    def __init__(self) -> None:
        self.seq = {CLIENT: 1000, SERVER: 5000}
        self.packets: list = []
        self.add(CLIENT, SERVER, "S", b"", T0 - 1.0)
        self.add(SERVER, CLIENT, "SA", b"", T0 - 0.9)
        self.add(CLIENT, SERVER, "A", b"", T0 - 0.8)

    def add(self, src: tuple[str, int], dst: tuple[str, int], flags: str, payload: bytes, at: float) -> None:
        p = (
            Ether(src=MAC[src], dst=MAC[dst])
            / IP(src=src[0], dst=dst[0])
            / TCP(sport=src[1], dport=dst[1], flags=flags, seq=self.seq[src])
            / payload
        )
        p.time = at
        self.packets.append(p)
        self.seq[src] += len(payload) + (1 if "S" in flags else 0)


def build() -> list:
    c = Connection()
    for tid, (at, request, response) in enumerate(events(), start=1):
        c.add(CLIENT, SERVER, "PA", frame(tid, request), at)
        c.add(SERVER, CLIENT, "PA", frame(tid, response), at + RESPONSE_DELAY)
    return c.packets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the synthetic modbus-sentinel demo capture.")
    parser.add_argument("out", type=Path, help="output pcap path")
    args = parser.parse_args(argv)
    packets = build()
    wrpcap(str(args.out), packets)
    print(f"wrote {args.out}: {len(packets)} packets; use --baseline-until 2026-07-06T08:02:00Z")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
