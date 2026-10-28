"""Shared synthetic pcap builder for the test suite.

Moved unchanged from tests/test_ingest.py so baseline and detection tests can
build fixtures the same way (scapy at test time, written to pytest tmp dirs,
never committed). Additions: an explicit timestamp (`at=`) on Conn packets,
write_multi_req for FC 15/16 requests, and write_multi_resp for their
responses. All packet data is synthetic.
"""

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"
CPORT = 49152
SPORT = 502


def mbap(tid: int, unit: int, pdu: bytes) -> bytes:
    return tid.to_bytes(2, "big") + b"\x00\x00" + (len(pdu) + 1).to_bytes(2, "big") + bytes([unit])


def frame(tid: int, unit: int, pdu: bytes) -> bytes:
    return mbap(tid, unit, pdu) + pdu


def read_req(tid: int, unit: int = 1, fc: int = 3, addr: int = 100, qty: int = 10) -> bytes:
    return frame(tid, unit, bytes([fc]) + addr.to_bytes(2, "big") + qty.to_bytes(2, "big"))


def read_resp(tid: int, unit: int = 1, fc: int = 3, qty: int = 10) -> bytes:
    payload = b"\x00\x01" * qty
    return frame(tid, unit, bytes([fc, len(payload)]) + payload)


def exc_resp(tid: int, unit: int = 1, fc: int = 3, code: int = 2) -> bytes:
    return frame(tid, unit, bytes([fc | 0x80, code]))


def write_single_req(tid: int, unit: int = 1, addr: int = 40, value: int = 7) -> bytes:
    return frame(tid, unit, b"\x06" + addr.to_bytes(2, "big") + value.to_bytes(2, "big"))


def write_multi_req(
    tid: int, unit: int = 1, fc: int = 16, addr: int = 40, values: tuple[int, ...] = (7,)
) -> bytes:
    """FC 16 (write multiple registers) or FC 15 (write multiple coils) request.

    quantity = len(values). FC 16 packs each value as a 2-byte big-endian word;
    FC 15 packs each value as one bit, LSB first within each byte, per the
    Modbus spec. Byte count matches what mbap.py checks for a well-formed request.
    """
    qty = len(values)
    if fc == 16:
        payload = b"".join(v.to_bytes(2, "big") for v in values)
    elif fc == 15:
        packed = bytearray((qty + 7) // 8)
        for i, bit in enumerate(values):
            if bit:
                packed[i // 8] |= 1 << (i % 8)
        payload = bytes(packed)
    else:
        raise ValueError(f"write_multi_req builds FC 15 or 16, got {fc}")
    return frame(
        tid,
        unit,
        bytes([fc]) + addr.to_bytes(2, "big") + qty.to_bytes(2, "big") + bytes([len(payload)]) + payload,
    )


def write_multi_resp(tid: int, unit: int = 1, fc: int = 16, addr: int = 40, qty: int = 1) -> bytes:
    """FC 16 or FC 15 response: echoes the function code, start address and
    quantity of the request, per the Modbus spec (no data bytes)."""
    if fc not in (15, 16):
        raise ValueError(f"write_multi_resp builds FC 15 or 16, got {fc}")
    return frame(tid, unit, bytes([fc]) + addr.to_bytes(2, "big") + qty.to_bytes(2, "big"))


class Conn:
    """Builds one TCP connection's packets with consistent seq numbers."""

    def __init__(
        self,
        client: tuple[str, int] = (CLIENT, CPORT),
        server: tuple[str, int] = (SERVER, SPORT),
        t0: float = 1000.0,
        handshake: bool = True,
    ):
        self.client, self.server = client, server
        self.t = t0
        self.seq = {client: 1000, server: 5000}
        self.pkts: list = []
        if handshake:
            self._pkt(client, server, flags="S")
            self._pkt(server, client, flags="SA")
            self._pkt(client, server, flags="A")

    def _pkt(self, src, dst, flags="PA", payload=b"", seq=None, at=None):
        # at=None keeps the original fixed 0.1 s step. An explicit at= sets the
        # packet time; later default steps continue from it.
        if at is None:
            self.t += 0.1
        else:
            self.t = at
        if seq is None:
            seq = self.seq[src]
        p = (
            Ether()
            / IP(src=src[0], dst=dst[0])
            / TCP(sport=src[1], dport=dst[1], flags=flags, seq=seq)
            / payload
        )
        p.time = self.t
        self.pkts.append(p)
        if seq == self.seq[src]:
            self.seq[src] += len(payload) + (1 if "S" in flags else 0)
        return p

    def send(self, payload: bytes, **kw):
        return self._pkt(self.client, self.server, payload=payload, **kw)

    def recv(self, payload: bytes, **kw):
        return self._pkt(self.server, self.client, payload=payload, **kw)
