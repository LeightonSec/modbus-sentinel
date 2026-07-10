"""Pcap ingestion: TCP streams → direction attribution → pairing (D10/D11).

Pipeline: scapy PcapReader (streaming, D3) → per-4-tuple stream state →
direction attribution (D10: port-502 rule + SYN rule, conflict or absence of
evidence = counted refusal, never a guess) → one StreamParser per direction
(mbap.py, fail-closed) → transaction pairing on (transaction id, unit id)
(D11) → TransactionRecords keyed by (server IP, unit id) (D1).

Fail-closed accounting (D2/D4): every Modbus stream byte ends up in a
TransactionRecord, a counted IngestAnomaly, or a counter on IngestResult.
Unattributed and direction-conflict streams are tallied whole (packets/bytes)
and surfaced as one anomaly each at finalization. TCP sequence gaps flush the
parser (partial frame → truncated_stream) and are counted as reassembly_gap —
post-gap bytes are then fed to an empty parser buffer so a gap can never
silently mispair frame boundaries. Retransmitted bytes are deduplicated by
sequence number and tallied byte-exactly (retransmitted_bytes), never
double-fed — full and partial overlaps both land in the counter, so the
byte-accounting invariant above holds with no silent trim. Overlap handling is
first-copy-wins by sequence number: overlap *content* is not compared against
what was already delivered (that would require retaining fed bytes), so a
capture containing divergent overlapping segments — the classic passive-monitor
desync evasion — is resolved by arrival order, not endpoint semantics.
Declared v0.1 limitation.

Stream lifecycle (D11): pairing and parser state live per connection
incarnation. A new SYN on a live 4-tuple finalizes the old incarnation
(outstanding requests → orphan_request, partial frames → truncated_stream)
before state resets; end of capture finalizes every incarnation the same way.
A SYN carrying payload (TCP Fast Open, or crafted) has its bytes delivered
into the NEW incarnation — the correct destination, but stated explicitly:
real Modbus masters essentially never use TFO, so this path is a declared
boundary, not a tested one.

Scope note: every TCP stream in the capture is attributed and parsed by the
D10 rules — the input is declared to be a Modbus TCP pcap. Non-Modbus TCP
streams that pass attribution produce bounded, counted parse anomalies
(mbap.py guarantees ≥7 bytes consumed per anomaly), visible in the report
rather than filtered invisibly.
"""

from dataclasses import dataclass, field

from scapy.layers.inet import IP, TCP
from scapy.utils import PcapReader

from modbus_sentinel.mbap import ParseAnomaly, ParsedADU, StreamParser

MODBUS_PORT = 502

# D11: outstanding-request table cap = the transaction-id space. A pcap built
# to inflate state gets reported (state_overflow), not obeyed.
OUTSTANDING_CAP = 65536

_SEQ_MOD = 2**32
_SEQ_HALF = 2**31

# (ip, port) endpoint of a TCP stream.
_Endpoint = tuple[str, int]


@dataclass(frozen=True)
class TransactionRecord:
    """One paired Modbus transaction (D11 record shape).

    Canonical timestamp for baseline math is request_ts — D5's poll-group
    intervals model master behavior, and the request is the master's act.
    """

    request_ts: float
    response_ts: float
    server_ip: str
    unit_id: int
    function_code: int
    is_write: bool
    is_exception: bool
    exception_code: int | None
    start_address: int | None
    quantity: int | None
    value: int | None


@dataclass(frozen=True)
class IngestAnomaly:
    """Stream-context anomaly: parser anomalies plus ingest-level kinds.

    kinds from mbap.py: bad_protocol_id | bad_length | unknown_function_code |
    malformed_pdu | truncated_stream
    kinds added here:    unattributed_stream | direction_conflict |
    orphan_request | orphan_response | pairing_mismatch | state_overflow |
    reassembly_gap
    """

    kind: str
    detail: str
    stream: str
    timestamp: float | None
    snippet: bytes = b""  # hex-escaped at the report sink (Gate 4), never printed raw


@dataclass
class IngestResult:
    records: list[TransactionRecord] = field(default_factory=list)
    anomalies: list[IngestAnomaly] = field(default_factory=list)
    packets_total: int = 0
    packets_non_tcp: int = 0
    # Byte-exact dedup accounting: full retransmits tally their whole payload,
    # partial overlaps tally the trimmed prefix. Without the bytes counter a
    # partial overlap's trimmed prefix lands in NO bucket — a silent violation
    # of the module docstring's every-byte-lands-somewhere invariant (round 6).
    retransmitted_segments: int = 0
    retransmitted_bytes: int = 0

    def anomaly_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for a in self.anomalies:
            counts[a.kind] = counts.get(a.kind, 0) + 1
        return counts


def _stream_id(a: _Endpoint, b: _Endpoint) -> str:
    lo, hi = sorted((a, b))
    return f"{lo[0]}:{lo[1]}<->{hi[0]}:{hi[1]}"


class _Incarnation:
    """One connection incarnation of a 4-tuple: direction, parsers, pairing."""

    def __init__(self, end_a: _Endpoint, end_b: _Endpoint, syn_from: _Endpoint | None):
        self.stream = _stream_id(end_a, end_b)
        self.refused: str | None = None  # unattributed_stream | direction_conflict
        self.refused_packets = 0
        self.refused_bytes = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None

        server = self._attribute(end_a, end_b, syn_from)
        if server is None:
            return
        self.server: _Endpoint = server
        self.client: _Endpoint = end_b if server == end_a else end_a
        self._parsers = {
            self.client: StreamParser(is_request=True),
            self.server: StreamParser(is_request=False),
        }
        self._expected_seq: dict[_Endpoint, int | None] = {self.client: None, self.server: None}
        # (transaction id, unit id) -> (request ADU, request timestamp)
        self._outstanding: dict[tuple[int, int], tuple[ParsedADU, float]] = {}

    def _attribute(
        self, end_a: _Endpoint, end_b: _Endpoint, syn_from: _Endpoint | None
    ) -> _Endpoint | None:
        """D10: return the server endpoint, or None with self.refused set."""
        port_says: _Endpoint | None = None
        a_is_502 = end_a[1] == MODBUS_PORT
        b_is_502 = end_b[1] == MODBUS_PORT
        if a_is_502 != b_is_502:  # exactly one endpoint on 502
            port_says = end_a if a_is_502 else end_b
        syn_says: _Endpoint | None = None
        if syn_from is not None:
            syn_says = end_b if syn_from == end_a else end_a

        if port_says is not None and syn_says is not None and port_says != syn_says:
            self.refused = "direction_conflict"
            return None
        server = port_says if port_says is not None else syn_says
        if server is None:
            self.refused = "unattributed_stream"
        return server

    def deliver(self, src: _Endpoint, seq: int, payload: bytes, ts: float, result: IngestResult) -> None:
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts
        if self.refused is not None:
            self.refused_packets += 1
            self.refused_bytes += len(payload)
            return

        expected = self._expected_seq[src]
        if expected is not None:
            delta = (seq - expected) % _SEQ_MOD
            if delta == 0:
                pass  # in order
            elif delta < _SEQ_HALF:
                # Forward gap: bytes were lost or captured out of order. Flush
                # the parser (partial frame → truncated_stream) so post-gap
                # bytes never splice onto a pre-gap partial frame, count the
                # gap, resync.
                for anomaly in self._parsers[src].finish():
                    self._emit(anomaly, ts, result)
                result.anomalies.append(
                    IngestAnomaly(
                        kind="reassembly_gap",
                        detail=f"{delta} bytes missing before segment (seq jump)",
                        stream=self.stream,
                        timestamp=ts,
                    )
                )
            else:
                # Segment (partially) precedes what was already delivered.
                # First-copy-wins: dedup by sequence number only; overlap
                # content is not compared (declared v0.1 limitation, see
                # module docstring). Every deduplicated byte is tallied.
                overlap = _SEQ_MOD - delta
                if overlap >= len(payload):
                    result.retransmitted_segments += 1
                    result.retransmitted_bytes += len(payload)
                    return
                result.retransmitted_bytes += overlap
                payload = payload[overlap:]  # feed only the new tail
        self._expected_seq[src] = (seq + len(payload)) % _SEQ_MOD

        for item in self._parsers[src].feed(payload):
            if isinstance(item, ParseAnomaly):
                self._emit(item, ts, result)
            elif src == self.client:
                self._handle_request(item, ts, result)
            else:
                self._handle_response(item, ts, result)

    def _handle_request(self, adu: ParsedADU, ts: float, result: IngestResult) -> None:
        key = (adu.transaction_id, adu.unit_id)
        stale = self._outstanding.pop(key, None)
        if stale is not None:
            result.anomalies.append(
                IngestAnomaly(
                    kind="orphan_request",
                    detail=(
                        f"tid_reuse: request tid={key[0]} unit={key[1]} superseded "
                        "while unanswered"
                    ),
                    stream=self.stream,
                    timestamp=stale[1],
                )
            )
        elif len(self._outstanding) >= OUTSTANDING_CAP:
            result.anomalies.append(
                IngestAnomaly(
                    kind="state_overflow",
                    detail=(
                        f"outstanding-request table at cap {OUTSTANDING_CAP}; "
                        f"request tid={key[0]} unit={key[1]} counted, not tracked"
                    ),
                    stream=self.stream,
                    timestamp=ts,
                )
            )
            return
        self._outstanding[key] = (adu, ts)

    def _handle_response(self, adu: ParsedADU, ts: float, result: IngestResult) -> None:
        key = (adu.transaction_id, adu.unit_id)
        pending = self._outstanding.pop(key, None)
        if pending is None:
            result.anomalies.append(
                IngestAnomaly(
                    kind="orphan_response",
                    detail=f"response tid={key[0]} unit={key[1]} with no outstanding request",
                    stream=self.stream,
                    timestamp=ts,
                )
            )
            return
        request, request_ts = pending
        # D11: match on parser-normalized FC. mbap.py has already stripped the
        # 0x80 exception bit, so exception responses pair here and become
        # records with is_exception=True — never discarded.
        if adu.function_code != request.function_code:
            result.anomalies.append(
                IngestAnomaly(
                    kind="pairing_mismatch",
                    detail=(
                        f"tid={key[0]} unit={key[1]}: response fc {adu.function_code} "
                        f"!= request fc {request.function_code}"
                    ),
                    stream=self.stream,
                    timestamp=ts,
                )
            )
            return
        result.records.append(
            TransactionRecord(
                request_ts=request_ts,
                response_ts=ts,
                server_ip=self.server[0],
                unit_id=request.unit_id,
                function_code=request.function_code,
                is_write=request.function_code in {5, 6, 15, 16},
                is_exception=adu.is_exception,
                exception_code=adu.exception_code,
                start_address=request.start_address,
                quantity=request.quantity,
                value=request.value,
            )
        )

    def finalize(self, result: IngestResult) -> None:
        """End of incarnation (new SYN on the 4-tuple, or end of capture)."""
        if self.refused is not None:
            result.anomalies.append(
                IngestAnomaly(
                    kind=self.refused,
                    detail=(
                        f"stream not parsed: {self.refused_packets} payload packets, "
                        f"{self.refused_bytes} bytes"
                    ),
                    stream=self.stream,
                    timestamp=self.first_ts,
                )
            )
            return
        for parser in self._parsers.values():
            for anomaly in parser.finish():
                self._emit(anomaly, self.last_ts, result)
        for (tid, unit), (_, request_ts) in self._outstanding.items():
            result.anomalies.append(
                IngestAnomaly(
                    kind="orphan_request",
                    detail=f"request tid={tid} unit={unit} unanswered at stream end",
                    stream=self.stream,
                    timestamp=request_ts,
                )
            )
        self._outstanding.clear()

    def _emit(self, anomaly: ParseAnomaly, ts: float | None, result: IngestResult) -> None:
        result.anomalies.append(
            IngestAnomaly(
                kind=anomaly.kind,
                detail=anomaly.detail,
                stream=self.stream,
                timestamp=ts,
                snippet=anomaly.snippet,
            )
        )


def ingest_pcap(path: str) -> IngestResult:
    """Stream a pcap into TransactionRecords + counted anomalies."""
    result = IngestResult()
    streams: dict[tuple[_Endpoint, _Endpoint], _Incarnation] = {}

    with PcapReader(path) as reader:
        for pkt in reader:
            result.packets_total += 1
            if IP not in pkt or TCP not in pkt:
                result.packets_non_tcp += 1
                continue
            ip = pkt[IP]
            tcp = pkt[TCP]
            src: _Endpoint = (ip.src, int(tcp.sport))
            dst: _Endpoint = (ip.dst, int(tcp.dport))
            key = (src, dst) if src <= dst else (dst, src)
            ts = float(pkt.time)

            flags = tcp.flags
            if flags.S and not flags.A:  # new SYN: D11 incarnation boundary
                old = streams.get(key)
                if old is not None:
                    old.finalize(result)
                streams[key] = _Incarnation(src, dst, syn_from=src)
            elif key not in streams:
                # Mid-capture stream: no handshake evidence exists for this
                # incarnation (a later SYN would start a new one), so the
                # port rule alone decides — or the stream is refused (D10).
                streams[key] = _Incarnation(src, dst, syn_from=None)

            # Ethernet trailer padding lands in scapy's TCP payload; trust the
            # IP header lengths to bound the slice instead.
            payload = bytes(tcp.payload)
            declared = ip.len - ip.ihl * 4 - tcp.dataofs * 4
            if 0 <= declared < len(payload):
                payload = payload[:declared]
            if payload:
                streams[key].deliver(src, int(tcp.seq), payload, ts, result)

    for incarnation in streams.values():
        incarnation.finalize(result)
    return result
