"""Hand-rolled MBAP/PDU parser (DECISIONS.md D3).

Fail-closed by construction (D2/D4): every input byte is either consumed into a
ParsedADU, consumed into a ParseAnomaly, or left as a bounded partial buffer
that finish() converts to a truncated_stream anomaly. Nothing is silently
skipped and no input can make the loop stop progressing — each iteration
either consumes at least one full frame or terminates.

Framing recovery policy: when the MBAP header itself is untrustworthy (wrong
protocol id, impossible length) the length field cannot be believed, so exactly
the 7 untrusted header bytes are consumed as one counted anomaly and framing
resumes at the next byte. Fixed-size consumption keeps output independent of
how the TCP stream was segmented into feed() calls (enforced by the corpus
chunking-determinism test, which falsified the earlier discard-the-remainder
policy) and keeps progress linear. Recovery is best-effort: a skip can land
mid-frame and cascade into further counted skips until framing realigns — every
skipped byte is counted, never silent. A malformed PDU inside a *well-framed*
ADU costs only that ADU.
"""

from dataclasses import dataclass

MBAP_HEADER_LEN = 7
# MBAP length field counts unit id + PDU; PDU max is 253 bytes per spec.
MBAP_LENGTH_MIN = 2
MBAP_LENGTH_MAX = 254

READ_FCS = frozenset({1, 2, 3, 4})
WRITE_SINGLE_FCS = frozenset({5, 6})
WRITE_MULTI_FCS = frozenset({15, 16})
SUPPORTED_FCS = READ_FCS | WRITE_SINGLE_FCS | WRITE_MULTI_FCS

# Spec maxima for quantity fields (Modbus Application Protocol V1.1b3).
_MAX_QUANTITY = {1: 2000, 2: 2000, 3: 125, 4: 125, 15: 1968, 16: 123}

# Bytes of offending input carried on an anomaly record. Bounded so a hostile
# pcap cannot inflate report memory; hex-escaped at the report sink (Gate 4).
_ANOMALY_SNIPPET_LEN = 16


@dataclass(frozen=True)
class ParsedADU:
    """One well-formed Modbus TCP ADU."""

    transaction_id: int
    unit_id: int
    function_code: int
    is_request: bool
    is_exception: bool = False
    exception_code: int | None = None
    start_address: int | None = None
    quantity: int | None = None
    value: int | None = None
    byte_count: int | None = None


@dataclass(frozen=True)
class ParseAnomaly:
    """Malformed input, counted and reported — never silently dropped."""

    kind: str  # bad_protocol_id | bad_length | unknown_function_code |
    #            malformed_pdu | truncated_stream
    detail: str
    offset: int  # byte offset into this direction's stream
    snippet: bytes  # bounded slice of the offending bytes


class StreamParser:
    """Incremental parser for one direction of one TCP stream.

    feed() accepts payload bytes in stream order (multiple ADUs per call and
    ADUs split across calls are both handled); finish() flags any leftover
    partial frame as truncated_stream. The internal buffer never exceeds one
    maximal frame after feed() returns, so memory is bounded regardless of
    input.
    """

    def __init__(self, is_request: bool):
        self.is_request = is_request
        self._buf = b""
        self._offset = 0  # stream offset of _buf[0]

    def feed(self, data: bytes) -> list[ParsedADU | ParseAnomaly]:
        self._buf += data
        out: list[ParsedADU | ParseAnomaly] = []
        while len(self._buf) >= MBAP_HEADER_LEN:
            transaction_id = int.from_bytes(self._buf[0:2], "big")
            protocol_id = int.from_bytes(self._buf[2:4], "big")
            length = int.from_bytes(self._buf[4:6], "big")
            unit_id = self._buf[6]

            if protocol_id != 0:
                out.append(self._skip_header("bad_protocol_id", f"protocol id {protocol_id:#06x}"))
                continue
            if not (MBAP_LENGTH_MIN <= length <= MBAP_LENGTH_MAX):
                out.append(self._skip_header("bad_length", f"length field {length}"))
                continue

            frame_len = 6 + length
            if len(self._buf) < frame_len:
                return out  # partial frame — wait for more bytes or finish()

            pdu = self._buf[MBAP_HEADER_LEN:frame_len]
            out.append(self._parse_pdu(transaction_id, unit_id, pdu))
            self._buf = self._buf[frame_len:]
            self._offset += frame_len
        return out

    def finish(self) -> list[ParseAnomaly]:
        """End of stream: any partial frame becomes a truncated_stream anomaly."""
        if not self._buf:
            return []
        anomaly = ParseAnomaly(
            kind="truncated_stream",
            detail=f"{len(self._buf)} byte partial frame at end of stream",
            offset=self._offset,
            snippet=self._buf[:_ANOMALY_SNIPPET_LEN],
        )
        self._offset += len(self._buf)
        self._buf = b""
        return [anomaly]

    def _skip_header(self, kind: str, detail: str) -> ParseAnomaly:
        """Consume exactly the 7 untrusted header bytes; framing resumes after.

        Fixed-size consumption is what makes output independent of feed()
        chunking — the decision uses only the first 7 buffered bytes and always
        costs exactly 7, so segmentation cannot change the result.
        """
        anomaly = ParseAnomaly(
            kind=kind,
            detail=f"{detail}; 7 header bytes skipped, framing resumes at next byte",
            offset=self._offset,
            snippet=self._buf[:MBAP_HEADER_LEN],
        )
        self._buf = self._buf[MBAP_HEADER_LEN:]
        self._offset += MBAP_HEADER_LEN
        return anomaly

    def _pdu_anomaly(self, detail: str, pdu: bytes) -> ParseAnomaly:
        return ParseAnomaly(
            kind="malformed_pdu",
            detail=detail,
            offset=self._offset,
            snippet=pdu[:_ANOMALY_SNIPPET_LEN],
        )

    def _parse_pdu(self, transaction_id: int, unit_id: int, pdu: bytes) -> ParsedADU | ParseAnomaly:
        function_code = pdu[0]  # length >= 2 guarantees pdu is non-empty
        data = pdu[1:]

        if function_code & 0x80 and not self.is_request:
            base_fc = function_code & 0x7F
            if len(data) != 1:
                return self._pdu_anomaly(
                    f"exception response for fc {base_fc} with {len(data)} data bytes (want 1)", pdu
                )
            # Exception codes outside the spec's defined set still parse: the
            # code is data, and a bogus one is behavioral signal, not framing.
            return ParsedADU(
                transaction_id=transaction_id,
                unit_id=unit_id,
                function_code=base_fc,
                is_request=False,
                is_exception=True,
                exception_code=data[0],
            )

        if function_code not in SUPPORTED_FCS:
            return ParseAnomaly(
                kind="unknown_function_code",
                detail=f"function code {function_code:#04x} not in supported set",
                offset=self._offset,
                snippet=pdu[:_ANOMALY_SNIPPET_LEN],
            )

        if self.is_request:
            return self._parse_request(transaction_id, unit_id, function_code, data, pdu)
        return self._parse_response(transaction_id, unit_id, function_code, data, pdu)

    def _parse_request(
        self, transaction_id: int, unit_id: int, fc: int, data: bytes, pdu: bytes
    ) -> ParsedADU | ParseAnomaly:
        if fc in READ_FCS:
            if len(data) != 4:
                return self._pdu_anomaly(f"fc {fc} request with {len(data)} data bytes (want 4)", pdu)
            quantity = int.from_bytes(data[2:4], "big")
            if not (1 <= quantity <= _MAX_QUANTITY[fc]):
                return self._pdu_anomaly(f"fc {fc} request quantity {quantity} outside 1..{_MAX_QUANTITY[fc]}", pdu)
            return ParsedADU(
                transaction_id=transaction_id,
                unit_id=unit_id,
                function_code=fc,
                is_request=True,
                start_address=int.from_bytes(data[0:2], "big"),
                quantity=quantity,
            )

        if fc in WRITE_SINGLE_FCS:
            if len(data) != 4:
                return self._pdu_anomaly(f"fc {fc} request with {len(data)} data bytes (want 4)", pdu)
            return ParsedADU(
                transaction_id=transaction_id,
                unit_id=unit_id,
                function_code=fc,
                is_request=True,
                start_address=int.from_bytes(data[0:2], "big"),
                value=int.from_bytes(data[2:4], "big"),
            )

        # fc 15 / 16: addr(2) quantity(2) byte_count(1) payload(byte_count)
        if len(data) < 5:
            return self._pdu_anomaly(f"fc {fc} request with {len(data)} data bytes (want >= 5)", pdu)
        quantity = int.from_bytes(data[2:4], "big")
        byte_count = data[4]
        if not (1 <= quantity <= _MAX_QUANTITY[fc]):
            return self._pdu_anomaly(f"fc {fc} request quantity {quantity} outside 1..{_MAX_QUANTITY[fc]}", pdu)
        expected = (quantity + 7) // 8 if fc == 15 else quantity * 2
        if byte_count != expected or len(data) - 5 != byte_count:
            return self._pdu_anomaly(
                f"fc {fc} request byte count {byte_count} / payload {len(data) - 5} "
                f"inconsistent with quantity {quantity} (want {expected})",
                pdu,
            )
        return ParsedADU(
            transaction_id=transaction_id,
            unit_id=unit_id,
            function_code=fc,
            is_request=True,
            start_address=int.from_bytes(data[0:2], "big"),
            quantity=quantity,
            byte_count=byte_count,
        )

    def _parse_response(
        self, transaction_id: int, unit_id: int, fc: int, data: bytes, pdu: bytes
    ) -> ParsedADU | ParseAnomaly:
        if fc in READ_FCS:
            if not data or data[0] != len(data) - 1:
                got = data[0] if data else "none"
                return self._pdu_anomaly(
                    f"fc {fc} response byte count {got} vs {max(len(data) - 1, 0)} payload bytes", pdu
                )
            return ParsedADU(
                transaction_id=transaction_id,
                unit_id=unit_id,
                function_code=fc,
                is_request=False,
                byte_count=data[0],
            )

        if fc in WRITE_SINGLE_FCS:
            if len(data) != 4:
                return self._pdu_anomaly(f"fc {fc} response with {len(data)} data bytes (want 4)", pdu)
            return ParsedADU(
                transaction_id=transaction_id,
                unit_id=unit_id,
                function_code=fc,
                is_request=False,
                start_address=int.from_bytes(data[0:2], "big"),
                value=int.from_bytes(data[2:4], "big"),
            )

        # fc 15 / 16 response: addr(2) quantity(2)
        if len(data) != 4:
            return self._pdu_anomaly(f"fc {fc} response with {len(data)} data bytes (want 4)", pdu)
        quantity = int.from_bytes(data[2:4], "big")
        if not (1 <= quantity <= _MAX_QUANTITY[fc]):
            return self._pdu_anomaly(f"fc {fc} response quantity {quantity} outside 1..{_MAX_QUANTITY[fc]}", pdu)
        return ParsedADU(
            transaction_id=transaction_id,
            unit_id=unit_id,
            function_code=fc,
            is_request=False,
            start_address=int.from_bytes(data[0:2], "big"),
            quantity=quantity,
        )
