"""Unit tests for the hand-rolled MBAP/PDU parser (DESIGN.md Gate 1 criterion 1).

Covers FC 01, 02, 03, 04, 05, 06, 15, 16 requests and responses, exception
responses, pipelined ADUs, frames split across feed() calls, and end-of-stream
truncation. FC 08 and FC 43 (MEI 0x0E) are covered at the end (D13).
"""

from pathlib import Path

import pytest

from modbus_sentinel.mbap import ParseAnomaly, ParsedADU, StreamParser


def frame(pdu: bytes, transaction_id: int = 1, unit_id: int = 1) -> bytes:
    return (
        transaction_id.to_bytes(2, "big")
        + b"\x00\x00"
        + (len(pdu) + 1).to_bytes(2, "big")
        + bytes([unit_id])
        + pdu
    )


def parse_one(pdu: bytes, is_request: bool, **frame_kwargs) -> ParsedADU:
    parser = StreamParser(is_request=is_request)
    out = parser.feed(frame(pdu, **frame_kwargs))
    assert parser.finish() == []
    assert len(out) == 1, out
    assert isinstance(out[0], ParsedADU), out[0]
    return out[0]


@pytest.mark.parametrize("fc", [1, 2, 3, 4])
def test_read_request(fc: int) -> None:
    adu = parse_one(bytes([fc]) + (0x0010).to_bytes(2, "big") + (8).to_bytes(2, "big"), is_request=True)
    assert adu.function_code == fc
    assert adu.is_request and not adu.is_exception
    assert adu.start_address == 0x0010
    assert adu.quantity == 8


@pytest.mark.parametrize("fc", [1, 2, 3, 4])
def test_read_response(fc: int) -> None:
    adu = parse_one(bytes([fc, 2, 0xAB, 0xCD]), is_request=False)
    assert adu.function_code == fc
    assert not adu.is_request
    assert adu.byte_count == 2
    assert adu.start_address is None  # responses carry no address; pairing recovers it


@pytest.mark.parametrize("fc,value", [(5, 0xFF00), (6, 0x1234)])
def test_write_single_request_and_response(fc: int, value: int) -> None:
    pdu = bytes([fc]) + (0x0002).to_bytes(2, "big") + value.to_bytes(2, "big")
    for is_request in (True, False):
        adu = parse_one(pdu, is_request=is_request)
        assert adu.function_code == fc
        assert adu.start_address == 0x0002
        assert adu.value == value


def test_fc15_request() -> None:
    quantity = 16  # 16 coils -> 2 data bytes
    pdu = bytes([15]) + (0).to_bytes(2, "big") + quantity.to_bytes(2, "big") + bytes([2, 0xFF, 0x00])
    adu = parse_one(pdu, is_request=True)
    assert adu.function_code == 15
    assert adu.quantity == 16
    assert adu.byte_count == 2


def test_fc16_request() -> None:
    quantity = 2
    pdu = bytes([16]) + (0x0100).to_bytes(2, "big") + quantity.to_bytes(2, "big") + bytes([4, 0, 1, 0, 2])
    adu = parse_one(pdu, is_request=True)
    assert adu.function_code == 16
    assert adu.start_address == 0x0100
    assert adu.quantity == 2
    assert adu.byte_count == 4


@pytest.mark.parametrize("fc", [15, 16])
def test_write_multi_response(fc: int) -> None:
    pdu = bytes([fc]) + (0x0100).to_bytes(2, "big") + (2).to_bytes(2, "big")
    adu = parse_one(pdu, is_request=False)
    assert adu.function_code == fc
    assert adu.start_address == 0x0100
    assert adu.quantity == 2


def test_exception_response() -> None:
    adu = parse_one(bytes([0x83, 0x02]), is_request=False)
    assert adu.is_exception
    assert adu.function_code == 3  # base fc, high bit stripped
    assert adu.exception_code == 2


def test_exception_code_outside_spec_still_parses() -> None:
    adu = parse_one(bytes([0x90, 0x99]), is_request=False)
    assert adu.is_exception
    assert adu.exception_code == 0x99


def test_pipelined_adus_one_feed() -> None:
    pdu = bytes([3]) + (0).to_bytes(2, "big") + (1).to_bytes(2, "big")
    data = b"".join(frame(pdu, transaction_id=t) for t in (7, 8, 9))
    parser = StreamParser(is_request=True)
    out = parser.feed(data)
    assert [a.transaction_id for a in out] == [7, 8, 9]
    assert parser.finish() == []


def test_frame_split_across_feeds() -> None:
    data = frame(bytes([3]) + (0).to_bytes(2, "big") + (1).to_bytes(2, "big"))
    parser = StreamParser(is_request=True)
    assert parser.feed(data[:5]) == []
    out = parser.feed(data[5:])
    assert len(out) == 1 and isinstance(out[0], ParsedADU)
    assert parser.finish() == []


def test_truncated_stream_counted_at_finish() -> None:
    data = frame(bytes([3]) + (0).to_bytes(2, "big") + (1).to_bytes(2, "big"))
    parser = StreamParser(is_request=True)
    assert parser.feed(data[:-2]) == []
    anomalies = parser.finish()
    assert len(anomalies) == 1
    assert anomalies[0].kind == "truncated_stream"


def test_malformed_pdu_costs_one_adu_not_the_stream() -> None:
    good = frame(bytes([3]) + (0).to_bytes(2, "big") + (1).to_bytes(2, "big"), transaction_id=2)
    bad = frame(bytes([0x2A, 0xDE, 0xAD]), transaction_id=1)  # unknown fc, well framed
    parser = StreamParser(is_request=True)
    out = parser.feed(bad + good)
    assert isinstance(out[0], ParseAnomaly) and out[0].kind == "unknown_function_code"
    assert isinstance(out[1], ParsedADU) and out[1].transaction_id == 2


# A good FC 3 ADU for each direction, fed ahead of the bad frame so the anomaly
# offset is not 0 and the good ADU proves the bad frame costs only itself.
GOOD_FC3 = {
    True: bytes([3]) + (0).to_bytes(2, "big") + (1).to_bytes(2, "big"),
    False: bytes([3, 2, 0xAB, 0xCD]),
}


def anomaly_after_good_adu(pdu: bytes, is_request: bool) -> tuple[ParseAnomaly, int]:
    """Feed one good ADU, then pdu as the second frame. Returns the one anomaly
    and the offset it must carry: the first byte after the good frame."""
    good = frame(GOOD_FC3[is_request], transaction_id=2)
    parser = StreamParser(is_request=is_request)
    out = parser.feed(good + frame(pdu))
    assert parser.finish() == []
    assert len(out) == 2, out
    assert isinstance(out[0], ParsedADU) and out[0].transaction_id == 2
    assert isinstance(out[1], ParseAnomaly), out[1]
    return out[1], len(good)


@pytest.mark.parametrize("fc", [1, 2, 3, 4])
@pytest.mark.parametrize("data", [b"\x00\x10\x08", b"\x00\x10\x00\x08\x00"])
def test_read_request_wrong_data_length_malformed(fc: int, data: bytes) -> None:
    """A read request is address(2) plus quantity(2): three or five data bytes
    is malformed. Both inputs would otherwise yield a quantity of 8."""
    a, at = anomaly_after_good_adu(bytes([fc]) + data, is_request=True)
    assert a.kind == "malformed_pdu" and a.offset == at
    assert a.detail == f"fc {fc} request with {len(data)} data bytes (want 4)"


@pytest.mark.parametrize("fc", [15, 16])
def test_write_multi_request_missing_byte_count_malformed(fc: int) -> None:
    """An FC 15/16 request needs address, quantity and byte count (5 bytes)
    before any payload. Four data bytes is the response shape sent as a request."""
    a, at = anomaly_after_good_adu(bytes([fc]) + (0x0100).to_bytes(2, "big") + (1).to_bytes(2, "big"), is_request=True)
    assert a.kind == "malformed_pdu" and a.offset == at
    assert a.detail == f"fc {fc} request with 4 data bytes (want >= 5)"


@pytest.mark.parametrize(
    "fc,quantity,detail",
    [
        (15, 0, "fc 15 response quantity 0 outside 1..1968"),
        (15, 1969, "fc 15 response quantity 1969 outside 1..1968"),
        (16, 0, "fc 16 response quantity 0 outside 1..123"),
        (16, 124, "fc 16 response quantity 124 outside 1..123"),
    ],
)
def test_write_multi_response_quantity_out_of_range_malformed(fc: int, quantity: int, detail: str) -> None:
    """The FC 15/16 response echoes the quantity; zero, or one past the spec
    maximum (1968 coils, 123 registers), is malformed, as on the request side."""
    a, at = anomaly_after_good_adu(bytes([fc]) + (0x0100).to_bytes(2, "big") + quantity.to_bytes(2, "big"), is_request=False)
    assert a.kind == "malformed_pdu" and a.offset == at
    assert a.detail == detail


# Spec quantity limits (Modbus Application Protocol V1.1b3), pinned as literals
# rather than imported from mbap._MAX_QUANTITY, so a wrong dict value fails here.


@pytest.mark.parametrize(
    "fc,quantity",
    [(1, 1), (1, 2000), (2, 1), (2, 2000), (3, 1), (3, 125), (4, 1), (4, 125)],
)
def test_read_request_quantity_at_spec_bounds_parses(fc: int, quantity: int) -> None:
    adu = parse_one(bytes([fc]) + (0).to_bytes(2, "big") + quantity.to_bytes(2, "big"), is_request=True)
    assert (adu.function_code, adu.quantity) == (fc, quantity)


@pytest.mark.parametrize(
    "fc,quantity,byte_count",
    [(15, 1, 1), (15, 1968, 246), (16, 1, 2), (16, 123, 246)],
)
def test_write_multi_request_quantity_at_spec_bounds_parses(fc: int, quantity: int, byte_count: int) -> None:
    """Byte count and payload are consistent with the quantity. At the maximum
    the PDU is 252 bytes (MBAP length 253), inside the 254 cap."""
    pdu = bytes([fc]) + (0).to_bytes(2, "big") + quantity.to_bytes(2, "big") + bytes([byte_count]) + b"\x00" * byte_count
    adu = parse_one(pdu, is_request=True)
    assert (adu.function_code, adu.quantity, adu.byte_count) == (fc, quantity, byte_count)


@pytest.mark.parametrize("fc,quantity", [(15, 1), (15, 1968), (16, 1), (16, 123)])
def test_write_multi_response_quantity_at_spec_bounds_parses(fc: int, quantity: int) -> None:
    adu = parse_one(bytes([fc]) + (0x0100).to_bytes(2, "big") + quantity.to_bytes(2, "big"), is_request=False)
    assert (adu.function_code, adu.quantity) == (fc, quantity)


@pytest.mark.parametrize(
    "fc,quantity,detail",
    [
        (1, 2001, "fc 1 request quantity 2001 outside 1..2000"),
        (2, 2001, "fc 2 request quantity 2001 outside 1..2000"),
        (3, 126, "fc 3 request quantity 126 outside 1..125"),
        (4, 126, "fc 4 request quantity 126 outside 1..125"),
    ],
)
def test_read_request_quantity_past_spec_max_malformed(fc: int, quantity: int, detail: str) -> None:
    a, at = anomaly_after_good_adu(bytes([fc]) + (0).to_bytes(2, "big") + quantity.to_bytes(2, "big"), is_request=True)
    assert a.kind == "malformed_pdu" and a.offset == at
    assert a.detail == detail


@pytest.mark.parametrize(
    "fc,quantity,detail",
    [
        (15, 1969, "fc 15 request quantity 1969 outside 1..1968"),
        (16, 124, "fc 16 request quantity 124 outside 1..123"),
    ],
)
def test_write_multi_request_quantity_past_spec_max_malformed(fc: int, quantity: int, detail: str) -> None:
    """Byte count 0 and no payload: the quantity check runs before the byte count
    check. A consistent payload for FC 16 at 124 registers (248 bytes) would push
    the MBAP length to 255, past the 254 cap, and fail framing instead."""
    a, at = anomaly_after_good_adu(bytes([fc]) + (0).to_bytes(2, "big") + quantity.to_bytes(2, "big") + b"\x00", is_request=True)
    assert a.kind == "malformed_pdu" and a.offset == at
    assert a.detail == detail


@pytest.mark.timeout(5)
def test_skip_cascade_realigns_on_7_multiple() -> None:
    """14 garbage bytes = two skip-7s, then the valid ADU behind them parses."""
    valid = frame(bytes([3]) + (0).to_bytes(2, "big") + (1).to_bytes(2, "big"))
    parser = StreamParser(is_request=True)
    out = parser.feed(b"\xff" * 14 + valid)
    out.extend(parser.finish())
    assert [type(r).__name__ for r in out] == ["ParseAnomaly", "ParseAnomaly", "ParsedADU"]
    assert all(r.kind == "bad_protocol_id" for r in out[:2])
    assert out[2].function_code == 3


@pytest.mark.timeout(5)
def test_skip_cascade_misaligned_loses_frame_but_counts_every_byte() -> None:
    """10 garbage bytes: skip-7 lands mid-frame and the valid ADU is consumed
    into the cascade, the documented best-effort limit. No ADU is recovered,
    but every input byte is accounted for in anomaly records."""
    valid = frame(bytes([3]) + (0).to_bytes(2, "big") + (1).to_bytes(2, "big"))
    data = b"\xff" * 10 + valid
    parser = StreamParser(is_request=True)
    out = parser.feed(data)
    out.extend(parser.finish())
    assert all(isinstance(r, ParseAnomaly) for r in out)
    consumed = sum(7 if r.kind != "truncated_stream" else len(r.snippet) for r in out)
    assert consumed == len(data)


def test_anomaly_snippet_is_bounded() -> None:
    parser = StreamParser(is_request=True)
    out = parser.feed(b"\x00\x01\xde\xad" + b"\xff" * 500)  # bad protocol id, big buffer
    anomalies = [r for r in out if isinstance(r, ParseAnomaly)]
    assert anomalies and all(len(a.snippet) <= 16 for a in anomalies)


# --- D13: FC 08 (diagnostics) and FC 43 / MEI 0x0E (read device id) -----------

OVERRUN_FIXTURE = Path(__file__).parent / "corpus" / "fc43_object_overrun.bin"
OVERRUN_LENGTH_INDEX = 22  # second object's length byte: 7 MBAP bytes + 15 into the PDU
VENDOR = [(0x00, b"ACME!"), (0x01, b"V1.0")]


def run(data: bytes, is_request: bool, chunk: int | None = None) -> list:
    parser = StreamParser(is_request=is_request)
    out: list = []
    if chunk is None:
        out.extend(parser.feed(data))
    else:
        for i in range(0, len(data), chunk):
            out.extend(parser.feed(data[i : i + chunk]))
    out.extend(parser.finish())
    return out


def mei_response(objects, count: int | None = None, read_code: int = 1, more_follows: int = 0x00) -> bytes:
    """FC 43 / MEI 0x0E response PDU: fc, MEI, read code, conformity,
    more-follows, next object id, object count, then (id, length, value) objects."""
    pdu = bytes([0x2B, 0x0E, read_code, 0x01, more_follows, 0x00, len(objects) if count is None else count])
    for obj_id, value in objects:
        pdu += bytes([obj_id, len(value)]) + value
    return pdu


@pytest.mark.parametrize("is_request", [True, False])
@pytest.mark.parametrize("subfunction", [0x0000, 0x0004, 0xFFFF])
def test_fc08_parses_both_directions_any_subfunction(is_request: bool, subfunction: int) -> None:
    adu = parse_one(bytes([0x08]) + subfunction.to_bytes(2, "big") + b"\xa5\x37", is_request=is_request)
    assert adu.function_code == 8 and adu.is_request == is_request
    assert adu.subfunction == subfunction
    assert (adu.start_address, adu.quantity, adu.value, adu.byte_count) == (None, None, None, None)


@pytest.mark.parametrize("is_request", [True, False])
@pytest.mark.parametrize("data", [b"", b"\x00", b"\x00\x00\x01"])
def test_fc08_short_or_odd_data_malformed(is_request: bool, data: bytes) -> None:
    (a,) = run(frame(bytes([0x08]) + data), is_request)
    assert isinstance(a, ParseAnomaly) and a.kind == "malformed_pdu"
    assert "want an even count >= 2" in a.detail


def test_fc43_read_device_id_request_parses() -> None:
    adu = parse_one(bytes([0x2B, 0x0E, 0x01, 0x00]), is_request=True)
    assert adu.function_code == 43 and adu.is_request
    assert adu.subfunction == 0x0E
    assert adu.start_address is None and adu.quantity is None


@pytest.mark.parametrize(
    "data,detail",
    [
        (b"", "fc 43 request with 0 data bytes (want 3)"),
        (b"\x0e\x01", "fc 43 request with 2 data bytes (want 3)"),
        (b"\x0e\x01\x00\x00", "fc 43 request with 4 data bytes (want 3)"),
        (b"\x0e\x00\x00", "fc 43 request read code 0 outside 1..4"),
        (b"\x0e\x05\x00", "fc 43 request read code 5 outside 1..4"),
    ],
)
def test_fc43_request_malformed(data: bytes, detail: str) -> None:
    (a,) = run(frame(bytes([0x2B]) + data), is_request=True)
    assert isinstance(a, ParseAnomaly) and a.kind == "malformed_pdu"
    assert a.detail == detail


@pytest.mark.parametrize("is_request", [True, False])
def test_fc43_other_mei_stays_unknown(is_request: bool) -> None:
    (a,) = run(frame(bytes([0x2B, 0x0D, 0x01, 0x00])), is_request)
    assert isinstance(a, ParseAnomaly) and a.kind == "unknown_function_code"
    assert a.detail == "fc 0x2b MEI type 0x0d not supported"


def test_fc43_response_parses_and_keeps_no_object_bytes() -> None:
    adu = parse_one(mei_response(VENDOR), is_request=False)
    assert adu.function_code == 43 and not adu.is_request
    assert adu.subfunction == 0x0E
    assert "ACME" not in repr(adu) and "V1.0" not in repr(adu)
    assert not any(isinstance(v, (bytes, bytearray, str)) for v in vars(adu).values())


def test_fc43_response_more_follows_ff_parses() -> None:
    adu = parse_one(mei_response(VENDOR, more_follows=0xFF), is_request=False)
    assert adu.function_code == 43


def test_fc43_overrun_fixture_detail_and_no_object_bytes() -> None:
    """Same bytes as the corpus fixture, response-side. The golden pins kind and
    offset only, so the detail that names the object walk is pinned here."""
    (a,) = run(OVERRUN_FIXTURE.read_bytes(), is_request=False)
    assert isinstance(a, ParseAnomaly) and a.kind == "malformed_pdu"
    assert a.detail == "fc 43 response object list overruns pdu"
    assert len(a.snippet) == 7 and b"ACME" not in a.snippet  # header only


def test_fc43_overrun_fixture_with_correct_length_parses() -> None:
    """The fixture with its second object's length corrected from 9 to 4 parses,
    so the overrun is the only thing wrong with it."""
    data = bytearray(OVERRUN_FIXTURE.read_bytes())
    assert data[OVERRUN_LENGTH_INDEX] == 9 and bytes(data[OVERRUN_LENGTH_INDEX + 1 :]) == b"V1.0"
    data[OVERRUN_LENGTH_INDEX] = 4
    (adu,) = run(bytes(data), is_request=False)
    assert isinstance(adu, ParsedADU) and adu.function_code == 43


@pytest.mark.parametrize(
    "pdu,detail",
    [
        (mei_response(VENDOR) + b"\x00", "fc 43 response object list leaves 1 trailing bytes"),
        (mei_response(VENDOR, count=1), "fc 43 response object list leaves 6 trailing bytes"),
        (mei_response(VENDOR, count=3), "fc 43 response object list overruns pdu"),
        (mei_response(VENDOR, count=3) + b"\x02", "fc 43 response object list overruns pdu"),
    ],
)
def test_fc43_response_object_list_checks(pdu: bytes, detail: str) -> None:
    (a,) = run(frame(pdu), is_request=False)
    assert isinstance(a, ParseAnomaly) and a.kind == "malformed_pdu"
    assert a.detail == detail
    assert b"ACME" not in a.snippet


@pytest.mark.parametrize(
    "pdu,detail",
    [
        (bytes([0x2B]), "fc 43 response with 0 data bytes (want >= 6)"),
        (bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00]), "fc 43 response with 5 data bytes (want >= 6)"),
        (mei_response(VENDOR, read_code=0), "fc 43 response read code 0 outside 1..4"),
        (mei_response(VENDOR, more_follows=0x7F), "fc 43 response more-follows 0x7f not 0x00 or 0xff"),
    ],
)
def test_fc43_response_header_checks_malformed(pdu: bytes, detail: str) -> None:
    (a,) = run(frame(pdu), is_request=False)
    assert isinstance(a, ParseAnomaly) and a.kind == "malformed_pdu"
    assert a.detail == detail
    assert b"ACME" not in a.snippet


@pytest.mark.parametrize("fc", [0x88, 0xAB])
def test_request_side_exception_bit_on_new_fcs_not_laundered(fc: int) -> None:
    (a,) = run(frame(bytes([fc, 0x01])), is_request=True)
    assert isinstance(a, ParseAnomaly) and a.kind == "unknown_function_code"
    assert f"{fc:#04x}" in a.detail


@pytest.mark.parametrize("fc,base", [(0x88, 8), (0xAB, 43)])
def test_exception_response_for_new_fcs(fc: int, base: int) -> None:
    adu = parse_one(bytes([fc, 0x01]), is_request=False)
    assert adu.is_exception and adu.function_code == base
    assert adu.exception_code == 1
    assert adu.subfunction is None


@pytest.mark.parametrize("is_request", [True, False])
@pytest.mark.parametrize("fc", [0x07, 0x11, 0x17, 0x2A])
def test_other_fcs_still_unknown(fc: int, is_request: bool) -> None:
    (a,) = run(frame(bytes([fc, 0x00, 0x00])), is_request)
    assert isinstance(a, ParseAnomaly) and a.kind == "unknown_function_code"


def test_new_fcs_chunking_deterministic() -> None:
    cases = [
        (frame(bytes([0x08, 0x00, 0x00, 0xA5, 0x37])), True),
        (frame(bytes([0x2B, 0x0E, 0x01, 0x00])), True),
        (frame(mei_response(VENDOR)), False),
        (frame(mei_response(VENDOR, count=3)), False),
        (OVERRUN_FIXTURE.read_bytes(), False),
    ]
    for data, is_request in cases:
        assert run(data, is_request) == run(data, is_request, chunk=1)


def test_existing_fcs_have_no_subfunction() -> None:
    adu = parse_one(bytes([3]) + (0).to_bytes(2, "big") + (1).to_bytes(2, "big"), is_request=True)
    assert adu.subfunction is None


def test_fc43_object_length_overshoot_by_one_overruns() -> None:
    """Boundary: the last object's declared length raised by exactly 1 (4 -> 5),
    value bytes unchanged, must overrun rather than read one byte past the PDU."""
    pdu = bytearray(mei_response(VENDOR))
    last_length_index = 7 + 2 + len(b"ACME!") + 1  # header, first object, last object's id
    assert pdu[last_length_index] == 4 and bytes(pdu[last_length_index + 1 :]) == b"V1.0"
    pdu[last_length_index] = 5
    (a,) = run(frame(bytes(pdu)), is_request=False)
    assert isinstance(a, ParseAnomaly) and a.kind == "malformed_pdu"
    assert a.detail == "fc 43 response object list overruns pdu"


def test_fc43_response_zero_objects_parses() -> None:
    pdu = mei_response([])
    assert len(pdu) - 1 == 6 and pdu[6] == 0  # exactly 6 data bytes, object count 0
    adu = parse_one(pdu, is_request=False)
    assert adu.function_code == 43 and adu.subfunction == 0x0E
