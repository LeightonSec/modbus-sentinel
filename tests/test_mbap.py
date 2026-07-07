"""Unit tests for the hand-rolled MBAP/PDU parser (DESIGN.md Gate 1 criterion 1).

Covers FC 01, 02, 03, 04, 05, 06, 15, 16 requests and responses, exception
responses, pipelined ADUs, frames split across feed() calls, and end-of-stream
truncation.
"""

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
    assert adu.start_address is None  # responses carry no address — pairing recovers it


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
    into the cascade — the documented best-effort limit. No ADU is recovered,
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
