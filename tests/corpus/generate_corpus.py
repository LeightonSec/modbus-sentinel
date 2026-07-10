"""Deterministic malformed-input corpus generator (DESIGN.md Gate 1 / D4).

Run from the repo root to (re)create the checked-in .bin fixtures:

    python tests/corpus/generate_corpus.py

Every fixture is built from literal bytes — no randomness — so regeneration is
reproducible and diffs are reviewable. Local fuzzing that finds a new crasher
should minimize it and add it here, then check the .bin in.

Growth log (mirror of D4): 16 fixtures at first draft; 18 after round 5, when
the chunking-determinism test falsified the discard-remainder header policy and
the skip-cascade pair was added to pin the replacement's behavior; 19 after
round 6, when D11's exception-FC review exposed that the request-side
exception-bit path was correct but unguarded.
"""

from pathlib import Path


def mbap(transaction_id: int, length: int, unit_id: int = 1, protocol_id: int = 0) -> bytes:
    return (
        transaction_id.to_bytes(2, "big")
        + protocol_id.to_bytes(2, "big")
        + length.to_bytes(2, "big")
        + bytes([unit_id])
    )


def frame(pdu: bytes, transaction_id: int = 1, unit_id: int = 1, protocol_id: int = 0) -> bytes:
    return mbap(transaction_id, len(pdu) + 1, unit_id, protocol_id) + pdu


FC3_READ_REQ = bytes([0x03]) + (0x0000).to_bytes(2, "big") + (10).to_bytes(2, "big")

CORPUS: dict[str, bytes] = {
    # -- header-level failures: length field cannot be trusted --------------
    "truncated_mbap_header": mbap(1, 6)[:4],
    "length_zero": mbap(1, 0) + b"\x03",
    "length_over_max": mbap(1, 0xFFFF) + b"\x03" * 8,
    "length_exceeds_buffer": mbap(1, 200) + b"\x03\x00\x00\x00\x0a",
    "bad_protocol_id": frame(FC3_READ_REQ, protocol_id=0xDEAD),
    # -- well-framed PDU-level failures: cost one ADU, stream continues -----
    "unknown_function_code": frame(bytes([0x2A, 0x01, 0x02])),
    "fc3_quantity_zero": frame(bytes([0x03]) + (0).to_bytes(2, "big") + (0).to_bytes(2, "big")),
    "fc3_quantity_absurd": frame(bytes([0x03]) + (0).to_bytes(2, "big") + (0xFFFF).to_bytes(2, "big")),
    "fc16_quantity_absurd": frame(
        bytes([0x10]) + (0).to_bytes(2, "big") + (0xFFFF).to_bytes(2, "big") + bytes([2, 0, 0])
    ),
    "fc15_bytecount_mismatch": frame(
        bytes([0x0F]) + (0).to_bytes(2, "big") + (16).to_bytes(2, "big") + bytes([9]) + b"\x00" * 9
    ),
    "fc6_short_data": frame(bytes([0x06, 0x00])),
    # Exception bit (0x80) on the REQUEST side: the corpus harness parses
    # request-direction, where the response-only strip branch must NOT fire —
    # 0x83 has to surface as unknown_function_code, never be laundered to fc 3
    # (which could then pair against a genuine fc 3 response). Round 6.
    "exception_bit_on_request": frame(bytes([0x83, 0x02])),
    "exception_trailing_garbage": frame(bytes([0x83, 0x02, 0x99, 0x99])),
    "garbage_after_valid_adu": frame(FC3_READ_REQ) + mbap(2, 0) + b"\xff" * 5,
    "all_ff": b"\xff" * 64,
    "single_byte": b"\x00",
    # 14 garbage bytes = exactly two skip-7s, then framing REALIGNS onto a
    # valid ADU which must parse. Proves cascade recovery, not just survival.
    "skip_cascade_realigns": b"\xff" * 14 + frame(FC3_READ_REQ),
    # 10 garbage bytes: second skip-7 lands mid-frame, eating into the valid
    # ADU — the documented best-effort limit. Everything must still be counted.
    "skip_cascade_misaligned": b"\xff" * 10 + frame(FC3_READ_REQ),
    # -- positive control: three valid pipelined ADUs, zero anomalies -------
    "pipelined_valid_3": b"".join(frame(FC3_READ_REQ, transaction_id=t) for t in (1, 2, 3)),
}


def main() -> None:
    out_dir = Path(__file__).parent
    for name, data in sorted(CORPUS.items()):
        (out_dir / f"{name}.bin").write_bytes(data)
        print(f"wrote {name}.bin ({len(data)} bytes)")


if __name__ == "__main__":
    main()
