"""Malformed-input corpus gate (DESIGN.md Gate 1 pass criterion 3 / D4).

Every .bin under tests/corpus/ is fed to the parser whole AND byte-by-byte.
Pass = no exception, no hang (pytest-timeout), every output is a typed record,
output is identical across runs and across feeding granularities, and no
malformed fixture is silently swallowed.
"""

from pathlib import Path

import pytest

from modbus_sentinel.mbap import ParseAnomaly, ParsedADU, StreamParser

CORPUS_DIR = Path(__file__).parent / "corpus"
CORPUS_FILES = sorted(CORPUS_DIR.glob("*.bin"))

# Fixtures that are valid on the request side and must produce ZERO anomalies —
# the positive control proving the corpus gate can actually fail.
CLEAN_FIXTURES = {"pipelined_valid_3"}


def run_parser(data: bytes, chunk_size: int | None = None) -> list:
    parser = StreamParser(is_request=True)
    out: list = []
    if chunk_size is None:
        out.extend(parser.feed(data))
    else:
        for i in range(0, len(data), chunk_size):
            out.extend(parser.feed(data[i : i + chunk_size]))
    out.extend(parser.finish())
    return out


def test_corpus_present() -> None:
    assert len(CORPUS_FILES) >= 10, "corpus missing — run tests/corpus/generate_corpus.py"


@pytest.mark.timeout(5)
@pytest.mark.parametrize("path", CORPUS_FILES, ids=lambda p: p.stem)
def test_never_crashes_and_fails_closed(path: Path) -> None:
    data = path.read_bytes()
    out = run_parser(data)

    assert all(isinstance(r, (ParsedADU, ParseAnomaly)) for r in out)

    anomalies = [r for r in out if isinstance(r, ParseAnomaly)]
    if path.stem in CLEAN_FIXTURES:
        assert not anomalies, f"clean fixture produced anomalies: {anomalies}"
        assert len([r for r in out if isinstance(r, ParsedADU)]) == 3
    else:
        # Fail closed: malformed input is COUNTED, never silently consumed.
        assert anomalies, "malformed fixture produced no anomaly record"


@pytest.mark.timeout(5)
@pytest.mark.parametrize("path", CORPUS_FILES, ids=lambda p: p.stem)
def test_deterministic_across_runs_and_chunking(path: Path) -> None:
    data = path.read_bytes()
    whole = run_parser(data)
    again = run_parser(data)
    byte_by_byte = run_parser(data, chunk_size=1)
    assert whole == again
    assert whole == byte_by_byte


@pytest.mark.timeout(5)
def test_exception_bit_on_request_flagged_not_laundered() -> None:
    """Fixture-specific guard (round 6): the generic corpus assertion only
    proves "some anomaly"; this pins the KIND and the non-laundering.

    Request-side 0x83 must surface as unknown_function_code. If a refactor
    hoists mbap.py's 0x80-strip above the is_request gate, 0x83 gets
    normalized to a well-formed fc-3 ParsedADU instead — zero anomalies,
    generic corpus test still green, and the crafted request becomes pairable
    against a genuine fc-3 response. This test is what goes red.

    The parser is constructed inline, NOT via run_parser: the property under
    test IS the direction gate, so the direction must be load-bearing here,
    not inherited from a helper whose internals could change.
    """
    data = (CORPUS_DIR / "exception_bit_on_request.bin").read_bytes()
    parser = StreamParser(is_request=True)  # explicit — the gate under test
    out = parser.feed(data)
    out.extend(parser.finish())
    assert not any(isinstance(r, ParsedADU) for r in out), "0x83 request was laundered to an ADU"
    (anomaly,) = [r for r in out if isinstance(r, ParseAnomaly)]
    assert anomaly.kind == "unknown_function_code"
    assert "0x83" in anomaly.detail


@pytest.mark.timeout(5)
def test_response_side_never_crashes() -> None:
    """Crash smoke only: the corpus is request-formatted, so through the
    response parser it mostly exercises the byte-count-mismatch path. Semantic
    response-side coverage lives in test_mbap.py's targeted unit tests."""
    for path in CORPUS_FILES:
        parser = StreamParser(is_request=False)
        out = parser.feed(path.read_bytes())
        out.extend(parser.finish())
        assert all(isinstance(r, (ParsedADU, ParseAnomaly)) for r in out)
