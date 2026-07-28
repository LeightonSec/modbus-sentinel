"""Malformed-input corpus gate (DESIGN.md Gate 1 pass criterion 3 / D4).

Every .bin under tests/corpus/ is fed to the parser whole AND byte-by-byte.
Pass = no exception, no hang (pytest-timeout), every output is a typed record,
full-record output is identical run-to-run and across feed granularities, and
each fixture matches its pinned golden signature (ordered records, anomaly kinds
and stream offsets, each recovered ADU's fc/transaction_id).
"""
import ast
from pathlib import Path

import pytest

from golden_corpus import GOLDEN
from golden_support import CORPUS_DIR, corpus_files, run_parser, signature
from modbus_sentinel.mbap import ParseAnomaly, ParsedADU, StreamParser

CORPUS_FILES = corpus_files()

# Valid on the request side, expected to produce ZERO anomalies: the positive
# control proving the corpus gate can actually fail. Exact ADU count is pinned by
# GOLDEN (pipelined_valid_3 -> three distinct ADU tuples).
CLEAN_FIXTURES = {"pipelined_valid_3"}


def _generator_keys() -> set[str]:
    """CORPUS dict keys parsed STATICALLY from generate_corpus.py (ast, not exec):
    the generator writes .bin files under a __main__ guard, and reading a set of
    strings must never risk rewriting ground truth at collection time."""
    tree = ast.parse((CORPUS_DIR / "generate_corpus.py").read_text())
    for node in ast.walk(tree):
        target = None
        if isinstance(node, ast.AnnAssign):
            target = node.target
        elif isinstance(node, ast.Assign) and node.targets:
            target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == "CORPUS" and isinstance(node.value, ast.Dict):
            return {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
    raise AssertionError("CORPUS dict literal not found in generate_corpus.py")


GENERATOR_KEYS = _generator_keys()


def test_corpus_present() -> None:
    assert len(CORPUS_FILES) >= 10, "corpus missing, run tests/corpus/generate_corpus.py"


def test_golden_covers_every_fixture() -> None:
    """Three-way: .bin on disk, golden keys, and generator keys must be one set.
    Any single-sided drift (orphan .bin, stale golden entry, deleted generator
    key) fails loudly rather than silently shrinking coverage."""
    on_disk = {p.stem for p in CORPUS_FILES}
    golden = set(GOLDEN)
    assert on_disk == golden == GENERATOR_KEYS, (
        f"corpus drift -> on_disk={on_disk}, golden={golden}, generator={GENERATOR_KEYS}"
    )


@pytest.mark.timeout(5)
@pytest.mark.parametrize("path", CORPUS_FILES, ids=lambda p: p.stem)
def test_never_crashes_and_fails_closed(path: Path) -> None:
    data = path.read_bytes()
    out = run_parser(data)
    assert all(isinstance(r, (ParsedADU, ParseAnomaly)) for r in out)
    anomalies = [r for r in out if isinstance(r, ParseAnomaly)]
    if path.stem in CLEAN_FIXTURES:
        assert not anomalies, f"clean fixture produced anomalies: {anomalies}"
    else:
        assert anomalies, "malformed fixture produced no anomaly record"


@pytest.mark.timeout(5)
@pytest.mark.parametrize("path", CORPUS_FILES, ids=lambda p: p.stem)
def test_deterministic_full_records(path: Path) -> None:
    """Full-record invariance: run-to-run determinism AND identical output across
    feed granularities, comparing EVERY field (detail strings, snippet bytes, all
    ADU fields) that the golden signature deliberately does not pin. Golden and
    this test cover different things; both are load-bearing."""
    data = path.read_bytes()
    whole = run_parser(data)
    again = run_parser(data)
    byte_by_byte = run_parser(data, chunk_size=1)
    assert whole == again, f"{path.stem}: output not deterministic run-to-run"
    assert whole == byte_by_byte, f"{path.stem}: output changes with feed chunking"


@pytest.mark.timeout(5)
@pytest.mark.parametrize("path", CORPUS_FILES, ids=lambda p: p.stem)
def test_matches_golden_whole_and_bytewise(path: Path) -> None:
    """Exact behaviour against the pinned golden, whole-feed AND byte-by-byte.
    Asserting the same signature at chunk=None and chunk=1 is what proves offsets
    are stream-absolute; a buffer-relative offset regression goes red here rather
    than being excused by a comment."""
    expected = GOLDEN[path.stem]
    data = path.read_bytes()
    assert signature(data, None) == expected, f"{path.stem}: whole-feed signature drift"
    assert signature(data, 1) == expected, f"{path.stem}: byte-by-byte signature drift"


@pytest.mark.timeout(5)
def test_exception_bit_on_request_flagged_not_laundered() -> None:
    """Fixture-specific guard (round 6): the generic assertions prove "some
    anomaly" and a pinned signature; this pins the KIND and the non-laundering.

    Request-side 0x83 must surface as unknown_function_code. If a refactor hoists
    mbap.py's 0x80-strip above the is_request gate, 0x83 gets normalized to a
    well-formed fc-3 ParsedADU and the crafted request becomes pairable against a
    genuine fc-3 response. This test is what goes red.

    The parser is constructed inline, NOT via run_parser: the property under test
    IS the direction gate, so direction must be load-bearing here, not inherited
    from a helper whose internals could change."""
    data = (CORPUS_DIR / "exception_bit_on_request.bin").read_bytes()
    parser = StreamParser(is_request=True)  # explicit: the gate under test
    out = parser.feed(data)
    out.extend(parser.finish())
    assert not any(isinstance(r, ParsedADU) for r in out), "0x83 request was laundered to an ADU"
    (anomaly,) = [r for r in out if isinstance(r, ParseAnomaly)]
    assert anomaly.kind == "unknown_function_code"
    assert "0x83" in anomaly.detail


@pytest.mark.timeout(5)
def test_response_side_never_crashes() -> None:
    """Crash smoke only: the corpus is request-formatted, so through the response
    parser it mostly exercises the byte-count-mismatch path. Semantic response
    coverage lives in test_mbap.py's targeted unit tests."""
    for path in CORPUS_FILES:
        parser = StreamParser(is_request=False)
        out = parser.feed(path.read_bytes())
        out.extend(parser.finish())
        assert all(isinstance(r, (ParsedADU, ParseAnomaly)) for r in out)
