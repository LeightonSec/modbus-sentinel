"""Malformed-input corpus gate (DESIGN.md Gate 1 pass criterion 3 / D4).

Every .bin under tests/corpus/ is fed to the parser whole AND byte-by-byte, in
its own direction: request-side unless listed in golden_support.RESPONSE_FIXTURES.
Pass = no exception, no hang (pytest-timeout), every output is a typed record,
full-record output is identical run-to-run and across feed granularities, and
each fixture matches its pinned golden signature (ordered records, anomaly kinds
and stream offsets, each recovered ADU's fc/transaction_id).
"""
import ast
from pathlib import Path

import pytest

from golden_corpus import GOLDEN
from golden_support import (
    CORPUS_DIR,
    RESPONSE_FIXTURES,
    corpus_files,
    is_request_fixture,
    run_parser,
    signature,
)
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


def test_response_fixtures_exist() -> None:
    """A misspelt name in RESPONSE_FIXTURES would silently run that fixture
    request-side again. Every listed name must be a real fixture, on disk and in
    the generator."""
    on_disk = {p.stem for p in CORPUS_FILES}
    assert RESPONSE_FIXTURES, "RESPONSE_FIXTURES is empty"
    assert RESPONSE_FIXTURES <= on_disk, f"not on disk: {RESPONSE_FIXTURES - on_disk}"
    assert RESPONSE_FIXTURES <= GENERATOR_KEYS, f"not generated: {RESPONSE_FIXTURES - GENERATOR_KEYS}"


@pytest.mark.parametrize("name", sorted(RESPONSE_FIXTURES))
def test_response_fixtures_use_response_parser(name: str) -> None:
    """The golden pins (kind, offset) only, and for fc43_object_overrun those are
    identical request-side and response-side, so the golden cannot tell the
    directions apart. This test enforces the direction: the harness must choose
    the response parser, and the full records must differ between directions."""
    data = (CORPUS_DIR / f"{name}.bin").read_bytes()
    assert not is_request_fixture(name)
    chosen = run_parser(data, is_request=is_request_fixture(name))
    assert chosen == run_parser(data, is_request=False)
    assert chosen != run_parser(data, is_request=True)  # direction changes the output, so this test can fail


def test_request_fixture_control() -> None:
    """Control for the direction helper: a real request-side fixture maps to the
    request parser."""
    assert (CORPUS_DIR / "pipelined_valid_3.bin").is_file()
    assert is_request_fixture("pipelined_valid_3") is True


@pytest.mark.timeout(5)
@pytest.mark.parametrize("path", CORPUS_FILES, ids=lambda p: p.stem)
def test_never_crashes_and_fails_closed(path: Path) -> None:
    data = path.read_bytes()
    out = run_parser(data, is_request=is_request_fixture(path.stem))
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
    is_request = is_request_fixture(path.stem)
    whole = run_parser(data, is_request=is_request)
    again = run_parser(data, is_request=is_request)
    byte_by_byte = run_parser(data, chunk_size=1, is_request=is_request)
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
    is_request = is_request_fixture(path.stem)
    assert signature(data, None, is_request=is_request) == expected, f"{path.stem}: whole-feed signature drift"
    assert signature(data, 1, is_request=is_request) == expected, f"{path.stem}: byte-by-byte signature drift"


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
    """Crash smoke only: every fixture through the response parser, whatever its
    own direction. Most of the corpus is request-formatted, so here it mostly
    exercises the byte-count-mismatch path. Direction for the RESPONSE_FIXTURES
    is enforced by test_response_fixtures_use_response_parser, not by the golden;
    semantic response coverage also lives in test_mbap.py's targeted unit tests."""
    for path in CORPUS_FILES:
        parser = StreamParser(is_request=False)
        out = parser.feed(path.read_bytes())
        out.extend(parser.finish())
        assert all(isinstance(r, (ParsedADU, ParseAnomaly)) for r in out)
