"""Single source of truth for the corpus golden: the record-to-tuple mapping,
the parser-run helper, and the corpus glob. Imported by BOTH
scripts/emit_golden.py (which writes tests/golden_corpus.py) and
tests/test_corpus.py (which asserts against it), so the mapping cannot exist in
two places and drift.
"""
from pathlib import Path

from modbus_sentinel.mbap import ParseAnomaly, ParsedADU, StreamParser

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"


def corpus_files() -> list[Path]:
    return sorted(CORPUS_DIR.glob("*.bin"))


def summarize(rec) -> tuple:
    """Output record -> hashable identity tuple.

    anomaly -> ("anom", kind, stream_byte_offset)
    ADU     -> ("adu", function_code, transaction_id)

    Unknown record types raise rather than fall through to an ADU tuple: this
    module defines ground truth, so an unrecognised record must fail loudly, not
    be silently mislabelled.
    """
    if isinstance(rec, ParseAnomaly):
        return ("anom", rec.kind, rec.offset)
    if isinstance(rec, ParsedADU):
        return ("adu", rec.function_code, rec.transaction_id)
    raise TypeError(f"unexpected parser record type: {type(rec).__name__}")


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


def signature(data: bytes, chunk_size: int | None = None) -> tuple:
    """Ordered tuple of summarize() over the parser's output for `data`."""
    return tuple(summarize(r) for r in run_parser(data, chunk_size))


def compute_golden() -> dict[str, tuple]:
    return {path.stem: signature(path.read_bytes()) for path in corpus_files()}
