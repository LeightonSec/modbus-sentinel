"""Prose gate: fail if tracked text carries machine-generated punctuation tells
or tooling-hostile whitespace, or if any captured-traffic file is committed (the
corpus must stay synthetic, per GATES.md).

Banned: em dash (U+2014), horizontal bar (U+2015), curly quotes
(U+2018/2019/201C/201D), the ellipsis character (U+2026), and non-breaking
spaces (U+00A0/2007/202F, which can silently break YAML and Makefiles).
Allowed: en dash (U+2013) is correct typography for numeric ranges.

Assertion style: prints PASS with what was proven or FAIL with every offending
location; exits non-zero on any failure; always prints the skipped file list so
scan coverage is measured, not assumed. A tracked file that will not decode as
UTF-8 is a routine binary SKIP; a tracked file that cannot be opened at all
(missing, unreadable) is a repo inconsistency and FAILS, never a silent skip.
Runs its own `git ls-files` via subprocess, unaffected by any shell rewriter.
"""
import subprocess
import sys
from pathlib import Path

BANNED = {
    0x2014: "EM-DASH",
    0x2015: "HORIZONTAL-BAR",
    0x2018: "LEFT-SINGLE-QUOTE",
    0x2019: "RIGHT-SINGLE-QUOTE",
    0x201C: "LEFT-DOUBLE-QUOTE",
    0x201D: "RIGHT-DOUBLE-QUOTE",
    0x2026: "ELLIPSIS",
    0x00A0: "NBSP",
    0x2007: "FIGURE-SPACE",
    0x202F: "NARROW-NBSP",
}


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    # -z: NUL-delimited, so paths with spaces or newlines are handled safely
    # (whitespace split would corrupt them).
    raw = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, capture_output=True, text=True, check=True
    ).stdout
    files = [f for f in raw.split("\0") if f]

    # The corpus is synthetic (GATES.md); a committed capture would silently
    # falsify the "no captured traffic" claim, so a tracked capture is a failure.
    captures = [f for f in files if f.lower().endswith((".pcap", ".pcapng", ".cap"))]

    scanned: list[str] = []
    skipped: list[str] = []          # undecodable binary: expected
    unreadable: list[tuple[str, str]] = []  # tracked but cannot open: FAIL
    hits: list[tuple[str, int, int, int, str, str]] = []

    for rel in files:
        try:
            text = (root / rel).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            skipped.append(rel)
            continue
        except OSError as exc:
            unreadable.append((rel, type(exc).__name__))
            continue
        scanned.append(rel)
        for lineno, line in enumerate(text.splitlines(), 1):
            for col, ch in enumerate(line, 1):
                if ord(ch) in BANNED:
                    hits.append((rel, lineno, col, ord(ch), BANNED[ord(ch)], line.strip()[:70]))

    # Full accounting: tracked == scanned + skipped + unreadable, so no file
    # falls out of the tally unmentioned.
    print(
        f"prose gate: {len(files)} tracked, {len(scanned)} scanned, "
        f"{len(skipped)} skipped (undecodable), {len(unreadable)} unreadable"
    )
    for rel in skipped:
        print(f"  SKIP {rel} [UnicodeDecodeError]")

    failed = False
    if captures:
        failed = True
        print(f"FAIL: {len(captures)} captured-traffic file(s) committed (corpus must stay synthetic):")
        for cap in captures:
            print(f"  CAPTURE {cap}")
    if unreadable:
        failed = True
        print(f"FAIL: {len(unreadable)} tracked file(s) could not be read (repo inconsistency):")
        for rel, why in unreadable:
            print(f"  UNREADABLE {rel} [{why}]")
    if hits:
        failed = True
        print(f"FAIL: {len(hits)} banned punctuation character(s):")
        for rel, lineno, col, cp, name, ctx in hits:
            print(f"  {rel}:{lineno}:{col} U+{cp:04X} {name}: {ctx}")

    if failed:
        return 1
    print(f"PASS: no banned punctuation in {len(scanned)} tracked text files (en dash U+2013 allowed).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
