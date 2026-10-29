# modbus-sentinel: gate status

Canonical status lives **here**. README.md and DESIGN.md may echo it but must
not state gate status that is not derived from this file: two sources of truth
are what let the README claim "Gate 1 in progress" while Gate 1 was complete. If
a status or number appears in two files, this one is the source and wins on any
conflict.

**"Complete" means** the gate's pass criteria as written at sign-off were met.
Findings logged against a completed gate afterwards (see Open findings) are
tracked forward, not retroactive reopenings.

## Gates

| Gate | Scope | Pass criteria (see DESIGN.md) | Status | Commit |
|---|---|---|---|---|
| 1. Ingestion | pcap to per-transaction records; direction attribution (D10), pairing (D11), malformed-input corpus (D4) | known-good pcaps parse; pipelined/split-ADU handled; malformed corpus is deterministic, fails closed, never crashes | Complete | `7ebc595` |
| 2. Baseline construction | per-device baseline from a user-designated normal period (D6) | baseline object serializable, inspectable, readable by a human without reading code | Complete | `cd1672b` |
| 3. Anomaly detection | the five heuristics (D7/D8) over the post-baseline period | injected anomaly flagged; clean pcap yields zero false positives; both in CI | First cut met (classes 1, 2, 5); classes 3 and 4 pending | `f81c3bd` |
| 4. Reporting | human-readable + `--json`; terminal-escape sanitization of packet-derived bytes | "what happened" separated from "why flagged"; sanitization test present | Minimum met; not built: classes 3 and 4 | `c021463` |
| 5. CI and tests | pinned lockfile; CI on every push; prose + golden gates; coverage floor | `make check` green (prose gate, golden freshness, ruff, tests at the 97.9% coverage floor) on every push | Met | `c021463` |

Gate 5 note: CI ran `make check` (prose gate, golden freshness, ruff, tests at
the 97.9% floor) green on the pushed commits `cd1672b`, `f81c3bd` and
`c021463`, so the status is "Met" at `c021463`. Status is never ahead of the
evidence.

Gates 2 to 4 note (2026-10-28): Gate 2 met its pass criteria at `cd1672b`: the
baseline round-trips through JSON, and its text render is pinned by
`tests/golden_baseline.txt`. Gate 3 is a first cut at `f81c3bd`: class 1
(unscheduled write), class 2 (write to unknown register) and class 5
(never-seen function code, supported FCs only) run, and both pass criteria are
tests that ran green in CI. Gate 3 is not Complete: class
3 (polling-interval break) and class 4 (off-hours activity) wait until N and
the arming details are decided (D12). The Gate 4 minimum landed at `c021463`:
text report and `--json`, what happened separate from why flagged, and every
text line escaped to printable ASCII, with sanitisation tests. Not built yet:
classes 3 and 4.

D13 update (2026-10-29): FC 08 (diagnostics) and FC 43 with MEI type 0x0E (read
device identification) are attributed to a device as address-less transactions,
so class 5 fires on them for a known device; they never enter the address sets
or the poll groups, and classes 1 and 2 never fire on them. Commits: `87c239f`
(decision record), `b16d477` (parser), `99a3639` (corpus), `2701f9a` (detection
and report). CI run 40821511536 on `2701f9a` was green: security, and tests on
Python 3.10, 3.11 and 3.12. Not caught: FC 08 sub-function 0x0004 (force listen
only) gets no response by specification, so it stays a counted orphan request
and is not attributed. The report states this limit as fixed text, not a count.

## Coverage

`make check` enforces `--cov-fail-under=97.9` via `addopts`, so the floor applies
to every pytest invocation. `[tool.coverage.run].omit` excludes only `tests/*`:
since `c021463`, `modbus_sentinel/cli.py` is measured, with its `__main__` guard
marked `# pragma: no cover`. A local run on Python 3.12 measured 290 tests and
99.31% total. Its only missed statements were mbap.py:288, 315, 376 and
ingest.py:238-249, 375, so `cli.py` and `report.py` are at 100%. CI run
40821511536 on `2701f9a` measured, on each of Python 3.10, 3.11 and 3.12, 866
statements, 6 missed, 99.31% total, and reported the 97.9% floor reached.

The floor is 97.9, not 98, on purpose: it was set when coverage was 287/293 =
97.95% of the parser and ingest layer (Gate 1), which the coverage table
*displays* as 98% while `--cov-fail-under` compares the unrounded value. The six
statements uncovered then were error branches (mbap.py:186, 213, 269 and
ingest.py:237-248, 373 at that time). The current missed statements are listed
above.

## Gate 1 corpus

The malformed-input corpus is **22 fixtures = 21 reject/partial + 1 accept**
(`pipelined_valid_3` is the sole accept case, the positive control that proves
the gate can fail). Fixtures 18 to 19 landed in `7ebc595` (the round-6
exception-FC guard); the "18" in DECISIONS.md D4's growth log is a round-5
snapshot, corrected there with a dated note. Fixtures 20 to 22
(`fc08_short_data`, `fc43_other_mei`, `fc43_object_overrun`) landed in
`99a3639` (D13).

`fc43_object_overrun` is response-side. Its golden signature pins kind and
offset only, and those are identical in both directions, so the golden cannot
tell which parser ran. `test_response_fixtures_use_response_parser` in
`tests/test_corpus.py` enforces the direction.

The corpus is **synthetic and deterministic**: every fixture is built from
literal bytes by `tests/corpus/generate_corpus.py`, contains no captured
traffic, and regenerates byte-identically. Behaviour is pinned by a golden
signature per fixture (`tests/golden_corpus.py`, generated by
`scripts/emit_golden.py`, asserted by `tests/test_corpus.py`, kept fresh by
`emit_golden.py --check` in CI). The signature pins, per fixture, the **ordered
sequence** of output records: each anomaly's `(kind, stream_byte_offset)` and
each recovered ADU's `(function_code, transaction_id)`. Legend of what each
fixture is meant to break: `tests/corpus/README.md`.

**Two test layers, do not conflate them:** this `.bin` corpus feeds the
hand-rolled MBAP/PDU parser (`mbap.py`) raw byte streams. The pcap ingest layer
(`ingest.py`: direction attribution and transaction pairing) is tested
separately in `tests/test_ingest.py`, which builds known-good and adversarial
packets with scapy, writes them with `wrpcap`, and parses the resulting pcaps
through the real `ingest_pcap` reader. So Gate 1's "known-good pcaps parse" is
met by synthetic pcaps built at test time, not committed `.pcap` blobs. No
captured traffic, device fingerprints, or committed `.pcap` files exist anywhere
in the repo: all packet data is synthetic and built from code.

## Open findings

Tracked here so they cannot drift out of view. Severity and priority are the
owner's call; this file only records existence.

- Independent security review of the D12 and D13 locked-text amendments (DESIGN.md:3-5) is pending.
- Orphan details carry tid and unit only, no function code, so the report cannot
  count unanswered FC 08 0x0004 requests (D13 Revisit).
- DESIGN.md:114 says known-good sample pcaps (pymodbus test captures); none
  exist, Gate 1 is met by synthetic pcaps (see Gate 1 corpus note). DESIGN.md:3
  marks the document LOCKED; not edited here.

**Against Gate 1 (scope note, not an untested gap):**

- **Pairing is tested at the pcap layer, not in the `.bin` corpus.** D11 pairing
  is covered by the ~25 tests in `tests/test_ingest.py`, including the
  adversarial cases: response with no outstanding request (orphan), unanswered
  request (orphan), duplicate in-flight transaction ID (tid reuse), FC mismatch,
  unit-id keying, pipelined and split ADUs, retransmission, and sequence gaps.
  The `.bin` corpus deliberately does not exercise pairing (it is the mbap
  byte-stream layer). Any further adversarial pairing case should be weighed
  against what `test_ingest.py` already asserts, not assumed missing.

**Against the golden itself (what it does NOT pin):**

- Anomaly `detail` strings and `snippet` bytes are not pinned, only kind and
  offset. The full-record determinism test fixes their invariance across
  chunking, but nothing pins their expected value.
- Non-identifying ADU fields (`start_address`, `quantity`, `value`,
  `byte_count`) are not pinned; only `(function_code, transaction_id)` are.

**For Gate 2 (add to the corpus before or with baseline work):**

- Length field **understating** payload with extra bytes in the same segment
  (every current length fixture overstates).
- Boundary-exact length at the Modbus 253/260 ADU limit.
- Zero-byte input.
- Unit ID 0 and 255.
- One ADU split across two reads (distinct from pipelining).
- A genuine **trailing-garbage-outside-the-frame** case (the fixture formerly
  misnamed `exception_trailing_garbage` put its bytes inside the framed length;
  renamed to `exception_bit_request_padded`).

**Tooling (separate commit, needs its own test):**

- `generate_corpus.py` accepted `--out`, silently ignored it, and overwrote the
  tracked ground-truth fixtures in place. Fix: argparse, error on unknown flags,
  refuse to overwrite without `--force`, print the resolved absolute output path.
