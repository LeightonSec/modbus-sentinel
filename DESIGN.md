# modbus-sentinel — v0.1 Design

**Status: LOCKED 2026-07-07** (amended same day, review round 3). Changes to locked
sections require architect re-review **and a pass through independent security
review** before implementation — the architect does not re-approve its own
amendments alone. Rationale and rejected alternatives for every locked decision live in
[DECISIONS.md](DECISIONS.md) — this file says *what*, that file says *why*.

---

## What this is

A state-based anomaly detector for Modbus TCP traffic. It does not validate frame
structure (that's a parser problem, and solved ones exist). It answers a different
question: given a sequence of otherwise well-formed Modbus transactions, is this
device's behavior consistent with its own history?

A malformed packet is trivially caught by any protocol parser. A sequence of valid,
individually-legal function codes that together represent an attacker manipulating a
process — unscheduled writes, polling-interval drift, a write to a register that's
only ever been read — is invisible to signature-based tooling and is exactly the
class of activity the 2026 Dragos and Bitsight reporting flags as the defender blind
spot: sub-10% OT monitoring coverage, incidents caught by human suspicion rather
than tooling.

## Scope

**In scope for v0.1:**

- Modbus TCP only (not RTU, not serial)
- Ingests a pcap file (offline analysis, not live capture)
- Per-device behavioral baseline: function codes seen, read/write ratio, register
  addresses touched, polling interval
- Five anomaly classes (below)
- CLI tool, single command, human-readable report + `--json`

**Explicitly out of scope:**

- Not a general IDS. Not a replacement for Zeek, Snort, or a commercial NIDS.
- Not live/inline monitoring. Offline pcap only.
- Not DNP3, S7comm, BACnet, or any other protocol.
- Not a fuzzer or vulnerability scanner. It doesn't attack anything.
- No ML/statistical model in v0.1. Baseline-and-deviation logic only, deterministic
  and auditable. "Why did this fire" must be answerable in plain English before
  anything fancier is added.

## Device identity — LOCKED (D1)

A device is identified by the tuple **(server IP, unit ID)** — never unit ID alone.
On Modbus TCP the unit ID is frequently 0, 1, or 255 for direct-TCP devices and is
only discriminating behind serial gateways, where multiple physical devices share
one IP. Every baseline object, anomaly record, and report line is keyed by this
tuple.

## Anomaly classes (five) — LOCKED (D7)

Each is a heuristic, not a proof of malice. The report says "anomalous," not
"attack."

1. **Unscheduled write** — a write FC (05/06/15/16) to a register that, in the
   baseline period, appears in the device's read-set but not its write-set.
2. **Write to unknown register** — a write to a register absent from the baseline
   entirely (never read, never written). Suggests register-map knowledge acquired
   outside normal operational discovery — the recon-then-strike pattern.
3. **Polling-interval break** — a request in an established poll group arrives
   outside the median ± N·MAD band for that group (D5). Never computed per-device;
   always per poll group. A poll group arms only after **≥ 10 baseline
   observations**; sub-threshold groups are listed in the report as
   *"insufficient baseline data (n=X) — interval not monitored"*, never silently
   unmonitored.
4. **Off-hours activity** — traffic outside the device's observed operational
   window. The window is the smallest contiguous time-of-day interval (mod 24 h)
   containing **100%** of the device's baseline transactions. Arms only if the
   baseline spans ≥ 72 hours **and** that window covers ≤ 20 of 24 hours;
   otherwise skipped and the skip (with reason) is stated in the report.
5. **Never-seen function code** — any FC (including diagnostics FC 08 and device
   identification FC 43) not present in the device's baseline FC set. Read-side
   recon and DoS-primitive FCs are caught here, not just writes.

**Write decision tree (classes 1 vs 2):** one write event fires exactly one class —
register in baseline read-set → class 1; register absent from baseline → class 2.
Never both. Double-flagging a single packet reads as noise and erodes report trust.

## Gate structure

### Gate 1 — Ingestion

Parse a Modbus TCP pcap into per-transaction records:
timestamp, (server IP, unit ID), function code, register address(es)/count,
read/write, exception flag.

Scope that is the actual work (D2):

- **Request/response pairing** via MBAP transaction ID, per TCP stream
  (client IP:port ↔ server IP:port). A read response carries no address; only
  pairing recovers it.
- **Exception responses** (FC | 0x80) captured as first-class records with
  exception code.
- **Orphans** (unpaired requests or responses) counted and reported, never dropped
  silently.
- **ADU pipelining:** multiple Modbus ADUs in one TCP segment are parsed correctly
  (pymodbus masters pipeline). Explicit test case.
- **Split ADUs** (one ADU across TCP segments): *detected and counted* as
  `truncated_stream` events in v0.1, not reassembled. Documented limitation; the
  count appearing in the report is what keeps it honest.

**Pass criteria:**

1. Correctly parses known-good sample pcaps (pymodbus test captures); unit tests
   cover FC 01, 02, 03, 04, 05, 06, 15, 16 plus exception responses.
2. Pipelined-ADU test passes; split-ADU input produces a nonzero
   `truncated_stream` count, not a crash or silent drop.
3. **Malformed-input corpus (D4):** a checked-in fixture corpus — truncated MBAP
   header, length field exceeding remaining bytes, length field 0, unknown FC,
   register count 0 and absurd (0xFFFF), garbage exception codes — runs in CI.
   Pass = the parser never crashes and never hangs (harness-enforced timeout);
   every malformed input becomes a counted parse-anomaly record; output is
   byte-identical across runs. Free-running fuzzing happens locally as a corpus
   *generator* — any crasher found is minimized and checked into the corpus. Fuzzing
   itself never runs in CI (nondeterministic CI failures are undebuggable).

### Gate 2 — Baseline construction

Per-device baseline from a user-designated normal period (`--baseline-until
<timestamp|packet-count>`, D6). Baseline contents per (server IP, unit ID):

- FC set
- read-set and write-set of register addresses
- poll groups — key (FC, start address, count) — each with observation count,
  median inter-arrival, MAD
- operational window (if armable per class-4 rules)

**Pass criteria:** baseline object is serializable, inspectable, and a human can
read it and understand what "normal" means for that device without reading code.

### Gate 3 — Anomaly detection

Run the five heuristics against the post-baseline period.

**Pass criteria:** on a synthetic pcap with an injected unscheduled write, the tool
flags it. On a clean pcap with no injected anomaly, zero false positives. Both
checked in CI. The clean pcap comes from the same capture family as the baseline
pcap — otherwise the test measures capture-environment differences, not detection
logic.

### Gate 4 — Reporting

Human-readable CLI report plus `--json`. Report separates "what happened" from
"why it's flagged" (cascade-map report style).

**Sanitization requirement (locked):** any byte sequence that originated in a
packet — register values, payload-derived strings — is hex-escaped or
ANSI-stripped before reaching the terminal. Terminal escape injection into the
analyst's console is a documented attack against exactly this class of tool. The
`--json` path gets escaping from the encoder; the human report is where it bites,
and it gets a test.

### Gate 5 — CI and tests

Portfolio bar: pinned lockfile, CI on every push, no exit-code shortcuts, gates run
bare with full output.

## Trust boundaries and assumptions

Stated here and repeated in the README:

- **The baseline period is assumed clean.** This tool detects deviation from
  *observed* behavior, not from ground-truth-legitimate behavior. An attacker
  present during the baseline period is learned as normal. This is a structural
  property of all baseline-and-deviation detection, not a fixable bug in v0.1.
- **The pcap is hostile input.** The adversary being analyzed authored some of
  those bytes. The parser fails closed (malformed → counted parse-anomaly record,
  never a crash, never a silent skip) and bounds memory: transaction table capped,
  streaming parse, a pcap built to inflate state gets reported, not obeyed.
- **Timestamps are capture-clock, not device-clock.** Off-hours and interval logic
  inherit the capture point's clock; stated in the report header.

## Dependency surface — LOCKED (D3)

**scapy, and nothing else** beyond stdlib. scapy is used solely for pcap I/O and
ordered TCP payload delivery. The MBAP header and PDU parsing for the eight
in-scope FCs is hand-rolled (~100 lines against the published spec). Neither
pyshark (tshark subprocess: external binary, CVE-rich dissector surface, brittle
CI) nor scapy's contrib Modbus layer is used. No web framework, no database, no ML
library.

## What "done" looks like for Thursday (2026-07-09)

Gate 1 complete, Gate 2 skeleton (baseline object exists, may be minimally
populated). Honest sentence if asked: "I'm building a state-based Modbus anomaly
detector — ingestion's done, baseline modeling is next." Don't reach for more.
