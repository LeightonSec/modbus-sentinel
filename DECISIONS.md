# modbus-sentinel — Decision Log

Locked 2026-07-07, before Gate 1 code, per gate build doctrine (lock decisions
before code; explicit gates; verify don't assert). Each entry: decision, rationale,
rejected alternatives, revisit trigger. DESIGN.md states *what*; this file states
*why*.

---

## D1 — Device identity = (server IP, unit ID) tuple

**Decision:** every baseline, anomaly record, and report line is keyed by
(server IP, unit ID), never unit ID alone.

**Rationale:** on Modbus TCP the unit ID is commonly 0, 1, or 255 for direct-TCP
devices and only discriminating behind serial gateways, where multiple physical
devices share one IP and differ only by unit ID — while two unrelated PLCs on
different IPs both use unit ID 1. Keying by unit ID alone merges unrelated devices
and splits nothing correctly.

**Rejected:** unit ID alone (original draft). One-line fix now; a full baseline
re-key later.

**Revisit:** if v0.2 adds RTU/serial, identity needs a transport-aware scheme.

## D2 — Transaction pairing is Gate 1's core scope

**Decision:** Gate 1 includes MBAP transaction-ID pairing per TCP stream, exception
responses as first-class records, orphan counting, pipelined-ADU handling, and
split-ADU *detection* (counted as `truncated_stream`, not reassembled).

**Rationale:** a read response carries no register address — only pairing recovers
the per-transaction record the whole tool is built on. Pipelining is common
(pymodbus masters); a one-ADU-per-packet assumption silently drops transactions and
corrupts every baseline downstream. Full TCP stream reassembly is deferred, but the
drop must be *visible* — a counted limitation is honest, a silent one is a bug.

**Header-failure recovery = skip-7 (round 5, revised before the parser's first
commit):** the originally drafted policy — on a bad protocol id or impossible
length field, discard the buffered remainder from the offending header onward —
was **falsified by the corpus chunking-determinism test on the parser's first
ever run**: the amount discarded depended on how many bytes happened to be
buffered at decision time, i.e. on TCP segmentation, so the same stream bytes
could produce different reports depending on capture chunking. That violates the
Gate 1 determinism criterion. Replaced: a header-level failure consumes **exactly
the 7 untrusted header bytes** as one counted anomaly and framing resumes at the
next byte. Properties: output is independent of segmentation (the decision uses
only the first 7 buffered bytes and always costs exactly 7; enforced in CI by the
chunking-determinism test); progress stays linear (≥7 bytes per anomaly, so a
pure-garbage segment yields at most n/7 records — the same order as legitimate
traffic's n/8); and adversarial suppression shrinks from "rest of the chunk" to a
best-effort misalignment cascade in which every skipped byte is counted, never
silent. Recovery remains best-effort: a skip can land mid-frame and cascade into
further counted skips until framing realigns; per-kind anomaly counts in the
report make that visible.

**Rejected:** parse-requests-only (loses response/exception signal); full TCP
reassembly in v0.1 (scope creep for a rare case in typical captures, provided the
rare case is counted when it occurs); discard-remainder on header failure
(segmentation-dependent output — proven, not argued, by the corpus test);
byte-granular resync with coalesced garbage-run records (more state and subtler
determinism argument; revisit only if real captures show noisy skip cascades).

**Revisit:** if `truncated_stream` counts are material on real captures, promote
reassembly to v0.2.

## D3 — Parser: scapy for pcap I/O, hand-rolled MBAP/PDU parsing

**Decision:** scapy is the single third-party dependency, used only for pcap
reading and ordered TCP payload delivery. MBAP + PDU parsing for the eight in-scope
FCs is written by hand against the Modbus spec.

**Rationale:** pyshark is a subprocess wrapper around tshark — an external binary
dependency that is brittle in CI and pulls all of Wireshark's historically CVE-rich
dissector surface into the trust chain. scapy's contrib Modbus layer adds audit
surface for what is ~100 lines of spec-driven code. Small audit surface is the
point (same principle as cascade-map's pyyaml-only runtime dependency), and the
hand-written parser is itself portfolio evidence — provided D4 proves it safe.

**Rejected:** pyshark (subprocess + dissector CVE surface); scapy contrib modbus
(unaudited layer for trivial parsing); fully hand-rolled pcap reader (reimplements
solved file-format and TCP-ordering problems for no audit gain).

**Revisit:** if scapy's pcap ordering proves unreliable on real captures.

## D4 — Malformed-input corpus in CI; fuzzing local-only

**Decision:** Gate 1 pass criteria include a checked-in malformed-input fixture
corpus (truncated MBAP, oversized/zero length fields, unknown FCs, absurd register
counts, garbage exception codes) run in CI with a harness-enforced timeout. Pass =
no crash, no hang, every malformed input becomes a counted parse-anomaly record,
deterministic output. Free-running fuzzing runs locally as a corpus generator;
crashers are minimized and checked in. Fuzzing never runs in CI.

**Rationale:** a hand-rolled binary parser in a security tool is exactly the code
that introduces the bug class the tool exists to catch — off-by-one on length
fields, overread on truncated input. "Must fail closed" is an intention;
"is tested against malformed input" is a gate criterion (architect review round 2).
Deterministic corpus in CI because nondeterministic CI failures are unreproducible
and make red runs undebuggable.

**Rejected:** fail-closed as an unstated design intention (unverifiable);
free-running fuzz in CI (flaky, slow, unreproducible).

**Revisit:** corpus grows whenever local fuzzing or real captures find a new
crasher or mis-parse. Growth log: 16 → 18 in round 5 — skip-cascade realignment
and misalignment fixtures added after the chunking-determinism test falsified
the original header-failure policy (see D2).

## D5 — Polling interval: per poll group, median + MAD

**Decision:** interval baselines are computed per poll group — key
(device, FC, start address, count) — never per device. Deviation band is
median ± N·MAD, N conservative and documented in the baseline object, tuned only
against real traffic.

**Rationale:** real masters run multiple concurrent poll loops at different rates
(fast scan / slow scan), so per-device inter-arrival is multimodal and a single
mean/stddev either alarms constantly or never. Identical requests naturally
separate the loops. Within a loop the distribution is a spike with a retry tail,
not Gaussian: median + MAD is robust to it, equally deterministic, and yields the
better plain-English sentence ("arrived at 14× the median interval for this poll
group").

**Rejected:** per-device mean ± N·σ (original draft — meaningless on multimodal,
non-Gaussian data).

**Arming floor (round 3):** a poll group arms only after ≥ 10 baseline
observations. Median/MAD on 2–3 samples is noise wearing statistics — the band is
degenerate and the next observation fires almost by definition. Sub-threshold
groups appear in the report as "insufficient baseline data (n=X) — interval not
monitored" rather than being silently unmonitored: a stated gap preserves report
honesty; a silent one misleads the analyst into believing coverage that doesn't
exist.

**Revisit:** N (band width) after first real-traffic tuning pass; record old and
new values here. Floor of 10 likewise tunable against real capture durations.

## D6 — Baseline split is user-supplied

**Decision:** `--baseline-until <timestamp|packet-count>` designates the baseline
period. No auto-splitting.

**Rationale:** choosing the clean period is a human judgment the tool must not
pretend to make. An auto-split heuristic hides a judgment call inside logic the
design promises is deterministic and auditable. This also forces the
baseline-poisoning assumption (below) to the user's attention at invocation time.

**Rejected:** fixed time window, fixed transaction count, changepoint detection
(all encode the clean/dirty judgment the user must own).

**Revisit:** v0.2 could *suggest* a split point, clearly labeled as a suggestion.

## D7 — Write decision tree + fifth anomaly class

**Decision:** classes 1 (unscheduled write) and 2 (write to unknown register) are
exclusive branches of one check — register in baseline read-set vs. absent from
baseline — so one write event fires exactly one class. A fifth class,
**never-seen function code**, fires on any FC absent from the device's baseline
FC set.

**Rationale:** double-flagging one packet reads as noise and erodes exactly the
trust the "anomalous, not attack" framing buys. The original four classes were
write-centric: FC 08 (diagnostics — includes force-listen-only, a known DoS
primitive) or FC 43 (device identification — pure recon) appearing on a device
that only ever speaks FC 03/16 is the recon-then-strike signal the tool exists
for, and costs ~10 lines against data the baseline already records.

**Rejected:** overlapping classes 1/2 (original draft); FC-specific signatures for
08/43 (signature logic contradicts the behavioral premise — "not in baseline" is
the correct generalization).

**Revisit:** none expected for v0.1.

## D8 — Off-hours arming condition (amended round 3)

**Decision:** per device, the operational window is the smallest contiguous
time-of-day interval (mod 24 h) containing 100% of that device's baseline
transactions. The off-hours heuristic arms only when the baseline spans ≥ 72 hours
**and** the window covers ≤ 20 of 24 hours. Any test-period transaction outside
the window flags. When skipped, the skip and its reason are stated in the report.

**Rationale:** the original wording ("shows a clear non-24/7 pattern") was an
undefined heuristic inside a document that argues against undefined heuristics —
the same flaw D6 fixed for baseline splitting, reintroduced one section later
(caught in round 3; the review process catching its own inconsistency is the
point of having rounds). The 100%-containment rule is chosen over a percentile
rule (e.g. "90% within window") because any baseline traffic left outside the
window guarantees false positives on identical behavior in the test period — if
the device was ever active at 03:00 during baseline, 03:00 is not off-hours for
it. This also means one stray nocturnal baseline packet disarms the heuristic;
that is honest, not a bug: the baseline says the device is sometimes active at
night. A sub-72-hour baseline can't distinguish an operational window from a
short capture. Timestamps are capture-clock, not device-clock — stated in the
report header.

**Rejected:** undefined "clear pattern" (original draft); percentile containment
(builds guaranteed false positives into arming); user-supplied window (unlike the
baseline clean/dirty split of D6, the operational window is directly observable
from the data — no human judgment is being hidden, so a deterministic documented
rule is strictly better); always-on (false positives on short baselines); silent
skip (dishonest report).

**Revisit:** weekly patterns need ≥ 1 week of baseline; consider a second arming
tier in v0.2.

## D9 — Separate repo; do not extend pcap-analyser (round 4)

**Decision:** modbus-sentinel is a new repo. It does not extend or import from the
existing pcap-analyser repo.

**Rationale:** the overlap was checked against pcap-analyser's source before this
spec was written, evidence as follows. Its analyser imports
`from scapy.all import ARP, DNS, ICMP, IP, TCP, PcapReader` and performs flat
per-packet iteration feeding seven IT-layer signature engines (DoS packet-rate
thresholds, SYN-without-ACK, port-scan fan-out, ARP MAC conflict, C2 beaconing
timing, ICMP flood, DNS query length), fronted by a Flask upload UI with AbuseIPDB
enrichment. It contains no TCP stream tracking, no request/response pairing, and
no application-layer protocol parsing. The entire reusable surface for
modbus-sentinel's Gate 1 is the `PcapReader` import — one line, already the D3
choice. Gate 1's actual work (MBAP transaction-ID pairing, exception responses,
pipelined ADUs, malformed-input corpus) does not exist there to reuse, so building
separate loses no Thursday hours to redundant parsing.

Extending was also rejected on positioning grounds: pcap-analyser is
signature-based IT/SOC detection with a web UI and a live third-party API
dependency; modbus-sentinel's premise is state-based behavioral detection with a
minimal audit surface. Merging them blurs the exact distinction the design's
opening paragraph is built on, and would drag flask/requests/pydantic into a tool
whose dependency surface is locked at scapy-only (D3).

**Reused anyway (technique, not code):** pcap-analyser's `generate_test_pcaps.py`
pattern for synthetic fixture captures (feeds Gate 3's injected-anomaly pcaps and
the D4 malformed corpus) and its `requirements.in` header documenting the
lockfile-vs-CI-floor compile discipline.

**Rejected:** extending pcap-analyser (no reusable ingestion logic; positioning
blur; dependency surface violation); shared parsing library between the two repos
(premature — one line of shared code).

**Revisit:** if a third pcap-consuming tool appears, reconsider a shared ingestion
library.

## D10 — Direction attribution is evidence-based and fails closed (round 6)

**Decision:** which side of a TCP stream is the Modbus client is decided from two
independent evidence sources, never guessed:

1. **Port rule:** exactly one endpoint's port is 502 → that endpoint is the
   server.
2. **Handshake rule:** a SYN (without ACK) is observed → its sender is the
   client.

If only one rule fires, it decides. If **neither** fires, the stream is counted as
an `unattributed_stream` anomaly (with packet/byte counts) and not parsed. If
**both fire and disagree** — only possible when a host initiates a connection
*from* source port 502 — the stream is counted as a `direction_conflict` anomaly
and not parsed. Disagreeing evidence is itself signal (broken NAT, or a capture
crafted to probe the tiebreak); silently letting rule ordering win would be a
guessed direction, and a guessed direction is a silent lie in every downstream
record. (Conflict flagging added in review round 6 — the original draft let the
port rule win by ordering, unflagged.)

**Rejected:** content-based direction sniffing (parse both ways, pick the cleaner
side) — the pcap is hostile input; the adversary authored the bytes and therefore
gets a vote in any content-based decision. A counted refusal is honest.

**Revisit:** if real captures show material `unattributed_stream` counts on
nonstandard ports without handshakes, consider an explicit `--server` operator
override (operator assertion, not inference).

## D11 — Pairing semantics, exception matching, and stream lifecycle (round 6)

**Decision:** request/response pairing within one TCP stream incarnation:

- **Pairing key:** `(transaction_id, unit_id)`. Unit ID is in the key so serial
  gateways multiplexing several units over one connection pair correctly.
- **FC match condition — on the parser-normalized FC:** a response pairs when its
  `ParsedADU.function_code` equals the request's. The parser (mbap.py) already
  strips the 0x80 exception bit and sets `is_exception`/`exception_code`, so
  legitimate exception responses (wire FC = request FC | 0x80) pair on the base
  FC and become TransactionRecords with `exception=true` — never discarded. This
  is stated explicitly because the wire-level FCs *differ* for exceptions: an
  implementation matching raw wire bytes silently drops every exception response.
  (Caught in review round 6 at the spec layer; the shipped parser's
  normalization masked it. An exception-response pairing fixture is a required
  positive control in the Gate 1 test plan.)
- **FC mismatch after normalization** → counted `pairing_mismatch`; neither side
  becomes a transaction record.
- **Response with no outstanding request** → counted `orphan_response`.
- **Duplicate outstanding key** (new request while same key unanswered) → old
  request becomes a counted `orphan_request` (detail: `tid_reuse`), new request
  takes the slot. Deterministic, bounded.
- **Stream lifecycle:** pairing state is per **connection incarnation**. A new
  SYN on a live 4-tuple finalizes the previous incarnation first — outstanding
  requests → counted `orphan_request`s, parser `finish()` flushes any partial
  frame as `truncated_stream` — then state resets. Stale TIDs never bleed across
  incarnations. End of capture finalizes all incarnations the same way.
- **Memory bound:** outstanding-request table capped at 65536 per stream (the
  TID space); overflow is counted, not obeyed — a pcap built to inflate state
  gets reported.
- **Record shape:** TransactionRecord carries request and response timestamps,
  device key (server IP, unit ID), FC, address/quantity/value, read/write class,
  exception flag + code. Canonical timestamp for baseline math is the **request**
  timestamp — D5's poll-group intervals model master behavior, and the request is
  the master's act.

**Rejected:** wire-FC equality for pairing (drops all exception responses —
protocol-defined FC|0x80 fails naive equality); pairing on transaction ID alone
(mispairs multiplexed gateway units); letting stale outstanding requests survive
connection reuse (nondeterministic bleed discovered four review rounds late is
exactly the failure mode this file exists to prevent).

**Revisit:** if real captures show masters legitimately reusing TIDs with
multiple outstanding requests (nonconforming but observed in the field), revisit
the replace-and-orphan policy.

---

## Standing assumption (not a decision — a boundary)

**Baseline assumed clean.** An attacker present during the baseline period is
learned as normal. Structural to all baseline-and-deviation detection; stated in
the README so the tool declares its own trust boundary instead of hoping nobody
asks.
