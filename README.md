# modbus-sentinel

![Version](https://img.shields.io/badge/version-v0.1.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![CI](https://github.com/LeightonSec/modbus-sentinel/actions/workflows/ci.yml/badge.svg)

> State-based anomaly detector for Modbus TCP pcaps. Given a sequence of
> well-formed Modbus transactions, it answers one question: is this device's
> behavior consistent with its own history?

**Status: Gates 1 (ingestion) and 2 (baseline) complete; Gate 3 (detection)
runs classes 1, 2 and 5, with classes 3 and 4 not yet implemented; the Gate 4
minimum report is built.** Live gate status is tracked in [GATES.md](GATES.md).
The full spec is in [DESIGN.md](DESIGN.md); every locked decision with rationale
and rejected alternatives is in [DECISIONS.md](DECISIONS.md).

---

## Ethical Use

This tool is provided for **authorised security testing, research, and educational
purposes only**. Analyse only traffic captures you own or have explicit written
permission to analyse. Unauthorised use may violate the Computer Misuse Act (UK),
the CFAA (US), and equivalent laws. The author accepts no liability for misuse.

---

## What it does (and deliberately doesn't)

A malformed Modbus packet is trivially caught by any protocol parser. A sequence
of valid, individually-legal transactions that together represent process
manipulation (an unscheduled write, polling-interval drift, a write to a register
that has only ever been read) is invisible to signature-based tooling. That
behavioral gap is what this tool targets.

It is **not** a general IDS, not a Zeek/Snort replacement, not live/inline
monitoring, not a fuzzer, and speaks Modbus TCP only. There is no ML: detection is
baseline-and-deviation logic, deterministic and auditable, so "why did this fire"
is always answerable in plain English.

## Usage

```sh
modbus-sentinel capture.pcap --baseline-until 2026-07-06T08:00:00Z
modbus-sentinel capture.pcap --baseline-until 1783324800 --json
```

Transactions requested before `--baseline-until` form the baseline; everything
after it is checked against that baseline. `--baseline-until` takes epoch
seconds or ISO 8601 with an offset. The baseline period is assumed clean:
anything in it is learned as normal.

Exit codes: `0` no findings, `1` at least one finding, `2` usage or input error
(a bad `--baseline-until`, an unreadable pcap, or no transactions before
`--baseline-until`).

## Try it

From a clone, with Python 3.10 or later, run from the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install --require-hashes -r requirements.txt
pip install --no-deps -e .
python -m scripts.make_demo_pcap demo.pcap
modbus-sentinel demo.pcap --baseline-until 2026-07-06T08:02:00Z
```

`--require-hashes` checks scapy, the only runtime dependency, against the hashes in `requirements.txt`. The editable install still downloads its build tools (setuptools and wheel) without hash checks.

The demo capture starts at 2026-07-06T08:00:00Z, so the cutoff sits two minutes
in; the Usage example's cutoff would leave this capture no baseline.

```text
For authorised use only. Analyse only captures you own or have explicit
written permission to analyse.

modbus-sentinel report
  pcap: demo.pcap
  clock: capture clock, UTC (not device clock). Addresses are 0-based wire addresses.
  baseline period: transactions requested before 2026-07-06T08:02:00Z; assumed clean, so anything in it is learned as normal.
  wording: findings are anomalous, not attack; each class is a heuristic, not proof of malice.

ingest
  packets: 119 (0 non-TCP), paired transactions: 58
  retransmissions deduplicated: 0 segments, 0 bytes
  parse and pairing anomalies: none

baseline
  28 transactions in the baseline period, 1 device (full baseline in --json)
  device 192.0.2.20 unit 1: 28 transactions, 0 exception responses, function codes 03, 06

detection
  classes run: 1 unscheduled write, 2 write to unknown register, 5 never-seen function code
  transactions analysed: 30
  findings: 2

  finding 1 of 2
    what happened: 2026-07-06T08:02:30.300Z 192.0.2.20 unit 1 FC 06 write single register, holding registers 105, value 500
    why flagged:   class 1 unscheduled write: anomalous: holding registers 105 only ever read in the baseline, never written

  finding 2 of 2
    what happened: 2026-07-06T08:02:50.300Z 192.0.2.20 unit 1 FC 08 diagnostics, sub-function 0x0001
    why flagged:   class 5 never-seen function code: anomalous: function code 08 (diagnostics) was never used successfully with this device in the baseline

coverage gaps
  classes not implemented: 3 (polling-interval break), 4 (off-hours activity)
  unanswered or superseded requests are not analysed: 0 orphan requests counted
  function codes outside the supported set are counted, not attributed to a device: 0
  streams not parsed (direction unknown or conflicting): 0
  FC 08 sub-function 0x0004 (force listen only) gets no response by specification, so an unanswered one is counted as an orphan request and is not attributed to a device; class 5 cannot see it
```

The exit code is 1 because there are findings; see Usage for the exit codes.

What you are looking at:

- One capture, split at the cutoff: the first two minutes are the baseline, the
  last two are checked against it. The baseline is rebuilt on every run.
- The baseline period is assumed clean, as in real use.
- The data is synthetic and regular: one client reads holding registers 100-109
  every 5 s and writes register 40 every 30 s, with two planted events after the
  cutoff. `scripts/make_demo_pcap.py` writes it at run time.
- The FC 6 write to register 105, which was only ever read, is class 1. The FC 08
  request, a function code this device never used, is class 5. A hit on a
  planted event shows the logic works; it is not a detection rate.
- Classes 3 and 4 are not implemented. An FC 08 sub-function 0x0004 request
  gets no response and is the documented miss.

## The five anomaly classes

Classes 1, 2 and 5 run today; classes 3 and 4 are not yet implemented, and the
report names them as such. Per device, identified as (server IP, unit ID), never
unit ID alone, a baseline period of the capture establishes normal, and the
detection period is checked for:

1. **Unscheduled write:** write to a register only ever read in baseline
2. **Write to unknown register:** write to a register the baseline never saw
   (recon-then-strike pattern)
3. **Polling-interval break:** per poll group, median ± N·MAD band, armed at
   ≥ 10 baseline observations (not yet implemented: N not decided)
4. **Off-hours activity:** traffic outside the device's observed operational
   window (arming rules in DESIGN.md; not yet implemented)
5. **Never-seen function code:** any supported FC absent from the device's
   baseline set, including FC 08 (diagnostics) and FC 43 (device
   identification, MEI type 0x0E) (DECISIONS.md D13). Not caught: FC 08
   sub-function 0x0004 (force listen only) gets no response by specification,
   so it stays an unanswered request, and the report says so.

Classes 1 and 2 compare addresses per Modbus table (coils, discrete inputs,
holding registers, input registers). Each class is a heuristic, not a proof of
malice. The report says **anomalous, not attack** and states what it did not
analyse: classes 3 and 4, devices with no baseline, unanswered requests,
function codes outside the supported set, unparsed streams, and records
rejected as malformed. A silent gap misleads the analyst into believing coverage
that doesn't exist.

## Trust boundaries: read before trusting the output

- **The baseline period is assumed clean.** You designate it with
  `--baseline-until`; the tool will not guess. An attacker present during the
  baseline is learned as normal. This is structural to all
  baseline-and-deviation detection, not a fixable bug.
- **The pcap is treated as hostile input.** The adversary being analysed authored
  some of those bytes. Malformed frames become counted parse-anomaly records
  (never crashes, never silent skips). Every line of the text report is escaped
  to printable ASCII and packet bytes appear only as hex, so nothing
  packet-derived reaches your terminal raw. A record whose address range runs
  past 65535 is rejected and listed, and the run continues.
- **Unanswered writes are not analysed.** A write with no response is counted as
  an orphan request, not passed to detection (DECISIONS.md D12).
- **Timestamps are capture-clock, not device-clock.**

## Dependency surface

One runtime dependency: **scapy**, used solely for pcap I/O and ordered TCP
payload delivery. MBAP/PDU parsing is hand-rolled against the Modbus
specification and tested against a synthetic,
deterministic malformed-input corpus, committed as ground truth and run in CI
(built from literal bytes, no captured traffic). Small audit surface is the point.

## License

MIT. See [LICENSE](LICENSE).
