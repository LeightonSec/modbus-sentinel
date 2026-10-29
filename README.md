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
