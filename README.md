# modbus-sentinel

![Version](https://img.shields.io/badge/version-v0.1.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![CI](https://github.com/LeightonSec/modbus-sentinel/actions/workflows/ci.yml/badge.svg)

> State-based anomaly detector for Modbus TCP pcaps. Given a sequence of
> well-formed Modbus transactions, it answers one question: is this device's
> behavior consistent with its own history?

**Status: Gate 1 (ingestion) complete (commit `7ebc595`); Gate 2 (baseline
construction) and Gate 3 (anomaly detection) in progress.** Live gate status is
tracked in [GATES.md](GATES.md). The full spec is in [DESIGN.md](DESIGN.md);
every locked decision with rationale and rejected alternatives is in
[DECISIONS.md](DECISIONS.md).

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

## The five anomaly classes

**Not yet implemented.** Baseline (Gate 2) and detection (Gate 3) are in
progress; see [GATES.md](GATES.md). The design: per device, identified as
(server IP, unit ID), never unit ID alone, a baseline period of the capture
establishes normal, and the detection period is checked for:

1. **Unscheduled write:** write to a register only ever read in baseline
2. **Write to unknown register:** write to a register the baseline never saw
   (recon-then-strike pattern)
3. **Polling-interval break:** per poll group, median ± N·MAD band, armed at
   ≥ 10 baseline observations (deferred until N is decided)
4. **Off-hours activity:** traffic outside the device's observed operational
   window (arming rules in DESIGN.md; deferred)
5. **Never-seen function code:** any supported FC absent from the device's
   baseline set. FC 08 and FC 43 are not yet covered (DECISIONS.md D12)

Classes 1 and 2 compare addresses per Modbus table (coils, discrete inputs,
holding registers, input registers). Each class is a heuristic, not a proof of
malice. Reports will say **anomalous, not attack**, and will state every skipped
heuristic with its reason. A silent gap misleads the analyst into believing
coverage that doesn't exist.

## Trust boundaries: read before trusting the output

- **The baseline period is assumed clean.** You will designate it
  (`--baseline-until`, a timestamp; not yet wired into analysis); the tool will
  not guess. An attacker present during the baseline is learned as normal. This
  is structural to all baseline-and-deviation detection, not a fixable bug.
- **The pcap is treated as hostile input.** The adversary being analysed authored
  some of those bytes. Malformed frames become counted parse-anomaly records
  (never crashes, never silent skips). Escaping packet-derived bytes before they
  reach your terminal is a Gate 4 requirement and is not built yet.
- **Unanswered writes are not analysed.** A write with no response is counted as
  an orphan request, not passed to detection (DECISIONS.md D12).
- **Timestamps are capture-clock, not device-clock.**

## Dependency surface

One runtime dependency: **scapy**, used solely for pcap I/O. MBAP/PDU parsing is
hand-rolled against the Modbus specification and tested against a synthetic,
deterministic malformed-input corpus, committed as ground truth and run in CI
(built from literal bytes, no captured traffic). Small audit surface is the point.

## License

MIT. See [LICENSE](LICENSE).
