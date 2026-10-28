"""CLI tests: the real pipeline through main() in-process (so coverage counts).

The Gate 3 family pcaps (tests/family_builder.py) run through the CLI: the
injected unscheduled write exits 1 with the finding in the report, the clean
pcap from the same family exits 0. Exit codes: 0 no findings, 1 findings,
2 usage or input error (B2, B3).
"""

import json
from pathlib import Path

import pytest
from family_builder import END, T0, UNTIL, write_family_pcap
from pcap_builder import read_req, read_resp, write_single_req

from modbus_sentinel import __version__
from modbus_sentinel.cli import main

UNTIL_ARG = str(int(UNTIL))  # epoch seconds, 2026-07-06T08:02:00Z
INJECT_105 = [
    (T0 + 150.3, lambda t: write_single_req(t, 1, 105, 7), lambda t: write_single_req(t, 1, 105, 7))
]


def family(tmp_path: Path, inject=None) -> str:
    return str(write_family_pcap(tmp_path / "family.pcap", inject))


def test_gate3_injected_write_exit_1_and_finding(tmp_path: Path, capsys) -> None:
    rc = main([family(tmp_path, INJECT_105), "--baseline-until", UNTIL_ARG])
    out = capsys.readouterr().out
    assert rc == 1
    assert "  findings: 1" in out
    assert "class 1 unscheduled write" in out
    assert "holding registers 105, value 7" in out


def test_gate3_clean_pcap_exit_0(tmp_path: Path, capsys) -> None:
    rc = main([family(tmp_path), "--baseline-until", UNTIL_ARG])
    out = capsys.readouterr().out
    assert rc == 0
    assert "  findings: none" in out
    assert "  parse and pairing anomalies: none" in out


def test_iso_baseline_until_accepted(tmp_path: Path, capsys) -> None:
    assert main([family(tmp_path), "--baseline-until", "2026-07-06T08:02:00Z"]) == 0
    assert "transactions requested before 2026-07-06T08:02:00Z" in capsys.readouterr().out


def test_json_output_parses(tmp_path: Path, capsys) -> None:
    rc = main([family(tmp_path, INJECT_105), "--baseline-until", UNTIL_ARG, "--json"])
    captured = capsys.readouterr()
    assert rc == 1
    data = json.loads(captured.out)  # stdout is pure JSON
    (f,) = data["detection"]["findings"]
    assert [r["anomaly_class"] for r in f["why"]] == [1]
    assert f["what"]["value"] == 7
    assert "For authorised use only" in captured.err


def test_missing_baseline_until_exit_2(tmp_path: Path, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main([family(tmp_path)])
    assert exc.value.code == 2
    assert "--baseline-until" in capsys.readouterr().err


def test_malformed_baseline_until_exit_2(tmp_path: Path, capsys) -> None:
    assert main([family(tmp_path), "--baseline-until", "yesterday"]) == 2
    assert "is not a timestamp" in capsys.readouterr().err


def test_naive_baseline_until_exit_2(tmp_path: Path, capsys) -> None:
    assert main([family(tmp_path), "--baseline-until", "2026-07-06T08:02:00"]) == 2
    assert "no UTC offset" in capsys.readouterr().err


def test_missing_pcap_arg_exit_2() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--baseline-until", UNTIL_ARG])
    assert exc.value.code == 2


def test_nonexistent_pcap_exit_2(tmp_path: Path, capsys) -> None:
    assert main([str(tmp_path / "missing.pcap"), "--baseline-until", UNTIL_ARG]) == 2
    assert "error: cannot read" in capsys.readouterr().err


def test_not_a_pcap_exit_2(tmp_path: Path, capsys) -> None:
    path = tmp_path / "notes.pcap"
    path.write_text("this is a text file, not a packet capture\n", encoding="utf-8")
    assert main([str(path), "--baseline-until", UNTIL_ARG]) == 2
    assert "error: cannot read" in capsys.readouterr().err


def test_empty_baseline_exit_2(tmp_path: Path, capsys) -> None:
    assert main([family(tmp_path), "--baseline-until", str(int(T0 - 10))]) == 2
    assert "nothing to learn" in capsys.readouterr().err


def test_empty_detection_period_exit_0(tmp_path: Path, capsys) -> None:
    assert main([family(tmp_path), "--baseline-until", str(int(END + 10))]) == 0
    assert "nothing analysed" in capsys.readouterr().out


def test_malformed_record_rejected_run_continues(tmp_path: Path, capsys) -> None:
    """B1: a request the parser accepts but whose range runs past 65535 is
    rejected and reported; the real finding in the same capture still shows."""
    bad = (T0 + 160.3, lambda t: read_req(t, 1, 3, 65530, 10), lambda t: read_resp(t, 1, 3, 10))
    rc = main([family(tmp_path, INJECT_105 + [bad]), "--baseline-until", UNTIL_ARG])
    out = capsys.readouterr().out
    assert rc == 1
    assert "rejected: malformed, not analysed" in out
    assert "address range 65530-65539 exceeds 65535" in out
    assert "class 1 unscheduled write" in out


def test_ethical_warning_on_stderr_not_stdout(tmp_path: Path, capsys) -> None:
    main([family(tmp_path), "--baseline-until", UNTIL_ARG])
    captured = capsys.readouterr()
    assert "For authorised use only" in captured.err
    assert "For authorised use only" not in captured.out


def test_version_exit_0(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert f"modbus-sentinel {__version__}" in capsys.readouterr().out


def test_unbaselined_device_does_not_change_exit_code(tmp_path: Path, capsys) -> None:
    unit3 = [(T0 + 150.3, lambda t: read_req(t, 3, 3, 100, 10), lambda t: read_resp(t, 3, 3, 10))]
    assert main([family(tmp_path, unit3), "--baseline-until", UNTIL_ARG]) == 0
    out = capsys.readouterr().out
    assert "not analysed: no baseline for these devices" in out
    assert "device 192.168.1.20 unit 3" in out
