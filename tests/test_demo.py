"""The README "Try it" demo, end to end.

scripts/make_demo_pcap.py runs as a subprocess, the way the README tells a user
to run it (python -m scripts.make_demo_pcap from the repo root, as make check
runs scripts.emit_golden). The CLI then runs in-process through main(), as in
tests/test_cli.py. The capture is synthetic and written to a pytest tmp dir.
"""

import json
import subprocess
import sys
from pathlib import Path

from modbus_sentinel.cli import main

REPO = Path(__file__).resolve().parent.parent
CUTOFF = "2026-07-06T08:02:00Z"  # the cutoff the README uses


def demo_pcap(tmp_path: Path) -> str:
    out = tmp_path / "demo.pcap"
    subprocess.run(
        [sys.executable, "-m", "scripts.make_demo_pcap", str(out)],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    )
    return str(out)


def test_demo_flags_exactly_the_two_planted_events(tmp_path: Path, capsys) -> None:
    """The FC 6 write to register 105 (read in the baseline, never written) is
    class 1 only, since FC 6 is in the baseline; the FC 08 request is class 5
    only. The steady polling and the register 40 writes produce nothing."""
    rc = main([demo_pcap(tmp_path), "--baseline-until", CUTOFF, "--json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 1
    (device,) = data["baseline"]["devices"]
    assert (device["server_ip"], device["unit_id"]) == ("192.0.2.20", 1)
    assert data["ingest"]["anomaly_counts"] == {}
    assert data["detection"]["unbaselined"] == [] and data["rejected"] == []
    write, probe = data["detection"]["findings"]
    assert [r["anomaly_class"] for r in write["why"]] == [1]
    assert (write["what"]["function_code"], write["what"]["start_address"], write["what"]["value"]) == (6, 105, 500)
    assert [r["anomaly_class"] for r in probe["why"]] == [5]
    assert (probe["what"]["function_code"], probe["what"]["subfunction"]) == (8, 0x0001)
