from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pesentinel.cli import app

runner = CliRunner()


def test_cli_scan_offline(tmp_path: Path) -> None:
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"benign content for cli test")
    result = runner.invoke(app, ["--file", str(sample), "--offline"])
    assert result.exit_code == 0, result.output
    assert "benign" in result.output.lower() or "unknown" in result.output.lower()


def test_cli_scan_missing_file_returns_nonzero(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--file", str(tmp_path / "nope.exe"), "--offline"])
    assert result.exit_code != 0


def test_cli_scan_writes_report(tmp_path: Path) -> None:
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"benign content for report test")
    report = tmp_path / "out.json"
    result = runner.invoke(
        app, ["--file", str(sample), "--offline", "--report", str(report)]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(report.read_text())
    assert "final_verdict" in data
    assert "signals" in data
