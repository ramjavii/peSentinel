from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pesentinel.cli import app

runner = CliRunner()


def test_batch_scan(tmp_path: Path) -> None:
    folder = tmp_path / "samples"
    folder.mkdir()
    (folder / "a.exe").write_bytes(b"file a content")
    (folder / "b.exe").write_bytes(b"file b content")
    audit_log = tmp_path / "audit.jsonl"
    import pesentinel.cli as cli_mod

    orig = cli_mod._DEFAULT_AUDIT_LOG
    cli_mod._DEFAULT_AUDIT_LOG = audit_log
    try:
        result = runner.invoke(app, ["batch", "--folder", str(folder), "--offline"])
    finally:
        cli_mod._DEFAULT_AUDIT_LOG = orig
    assert result.exit_code == 0, result.output
    assert "Scanning" in result.output or "BENIGN" in result.output


def test_batch_scan_with_report(tmp_path: Path) -> None:
    folder = tmp_path / "samples"
    folder.mkdir()
    (folder / "a.exe").write_bytes(b"content a")
    report = tmp_path / "batch_report.json"
    audit_log = tmp_path / "audit.jsonl"
    import pesentinel.cli as cli_mod

    orig = cli_mod._DEFAULT_AUDIT_LOG
    cli_mod._DEFAULT_AUDIT_LOG = audit_log
    try:
        result = runner.invoke(
            app,
            ["batch", "--folder", str(folder), "--offline", "--report", str(report)],
        )
    finally:
        cli_mod._DEFAULT_AUDIT_LOG = orig
    assert result.exit_code == 0, result.output
    data = json.loads(report.read_text())
    assert isinstance(data, list)
    assert len(data) == 1


def test_batch_scan_missing_dir(tmp_path: Path) -> None:
    result = runner.invoke(app, ["batch", "--folder", str(tmp_path / "nope")])
    assert result.exit_code != 0
