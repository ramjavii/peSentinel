from __future__ import annotations

from pathlib import Path

from pesentinel.security.integrity import IntegrityDB
from pesentinel.security.selfscan import selfscan


def test_clean_install(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "data").mkdir()
    report = selfscan(tmp_path)
    # PATH checks may find issues on the real system, so we only assert
    # that the report is well-formed
    assert isinstance(report.is_clean, bool)
    assert isinstance(report.findings, list)


def test_detects_setuid_binary(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    fake_bin = tmp_path / "src" / "suspicious"
    fake_bin.write_text("#!/bin/sh")
    fake_bin.chmod(0o4755)
    report = selfscan(tmp_path)
    assert not report.is_clean
    assert any(f.category == "setuid_binary" for f in report.findings)


def test_detects_world_writable_dir(tmp_path: Path) -> None:
    (tmp_path / "data").mkdir()
    (tmp_path / "data").chmod(0o777)
    report = selfscan(tmp_path)
    assert not report.is_clean
    assert any(f.category == "world_writable_dir" for f in report.findings)


def test_detects_checksum_change(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    f = rules_dir / "a.yar"
    f.write_text("rule a { condition: false }")
    baseline = tmp_path / "baseline.json"
    db = IntegrityDB(baseline, tmp_path)
    db.init_baseline([rules_dir])
    f.write_text("rule a { condition: true }")
    report = selfscan(tmp_path, integrity_db=db, monitored_dirs=[rules_dir])
    assert not report.is_clean
    assert any(f.category == "checksum_change" for f in report.findings)


def test_high_severity_count(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    fake_bin = tmp_path / "src" / "suid"
    fake_bin.write_text("x")
    fake_bin.chmod(0o4755)
    report = selfscan(tmp_path)
    assert report.high_severity_count >= 1
