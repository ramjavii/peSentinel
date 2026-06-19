from __future__ import annotations

from pathlib import Path

from pesentinel.security.integrity import IntegrityDB


def test_init_baseline_creates_db(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yar").write_text("rule a { condition: false }")
    (rules_dir / "b.yar").write_text("rule b { condition: false }")
    baseline = tmp_path / "baseline.json"
    db = IntegrityDB(baseline, tmp_path)
    count = db.init_baseline([rules_dir])
    assert count == 2
    assert baseline.exists()


def test_verify_clean(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yar").write_text("rule a { condition: false }")
    baseline = tmp_path / "baseline.json"
    db = IntegrityDB(baseline, tmp_path)
    db.init_baseline([rules_dir])
    report = db.verify([rules_dir])
    assert report.is_clean
    assert not report.is_tampered


def test_verify_detects_changed(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    f = rules_dir / "a.yar"
    f.write_text("rule a { condition: false }")
    baseline = tmp_path / "baseline.json"
    db = IntegrityDB(baseline, tmp_path)
    db.init_baseline([rules_dir])
    f.write_text("rule a { condition: true }")
    report = db.verify([rules_dir])
    assert report.changed
    assert report.is_tampered


def test_verify_detects_added(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yar").write_text("rule a { condition: false }")
    baseline = tmp_path / "baseline.json"
    db = IntegrityDB(baseline, tmp_path)
    db.init_baseline([rules_dir])
    (rules_dir / "b.yar").write_text("rule b { condition: false }")
    report = db.verify([rules_dir])
    assert any("b.yar" in p for p in report.added)


def test_verify_detects_deleted(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    f = rules_dir / "a.yar"
    f.write_text("rule a { condition: false }")
    baseline = tmp_path / "baseline.json"
    db = IntegrityDB(baseline, tmp_path)
    db.init_baseline([rules_dir])
    f.unlink()
    report = db.verify([rules_dir])
    assert any("a.yar" in p for p in report.deleted)


def test_verify_no_baseline(tmp_path: Path) -> None:
    db = IntegrityDB(tmp_path / "nonexistent.json", tmp_path)
    report = db.verify([tmp_path])
    assert not report.is_clean
