from __future__ import annotations

import json
from pathlib import Path

from pesentinel.protection.types import EventKind
from pesentinel.security.audit import JsonlAuditSink, is_strange_hour


def test_record_writes_jsonl(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(log)
    sink.record(EventKind.ACCESS_CHECK, "d", "s", "o", "READ", "allow", "ok")
    assert log.exists()
    lines = log.read_text().strip().split("\n")
    assert len(lines) == 1
    d = json.loads(lines[0])
    assert d["event"] == "access_check"
    assert d["domain"] == "d"
    assert d["decision"] == "allow"


def test_read_all_returns_records(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(log)
    sink.record(EventKind.AUTH_SUCCESS, "admin", "admin", "", "", "allow", "ok")
    sink.record(EventKind.AUTH_FAILURE, "admin", "admin", "", "", "deny", "bad")
    records = sink.read_all()
    assert len(records) == 2
    assert records[0].event == "auth_success"
    assert records[1].event == "auth_failure"


def test_read_all_empty_when_no_file(tmp_path: Path) -> None:
    sink = JsonlAuditSink(tmp_path / "nonexistent.jsonl")
    assert sink.read_all() == []


def test_is_strange_hour() -> None:
    import datetime

    # 2am UTC = strange
    ts2am = datetime.datetime(2026, 1, 1, 2, 0, tzinfo=datetime.UTC).timestamp()
    assert is_strange_hour(ts2am) is True
    # noon UTC = normal
    ts_noon = datetime.datetime(2026, 1, 1, 12, 0, tzinfo=datetime.UTC).timestamp()
    assert is_strange_hour(ts_noon) is False
    # 22:00 UTC = strange
    ts22 = datetime.datetime(2026, 1, 1, 22, 0, tzinfo=datetime.UTC).timestamp()
    assert is_strange_hour(ts22) is True


def test_creates_parent_dir(tmp_path: Path) -> None:
    log = tmp_path / "subdir" / "audit.jsonl"
    sink = JsonlAuditSink(log)
    sink.record(EventKind.ACCESS_CHECK, "d", "s", "o", "READ", "allow", "ok")
    assert log.exists()
