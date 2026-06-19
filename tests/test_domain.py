from __future__ import annotations

from pesentinel.protection.domain import (
    ActiveDomain,
    AuditSink,
    NullAuditSink,
    active_domain,
)
from pesentinel.protection.types import EventKind


class _RecordingSink:
    """Test audit sink that records all events."""

    def __init__(self) -> None:
        self.records: list[tuple[object, ...]] = []

    def record(
        self,
        event: EventKind,
        domain: str,
        subject: str,
        obj: str,
        right: str,
        decision: str,
        reason: str,
        stack_annot: bool = False,
    ) -> None:
        self.records.append((event, domain, subject, obj, right, decision, reason))


def test_active_domain_is_none_by_default() -> None:
    assert active_domain() is None


def test_active_domain_context_sets_and_restores() -> None:
    sink = _RecordingSink()
    with ActiveDomain("hash_signal", sink):
        assert active_domain() == "hash_signal"
    assert active_domain() is None


def test_active_domain_restores_previous() -> None:
    sink = _RecordingSink()
    with ActiveDomain("outer", sink):
        with ActiveDomain("inner", sink):
            assert active_domain() == "inner"
        assert active_domain() == "outer"
    assert active_domain() is None


def test_domain_switch_audited() -> None:
    sink = _RecordingSink()
    with ActiveDomain("d", sink):
        pass
    assert len(sink.records) == 2
    assert sink.records[0][0] == EventKind.DOMAIN_SWITCH
    assert sink.records[0][5] == "enter"
    assert sink.records[1][5] == "exit"


def test_null_sink_is_noop() -> None:
    sink: AuditSink = NullAuditSink()
    sink.record(EventKind.ACCESS_CHECK, "d", "s", "o", "READ", "allow", "ok")
