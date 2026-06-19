from __future__ import annotations

from pesentinel.protection.types import (
    AccessControlException,
    CapabilityForgeError,
    EventKind,
    ObjectOrphaned,
    Right,
    Verdict,
)


def test_right_values_are_distinct() -> None:
    assert Right.READ != Right.WRITE
    assert Right.NETWORK_CALL != Right.SCAN


def test_verdict_members() -> None:
    assert {v.value for v in Verdict} == {
        "benign",
        "suspicious",
        "malicious",
        "unknown",
    }


def test_event_kind_members() -> None:
    assert EventKind.AUTHZ_DENY.value == "authz_deny"


def test_access_control_exception_is_exception() -> None:
    assert issubclass(AccessControlException, Exception)


def test_capability_forge_error_subclasses_access() -> None:
    assert issubclass(CapabilityForgeError, AccessControlException)


def test_object_orphaned_is_exception() -> None:
    assert issubclass(ObjectOrphaned, Exception)
