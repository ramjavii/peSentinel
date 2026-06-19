from __future__ import annotations

from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import ObjectOrphaned, Right


def test_revoke_marks_object_orphaned_when_zero_rights() -> None:
    k = ProtectionKernel()
    k.grant("d", "o", Right.READ)
    assert not k.is_orphaned("o")
    k.revoke("d", "o", Right.READ)
    assert k.is_orphaned("o")


def test_object_not_orphaned_if_other_domains_hold_rights() -> None:
    k = ProtectionKernel()
    k.grant("d1", "o", Right.READ)
    k.grant("d2", "o", Right.WRITE)
    k.revoke("d1", "o", Right.READ)
    assert not k.is_orphaned("o")


def test_orphaned_objects_set() -> None:
    k = ProtectionKernel()
    k.grant("d", "o1", Right.READ)
    k.grant("d", "o2", Right.READ)
    k.revoke("d", "o1", Right.READ)
    assert k.orphaned_objects() == frozenset({"o1"})


def test_reclaim_orphaned() -> None:
    k = ProtectionKernel()
    k.grant("d", "o", Right.READ)
    k.revoke("d", "o", Right.READ)
    assert k.is_orphaned("o")
    # orphaned set is queryable; reclaiming via registry internals
    k._revocation.reclaim("o")  # noqa: SLF001
    assert not k.is_orphaned("o")


def test_reclaim_non_orphaned_raises() -> None:
    k = ProtectionKernel()
    try:
        k._revocation.reclaim("nope")  # noqa: SLF001
        raise AssertionError("expected ObjectOrphaned")
    except ObjectOrphaned:
        pass
