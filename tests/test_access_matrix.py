from __future__ import annotations

from pesentinel.protection.access_matrix import AccessMatrix
from pesentinel.protection.types import Right


def test_grant_and_has_right() -> None:
    m = AccessMatrix()
    m.grant("hash_signal", "sample_file", Right.READ)
    assert m.has_right("hash_signal", "sample_file", Right.READ)
    assert not m.has_right("hash_signal", "sample_file", Right.WRITE)


def test_grant_multiple_rights() -> None:
    m = AccessMatrix()
    m.grant("admin", "rules_dir", frozenset({Right.READ, Right.WRITE}))
    assert m.has_right("admin", "rules_dir", Right.READ)
    assert m.has_right("admin", "rules_dir", Right.WRITE)
    assert not m.has_right("admin", "rules_dir", Right.EXECUTE)


def test_revoke_removes_right() -> None:
    m = AccessMatrix()
    m.grant("d", "o", Right.READ)
    removed = m.revoke("d", "o", Right.READ)
    assert removed == {Right.READ}
    assert not m.has_right("d", "o", Right.READ)


def test_revoke_drops_empty_cell() -> None:
    m = AccessMatrix()
    m.grant("d", "o", Right.READ)
    m.revoke("d", "o", Right.READ)
    assert m.rights_for_domain("d") == {}


def test_access_list_view() -> None:
    m = AccessMatrix()
    m.grant("d1", "obj", Right.READ)
    m.grant("d2", "obj", Right.WRITE)
    view = m.rights_for_object("obj")
    assert view == {"d1": {Right.READ}, "d2": {Right.WRITE}}


def test_capability_list_view() -> None:
    m = AccessMatrix()
    m.grant("d", "o1", Right.READ)
    m.grant("d", "o2", Right.WRITE)
    view = m.rights_for_domain("d")
    assert view == {"o1": {Right.READ}, "o2": {Right.WRITE}}


def test_capabilities_for_domain_are_unforgeable() -> None:
    m = AccessMatrix()
    m.grant("d", "o", Right.READ)
    caps = m.capabilities_for_domain("d")
    assert len(caps) == 1
    assert caps[0].domain == "d"
    assert caps[0].right == Right.READ


def test_total_rights_counts_across_domains() -> None:
    m = AccessMatrix()
    m.grant("d1", "o", Right.READ)
    m.grant("d2", "o", Right.READ)
    m.grant("d2", "o", Right.WRITE)
    assert m.total_rights("o") == 3
