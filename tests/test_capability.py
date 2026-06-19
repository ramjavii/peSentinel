from __future__ import annotations

import copy

import pytest

from pesentinel.protection.capability import Capability, _CapabilityInternals, _mint
from pesentinel.protection.types import CapabilityForgeError, Right


def _make_cap() -> Capability:
    return _mint(_CapabilityInternals("hash_signal", "sample_file", Right.READ, 1))


def test_minted_capability_holds_fields() -> None:
    cap = _make_cap()
    assert cap.domain == "hash_signal"
    assert cap.obj == "sample_file"
    assert cap.right == Right.READ


def test_capability_outside_mint_is_forgery() -> None:
    internals = _CapabilityInternals("d", "o", Right.READ, 1)
    with pytest.raises(CapabilityForgeError):
        Capability(internals, object())  # wrong key


def test_copy_is_forbidden() -> None:
    cap = _make_cap()
    with pytest.raises(CapabilityForgeError):
        copy.copy(cap)


def test_deepcopy_is_forbidden() -> None:
    cap = _make_cap()
    with pytest.raises(CapabilityForgeError):
        copy.deepcopy(cap)


def test_repr_is_redacted() -> None:
    cap = _make_cap()
    assert "redacted" in repr(cap)
    assert "hash_signal" not in repr(cap)
