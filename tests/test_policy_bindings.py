from __future__ import annotations

import pytest

from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.policy_bindings import requires_capability
from pesentinel.protection.types import AccessControlException, Right


def test_decorator_allows_with_right() -> None:
    k = ProtectionKernel()
    ProtectionKernel._instance = k
    k.grant("d", "o", Right.READ)

    @requires_capability("o", Right.READ)
    def read_thing() -> str:
        return "ok"

    with k.enter_domain("d"):
        assert read_thing() == "ok"


def test_decorator_denies_without_right() -> None:
    k = ProtectionKernel()
    ProtectionKernel._instance = k

    @requires_capability("o", Right.READ)
    def read_thing() -> str:
        return "ok"

    with k.enter_domain("d"), pytest.raises(AccessControlException):
        read_thing()


def test_decorator_denies_without_active_domain() -> None:
    k = ProtectionKernel()
    ProtectionKernel._instance = k

    @requires_capability("o", Right.READ)
    def read_thing() -> str:
        return "ok"

    with pytest.raises(AccessControlException):
        read_thing()


def test_decorator_preserves_metadata() -> None:
    @requires_capability("o", Right.READ)
    def my_func() -> str:
        """My docstring."""
        return "ok"

    assert my_func.__name__ == "my_func"
    assert my_func.__doc__ == "My docstring."
