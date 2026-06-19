from __future__ import annotations

import pytest

from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.stack_inspection import check_permission, do_privileged
from pesentinel.protection.types import AccessControlException, Right


def test_check_denies_without_right() -> None:
    k = ProtectionKernel()
    k.grant("pipeline_core", "sample_file", Right.READ)
    with k.enter_domain("pipeline_core"), pytest.raises(AccessControlException):
        check_permission(k, "sample_file", Right.WRITE)


def test_check_allows_with_right() -> None:
    k = ProtectionKernel()
    k.grant("pipeline_core", "sample_file", Right.READ)
    with k.enter_domain("pipeline_core"):
        check_permission(k, "sample_file", Right.READ)


def test_do_privileged_allows_without_domain_right() -> None:
    """Fig 14.9 analogue: a privileged block grants access even if
    the caller's domain lacks the right (the caller takes
    responsibility)."""
    k = ProtectionKernel()
    with k.enter_domain("untrusted"), do_privileged():
        check_permission(k, "network", Right.NETWORK_CALL)


def test_no_privileged_and_no_right_denies() -> None:
    """Fig 14.9 analogue: without doPrivileged, the untrusted domain
    is denied."""
    k = ProtectionKernel()
    with k.enter_domain("untrusted"), pytest.raises(AccessControlException):
        check_permission(k, "network", Right.NETWORK_CALL)


def test_privileged_block_is_scoped() -> None:
    """After doPrivileged exits, the annotation is gone."""
    k = ProtectionKernel()
    with k.enter_domain("untrusted"):
        with do_privileged():
            check_permission(k, "network", Right.NETWORK_CALL)
        with pytest.raises(AccessControlException):
            check_permission(k, "network", Right.NETWORK_CALL)


def test_stack_walk_finds_innermost_privileged() -> None:
    k = ProtectionKernel()
    with k.enter_domain("outer"), do_privileged(), k.enter_domain("inner"):
        check_permission(k, "network", Right.NETWORK_CALL)
