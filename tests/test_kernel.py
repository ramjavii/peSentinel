from __future__ import annotations

from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import Right


def test_kernel_singleton() -> None:
    k1 = ProtectionKernel.instance()
    k2 = ProtectionKernel.instance()
    assert k1 is k2


def test_kernel_grant_and_check() -> None:
    k = ProtectionKernel()
    k.grant("hash_signal", "sample_file", Right.READ)
    with k.enter_domain("hash_signal"):
        k.check("sample_file", Right.READ)


def test_kernel_rights_views() -> None:
    k = ProtectionKernel()
    k.grant("d", "o", Right.READ)
    assert k.rights_for_object("o") == {"d": {Right.READ}}
    assert k.rights_for_domain("d") == {"o": {Right.READ}}


def test_kernel_capabilities_for_domain() -> None:
    k = ProtectionKernel()
    k.grant("d", "o", Right.READ)
    caps = k.capabilities_for_domain("d")
    assert len(caps) == 1
    assert caps[0].obj == "o"


def test_kernel_has_right_returns_false_for_non_right() -> None:
    k = ProtectionKernel()
    assert not k.has_right("d", "o", "not_a_right")  # type: ignore[arg-type]


def test_kernel_do_privileged_passthrough() -> None:
    k = ProtectionKernel()
    with k.enter_domain("untrusted"), k.do_privileged():
        k.check("anything", Right.READ)
