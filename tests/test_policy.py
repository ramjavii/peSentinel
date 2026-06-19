from __future__ import annotations

from pathlib import Path

from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import Right
from pesentinel.security.policy import (
    apply_policy,
    domains_for_role,
    load_policy,
)


def test_load_policy(tmp_path: Path) -> None:
    pol = load_policy(Path(__file__).resolve().parents[1] / "data" / "policy.yaml")
    assert "sample_file" in pol.objects
    assert "hash_signal" in pol.domains
    assert "Scanner" in pol.roles
    assert pol.scoring.hash_reputation == 0.40
    assert pol.auth.two_factor_for_admin is True
    assert pol.bayes_assumed_intrusion_rate == 0.00002
    assert len(pol.firewall_allow) == 1
    assert pol.firewall_allow[0].host == "mb-api.abuse.ch"


def test_apply_policy_populates_matrix() -> None:
    kernel = ProtectionKernel()
    ProtectionKernel._instance = kernel
    pol = load_policy(Path(__file__).resolve().parents[1] / "data" / "policy.yaml")
    apply_policy(kernel, pol)
    assert kernel.has_right("hash_signal", "sample_file", Right.READ)
    assert kernel.has_right("hash_signal", "network", Right.NETWORK_CALL)
    assert kernel.has_right("yara_signal", "rules_dir", Right.READ)
    assert kernel.has_right("admin", "rules_dir", Right.WRITE)
    assert not kernel.has_right("hash_signal", "rules_dir", Right.WRITE)


def test_domains_for_role() -> None:
    pol = load_policy(Path(__file__).resolve().parents[1] / "data" / "policy.yaml")
    scanner_domains = domains_for_role(pol, "Scanner")
    assert "pipeline_core" in scanner_domains
    assert "hash_signal" in scanner_domains
    assert domains_for_role(pol, "Nonexistent") == []


def test_load_minimal_policy(tmp_path: Path) -> None:
    p = tmp_path / "minimal.yaml"
    p.write_text("objects: [o1]\ndomains: {}\nroles: {}\n")
    pol = load_policy(p)
    assert pol.objects == ["o1"]
    assert pol.scoring.hash_reputation == 0.40
