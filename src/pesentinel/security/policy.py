from __future__ import annotations

import dataclasses
from pathlib import Path

import yaml

from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import Right

_RIGHT_NAMES: dict[str, Right] = {
    "READ": Right.READ,
    "WRITE": Right.WRITE,
    "EXECUTE": Right.EXECUTE,
    "NETWORK_CALL": Right.NETWORK_CALL,
    "SCAN": Right.SCAN,
}


@dataclasses.dataclass(slots=True)
class FirewallEntry:
    host: str
    port: int
    scheme: str


@dataclasses.dataclass(slots=True)
class ScoringConfig:
    hash_reputation: float = 0.40
    yara: float = 0.35
    heuristics: float = 0.25
    malicious_threshold: float = 0.60
    suspicious_threshold: float = 0.30


@dataclasses.dataclass(slots=True)
class AuthConfig:
    two_factor_for_admin: bool = True
    code_book_size: int = 100
    max_attempts: int = 3


@dataclasses.dataclass(slots=True)
class PolicyConfig:
    """Parsed policy.yaml (Ch.15 §6.1)."""

    objects: list[str]
    domains: dict[str, dict[str, list[str]]]
    roles: dict[str, list[str]]
    scoring: ScoringConfig
    firewall_allow: list[FirewallEntry]
    auth: AuthConfig
    bayes_assumed_intrusion_rate: float = 0.00002


def load_policy(path: Path) -> PolicyConfig:
    """Parse the policy YAML file into a PolicyConfig."""
    raw = yaml.safe_load(path.read_text())
    objects = list(raw.get("objects", []))
    domains = raw.get("domains", {})
    roles = raw.get("roles", {})
    scoring_raw = raw.get("scoring", {})
    scoring = ScoringConfig(
        hash_reputation=scoring_raw.get("hash_reputation", 0.40),
        yara=scoring_raw.get("yara", 0.35),
        heuristics=scoring_raw.get("heuristics", 0.25),
        malicious_threshold=scoring_raw.get("malicious_threshold", 0.60),
        suspicious_threshold=scoring_raw.get("suspicious_threshold", 0.30),
    )
    fw_raw = raw.get("firewall", {}).get("allow", [])
    firewall = [
        FirewallEntry(host=e["host"], port=e["port"], scheme=e["scheme"])
        for e in fw_raw
    ]
    auth_raw = raw.get("auth", {})
    auth = AuthConfig(
        two_factor_for_admin=auth_raw.get("two_factor_for_admin", True),
        code_book_size=auth_raw.get("code_book_size", 100),
        max_attempts=auth_raw.get("max_attempts", 3),
    )
    bayes_rate = raw.get("bayes", {}).get("assumed_intrusion_rate", 0.00002)
    return PolicyConfig(
        objects=objects,
        domains=domains,
        roles=roles,
        scoring=scoring,
        firewall_allow=firewall,
        auth=auth,
        bayes_assumed_intrusion_rate=bayes_rate,
    )


def apply_policy(kernel: ProtectionKernel, policy: PolicyConfig) -> None:
    """Populate the access matrix and register objects/domains (§6.1)."""
    for obj in policy.objects:
        kernel._matrix.register_object(obj)  # noqa: SLF001
    for domain_name, body in policy.domains.items():
        kernel._matrix.register_domain(domain_name)  # noqa: SLF001
        rights_map = body.get("rights", {})
        for obj, right_names in rights_map.items():
            for rn in right_names:
                right = _RIGHT_NAMES.get(rn)
                if right is not None:
                    kernel.grant(domain_name, obj, right)


def domains_for_role(policy: PolicyConfig, role: str) -> list[str]:
    """RBAC: return the domains assigned to a role (Solaris-style §14.10)."""
    return list(policy.roles.get(role, []))
