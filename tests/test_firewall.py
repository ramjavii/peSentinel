from __future__ import annotations

from pesentinel.security.firewall import EgressFirewall, validate_response
from pesentinel.security.policy import (
    AuthConfig,
    FirewallEntry,
    PolicyConfig,
    ScoringConfig,
)


def _policy_with_firewall() -> PolicyConfig:
    return PolicyConfig(
        objects=[],
        domains={},
        roles={},
        scoring=ScoringConfig(),
        firewall_allow=[
            FirewallEntry(host="mb-api.abuse.ch", port=443, scheme="https"),
        ],
        auth=AuthConfig(),
    )


def test_allowed_host_passes() -> None:
    fw = EgressFirewall(_policy_with_firewall())
    assert fw.is_allowed("https://mb-api.abuse.ch/api/v1/")


def test_blocked_host_fails() -> None:
    fw = EgressFirewall(_policy_with_firewall())
    assert not fw.is_allowed("https://evil.com/exfil")


def test_wrong_port_fails() -> None:
    fw = EgressFirewall(_policy_with_firewall())
    assert not fw.is_allowed("https://mb-api.abuse.ch:8080/api")


def test_wrong_scheme_fails() -> None:
    fw = EgressFirewall(_policy_with_firewall())
    assert not fw.is_allowed("http://mb-api.abuse.ch/api")


def test_validate_response_valid_json() -> None:
    payload = b'{"query_status": "ok", "data": []}'
    assert validate_response(payload)


def test_validate_response_malformed_json() -> None:
    assert not validate_response(b"not json at all")


def test_validate_response_missing_key() -> None:
    assert not validate_response(b'{"wrong_key": "value"}')


def test_validate_response_not_dict() -> None:
    assert not validate_response(b"[1, 2, 3]")
