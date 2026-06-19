from __future__ import annotations

import dataclasses
from urllib.parse import urlparse

from pesentinel.security.policy import FirewallEntry, PolicyConfig


@dataclasses.dataclass(slots=True)
class FirewallDecision:
    allowed: bool
    reason: str


class EgressFirewall:
    """Network egress firewall (Ch.15 §7).

    Enforces an allow-list of (host, port, scheme) tuples from the
    policy file. The NETWORK_CALL capability routes through this
    firewall — a signal cannot reach a host not in the allow-list.
    """

    def __init__(self, policy: PolicyConfig) -> None:
        self._allow: list[FirewallEntry] = list(policy.firewall_allow)

    def check(self, url: str) -> FirewallDecision:
        """Check if a URL is allowed through the egress firewall."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        scheme = parsed.scheme or "https"
        for entry in self._allow:
            if entry.host == host and entry.port == port and entry.scheme == scheme:
                return FirewallDecision(allowed=True, reason="allow-listed")
        return FirewallDecision(
            allowed=False,
            reason=f"host {host}:{port}/{scheme} not in allow-list",
        )

    def is_allowed(self, url: str) -> bool:
        return self.check(url).allowed


def validate_response(payload: bytes, expected_key: str = "query_status") -> bool:
    """Application-proxy-style response inspection (§7).

    Validates that the MalwareBazaar response is well-formed JSON
    with the expected key. Blocks malformed responses.
    """
    import json

    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    return expected_key in data
