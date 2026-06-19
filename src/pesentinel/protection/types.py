from __future__ import annotations

import enum


class Right(enum.IntEnum):
    """Access rights in the protection matrix (Ch.14)."""

    READ = 1
    WRITE = 2
    EXECUTE = 4
    NETWORK_CALL = 8
    SCAN = 16


class Verdict(enum.Enum):
    """Final aggregated verdict for a sample."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class EventKind(enum.Enum):
    """Audit event categories (Ch.15 §6.5)."""

    ACCESS_CHECK = "access_check"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    AUTHZ_DENY = "authz_deny"
    CAPABILITY_GRANT = "capability_grant"
    CAPABILITY_REVOKE = "capability_revoke"
    DOMAIN_SWITCH = "domain_switch"
    FORGERY_ATTEMPT = "forgery_attempt"


class AccessControlException(Exception):
    """Raised when an access check fails (Ch.14).

    This is EXPECTED control flow, not a crash: audit it, do not abort
    the pipeline (AGENTS.md error-handling rules).
    """


class CapabilityForgeError(AccessControlException):
    """Raised when code outside the Kernel tries to forge a Capability.

    Implements the unforgeable-capability requirement (Ex 14.10) and
    the Ex 14.21 stack-annotation-tamper defense.
    """


class ObjectOrphaned(Exception):
    """Internal signal that an object has zero remaining rights (Ex 14.8)."""
