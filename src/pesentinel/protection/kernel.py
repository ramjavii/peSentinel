from __future__ import annotations

from typing import Any

from pesentinel.protection.access_matrix import AccessMatrix
from pesentinel.protection.capability import Capability
from pesentinel.protection.domain import (
    ActiveDomain,
    AuditSink,
    NullAuditSink,
    active_domain,
)
from pesentinel.protection.revocation import RevocationRegistry
from pesentinel.protection.stack_inspection import check_permission, do_privileged
from pesentinel.protection.types import EventKind, Right


class ProtectionKernel:
    """The Trusted Computing Base facade (Ch.15 §8).

    This is the single entry point that ``signals/`` and ``core/`` use
    to interact with the protection system. It owns the access matrix,
    the revocation registry, and the active-domain state. Internal
    modules are not imported directly by outsiders — preserving the
    TCB boundary (AGENTS.md).
    """

    _instance: ProtectionKernel | None = None

    def __init__(self, audit: AuditSink | None = None) -> None:
        self._matrix = AccessMatrix()
        self._revocation = RevocationRegistry(self._matrix)
        self._audit: AuditSink = audit or NullAuditSink()

    @classmethod
    def instance(cls) -> ProtectionKernel:
        """Return the process-wide kernel singleton.

        The singleton is used by the ``@requires_capability`` decorator
        so that decorated functions need not receive the kernel
        explicitly.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton (used in tests)."""
        cls._instance = None

    # --- policy / matrix ---
    def grant(self, domain: str, obj: str, rights: Right | frozenset[Right]) -> None:
        self._matrix.grant(domain, obj, rights)
        rights_set = frozenset({rights}) if isinstance(rights, Right) else rights
        for r in rights_set:
            self._audit.record(
                EventKind.CAPABILITY_GRANT,
                domain,
                domain,
                obj,
                r.name,
                "allow",
                "granted",
            )

    def revoke(
        self, domain: str, obj: str, rights: Right | frozenset[Right]
    ) -> set[Right]:
        removed = self._revocation.revoke(domain, obj, rights)
        for r in removed:
            self._audit.record(
                EventKind.CAPABILITY_REVOKE,
                domain,
                domain,
                obj,
                r.name,
                "deny",
                "revoked",
            )
        return removed

    def has_right(self, domain: str, obj: str, right: Right | object) -> bool:
        if not isinstance(right, Right):
            return False
        allowed = self._matrix.has_right(domain, obj, right)
        self._audit.record(
            EventKind.ACCESS_CHECK,
            domain or active_domain() or "",
            "",
            obj,
            right.name,
            "allow" if allowed else "deny",
            "matrix lookup",
        )
        return allowed

    def check(self, obj: str, right: Right) -> None:
        """Raise ``AccessControlException`` if the active domain lacks
        ``right`` on ``obj``, with stack inspection."""
        check_permission(self, obj, right)

    # --- domain switching ---
    def enter_domain(self, name: str, subject: str = "") -> ActiveDomain:
        return ActiveDomain(name, self._audit, subject)

    @property
    def active_domain(self) -> str | None:
        return active_domain()

    @property
    def audit(self) -> AuditSink:
        return self._audit

    # --- capability views (Ex 14.1) ---
    def capabilities_for_domain(self, domain: str) -> list[Capability]:
        return self._matrix.capabilities_for_domain(domain)

    def rights_for_object(self, obj: str) -> dict[str, set[Right]]:
        return self._matrix.rights_for_object(obj)

    def rights_for_domain(self, domain: str) -> dict[str, set[Right]]:
        return self._matrix.rights_for_domain(domain)

    # --- revocation / orphan tracking (Ex 14.7/14.8) ---
    def is_orphaned(self, obj: str) -> bool:
        return self._revocation.is_orphaned(obj)

    def orphaned_objects(self) -> frozenset[str]:
        return self._revocation.orphaned_objects()

    # --- privileged block passthrough ---
    def do_privileged(self) -> Any:
        return do_privileged()
