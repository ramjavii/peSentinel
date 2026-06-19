from __future__ import annotations

import contextvars
import dataclasses
from typing import Protocol

from pesentinel.protection.types import EventKind


class AuditSink(Protocol):
    """Interface for audit logging (Ch.15 §6.5).

    The protection core depends on this Protocol, not on a concrete
    security/ module — preserving the TCB boundary (AGENTS.md).
    """

    def record(
        self,
        event: EventKind,
        domain: str,
        subject: str,
        obj: str,
        right: str,
        decision: str,
        reason: str,
        stack_annot: bool = False,
    ) -> None: ...


class NullAuditSink:
    """No-op sink for Stage 1 (real sink arrives in Stage 2)."""

    def record(
        self,
        event: EventKind,
        domain: str,
        subject: str,
        obj: str,
        right: str,
        decision: str,
        reason: str,
        stack_annot: bool = False,
    ) -> None:
        return None


@dataclasses.dataclass(frozen=True, slots=True)
class AuditRecord:
    ts: float
    event: EventKind
    domain: str
    subject: str
    obj: str
    right: str
    decision: str
    reason: str
    stack_annot: bool


_active_domain: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "pesentinel_active_domain", default=None
)


def active_domain() -> str | None:
    """Return the currently active protection domain, or None."""
    return _active_domain.get()


class ActiveDomain:
    """Context manager that switches the active protection domain
    (Ch.14 §14.10 domain switching). Audits DOMAIN_SWITCH on enter
    and exit, and restores the previous domain on exit."""

    def __init__(self, name: str, audit: AuditSink, subject: str = "") -> None:
        self._name = name
        self._audit = audit
        self._subject = subject
        self._prev: str | None = None

    @property
    def name(self) -> str:
        return self._name

    def __enter__(self) -> ActiveDomain:
        self._prev = active_domain()
        _active_domain.set(self._name)
        self._audit.record(
            EventKind.DOMAIN_SWITCH,
            self._name,
            self._subject,
            "",
            "",
            "enter",
            f"switched to {self._name} from {self._prev}",
        )
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        _active_domain.set(self._prev)
        self._audit.record(
            EventKind.DOMAIN_SWITCH,
            self._name,
            self._subject,
            "",
            "",
            "exit",
            f"restored {self._prev}",
        )
