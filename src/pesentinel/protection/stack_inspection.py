from __future__ import annotations

import contextvars
import dataclasses
from typing import TYPE_CHECKING

from pesentinel.protection.domain import active_domain
from pesentinel.protection.types import AccessControlException

if TYPE_CHECKING:
    from pesentinel.protection.kernel import ProtectionKernel


_PRIV_STACK: contextvars.ContextVar[tuple[_PrivEntry, ...]] = contextvars.ContextVar(
    "pesentinel_priv_stack", default=()
)


@dataclasses.dataclass(frozen=True, slots=True)
class _PrivEntry:
    """One entry on the privilege stack.

    ``privileged=True`` marks a doPrivileged frame (Ch.14 §9.2).
    ``domain`` is the active domain when the entry was pushed.
    """

    domain: str
    privileged: bool


def _stack() -> list[_PrivEntry]:
    return list(_PRIV_STACK.get())


class do_privileged:
    """Context manager that annotates the current frame as privileged
    (Java ``AccessController.doPrivileged`` analogue, Ch.14 §9.2).

    When ``check_permission`` walks the stack, finding this annotation
    stops the walk and allows the access — the caller takes
    responsibility (spec §6, Fig 14.9).
    """

    def __init__(self) -> None:
        self._token: contextvars.Token[tuple[_PrivEntry, ...]] | None = None
        self._entry: _PrivEntry | None = None

    def __enter__(self) -> do_privileged:
        dom = active_domain() or ""
        entry = _PrivEntry(domain=dom, privileged=True)
        stack = (*_PRIV_STACK.get(), entry)
        self._token = _PRIV_STACK.set(stack)
        self._entry = entry
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._token is not None:
            _PRIV_STACK.reset(self._token)


def check_permission(kernel: ProtectionKernel, obj: str, right: object) -> None:
    """Walk the privilege stack (Ch.14 §9.2, Fig 14.9).

    From newest to oldest:
      1. A ``doPrivileged`` frame is found -> ALLOW (stop).
      2. A frame whose domain lacks the right -> DENY (raise).
      3. Stack exhausted -> check the active domain; deny if absent.

    The frame annotation (``_PrivEntry``) is set only by
    ``do_privileged``; user code cannot forge it (no public API to
    push a privileged entry) — Ex 14.21 defense.
    """
    stack = list(_stack())
    for entry in reversed(stack):
        if entry.privileged:
            return
        if not kernel.has_right(entry.domain, obj, right):
            raise AccessControlException(
                f"domain {entry.domain!r} lacks {right!r} on {obj!r}"
            )
    dom = active_domain()
    if dom is not None and kernel.has_right(dom, obj, right):
        return
    raise AccessControlException(
        f"no privileged frame and active domain {dom!r} lacks {right!r} on {obj!r}"
    )
