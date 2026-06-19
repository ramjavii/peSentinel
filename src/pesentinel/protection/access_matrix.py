from __future__ import annotations

from collections import defaultdict

from pesentinel.protection.capability import Capability, _CapabilityInternals, _mint
from pesentinel.protection.types import Right


class AccessMatrix:
    """The access-matrix model (Ch.14 §14.10).

    Sparse storage: ``_cells[(domain, obj)] -> set[Right]``.
    Provides both the access-list view (per-object) and the
    capability-list view (per-domain), per Practice Ex 14.1.
    Policy lives here; mechanism (enforcement) lives in the Kernel.
    """

    def __init__(self) -> None:
        self._cells: dict[tuple[str, str], set[Right]] = defaultdict(set)
        self._objects: set[str] = set()
        self._domains: set[str] = set()
        self._serial: int = 0

    def register_object(self, obj: str) -> None:
        self._objects.add(obj)

    def register_domain(self, domain: str) -> None:
        self._domains.add(domain)

    def grant(self, domain: str, obj: str, rights: Right | frozenset[Right]) -> None:
        self._domains.add(domain)
        self._objects.add(obj)
        if isinstance(rights, Right):
            rights = frozenset({rights})
        self._cells[(domain, obj)] |= set(rights)

    def revoke(
        self, domain: str, obj: str, rights: Right | frozenset[Right]
    ) -> set[Right]:
        if isinstance(rights, Right):
            rights = frozenset({rights})
        cell = self._cells.get((domain, obj), set())
        removed = cell & set(rights)
        cell -= set(rights)
        if not cell:
            self._cells.pop((domain, obj), None)
        return removed

    def has_right(self, domain: str, obj: str, right: Right) -> bool:
        return right in self._cells.get((domain, obj), set())

    def rights_for_object(self, obj: str) -> dict[str, set[Right]]:
        """Access-list view: per-object, who has what (Ex 14.1)."""
        view: dict[str, set[Right]] = {}
        for (dom, o), rights in self._cells.items():
            if o == obj:
                view[dom] = set(rights)
        return view

    def rights_for_domain(self, domain: str) -> dict[str, set[Right]]:
        """Capability-list view: per-domain, what can it touch (Ex 14.1)."""
        view: dict[str, set[Right]] = {}
        for (dom, o), rights in self._cells.items():
            if dom == domain:
                view[o] = set(rights)
        return view

    def capabilities_for_domain(self, domain: str) -> list[Capability]:
        """Materialize unforgeable capabilities for a domain."""
        caps: list[Capability] = []
        for (dom, o), rights in self._cells.items():
            if dom != domain:
                continue
            for r in rights:
                self._serial += 1
                caps.append(_mint(_CapabilityInternals(domain, o, r, self._serial)))
        return caps

    def all_objects(self) -> frozenset[str]:
        return frozenset(self._objects)

    def all_domains(self) -> frozenset[str]:
        return frozenset(self._domains)

    def total_rights(self, obj: str) -> int:
        """Count of (domain, right) pairs for an object — used by
        revocation ref-counting (Ex 14.8)."""
        return sum(len(rights) for (_, o), rights in self._cells.items() if o == obj)
