from __future__ import annotations

from pesentinel.protection.access_matrix import AccessMatrix
from pesentinel.protection.types import ObjectOrphaned, Right


class RevocationRegistry:
    """Runtime revocation + ref-counted object deletion (Ex 14.7/14.8).

    Tracks per-object reference counts. When all rights across all
    domains are removed for an object, the object is considered
    orphaned and may be reclaimed (Ex 14.8).
    """

    def __init__(self, matrix: AccessMatrix) -> None:
        self._matrix = matrix
        self._orphaned: set[str] = set()

    def revoke(
        self, domain: str, obj: str, rights: Right | frozenset[Right]
    ) -> set[Right]:
        """Remove ``rights`` for ``domain`` on ``obj`` at runtime (Ex 14.7)."""
        removed = self._matrix.revoke(domain, obj, rights)
        if self._matrix.total_rights(obj) == 0 and obj not in self._orphaned:
            self._orphaned.add(obj)
        return removed

    def is_orphaned(self, obj: str) -> bool:
        return obj in self._orphaned

    def reclaim(self, obj: str) -> None:
        """Reclaim an orphaned object. Raises if not actually orphaned."""
        if not self.is_orphaned(obj):
            raise ObjectOrphaned(f"{obj!r} is not orphaned; cannot reclaim")
        self._orphaned.discard(obj)

    def orphaned_objects(self) -> frozenset[str]:
        return frozenset(self._orphaned)
