from __future__ import annotations

import dataclasses
from typing import Any

from pesentinel.protection.types import CapabilityForgeError, Right


class _MintKey:
    """Private sentinel. Only the Kernel holds the instance whose
    identity matches ``Capability._mint_key``."""

    __slots__ = ()


@dataclasses.dataclass(frozen=True, slots=True)
class _CapabilityInternals:
    """Sealed payload of a capability. Not exported.

    Only the Kernel constructs this. A Capability wraps it opaquely so
    that no code outside the Kernel can mint or copy one (Ex 14.10,
    Ch.14 §9.2 type-safety analogue).
    """

    domain: str
    obj: str
    right: Right
    serial: int


class Capability:
    """An unforgeable reference to a granted right.

    Construction is restricted: only ``Kernel.mint`` may create a
    Capability. Any attempt to copy, deepcopy, or reconstruct one
    outside the Kernel raises ``CapabilityForgeError`` and is audited
    (spec §10.2, Ex 14.10/14.21).
    """

    __slots__ = ("_internals",)
    _mint_key: object = _MintKey()
    _internals: _CapabilityInternals

    def __init__(self, internals: _CapabilityInternals, mint_key: object) -> None:
        if mint_key is not Capability._mint_key:
            raise CapabilityForgeError("Capability may only be minted by the Kernel")
        object.__setattr__(self, "_internals", internals)

    @property
    def domain(self) -> str:
        return self._internals.domain

    @property
    def obj(self) -> str:
        return self._internals.obj

    @property
    def right(self) -> Right:
        return self._internals.right

    def __repr__(self) -> str:
        return "<Capability redacted>"

    def __copy__(self) -> Capability:
        raise CapabilityForgeError("Capabilities cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> Capability:
        raise CapabilityForgeError("Capabilities cannot be deep-copied")


def _mint(internals: _CapabilityInternals) -> Capability:
    """Kernel-only factory. Bypasses the forge check via the shared key."""
    return Capability(internals, Capability._mint_key)
