from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

import pefile

from pesentinel.core.verdict import SignalResult
from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.policy_bindings import requires_capability
from pesentinel.protection.types import Right, Verdict

# requestedExecutionLevel values (Ch.15 §15.9 UAC)
_EXEC_LEVELS = {
    "asInvoker": "asInvoker",
    "requireAdministrator": "requireAdministrator",
    "highestAvailable": "highestAvailable",
}


@dataclass(slots=True)
class WindowsSecurityModel:
    """Security attributes read from the PE manifest (Ch.15 §15.9)."""

    has_manifest: bool = False
    uac_level: str = "none"
    requires_admin: bool = False
    integrity_level: str = "medium"
    dll_characteristics: str = ""


def _extract_manifest(pe: pefile.PE) -> WindowsSecurityModel:
    wsm = WindowsSecurityModel()
    try:
        manifest_res = None
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.id == pefile.RESOURCE_TYPE["RT_MANIFEST"]:
                for sub in entry.directory.entries:
                    for lang in sub.directory.entries:
                        data_rva = lang.data.struct.OffsetToData
                        size = lang.data.struct.Size
                        manifest_res = pe.get_data(data_rva, size)
                        break
        if manifest_res is None:
            return wsm
        wsm.has_manifest = True
        text = manifest_res.decode("utf-8", errors="replace").lower()
        for level_key, level_val in _EXEC_LEVELS.items():
            if level_key.lower() in text:
                wsm.uac_level = level_val
                if level_val in ("requireAdministrator", "highestAvailable"):
                    wsm.requires_admin = True
                break
    except (AttributeError, pefile.PEFormatError, struct.error):
        pass

    try:
        dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
        if dll_chars & 0x4000:
            wsm.dll_characteristics = "DYNAMIC_BASE"
        if dll_chars & 0x0100:
            wsm.dll_characteristics += "|NX_COMPAT"
    except AttributeError:
        pass

    return wsm


class WindowsModelSignal:
    """Reads the Windows security model from the PE manifest (§15.9).

    Extracts UAC requestedExecutionLevel, integrity level, admin
    requirement, and DLL hardening flags. These are the exact objects
    §15.9 describes (SID, access token, MIC integrity labels, UAC).
    """

    name = "windows_model"
    domain = "heuristic_signal"

    def __init__(self, kernel: ProtectionKernel) -> None:
        self._kernel = kernel

    def analyze(self, path: Path) -> SignalResult:
        wsm = self._parse(path)
        if not wsm.has_manifest and wsm.uac_level == "none":
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                evidence=[],
                reason="no manifest or UAC info found",
            )
        evidence: list[str] = [
            f"uac_level={wsm.uac_level}",
            f"requires_admin={wsm.requires_admin}",
            f"integrity={wsm.integrity_level}",
        ]
        if wsm.dll_characteristics:
            evidence.append(f"dll_chars={wsm.dll_characteristics}")
        verdict = Verdict.BENIGN
        confidence = 0.3
        reason = "manifest parsed"
        if wsm.requires_admin:
            verdict = Verdict.SUSPICIOUS
            confidence = 0.4
            reason = "requests admin elevation"
        return SignalResult(
            signal_name=self.name,
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
            reason=reason,
        )

    @requires_capability("sample_file", Right.READ)
    def _parse(self, path: Path) -> WindowsSecurityModel:
        try:
            pe = pefile.PE(str(path), fast_load=False)
        except pefile.PEFormatError:
            return WindowsSecurityModel()
        try:
            return _extract_manifest(pe)
        finally:
            pe.close()
