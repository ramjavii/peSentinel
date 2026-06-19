from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path

import pefile

from pesentinel.core.verdict import SignalResult
from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.policy_bindings import requires_capability
from pesentinel.protection.types import Right, Verdict

_HIGH_ENTROPY_THRESHOLD = 7.0
_PACKER_SECTION_NAMES = {"upx0", "upx1", ".upx0", ".upx1", ".aspack", ".adata"}
_SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "QueueUserAPC",
    "CryptAcquireContext",
    "BCryptOpenAlgorithmProvider",
    "WSAStartup",
    "InternetOpen",
    "URLDownloadToFile",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
}
_ANOMALOUS_SECTION_NAMES = {
    ".text",
    ".data",
    ".rdata",
    ".rsrc",
    ".reloc",
    ".idata",
    ".bss",
    ".tls",
}


@dataclass(slots=True)
class PEFeatures:
    is_pe: bool = False
    architecture: str = ""
    subsystem: str = ""
    imphash: str = ""
    sections: list[dict[str, object]] = field(default_factory=list)
    suspicious_imports: list[str] = field(default_factory=list)
    packer_detected: str = "none"
    max_section_entropy: float = 0.0
    entropy_anomaly: bool = False
    section_name_anomaly: bool = False


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _extract_features(pe: pefile.PE) -> PEFeatures:
    feats = PEFeatures(is_pe=True)
    machine = pe.FILE_HEADER.Machine
    feats.architecture = (
        "x64" if machine == 0x8664 else "x86" if machine == 0x14C else "unknown"
    )
    subsys = getattr(pe.OPTIONAL_HEADER, "Subsystem", 0)
    feats.subsystem = {1: "NATIVE", 2: "GUI", 3: "CONSOLE"}.get(subsys, str(subsys))
    try:
        feats.imphash = pe.get_imphash()
    except Exception:
        feats.imphash = ""

    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        raw = section.get_data()
        ent = _entropy(raw)
        feats.sections.append(
            {
                "name": name,
                "vsize": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": ent,
                "is_packed": ent >= _HIGH_ENTROPY_THRESHOLD,
            }
        )
        if ent > feats.max_section_entropy:
            feats.max_section_entropy = ent
        if name.lower() in _PACKER_SECTION_NAMES:
            feats.packer_detected = name
        if (
            name
            and name.lower() not in _ANOMALOUS_SECTION_NAMES
            and not name.startswith(".")
        ):
            feats.section_name_anomaly = True

    if feats.max_section_entropy >= _HIGH_ENTROPY_THRESHOLD:
        feats.entropy_anomaly = True

    packer = "none"
    for s in feats.sections:
        n = str(s["name"]).lower()
        if n in _PACKER_SECTION_NAMES:
            packer = "UPX" if "upx" in n else str(s["name"])
            break
    if packer == "none" and feats.entropy_anomaly:
        packer = "unknown"
    feats.packer_detected = packer

    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                iname = imp.name.decode("ascii", errors="replace") if imp.name else ""
                if iname in _SUSPICIOUS_IMPORTS:
                    feats.suspicious_imports.append(iname)
    except AttributeError:
        pass

    return feats


class PEHeuristicsSignal:
    """Anomaly-detection signal (Ch.15 §6.3).

    Parses a Windows PE file and flags anomalies: high-entropy
    sections (packing), suspicious Win32 imports, section-name
    anomalies, imphash. This is the 'anomaly' half of §6.3's
    signature-vs-anomaly duality.
    """

    name = "pe_heuristics"
    domain = "heuristic_signal"

    def __init__(self, kernel: ProtectionKernel) -> None:
        self._kernel = kernel

    def analyze(self, path: Path) -> SignalResult:
        feats = self._parse(path)
        if not feats.is_pe:
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                evidence=[],
                reason="not a valid PE file",
            )
        evidence: list[str] = []
        score = 0
        if feats.entropy_anomaly:
            score += 2
            evidence.append(f"high_entropy={feats.max_section_entropy:.2f}")
        if feats.packer_detected != "none":
            score += 2
            evidence.append(f"packer={feats.packer_detected}")
        if feats.suspicious_imports:
            score += len(feats.suspicious_imports)
            evidence.append(
                f"suspicious_imports={','.join(feats.suspicious_imports[:5])}"
            )
        if feats.section_name_anomaly:
            score += 1
            evidence.append("section_name_anomaly")
        if feats.imphash:
            evidence.append(f"imphash={feats.imphash}")

        if score >= 5:
            verdict = Verdict.MALICIOUS
            confidence = min(0.5 + score * 0.05, 0.95)
            reason = "multiple anomaly indicators"
        elif score >= 2:
            verdict = Verdict.SUSPICIOUS
            confidence = min(0.3 + score * 0.1, 0.7)
            reason = "some anomaly indicators"
        else:
            verdict = Verdict.BENIGN
            confidence = 0.5
            reason = "no significant anomalies"
        return SignalResult(
            signal_name=self.name,
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
            reason=reason,
        )

    @requires_capability("sample_file", Right.READ)
    def _parse(self, path: Path) -> PEFeatures:
        try:
            pe = pefile.PE(str(path), fast_load=False)
        except pefile.PEFormatError:
            return PEFeatures(is_pe=False)
        try:
            return _extract_features(pe)
        finally:
            pe.close()
