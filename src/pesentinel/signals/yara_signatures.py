from __future__ import annotations

from pathlib import Path

import yara

from pesentinel.core.verdict import SignalResult
from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import Verdict


class YaraSignaturesSignal:
    """Signature-based detection signal (Ch.15 §6.3).

    Loads and compiles YARA rule files from the rules directory, then
    scans the sample. Matches map to malware family + severity. This
    is the 'signature' half of §6.3's signature-vs-anomaly duality.
    """

    name = "yara_signatures"
    domain = "yara_signal"

    def __init__(self, kernel: ProtectionKernel, rules_dir: Path) -> None:
        self._kernel = kernel
        self._rules_dir = rules_dir
        self._rules: yara.Rules | None = None

    def _ensure_rules(self) -> None:
        if self._rules is not None:
            return
        rule_files: dict[str, str] = {}
        if self._rules_dir.is_dir():
            for p in sorted(self._rules_dir.glob("*.yar")):
                rule_files[p.stem] = str(p)
        if rule_files:
            self._rules = yara.compile(filepaths=rule_files)
        else:
            self._rules = yara.compile(source="rule dummy { condition: false }")

    def analyze(self, path: Path) -> SignalResult:
        self._ensure_rules()
        if self._rules is None:
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                evidence=[],
                reason="no YARA rules loaded",
            )
        try:
            matches = self._rules.match(str(path))
        except Exception as exc:
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                evidence=[],
                reason=f"YARA scan error: {exc}",
            )
        if not matches:
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.BENIGN,
                confidence=0.5,
                evidence=[],
                reason="no YARA rules matched",
            )
        families = [m.rule for m in matches]
        return SignalResult(
            signal_name=self.name,
            verdict=Verdict.MALICIOUS,
            confidence=0.85,
            evidence=[f"matched_rules={','.join(families)}"],
            reason=f"matched {len(matches)} YARA rule(s)",
        )
