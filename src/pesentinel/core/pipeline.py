from __future__ import annotations

from pathlib import Path
from typing import Protocol

from pesentinel.core.verdict import AggregatedVerdict, SignalResult
from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import AccessControlException, Verdict
from pesentinel.security.policy import PolicyConfig
from pesentinel.signals.scorer import aggregate as scorer_aggregate


class Signal(Protocol):
    name: str
    domain: str

    def analyze(self, path: Path) -> SignalResult: ...


class Pipeline:
    def __init__(
        self, kernel: ProtectionKernel, signals: list[Signal], policy: PolicyConfig
    ) -> None:
        self._kernel = kernel
        self._signals = signals
        self._policy = policy

    def run(self, path: Path) -> AggregatedVerdict:
        results: list[SignalResult] = []
        for sig in self._signals:
            with self._kernel.enter_domain(sig.domain, subject=sig.name):
                try:
                    result = sig.analyze(path)
                except AccessControlException as exc:
                    result = SignalResult(
                        signal_name=sig.name,
                        verdict=Verdict.UNKNOWN,
                        confidence=0.0,
                        evidence=[],
                        reason=f"access denied: {exc}",
                    )
                except Exception as exc:
                    result = SignalResult(
                        signal_name=sig.name,
                        verdict=Verdict.UNKNOWN,
                        confidence=0.0,
                        evidence=[],
                        reason=f"signal error: {exc}",
                    )
            results.append(result)

        sha = ""
        for r in results:
            for e in r.evidence:
                if e.startswith("sha256="):
                    sha = e.split("=", 1)[1]
                    break
        return scorer_aggregate(results, self._policy, str(path), sha)
