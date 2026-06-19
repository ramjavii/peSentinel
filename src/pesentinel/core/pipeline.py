from __future__ import annotations

from pathlib import Path
from typing import Protocol

from pesentinel.core.verdict import AggregatedVerdict, SignalResult
from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import AccessControlException, Verdict


class Signal(Protocol):
    """Protocol every detection signal satisfies."""

    name: str
    domain: str

    def analyze(self, path: Path) -> SignalResult: ...


class Pipeline:
    """Orchestrates detection signals through the protection kernel.

    For each signal the pipeline switches to the signal's least-
    privilege domain (Ch.14 §14.10 domain switching), runs the signal,
    and collects its ``SignalResult``. Access-control denials are
    EXPECTED control flow: they are caught and recorded as
    ``UNKNOWN("denied")`` (AGENTS.md error-handling rules).
    """

    def __init__(self, kernel: ProtectionKernel, signals: list[Signal]) -> None:
        self._kernel = kernel
        self._signals = signals

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
        return self._aggregate(path, results)

    def _aggregate(self, path: Path, results: list[SignalResult]) -> AggregatedVerdict:
        final = Verdict.BENIGN
        confidence = 0.0
        for r in results:
            if r.verdict == Verdict.MALICIOUS:
                final = Verdict.MALICIOUS
                confidence = max(confidence, r.confidence)
            elif r.verdict == Verdict.SUSPICIOUS and final != Verdict.MALICIOUS:
                final = Verdict.SUSPICIOUS
                confidence = max(confidence, r.confidence)
        sha = ""
        for r in results:
            for e in r.evidence:
                if e.startswith("sha256="):
                    sha = e.split("=", 1)[1]
                    break
        return AggregatedVerdict(
            final_verdict=final,
            confidence=confidence,
            signal_results=results,
            sample_path=str(path),
            sha256=sha,
        )
