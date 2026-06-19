from __future__ import annotations

import dataclasses

from pesentinel.protection.types import Verdict


@dataclasses.dataclass(slots=True)
class SignalResult:
    """Output of one detection signal."""

    signal_name: str
    verdict: Verdict
    confidence: float
    evidence: list[str]
    reason: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "signal_name": self.signal_name,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "reason": self.reason,
        }


@dataclasses.dataclass(slots=True)
class AggregatedVerdict:
    """Final verdict after all signals run (Stage 5 adds scoring)."""

    final_verdict: Verdict
    confidence: float
    signal_results: list[SignalResult]
    bayes_pia: float | None = None
    sample_path: str = ""
    sha256: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "final_verdict": self.final_verdict.value,
            "confidence": self.confidence,
            "sha256": self.sha256,
            "sample_path": self.sample_path,
            "signals": [r.to_dict() for r in self.signal_results],
            "bayes_pia": self.bayes_pia,
        }


def bayes_pia(
    p_i: float,
    p_a_given_i: float,
    p_a_given_not_i: float,
) -> float:
    """Bayes' theorem: P(I|A) from the text (Ch.15 §6.3).

    P(I|A) = P(I) * P(A|I) / (P(I)*P(A|I) + P(~I)*P(A|~I))

    - p_i: prior probability of intrusion P(I)
    - p_a_given_i: true-alarm rate P(A|I)
    - p_a_given_not_i: false-alarm rate P(A|~I)
    """
    if p_i <= 0:
        return 0.0
    numerator = p_i * p_a_given_i
    denominator = numerator + (1 - p_i) * p_a_given_not_i
    if denominator <= 0:
        return 0.0
    return numerator / denominator
