from __future__ import annotations

from pesentinel.core.verdict import AggregatedVerdict, SignalResult
from pesentinel.protection.types import Verdict
from pesentinel.security.policy import PolicyConfig

_SIGNAL_VALUES = {
    Verdict.BENIGN: 0.0,
    Verdict.UNKNOWN: 0.0,
    Verdict.SUSPICIOUS: 0.5,
    Verdict.MALICIOUS: 1.0,
}

_WEIGHT_KEYS = {
    "hash_reputation": "hash_reputation",
    "yara_signatures": "yara",
    "pe_heuristics": "heuristics",
}


def aggregate(
    results: list[SignalResult],
    policy: PolicyConfig,
    sample_path: str = "",
    sha256: str = "",
) -> AggregatedVerdict:
    """Weighted aggregation of signal outputs (spec §9.1).

    score = sum(weight[s] * signal_value(s) * confidence[s])
    unknown contributes 0 (neither clears nor condemns).
    """
    score = 0.0
    for r in results:
        key = _WEIGHT_KEYS.get(r.signal_name)
        if key is None:
            continue
        weight = getattr(policy.scoring, key, 0.0)
        val = _SIGNAL_VALUES.get(r.verdict, 0.0)
        score += weight * val * r.confidence

    mal_thresh = policy.scoring.malicious_threshold
    susp_thresh = policy.scoring.suspicious_threshold

    if score >= mal_thresh:
        final = Verdict.MALICIOUS
    elif score >= susp_thresh:
        final = Verdict.SUSPICIOUS
    else:
        final = Verdict.BENIGN

    # Floor: strong signals shouldn't be drowned out by conservative
    # weights. 2+ malicious -> malicious; 1 malicious with high
    # confidence (>=0.9) -> malicious; 1 malicious or any suspicious
    # -> at least suspicious.
    mal_count = sum(1 for r in results if r.verdict == Verdict.MALICIOUS)
    susp_count = sum(1 for r in results if r.verdict == Verdict.SUSPICIOUS)
    high_conf_mal = any(
        r.verdict == Verdict.MALICIOUS and r.confidence >= 0.9 for r in results
    )
    if mal_count >= 2 or high_conf_mal:
        final = Verdict.MALICIOUS
    elif (mal_count >= 1 or susp_count >= 1) and final == Verdict.BENIGN:
        final = Verdict.SUSPICIOUS

    confidence = min(score / mal_thresh if mal_thresh > 0 else 0.0, 1.0)
    return AggregatedVerdict(
        final_verdict=final,
        confidence=confidence,
        signal_results=results,
        sample_path=sample_path,
        sha256=sha256,
    )
