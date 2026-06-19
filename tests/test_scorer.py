from __future__ import annotations

from pesentinel.core.verdict import SignalResult
from pesentinel.protection.types import Verdict
from pesentinel.security.policy import (
    AuthConfig,
    PolicyConfig,
    ScoringConfig,
)
from pesentinel.signals.scorer import aggregate


def _policy() -> PolicyConfig:
    return PolicyConfig(
        objects=[],
        domains={},
        roles={},
        scoring=ScoringConfig(
            hash_reputation=0.40,
            yara=0.35,
            heuristics=0.25,
            malicious_threshold=0.60,
            suspicious_threshold=0.30,
        ),
        firewall_allow=[],
        auth=AuthConfig(),
    )


def test_all_benign_signals() -> None:
    results = [
        SignalResult("hash_reputation", Verdict.BENIGN, 0.4, [], "ok"),
        SignalResult("yara_signatures", Verdict.BENIGN, 0.5, [], "ok"),
        SignalResult("pe_heuristics", Verdict.BENIGN, 0.5, [], "ok"),
    ]
    v = aggregate(results, _policy())
    assert v.final_verdict == Verdict.BENIGN


def test_malicious_yara_triggers_suspicious() -> None:
    results = [
        SignalResult("hash_reputation", Verdict.BENIGN, 0.4, [], "ok"),
        SignalResult("yara_signatures", Verdict.MALICIOUS, 0.85, [], "matched"),
        SignalResult("pe_heuristics", Verdict.BENIGN, 0.5, [], "ok"),
    ]
    v = aggregate(results, _policy())
    assert v.final_verdict == Verdict.SUSPICIOUS


def test_two_malicious_signals_trigger_malicious() -> None:
    results = [
        SignalResult("hash_reputation", Verdict.MALICIOUS, 0.9, [], "found"),
        SignalResult("yara_signatures", Verdict.MALICIOUS, 0.85, [], "matched"),
        SignalResult("pe_heuristics", Verdict.BENIGN, 0.5, [], "ok"),
    ]
    v = aggregate(results, _policy())
    assert v.final_verdict == Verdict.MALICIOUS


def test_suspicious_heuristics_triggers_suspicious() -> None:
    results = [
        SignalResult("hash_reputation", Verdict.BENIGN, 0.4, [], "ok"),
        SignalResult("yara_signatures", Verdict.BENIGN, 0.5, [], "ok"),
        SignalResult("pe_heuristics", Verdict.SUSPICIOUS, 0.6, [], "anomalies"),
    ]
    v = aggregate(results, _policy())
    assert v.final_verdict == Verdict.SUSPICIOUS


def test_unknown_contributes_zero() -> None:
    results = [
        SignalResult("hash_reputation", Verdict.UNKNOWN, 0.0, [], "offline"),
        SignalResult("yara_signatures", Verdict.BENIGN, 0.5, [], "ok"),
        SignalResult("pe_heuristics", Verdict.BENIGN, 0.5, [], "ok"),
    ]
    v = aggregate(results, _policy())
    assert v.final_verdict == Verdict.BENIGN
