from __future__ import annotations

from pesentinel.core.verdict import AggregatedVerdict, SignalResult
from pesentinel.protection.types import Verdict


def test_signal_result_to_dict() -> None:
    r = SignalResult("hash", Verdict.MALICIOUS, 0.9, ["sha256=abc"], "found")
    d = r.to_dict()
    assert d == {
        "signal_name": "hash",
        "verdict": "malicious",
        "confidence": 0.9,
        "evidence": ["sha256=abc"],
        "reason": "found",
    }


def test_aggregated_verdict_to_dict() -> None:
    r = SignalResult("hash", Verdict.MALICIOUS, 0.9, ["sha256=abc"], "found")
    v = AggregatedVerdict(
        final_verdict=Verdict.MALICIOUS,
        confidence=0.9,
        signal_results=[r],
        sha256="abc",
        sample_path="/x.exe",
    )
    d = v.to_dict()
    assert d["final_verdict"] == "malicious"
    assert d["sha256"] == "abc"
    assert d["signals"][0]["signal_name"] == "hash"
