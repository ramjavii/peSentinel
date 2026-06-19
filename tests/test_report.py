from __future__ import annotations

import io

from rich.console import Console

from pesentinel.core.report import render_report
from pesentinel.core.verdict import AggregatedVerdict, SignalResult
from pesentinel.protection.types import Verdict


def _buf() -> Console:
    return Console(file=io.StringIO(), width=100, record=True)


def test_render_benign_report() -> None:
    r = SignalResult(
        "hash_reputation", Verdict.BENIGN, 0.4, ["sha256=abc"], "not found"
    )
    v = AggregatedVerdict(
        final_verdict=Verdict.BENIGN, confidence=0.4, signal_results=[r], sha256="abc"
    )
    c = _buf()
    render_report(v, c)
    out = c.export_text()
    assert "BENIGN" in out
    assert "hash_reputation" in out


def test_render_malicious_report() -> None:
    r = SignalResult("hash_reputation", Verdict.MALICIOUS, 0.9, ["sha256=def"], "found")
    v = AggregatedVerdict(
        final_verdict=Verdict.MALICIOUS,
        confidence=0.9,
        signal_results=[r],
        sha256="def",
    )
    c = _buf()
    render_report(v, c)
    out = c.export_text()
    assert "MALICIOUS" in out
    assert "found" in out


def test_render_unknown_report() -> None:
    r = SignalResult("hash_reputation", Verdict.UNKNOWN, 0.0, [], "offline")
    v = AggregatedVerdict(
        final_verdict=Verdict.BENIGN, confidence=0.0, signal_results=[r], sha256=""
    )
    c = _buf()
    render_report(v, c)
    out = c.export_text()
    assert "offline" in out
