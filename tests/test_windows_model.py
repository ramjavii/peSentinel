from __future__ import annotations

from pathlib import Path

from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import Right, Verdict
from pesentinel.signals.windows_model import WindowsModelSignal


def _grant(kernel: ProtectionKernel) -> None:
    kernel.grant("heuristic_signal", "sample_file", Right.READ)


def test_non_pe_returns_unknown(kernel: ProtectionKernel, non_pe_file: Path) -> None:
    _grant(kernel)
    sig = WindowsModelSignal(kernel)
    with kernel.enter_domain("heuristic_signal"):
        result = sig.analyze(non_pe_file)
    assert result.verdict == Verdict.UNKNOWN


def test_benign_pe_returns_result(kernel: ProtectionKernel, benign_pe: Path) -> None:
    _grant(kernel)
    sig = WindowsModelSignal(kernel)
    with kernel.enter_domain("heuristic_signal"):
        result = sig.analyze(benign_pe)
    # A minimal PE without manifest -> UNKNOWN
    assert result.verdict in (Verdict.UNKNOWN, Verdict.BENIGN, Verdict.SUSPICIOUS)


def test_access_denied(kernel: ProtectionKernel, benign_pe: Path) -> None:
    sig = WindowsModelSignal(kernel)
    with kernel.enter_domain("heuristic_signal"):
        try:
            sig.analyze(benign_pe)
            raise AssertionError("expected AccessControlException")
        except Exception as exc:
            assert "lacks" in str(exc) or "denied" in str(exc).lower()
