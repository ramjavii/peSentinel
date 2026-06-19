from __future__ import annotations

from pathlib import Path

from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import Right, Verdict
from pesentinel.signals.pe_heuristics import PEHeuristicsSignal


def _grant(kernel: ProtectionKernel) -> None:
    kernel.grant("heuristic_signal", "sample_file", Right.READ)


def test_non_pe_returns_unknown(kernel: ProtectionKernel, non_pe_file: Path) -> None:
    _grant(kernel)
    sig = PEHeuristicsSignal(kernel)
    with kernel.enter_domain("heuristic_signal"):
        result = sig.analyze(non_pe_file)
    assert result.verdict == Verdict.UNKNOWN
    assert "not a valid PE" in result.reason


def test_benign_pe_returns_benign_or_suspicious(
    kernel: ProtectionKernel, benign_pe: Path
) -> None:
    _grant(kernel)
    sig = PEHeuristicsSignal(kernel)
    with kernel.enter_domain("heuristic_signal"):
        result = sig.analyze(benign_pe)
    assert result.verdict in (Verdict.BENIGN, Verdict.SUSPICIOUS)
    # A minimal PE without imports may have empty evidence (no imphash)


def test_high_entropy_non_pe_returns_unknown(
    kernel: ProtectionKernel, high_entropy_file: Path
) -> None:
    _grant(kernel)
    sig = PEHeuristicsSignal(kernel)
    with kernel.enter_domain("heuristic_signal"):
        result = sig.analyze(high_entropy_file)
    assert result.verdict == Verdict.UNKNOWN


def test_access_denied_returns_unknown(
    kernel: ProtectionKernel, benign_pe: Path
) -> None:
    """Signal without READ right -> access denied -> pipeline catches it."""
    sig = PEHeuristicsSignal(kernel)
    with kernel.enter_domain("heuristic_signal"):
        try:
            sig.analyze(benign_pe)
            raise AssertionError("expected AccessControlException")
        except Exception as exc:
            assert "lacks" in str(exc) or "denied" in str(exc).lower()


def test_entropy_computation() -> None:
    from pesentinel.signals.pe_heuristics import _entropy

    assert _entropy(b"") == 0.0
    assert _entropy(b"\x00" * 100) == 0.0
    assert _entropy(b"\x00\x01\x02\x03") > 1.5


def test_suspicious_imports_set_nonempty() -> None:
    from pesentinel.signals.pe_heuristics import _SUSPICIOUS_IMPORTS

    assert "VirtualAllocEx" in _SUSPICIOUS_IMPORTS
    assert "WriteProcessMemory" in _SUSPICIOUS_IMPORTS
    assert "IsDebuggerPresent" in _SUSPICIOUS_IMPORTS
