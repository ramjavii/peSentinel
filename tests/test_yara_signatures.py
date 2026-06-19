from __future__ import annotations

from pathlib import Path

from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import Right, Verdict
from pesentinel.signals.yara_signatures import YaraSignaturesSignal


def _grant(kernel: ProtectionKernel) -> None:
    kernel.grant("yara_signal", "sample_file", Right.READ)
    kernel.grant("yara_signal", "rules_dir", Right.READ)


def test_yara_match_malicious(kernel: ProtectionKernel, tmp_path: Path) -> None:
    _grant(kernel)
    rules_dir = Path(__file__).resolve().parents[1] / "data" / "rules"
    sig = YaraSignaturesSignal(kernel, rules_dir)
    sample = tmp_path / "malware.exe"
    sample.write_bytes(b"PESENTINEL_TEST_MALWARE_MARKER inside a file")
    with kernel.enter_domain("yara_signal"):
        result = sig.analyze(sample)
    assert result.verdict == Verdict.MALICIOUS
    assert "pesentinel_test_marker" in result.evidence[0]


def test_yara_no_match_benign(kernel: ProtectionKernel, tmp_path: Path) -> None:
    _grant(kernel)
    rules_dir = Path(__file__).resolve().parents[1] / "data" / "rules"
    sig = YaraSignaturesSignal(kernel, rules_dir)
    sample = tmp_path / "benign.exe"
    sample.write_bytes(b"just a normal file with no markers")
    with kernel.enter_domain("yara_signal"):
        result = sig.analyze(sample)
    assert result.verdict == Verdict.BENIGN


def test_yara_empty_rules_dir(kernel: ProtectionKernel, tmp_path: Path) -> None:
    _grant(kernel)
    empty_dir = tmp_path / "empty_rules"
    empty_dir.mkdir()
    sig = YaraSignaturesSignal(kernel, empty_dir)
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"anything")
    with kernel.enter_domain("yara_signal"):
        result = sig.analyze(sample)
    assert result.verdict == Verdict.BENIGN
