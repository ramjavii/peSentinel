from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import Right, Verdict
from pesentinel.signals.hash_reputation import HashReputationSignal


def _grant_rights(kernel: ProtectionKernel) -> None:
    kernel.grant("hash_signal", "sample_file", Right.READ)
    kernel.grant("hash_signal", "network", Right.NETWORK_CALL)


def test_offline_returns_unknown(kernel: ProtectionKernel, benign_sample: Path) -> None:
    _grant_rights(kernel)
    sig = HashReputationSignal(kernel, offline=True)
    with kernel.enter_domain("hash_signal"):
        result = sig.analyze(benign_sample)
    assert result.verdict == Verdict.UNKNOWN
    assert "offline" in result.reason
    assert result.evidence[0].startswith("sha256=")


def test_hash_not_found_returns_benign(
    kernel: ProtectionKernel, benign_sample: Path
) -> None:
    _grant_rights(kernel)
    sig = HashReputationSignal(kernel, offline=False)
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"query_status": "hash_not_found"}
    with (
        patch(
            "pesentinel.signals.hash_reputation.requests.post", return_value=mock_resp
        ),
        kernel.enter_domain("hash_signal"),
    ):
        result = sig.analyze(benign_sample)
    assert result.verdict == Verdict.BENIGN
    assert "not proof of benign" in result.reason


def test_hash_found_returns_malicious(
    kernel: ProtectionKernel, benign_sample: Path
) -> None:
    _grant_rights(kernel)
    sig = HashReputationSignal(kernel, offline=False)
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "query_status": "ok",
        "data": [{"signature_name": "Emotet"}],
    }
    with (
        patch(
            "pesentinel.signals.hash_reputation.requests.post", return_value=mock_resp
        ),
        kernel.enter_domain("hash_signal"),
    ):
        result = sig.analyze(benign_sample)
    assert result.verdict == Verdict.MALICIOUS
    assert any("family=Emotet" in e for e in result.evidence)


def test_network_error_returns_unknown(
    kernel: ProtectionKernel, benign_sample: Path
) -> None:
    _grant_rights(kernel)
    sig = HashReputationSignal(kernel, offline=False)
    with (
        patch(
            "pesentinel.signals.hash_reputation.requests.post",
            side_effect=ConnectionError("dns fail"),
        ),
        kernel.enter_domain("hash_signal"),
    ):
        result = sig.analyze(benign_sample)
    assert result.verdict == Verdict.UNKNOWN
    assert "reputation query failed" in result.reason


def test_sha256_matches_known_value(
    kernel: ProtectionKernel, benign_sample: Path
) -> None:
    _grant_rights(kernel)
    sig = HashReputationSignal(kernel, offline=True)
    with kernel.enter_domain("hash_signal"):
        result = sig.analyze(benign_sample)
    expected = hashlib.sha256(benign_sample.read_bytes()).hexdigest()
    assert result.evidence[0] == f"sha256={expected}"


def test_empty_file_hashes_without_error(
    kernel: ProtectionKernel, empty_sample: Path
) -> None:
    _grant_rights(kernel)
    sig = HashReputationSignal(kernel, offline=True)
    with kernel.enter_domain("hash_signal"):
        result = sig.analyze(empty_sample)
    assert result.verdict == Verdict.UNKNOWN
    assert result.evidence[0].startswith("sha256=")
