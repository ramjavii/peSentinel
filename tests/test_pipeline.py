from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from pesentinel.core.pipeline import Pipeline
from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import Right, Verdict
from pesentinel.security.policy import PolicyConfig
from pesentinel.signals.hash_reputation import HashReputationSignal


def _grant(kernel: ProtectionKernel) -> None:
    kernel.grant("hash_signal", "sample_file", Right.READ)
    kernel.grant("hash_signal", "network", Right.NETWORK_CALL)
    kernel.grant("pipeline_core", "sample_file", Right.READ)


def test_pipeline_runs_signal_offline(
    kernel: ProtectionKernel, benign_sample: Path, default_policy: PolicyConfig
) -> None:
    _grant(kernel)
    sig = HashReputationSignal(kernel, offline=True)
    pipe = Pipeline(kernel, [sig], default_policy)
    v = pipe.run(benign_sample)
    assert len(v.signal_results) == 1
    assert v.signal_results[0].verdict == Verdict.UNKNOWN


def test_pipeline_aggregates_suspicious_single_malicious(
    kernel: ProtectionKernel, benign_sample: Path, default_policy: PolicyConfig
) -> None:
    """A single malicious signal -> suspicious (weighted scorer, floor logic)."""
    _grant(kernel)
    sig = HashReputationSignal(kernel, offline=False)
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "query_status": "ok",
        "data": [{"signature_name": "X"}],
    }
    with patch(
        "pesentinel.signals.hash_reputation.requests.post", return_value=mock_resp
    ):
        pipe = Pipeline(kernel, [sig], default_policy)
        v = pipe.run(benign_sample)
    assert v.final_verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
    assert v.sha256


def test_pipeline_aggregates_benign(
    kernel: ProtectionKernel, benign_sample: Path, default_policy: PolicyConfig
) -> None:
    _grant(kernel)
    sig = HashReputationSignal(kernel, offline=False)
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"query_status": "hash_not_found"}
    with patch(
        "pesentinel.signals.hash_reputation.requests.post", return_value=mock_resp
    ):
        pipe = Pipeline(kernel, [sig], default_policy)
        v = pipe.run(benign_sample)
    assert v.final_verdict == Verdict.BENIGN


def test_pipeline_catches_access_denial_as_unknown(
    kernel: ProtectionKernel, benign_sample: Path, default_policy: PolicyConfig
) -> None:
    sig = HashReputationSignal(kernel, offline=True)
    pipe = Pipeline(kernel, [sig], default_policy)
    v = pipe.run(benign_sample)
    assert v.signal_results[0].verdict == Verdict.UNKNOWN
    assert (
        "denied" in v.signal_results[0].reason or "error" in v.signal_results[0].reason
    )
