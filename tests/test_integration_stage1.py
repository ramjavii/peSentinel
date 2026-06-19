from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from pesentinel.cli import app
from pesentinel.core.pipeline import Pipeline
from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import Right, Verdict
from pesentinel.security.policy import (
    AuthConfig,
    PolicyConfig,
    ScoringConfig,
)
from pesentinel.signals.hash_reputation import HashReputationSignal

runner = CliRunner()


def test_end_to_end_benign_sample_offline(tmp_path: Path) -> None:
    sample = tmp_path / "benign.exe"
    sample.write_bytes(b"definitely not malware, just bytes")
    kernel = ProtectionKernel()
    ProtectionKernel._instance = kernel
    kernel.grant("hash_signal", "sample_file", Right.READ)
    kernel.grant("hash_signal", "network", Right.NETWORK_CALL)
    kernel.grant("pipeline_core", "sample_file", Right.READ)
    sig = HashReputationSignal(kernel, offline=True)
    pol = PolicyConfig(
        objects=[],
        domains={},
        roles={},
        scoring=ScoringConfig(),
        firewall_allow=[],
        auth=AuthConfig(),
    )
    pipe = Pipeline(kernel, [sig], pol)
    v = pipe.run(sample)
    assert v.final_verdict in (Verdict.BENIGN, Verdict.UNKNOWN)
    assert len(v.signal_results) == 1
    expected = hashlib.sha256(sample.read_bytes()).hexdigest()
    assert v.sha256 == expected


def test_end_to_end_malicious_sample_mocked(tmp_path: Path) -> None:
    sample = tmp_path / "evil.exe"
    sample.write_bytes(b"pretend this is a known-malware payload")
    kernel = ProtectionKernel()
    ProtectionKernel._instance = kernel
    kernel.grant("hash_signal", "sample_file", Right.READ)
    kernel.grant("hash_signal", "network", Right.NETWORK_CALL)
    kernel.grant("pipeline_core", "sample_file", Right.READ)
    sig = HashReputationSignal(kernel, offline=False)
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "query_status": "ok",
        "data": [{"signature_name": "TestTrojan"}],
    }
    with patch(
        "pesentinel.signals.hash_reputation.requests.post", return_value=mock_resp
    ):
        pol = PolicyConfig(
            objects=[],
            domains={},
            roles={},
            scoring=ScoringConfig(),
            firewall_allow=[],
            auth=AuthConfig(),
        )
        pipe = Pipeline(kernel, [sig], pol)
        v = pipe.run(sample)
    assert v.final_verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
    assert v.sha256 == digest
    assert any("TestTrojan" in e for e in v.signal_results[0].evidence)


def test_end_to_end_cli_writes_signed_report_schema(tmp_path: Path) -> None:
    sample = tmp_path / "x.exe"
    sample.write_bytes(b"cli integration bytes")
    report = tmp_path / "report.json"
    result = runner.invoke(
        app, ["scan", "--file", str(sample), "--offline", "--report", str(report)]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(report.read_text())
    required = {"final_verdict", "confidence", "sha256", "sample_path", "signals"}
    assert required.issubset(data.keys())
    assert data["signals"][0]["signal_name"] == "hash_reputation"
