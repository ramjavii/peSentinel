from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pesentinel.cli import app

runner = CliRunner()


def test_cli_loads_policy_and_scans(tmp_path: Path) -> None:
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"policy integration test bytes")
    audit_log = tmp_path / "audit.jsonl"
    # Patch the default audit log path so we can inspect it
    import pesentinel.cli as cli_mod

    orig = cli_mod._DEFAULT_AUDIT_LOG
    cli_mod._DEFAULT_AUDIT_LOG = audit_log
    try:
        result = runner.invoke(app, ["--file", str(sample), "--offline"])
    finally:
        cli_mod._DEFAULT_AUDIT_LOG = orig
    assert result.exit_code == 0, result.output
    # Audit log should have been written with access_check / domain_switch events
    assert audit_log.exists()
    lines = audit_log.read_text().strip().split("\n")
    events = [json.loads(line)["event"] for line in lines]
    assert "domain_switch" in events
    assert "capability_grant" in events


def test_cli_custom_policy(tmp_path: Path) -> None:
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"custom policy test")
    policy_file = tmp_path / "custom.yaml"
    policy_file.write_text(
        "objects: [sample_file, network]\n"
        "domains:\n"
        "  hash_signal:\n"
        "    rights:\n"
        "      sample_file: [READ]\n"
        "      network: [NETWORK_CALL]\n"
        "  pipeline_core:\n"
        "    rights:\n"
        "      sample_file: [READ]\n"
        "roles: {}\n"
    )
    import pesentinel.cli as cli_mod

    orig = cli_mod._DEFAULT_AUDIT_LOG
    cli_mod._DEFAULT_AUDIT_LOG = tmp_path / "audit.jsonl"
    try:
        result = runner.invoke(
            app,
            ["--file", str(sample), "--offline", "--policy", str(policy_file)],
        )
    finally:
        cli_mod._DEFAULT_AUDIT_LOG = orig
    assert result.exit_code == 0, result.output
