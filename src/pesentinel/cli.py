from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from pesentinel.core.pipeline import Pipeline
from pesentinel.core.report import render_report
from pesentinel.core.verdict import AggregatedVerdict
from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.security.audit import JsonlAuditSink
from pesentinel.security.policy import apply_policy, load_policy
from pesentinel.signals.hash_reputation import HashReputationSignal
from pesentinel.signals.pe_heuristics import PEHeuristicsSignal
from pesentinel.signals.windows_model import WindowsModelSignal
from pesentinel.signals.yara_signatures import YaraSignaturesSignal

app = typer.Typer(help="peSentinel — Windows-PE malware analyzer")

_DEFAULT_POLICY = Path(__file__).resolve().parents[2] / "data" / "policy.yaml"
_DEFAULT_AUDIT_LOG = Path("data") / "audit.jsonl"
_DEFAULT_RULES_DIR = Path(__file__).resolve().parents[2] / "data" / "rules"


def _build_kernel_and_signals(
    policy_path: Path, offline: bool
) -> tuple[ProtectionKernel, list[object]]:
    audit_sink = JsonlAuditSink(_DEFAULT_AUDIT_LOG)
    kernel = ProtectionKernel(audit=audit_sink)
    ProtectionKernel._instance = kernel
    pol = load_policy(policy_path)
    apply_policy(kernel, pol)
    signals: list[object] = [
        HashReputationSignal(kernel, offline=offline),
        PEHeuristicsSignal(kernel),
        WindowsModelSignal(kernel),
        YaraSignaturesSignal(kernel, _DEFAULT_RULES_DIR),
    ]
    return kernel, signals


@app.command()
def scan(
    file: Path = typer.Option(..., "--file", "-f", help="Sample to analyze"),  # noqa: B008
    report: Path | None = typer.Option(None, "--report", help="Write JSON report"),  # noqa: B008
    offline: bool = typer.Option(False, "--offline", help="Skip network signals"),  # noqa: B008
    policy: Path = typer.Option(
        _DEFAULT_POLICY, "--policy", help="Path to policy.yaml"
    ),  # noqa: B008
) -> None:
    """Analyze a single Windows PE sample."""
    console = Console()
    if not file.is_file():
        console.print(f"[red]Error:[/red] file not found: {file}", file=sys.stderr)
        raise typer.Exit(code=2)

    try:
        kernel, signals = _build_kernel_and_signals(policy, offline)
        pipeline = Pipeline(kernel, signals)
        verdict = pipeline.run(file)
        render_report(verdict, console)

        if report is not None:
            _write_report(verdict, report)
            console.print(f"\n[dim]Report written to {report}[/dim]")
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}", file=sys.stderr)
        raise typer.Exit(code=1) from exc


@app.command()
def batch(
    folder: Path = typer.Option(..., "--folder", help="Directory to batch scan"),  # noqa: B008
    report: Path | None = typer.Option(None, "--report", help="Write JSON report"),  # noqa: B008
    offline: bool = typer.Option(False, "--offline", help="Skip network signals"),  # noqa: B008
    policy: Path = typer.Option(
        _DEFAULT_POLICY, "--policy", help="Path to policy.yaml"
    ),  # noqa: B008
) -> None:
    """Batch-analyze all files in a directory."""
    console = Console()
    if not folder.is_dir():
        console.print(
            f"[red]Error:[/red] directory not found: {folder}", file=sys.stderr
        )
        raise typer.Exit(code=2)

    try:
        kernel, signals = _build_kernel_and_signals(policy, offline)
        pipeline = Pipeline(kernel, signals)
        files = sorted(p for p in folder.iterdir() if p.is_file())
        verdicts: list[AggregatedVerdict] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"Scanning {len(files)} files...", total=len(files)
            )
            for f in files:
                progress.update(task, description=f"Scanning {f.name}")
                v = pipeline.run(f)
                verdicts.append(v)
                progress.advance(task)

        for v in verdicts:
            render_report(v, console)
            console.print()

        if report is not None:
            _write_batch_report(verdicts, report)
            console.print(f"[dim]Batch report written to {report}[/dim]")
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}", file=sys.stderr)
        raise typer.Exit(code=1) from exc


def _write_report(verdict: AggregatedVerdict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(verdict.to_dict(), indent=2))


def _write_batch_report(verdicts: list[AggregatedVerdict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([v.to_dict() for v in verdicts], indent=2))


if __name__ == "__main__":
    app()
