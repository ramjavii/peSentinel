from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console

from pesentinel.core.pipeline import Pipeline
from pesentinel.core.report import render_report
from pesentinel.core.verdict import AggregatedVerdict
from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import Right
from pesentinel.signals.hash_reputation import HashReputationSignal

app = typer.Typer(help="peSentinel — Windows-PE malware analyzer")


@app.command()
def scan(
    file: Path = typer.Option(..., "--file", "-f", help="Sample to analyze"),  # noqa: B008
    report: Path | None = typer.Option(None, "--report", help="Write JSON report"),  # noqa: B008
    offline: bool = typer.Option(False, "--offline", help="Skip network signals"),  # noqa: B008
) -> None:
    """Analyze a single Windows PE sample."""
    console = Console()
    if not file.is_file():
        console.print(f"[red]Error:[/red] file not found: {file}", file=sys.stderr)
        raise typer.Exit(code=2)

    try:
        kernel = ProtectionKernel()
        ProtectionKernel._instance = kernel
        kernel.grant("hash_signal", "sample_file", Right.READ)
        kernel.grant("hash_signal", "network", Right.NETWORK_CALL)
        kernel.grant("pipeline_core", "sample_file", Right.READ)

        signal = HashReputationSignal(kernel, offline=offline)
        pipeline = Pipeline(kernel, [signal])
        verdict = pipeline.run(file)
        render_report(verdict, console)

        if report is not None:
            _write_report(verdict, report)
            console.print(f"\n[dim]Report written to {report}[/dim]")
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}", file=sys.stderr)
        raise typer.Exit(code=1) from exc


def _write_report(verdict: AggregatedVerdict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(verdict.to_dict(), indent=2))


if __name__ == "__main__":
    app()
