from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pesentinel.core.verdict import AggregatedVerdict

_VERDICT_STYLE = {
    "benign": "green",
    "suspicious": "yellow",
    "malicious": "bold red",
    "unknown": "dim",
}


def render_report(verdict: AggregatedVerdict, console: Console | None = None) -> None:
    """Render an ``AggregatedVerdict`` to the terminal via Rich."""
    console = console or Console()
    style = _VERDICT_STYLE.get(verdict.final_verdict.value, "white")
    header = Panel(
        f"[{style}]{verdict.final_verdict.value.upper()}[/{style}]"
        f"  confidence={verdict.confidence:.2f}"
        f"\nsha256={verdict.sha256 or 'n/a'}"
        f"\npath={verdict.sample_path}",
        title="peSentinel Verdict",
        border_style=style,
    )
    console.print(header)

    table = Table(title="Signal Results")
    table.add_column("Signal", style="cyan")
    table.add_column("Verdict")
    table.add_column("Confidence", justify="right")
    table.add_column("Reason")
    for r in verdict.signal_results:
        rs = _VERDICT_STYLE.get(r.verdict.value, "white")
        table.add_row(
            r.signal_name,
            f"[{rs}]{r.verdict.value}[/{rs}]",
            f"{r.confidence:.2f}",
            r.reason,
        )
    console.print(table)
