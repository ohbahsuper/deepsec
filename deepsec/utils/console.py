from rich.console import Console
from rich.table import Table

from ..models import Finding
from ..scoring import calculate_score, severity_counts

console = Console()


def render_terminal(target: str, findings: list[Finding]) -> None:
    console.print("[bold cyan]DeepSec 1.0[/bold cyan]\n")
    console.print(f"[bold]Target[/bold]\n{target}\n")
    console.print("[bold]Scanning...[/bold]\n")
    for finding in findings:
        console.print(
            f"[{finding.severity.lower()}][{finding.severity}] [/{finding.severity.lower()}]{finding.title} — {finding.evidence[:160]}"
        )
    console.print(f"\n[bold]Security score: {calculate_score(findings)} / 100[/bold] [dim](indicator only, not a guarantee)[/dim]")
    table = Table(show_header=False, box=None)
    counts = severity_counts(findings)
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        table.add_row(severity.title(), str(counts[severity]))
    console.print(table)
