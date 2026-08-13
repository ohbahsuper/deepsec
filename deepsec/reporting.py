import html
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .models import Finding
from .scoring import calculate_score, severity_counts


def report_data(target: str, findings: list[Finding]) -> dict[str, Any]:
    return {
        "tool": "DeepSec",
        "version": __version__,
        "target": target,
        "generated_at": datetime.now(UTC).isoformat(),
        "score": calculate_score(findings),
        "score_disclaimer": "This score is an indicator, not a guarantee of security.",
        "counts": dict(severity_counts(findings)),
        "findings": [f.to_dict() for f in findings],
    }


def json_report(target: str, findings: list[Finding]) -> str:
    return json.dumps(report_data(target, findings), indent=2, ensure_ascii=False)


def html_report(target: str, findings: list[Finding]) -> str:
    data = report_data(target, findings)
    rows = "".join(
        f"<tr><td>{html.escape(f.severity.value)}</td><td>{html.escape(f.title)}</td><td>{html.escape(f.category)}</td><td>{html.escape(f.evidence)}</td><td>{html.escape(f.remediation)}</td></tr>"
        for f in findings
    )
    template = """<!doctype html><meta charset='utf-8'><title>DeepSec report</title>
<style>body{font:15px system-ui;margin:2rem;color:#17202a}table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ccd;padding:.6rem;text-align:left}.score{font-size:2rem}</style>
<h1>DeepSec</h1><p>{target}</p><p class='score'>Security score: {score} / 100</p>
<p>Indicator only; not a guarantee of security.</p><table>
<tr><th>Severity</th><th>Title</th><th>Category</th><th>Evidence</th><th>Remediation</th></tr>{rows}</table>"""
    return template.format(target=html.escape(target), score=data["score"], rows=rows)


def write_report(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
