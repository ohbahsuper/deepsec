import re

from ..models import Finding, Severity
from ..utils.http import ResponseData


def scan(response: ResponseData) -> list[Finding]:
    matches: list[str] = []
    for name in ("server", "x-powered-by", "x-generator"):
        value = response.headers.get(name)
        if value:
            matches.append(f"{name}: {value}")
    for pattern, label in ((r"wp-content", "WordPress"), (r"__next_data__", "Next.js"), (r"ng-version", "Angular")):
        if re.search(pattern, response.body, re.I):
            matches.append(label)
    findings: list[Finding] = []
    if not matches:
        findings.extend(
            [
                Finding(
                    "No explicit technology disclosure",
                    Severity.PASS,
                    "Fingerprinting",
                    "No supported technology marker was observed.",
                    "No marker",
                    response.url,
                    "Continue minimizing unnecessary version disclosures.",
                )
            ]
        )
    else:
        findings.extend(
            [
                Finding(
                    "Technology disclosure observed",
                    Severity.LOW,
                    "Fingerprinting",
                    "Public responses reveal technology markers or versions.",
                    "; ".join(matches)[:500],
                    response.url,
                    "Remove unnecessary banners and exact versions where operationally possible.",
                )
            ]
        )
    if re.search(r"(?i)(index of /|directory listing|parent directory)", response.body):
        findings.append(
            Finding(
                "Directory listing visible",
                Severity.MEDIUM,
                "Exposure",
                "The response appears to expose a directory index directly.",
                "Directory index marker in normal response",
                response.url,
                "Disable directory indexing and serve only intended public assets.",
            )
        )
    if re.search(
        r"(?i)(traceback \\(most recent call last\\)|stack trace|exception in thread|sql syntax|undefined variable)", response.body
    ):
        findings.append(
            Finding(
                "Error information disclosed",
                Severity.MEDIUM,
                "Disclosure",
                "The public response contains a recognizable error or stack-trace marker.",
                "Error marker in response body",
                response.url,
                "Use generic production error pages and keep diagnostic details server-side.",
            )
        )
    return findings
