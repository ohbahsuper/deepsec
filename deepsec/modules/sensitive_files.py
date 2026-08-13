from ..models import Finding, Severity
from ..utils.http import SafeHttpClient

PATHS = ("/.env", "/.git/HEAD", "/backup.zip", "/config.php.bak", "/debug.log")


async def scan(base_url: str, client: SafeHttpClient) -> list[Finding]:
    findings = []
    for path in PATHS:
        url = base_url.rstrip("/") + path
        response = await client.head(url)
        if response is not None and 200 <= response.status_code < 300:
            findings.append(
                Finding(
                    f"Potentially sensitive file exposed: {path}",
                    Severity.HIGH,
                    "Exposure",
                    "A common sensitive path returned a successful HTTP response.",
                    f"HTTP {response.status_code}",
                    response.url,
                    "Remove the file from public serving and review access logs.",
                )
            )
    return findings or [
        Finding(
            "No sampled sensitive files exposed",
            Severity.PASS,
            "Exposure",
            "The conservative sensitive-path sample did not return successful responses.",
            "HEAD requests only",
            base_url,
            "Keep deployment artifacts outside the web root.",
        )
    ]
