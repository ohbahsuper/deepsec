from ..models import Finding, Severity
from ..utils.http import SafeHttpClient


async def scan(base_url: str, client: SafeHttpClient) -> list[Finding]:
    url = base_url.rstrip("/") + "/.well-known/security.txt"
    response = await client.get(url)
    if response is None or response.status_code >= 400:
        return [
            Finding(
                "security.txt not found",
                Severity.INFO,
                "Disclosure",
                "No security.txt was observed.",
                "HTTP resource unavailable",
                url,
                "Publish a valid security.txt with a monitored security contact.",
            )
        ]
    return [
        Finding(
            "security.txt found",
            Severity.INFO,
            "Disclosure",
            "A security contact policy is publicly available.",
            response.body[:500],
            response.url,
            "Keep contacts current and include an expiration date when appropriate.",
        )
    ]
