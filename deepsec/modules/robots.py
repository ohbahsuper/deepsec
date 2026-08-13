from ..models import Finding, Severity
from ..utils.http import SafeHttpClient


async def scan(base_url: str, client: SafeHttpClient) -> list[Finding]:
    url = base_url.rstrip("/") + "/robots.txt"
    response = await client.get(url)
    if response is None or response.status_code >= 400:
        return [
            Finding(
                "robots.txt not found",
                Severity.INFO,
                "Discovery",
                "No public robots.txt was observed.",
                "HTTP resource unavailable",
                url,
                "Publish one only when it accurately reflects intended indexing.",
            )
        ]
    return [
        Finding(
            "robots.txt found",
            Severity.INFO,
            "Discovery",
            "robots.txt is publicly accessible and may reveal paths.",
            response.body[:500],
            response.url,
            "Avoid listing sensitive paths; robots.txt is not an access-control mechanism.",
        )
    ]
