from ..models import Finding, Severity
from ..utils.http import ResponseData


def scan(response: ResponseData) -> list[Finding]:
    if not response.history:
        return [
            Finding(
                "No redirect chain",
                Severity.INFO,
                "Transport",
                "The target responded without an HTTP redirect chain.",
                "0 redirects",
                response.url,
                "Keep canonical HTTP/HTTPS behavior explicit.",
            )
        ]
    locations = [str(item.url) for item in response.history] + [response.url]
    return [
        Finding(
            "Redirect chain observed",
            Severity.INFO,
            "Transport",
            "HTTP redirects were followed without leaving HTTP(S).",
            " → ".join(locations),
            response.url,
            "Use a short canonical chain and validate redirect destinations.",
        )
    ]
