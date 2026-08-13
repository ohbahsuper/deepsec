from ..models import Finding, Severity
from ..utils.http import ResponseData


def scan(response: ResponseData) -> list[Finding]:
    origin = response.headers.get("access-control-allow-origin", "")
    credentials = response.headers.get("access-control-allow-credentials", "").lower()
    if origin == "*" and credentials == "true":
        return [
            Finding(
                "CORS allows wildcard origin with credentials",
                Severity.HIGH,
                "CORS",
                "The response combines a wildcard origin with credential support.",
                f"origin={origin}; credentials={credentials}",
                response.url,
                "Use an explicit allowlist and avoid credentialed wildcard access.",
            )
        ]
    if origin == "*":
        return [
            Finding(
                "CORS wildcard observed",
                Severity.LOW,
                "CORS",
                "The response permits requests from any origin.",
                "Access-Control-Allow-Origin: *",
                response.url,
                "Restrict origins when the resource is not intentionally public.",
            )
        ]
    return [
        Finding(
            "CORS policy not obviously unsafe",
            Severity.PASS,
            "CORS",
            "No obvious wildcard CORS misconfiguration was observed.",
            origin or "Header absent",
            response.url,
            "Review preflight and credentialed routes separately.",
        )
    ]
