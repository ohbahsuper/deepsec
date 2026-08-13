from http.cookies import SimpleCookie

from ..models import Finding, Severity
from ..utils.http import ResponseData


def scan(response: ResponseData) -> list[Finding]:
    raw = response.headers.get_list("set-cookie")
    findings: list[Finding] = []
    for item in raw:
        cookie = SimpleCookie()
        cookie.load(item)
        for name, morsel in cookie.items():
            flags = {key.lower(): value for key, value in morsel.items()}
            if "secure" not in item.lower() and response.url.startswith("https://"):
                findings.append(
                    Finding(
                        f'Cookie "{name}" missing Secure',
                        Severity.MEDIUM,
                        "Cookies",
                        "A cookie is set over HTTPS without the Secure attribute.",
                        item,
                        response.url,
                        "Add the Secure attribute.",
                    )
                )
            if "httponly" not in item.lower():
                findings.append(
                    Finding(
                        f'Cookie "{name}" missing HttpOnly',
                        Severity.LOW,
                        "Cookies",
                        "A cookie is readable by client-side scripts.",
                        item,
                        response.url,
                        "Add HttpOnly unless script access is required.",
                    )
                )
            if not flags.get("samesite"):
                findings.append(
                    Finding(
                        f'Cookie "{name}" missing SameSite',
                        Severity.MEDIUM,
                        "Cookies",
                        "A cookie has no explicit SameSite policy.",
                        item,
                        response.url,
                        "Set SameSite=Lax or Strict, or document why None is required.",
                    )
                )
    if not raw:
        return [
            Finding(
                "No cookies observed",
                Severity.INFO,
                "Cookies",
                "The response did not set cookies.",
                "No Set-Cookie header",
                response.url,
                "Review cookies on authenticated and state-changing flows.",
            )
        ]
    return findings or [
        Finding(
            "Cookie attributes present",
            Severity.PASS,
            "Cookies",
            "Observed cookies included the checked attributes.",
            "Set-Cookie attributes reviewed",
            response.url,
            "Keep cookie policies explicit.",
        )
    ]
