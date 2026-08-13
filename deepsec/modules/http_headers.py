from ..models import Finding, Severity
from ..utils.http import ResponseData


def scan(response: ResponseData) -> list[Finding]:
    checks = [
        (
            "Content-Security-Policy",
            Severity.HIGH,
            "A Content-Security-Policy header is missing.",
            "Define a restrictive CSP and report-only policy before enforcing it.",
        ),
        (
            "Strict-Transport-Security",
            Severity.MEDIUM,
            "HSTS is missing on the HTTPS response.",
            "Enable HSTS after confirming every subdomain supports HTTPS.",
        ),
        ("X-Content-Type-Options", Severity.LOW, "MIME sniffing protection is missing.", "Send X-Content-Type-Options: nosniff."),
        ("Referrer-Policy", Severity.LOW, "A Referrer-Policy is missing.", "Set an explicit restrictive referrer policy."),
        (
            "Permissions-Policy",
            Severity.LOW,
            "Permissions-Policy is missing.",
            "Disable browser capabilities that the application does not need.",
        ),
    ]
    findings = []
    names = {key.lower() for key in response.headers}
    for header, severity, description, remediation in checks:
        if header.lower() not in names:
            findings.append(
                Finding(f"{header} missing", severity, "HTTP headers", description, "Header not present", response.url, remediation)
            )
    protected = "frame-ancestors" in response.headers.get("content-security-policy", "").lower() or "x-frame-options" in response.headers
    if not protected:
        findings.append(
            Finding(
                "Clickjacking protection missing",
                Severity.MEDIUM,
                "HTTP headers",
                "Neither frame-ancestors nor X-Frame-Options was observed.",
                "No framing policy present",
                response.url,
                "Set CSP frame-ancestors and/or X-Frame-Options.",
            )
        )
    if not findings:
        findings.append(
            Finding(
                "Security headers present",
                Severity.PASS,
                "HTTP headers",
                "The baseline security headers were observed.",
                "All baseline checks passed",
                response.url,
                "Keep the policy reviewed as the application evolves.",
            )
        )
    return findings
