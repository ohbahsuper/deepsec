import asyncio
import ssl
from datetime import UTC, datetime

from cryptography import x509

from ..models import Finding, Severity


async def scan(host: str, port: int, url: str) -> list[Finding]:
    if not url.startswith("https://"):
        return [
            Finding(
                "HTTPS unavailable",
                Severity.HIGH,
                "TLS",
                "The target URL does not use HTTPS.",
                "HTTP target",
                url,
                "Serve the application over HTTPS and redirect HTTP safely.",
            )
        ]
    try:
        context = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=context, server_hostname=host), 10)
        certificate = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        writer.close()
        await writer.wait_closed()
        cert = x509.load_der_x509_certificate(certificate)
        expiry = cert.not_valid_after_utc
        days = (expiry - datetime.now(UTC)).days
        if days < 0:
            severity, title = Severity.CRITICAL, "TLS certificate expired"
        elif days <= 30:
            severity, title = Severity.MEDIUM, "TLS certificate expires soon"
        else:
            severity, title = Severity.PASS, "HTTPS and TLS available"
        return [
            Finding(
                title,
                severity,
                "TLS",
                f"The certificate expires in approximately {days} days.",
                f"notAfter={expiry.isoformat()}",
                url,
                "Renew the certificate and monitor expiry.",
            )
        ]
    except (OSError, ssl.SSLError, ValueError) as exc:
        return [
            Finding(
                "TLS validation failed",
                Severity.HIGH,
                "TLS",
                "A trusted TLS connection could not be established.",
                str(exc),
                url,
                "Install a valid certificate chain and review TLS configuration.",
            )
        ]
