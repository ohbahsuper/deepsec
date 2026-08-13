import asyncio
import socket

from ..models import Finding, Severity


async def scan(host: str, url: str) -> list[Finding]:
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, None, type=socket.SOCK_STREAM)
        addresses = sorted({info[4][0] for info in infos})
        return [
            Finding(
                "DNS resolved",
                Severity.INFO,
                "DNS",
                "The target resolved to public network addresses.",
                ", ".join(addresses),
                url,
                "Review exposed addresses and ownership regularly.",
            )
        ]
    except socket.gaierror as exc:
        return [
            Finding(
                "DNS resolution failed",
                Severity.HIGH,
                "DNS",
                "The target could not be resolved.",
                str(exc),
                url,
                "Verify DNS records and target ownership.",
            )
        ]
