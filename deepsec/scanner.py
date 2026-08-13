import asyncio
from urllib.parse import urlsplit

from .config import ScanConfig
from .models import Finding, Severity
from .modules import cookies, cors, dns, http_headers, javascript, redirects, robots, security_txt, sensitive_files, technologies, tls
from .utils.http import SafeHttpClient


class Scanner:
    def __init__(self, target: str, config: ScanConfig) -> None:
        self.target = target
        self.config = config

    async def run(self) -> list[Finding]:
        parsed = urlsplit(self.target)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        client = SafeHttpClient(self.config)
        try:
            dns_task = dns.scan(parsed.hostname or "", self.target)
            response = await client.get(self.target)
            findings = await dns_task
            if response is None:
                findings.append(
                    Finding(
                        "Target unreachable",
                        Severity.HIGH,
                        "Availability",
                        "The target did not return a usable HTTP response.",
                        "Network request failed or timed out",
                        self.target,
                        "Verify network access and target availability.",
                    )
                )
                return findings
            findings.extend(http_headers.scan(response))
            findings.extend(cookies.scan(response))
            findings.extend(technologies.scan(response))
            findings.extend(cors.scan(response))
            findings.extend(redirects.scan(response))
            findings.extend(await tls.scan(parsed.hostname or "", port, self.target))
            module_tasks = [
                robots.scan(self.target, client),
                security_txt.scan(self.target, client),
                sensitive_files.scan(self.target, client),
                javascript.scan(response.body, response.url, client, self.config.max_js_files),
            ]
            results = await asyncio.gather(*module_tasks)
            for result in results:
                findings.extend(result)
            return findings
        finally:
            await client.close()
