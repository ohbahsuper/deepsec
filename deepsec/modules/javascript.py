import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from ..models import Finding, Severity
from ..utils.http import SafeHttpClient
from ..utils.validation import safe_http_url

SECRET_RE = re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]")
URL_RE = re.compile(r"https?://[^\s'\"<>]+")


async def scan(response_body: str, base_url: str, client: SafeHttpClient, max_files: int) -> list[Finding]:
    soup = BeautifulSoup(response_body, "html.parser")
    scripts = [urljoin(base_url, tag["src"]) for tag in soup.find_all("script", src=True)]
    findings: list[Finding] = []
    for script_url in scripts[:max_files]:
        if not safe_http_url(script_url) or urlsplit(script_url).hostname != urlsplit(base_url).hostname:
            continue
        script = await client.get(script_url)
        if script is None:
            continue
        urls = URL_RE.findall(script.body)
        secrets = SECRET_RE.findall(script.body)
        external_domains = len({urlsplit(item).netloc for item in urls})
        evidence = f"URLs/endpoints: {len(urls)}; external domains: {external_domains}; secret-like strings: {len(secrets)}"
        if urls or secrets:
            findings.append(
                Finding(
                    "JavaScript exposure observed",
                    Severity.LOW if not secrets else Severity.HIGH,
                    "JavaScript",
                    "Public JavaScript contains endpoint/domain references or secret-like strings; values were not used.",
                    evidence,
                    script.url,
                    "Review bundles, remove sensitive values, and rotate any confirmed secrets through the owner process.",
                )
            )
    return findings or [
        Finding(
            "No JavaScript exposure detected",
            Severity.PASS,
            "JavaScript",
            "No supported endpoint or secret-like pattern was observed in sampled same-origin scripts.",
            "Scripts sampled without matches",
            base_url,
            "Review generated bundles during releases.",
        )
    ]
