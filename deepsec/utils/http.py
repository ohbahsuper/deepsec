import asyncio
import time
from collections.abc import Mapping
from dataclasses import dataclass

import httpx

from ..config import ScanConfig


@dataclass(slots=True)
class ResponseData:
    url: str
    status_code: int
    headers: httpx.Headers
    body: str
    history: list[httpx.Response]


class RateLimiter:
    def __init__(self, requests_per_second: float) -> None:
        self.interval = 1 / requests_per_second
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def wait(self) -> None:
        async with self._lock:
            delay = self.interval - (time.monotonic() - self._last)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last = time.monotonic()


class SafeHttpClient:
    def __init__(self, config: ScanConfig, client: httpx.AsyncClient | None = None) -> None:
        self.config = config
        self.limiter = RateLimiter(config.requests_per_second)
        self._workers = asyncio.Semaphore(config.max_workers)
        self.client = client or httpx.AsyncClient(
            follow_redirects=True,
            timeout=config.timeout,
            headers={"User-Agent": config.user_agent, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
        )
        self._owns_client = client is None

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def request(self, method: str, url: str) -> ResponseData | None:
        async with self._workers:
            await self.limiter.wait()
            try:
                response = await self.client.request(method, url)
                if response.url.scheme not in {"http", "https"}:
                    return None
                body = response.text[: self.config.max_body_bytes] if method != "HEAD" else ""
                return ResponseData(str(response.url), response.status_code, response.headers, body, list(response.history))
            except (httpx.HTTPError, UnicodeError):
                return None

    async def get(self, url: str) -> ResponseData | None:
        return await self.request("GET", url)

    async def head(self, url: str) -> ResponseData | None:
        return await self.request("HEAD", url)


def header_value(headers: Mapping[str, str], name: str) -> str:
    return headers.get(name, "")
