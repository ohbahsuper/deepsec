import httpx
import pytest

from deepsec.config import ScanConfig
from deepsec.utils.http import SafeHttpClient


@pytest.mark.asyncio
async def test_network_timeout_is_handled():
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("mock timeout", request=request)

    client = SafeHttpClient(ScanConfig(requests_per_second=10), httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert await client.get("https://example.test") is None
    await client.close()
