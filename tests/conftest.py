import httpx
import pytest


@pytest.fixture
def response_data():
    from deepsec.utils.http import ResponseData

    return ResponseData("https://example.test/", 200, httpx.Headers(), "<html></html>", [])
