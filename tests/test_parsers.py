import httpx

from deepsec.modules.cookies import scan as scan_cookies
from deepsec.modules.http_headers import scan as scan_headers
from deepsec.utils.http import ResponseData


def test_headers_case_insensitive():
    response = ResponseData(
        "https://example.test",
        200,
        httpx.Headers(
            {
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=1",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
                "X-Frame-Options": "DENY",
            }
        ),
        "",
        [],
    )
    assert scan_headers(response)[0].severity.value == "PASS"


def test_cookie_parser_detects_missing_samesite():
    response = ResponseData("https://example.test", 200, httpx.Headers({"Set-Cookie": "session=abc; Secure; HttpOnly"}), "", [])
    assert any("SameSite" in finding.title for finding in scan_cookies(response))
