from urllib.parse import urlsplit, urlunsplit


def validate_target(value: str) -> str:
    """Allow only absolute HTTP(S) URLs with a host and no user credentials."""
    candidate = value.strip()
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Target must use http:// or https://")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Target must contain a valid host and no credentials")
    if parsed.fragment:
        raise ValueError("Target fragments are not sent to servers")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Target port is invalid") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Target port is invalid")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))


def safe_http_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return parsed.scheme.lower() in {"http", "https"} and bool(parsed.hostname)
    except ValueError:
        return False
