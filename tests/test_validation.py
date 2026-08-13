import pytest

from deepsec.utils.validation import validate_target


@pytest.mark.parametrize("url", ["https://example.com", "http://localhost:8080", "https://192.168.1.20"])
def test_valid_targets(url):
    assert validate_target(url).startswith(("http://", "https://"))


@pytest.mark.parametrize("url", ["ftp://example.com", "example.com", "https://user:pass@example.com", "https://example.com/#frag"])
def test_invalid_targets(url):
    with pytest.raises(ValueError):
        validate_target(url)
