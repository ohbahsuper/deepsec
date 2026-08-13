from deepsec.models import Finding, Severity
from deepsec.scoring import calculate_score


def test_score_weights_and_floor():
    finding = Finding("x", Severity.HIGH, "x", "x", "x", "https://example.com", "x")
    assert calculate_score([finding]) == 82
    assert calculate_score([finding] * 10) == 0
