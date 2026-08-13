from collections import Counter

from .models import Finding, Severity

WEIGHTS = {Severity.CRITICAL: 30, Severity.HIGH: 18, Severity.MEDIUM: 9, Severity.LOW: 3}


def calculate_score(findings: list[Finding]) -> int:
    penalty = sum(WEIGHTS.get(f.severity, 0) for f in findings)
    return max(0, min(100, 100 - penalty))


def severity_counts(findings: list[Finding]) -> Counter[str]:
    counts = Counter(f.severity.value for f in findings)
    return Counter({severity.value: counts.get(severity.value, 0) for severity in Severity})
