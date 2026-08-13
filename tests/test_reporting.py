import json

from deepsec.models import Finding, Severity
from deepsec.reporting import json_report


def test_json_report_is_machine_readable():
    finding = Finding("Example", Severity.INFO, "Test", "Description", "Evidence", "https://example.test", "Fix")
    payload = json.loads(json_report("https://example.test", [finding]))
    assert payload["findings"][0]["severity"] == "INFO"
    assert payload["score"] == 100
