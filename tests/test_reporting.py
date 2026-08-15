from __future__ import annotations
import json
import pytest
from fastapi.testclient import TestClient
from server.app import app
from reporting import BenchmarkReport, AuditSummary, ReportExporter
from privacy.models import PrivacyReport, RedactionItem


@pytest.fixture
def client():
    return TestClient(app)


def test_benchmark_report_and_exporter_zero_leakage():
    report = BenchmarkReport(
        report_id="rep-123",
        scenario_id="easy-sql-review",
        dialect="postgres",
        difficulty="easy",
        overall_score=0.95,
        privacy_report=PrivacyReport(
            secrets_detected=1,
            pii_detected=1,
            redacted_items=1,
            details=[
                RedactionItem(category="secret", token="<PASSWORD_001>", reason="Secret detected"),
            ],
            token_map={"<PASSWORD_001>": "REAL_SECRET_PASS"},
        ),
    )

    exporter = ReportExporter()
    json_str = exporter.export_json(report)
    html_str = exporter.export_html(report)

    # 1. Verify JSON Validity
    data = json.loads(json_str)
    assert data["report_id"] == "rep-123"

    # 2. Verify Zero Leakage (token_map stripped in export)
    assert "token_map" not in data.get("privacy_report", {})
    assert "REAL_SECRET_PASS" not in json_str
    assert "REAL_SECRET_PASS" not in html_str


def test_api_metrics_endpoint(client):
    res = client.get("/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "total_episodes" in data
    assert "total_secrets_detected" in data


def test_api_report_endpoint(client):
    res = client.get("/api/report")
    assert res.status_code == 200
    data = res.json()
    # Handle string or dict json response
    if isinstance(data, str):
        data = json.loads(data)
    assert "scenario_id" in data
    assert "overall_score" in data


def test_dashboard_endpoint(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "SQL Review Environment V2" in res.text
    assert "Privacy Mode" in res.text


def test_no_llm_mode_execution(monkeypatch):
    monkeypatch.setenv("LLM_ENABLED", "false")
    monkeypatch.setenv("NO_LLM_MODE", "true")

    from security import get_model_provider, MockModelProvider
    provider = get_model_provider()

    assert isinstance(provider, MockModelProvider)
    resp = provider.generate("SYS", "USER")
    assert "sql_injection" in resp
