from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from server.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_v4_api_benchmark_summary(client):
    res = client.get("/api/benchmark/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["total_scenarios"] == 300
    assert "postgres" in data["dialects"]
    assert "baseline_mock_metrics" in data
    assert data["baseline_mock_metrics"]["macro_f1"] > 0


def test_v4_api_benchmark_scenarios_filtering(client):
    res = client.get("/api/benchmark/scenarios?dialect=postgres&difficulty=easy&limit=10")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] > 0
    assert len(data["scenarios"]) <= 10
    for sc in data["scenarios"]:
        assert sc["dialect"] == "postgres"
        assert sc["difficulty"] == "easy"


def test_v4_api_ground_truth_isolation(client):
    # Default public view must NOT expose ground_truth
    res_public = client.get("/api/benchmark/scenarios?limit=5")
    assert res_public.status_code == 200
    data_pub = res_public.json()
    for sc in data_pub["scenarios"]:
        assert "ground_truth" not in sc

    # Explicit audit view includes ground_truth
    res_audit = client.get("/api/benchmark/scenarios?include_ground_truth=true&limit=5")
    assert res_audit.status_code == 200
    data_audit = res_audit.json()
    for sc in data_audit["scenarios"]:
        assert "ground_truth" in sc


def test_v4_api_benchmark_scenario_detail(client):
    res = client.get("/api/benchmark/scenarios/v3-pg-0001")
    assert res.status_code == 200
    data = res.json()
    assert data["scenario_id"] == "v3-pg-0001"
    assert data["dialect"] == "postgres"


def test_v4_api_sql_analyze_valid(client):
    payload = {
        "query": "SELECT * FROM users u, orders o WHERE u.id = '` + user_id + `' AND u.status = 'active';",
        "dialect": "postgres",
        "schema_context": "CREATE TABLE users (id VARCHAR(50), status VARCHAR(50)); CREATE TABLE orders (id INT);",
    }
    res = client.post("/api/sql/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["parse_success"] is True
    assert len(data["findings"]) > 0
    issues = [f["issue"] for f in data["findings"]]
    assert "sql_injection" in issues or "unnecessary_columns" in issues


def test_v4_api_sql_analyze_malformed(client):
    payload = {
        "query": "SELECT FROM WHERE !!!",
        "dialect": "postgres",
    }
    res = client.post("/api/sql/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["parse_success"] is False
    assert data["parse_error"] is not None


def test_v4_api_sql_explain_allowed(client):
    payload = {
        "query": "SELECT a.id, b.event_name FROM tokens a JOIN events b ON a.id = b.token_id WHERE a.id = 5;",
        "schema_context": "CREATE TABLE tokens (id INT PRIMARY KEY); CREATE TABLE events (id INT, token_id INT, event_name TEXT);",
    }
    res = client.post("/api/sql/explain", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["allowed"] is True
    assert data["status"] in ("ok", "success", "error")


def test_v4_api_sql_explain_policy_rejection(client):
    payload = {
        "query": "DROP TABLE users;",
    }
    res = client.post("/api/sql/explain", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["allowed"] is False
    assert data["status"] == "policy_rejected"
    assert "Destructive SQL operation" in data["policy_reason"] or "DROP" in data["policy_reason"].upper()


def test_v4_api_benchmark_results_list(client):
    res = client.get("/api/benchmark/results")
    assert res.status_code == 200
    data = res.json()
    assert "runs" in data
    assert len(data["runs"]) > 0


def test_v4_api_benchmark_result_detail(client):
    res = client.get("/api/benchmark/results/run-v3-mock-300")
    assert res.status_code == 200
    data = res.json()
    assert data["run_id"] == "run-v3-mock-300"
    assert data["dataset_scenario_count"] == 300
    assert "metrics" in data


def test_v4_api_openenv_backwards_compatibility(client):
    # Health check
    res_h = client.get("/health")
    assert res_h.status_code == 200
    assert res_h.json()["status"] == "healthy"

    # HTML Platform UI
    res_ui = client.get("/")
    assert res_ui.status_code == 200
    assert "SQL Review Environment" in res_ui.text

    # OpenEnv state
    res_st = client.get("/state")
    assert res_st.status_code == 200
