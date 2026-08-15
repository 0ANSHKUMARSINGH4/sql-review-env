from __future__ import annotations

import pytest
from benchmarks.validator import BenchmarkValidator


@pytest.fixture
def validator():
    return BenchmarkValidator()


@pytest.fixture
def valid_scenario():
    return {
        "scenario_id": "v3-postgres-easy-0001",
        "version": "3.0.0",
        "dialect": "postgres",
        "difficulty": "easy",
        "query": "SELECT * FROM users WHERE id = 1;",
        "schema_context": "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100));",
        "is_benign": False,
        "is_adversarial": False,
        "ground_truth": {
            "total_issues_count": 1,
            "issues": [
                {
                    "issue": "unnecessary_columns",
                    "severity": "low",
                    "line": 1,
                    "evidence": "SELECT * projects all columns unnecessarily.",
                    "recommendation": "Specify explicit required columns.",
                    "status": "confirmed",
                    "confidence": 1.0
                }
            ]
        },
        "provenance": {
            "author": "curator_test",
            "created_at": "2026-08-15T00:00:00Z",
            "human_verified": True,
            "source": "synthetic_template"
        }
    }


def test_valid_scenario_passes(validator, valid_scenario):
    res = validator.validate_scenario(valid_scenario)
    assert res.valid is True
    assert len(res.errors) == 0
    assert res.scenario_id == "v3-postgres-easy-0001"


def test_invalid_json_schema_fails(validator, valid_scenario):
    invalid = valid_scenario.copy()
    del invalid["dialect"]  # Required field
    res = validator.validate_scenario(invalid)
    assert res.valid is False
    assert any("Schema validation error" in err for err in res.errors)


def test_invalid_dialect_fails(validator, valid_scenario):
    invalid = valid_scenario.copy()
    invalid["dialect"] = "oracle"  # Unsupported enum value
    res = validator.validate_scenario(invalid)
    assert res.valid is False
    assert any("Schema validation error" in err for err in res.errors)


def test_invalid_issue_category_fails(validator, valid_scenario):
    invalid = valid_scenario.copy()
    invalid["ground_truth"]["issues"][0]["issue"] = "buffer_overflow"
    res = validator.validate_scenario(invalid)
    assert res.valid is False
    assert any("Schema validation error" in err for err in res.errors)


def test_invalid_severity_fails(validator, valid_scenario):
    invalid = valid_scenario.copy()
    invalid["ground_truth"]["issues"][0]["severity"] = "super_high"
    res = validator.validate_scenario(invalid)
    assert res.valid is False
    assert any("Schema validation error" in err for err in res.errors)


def test_invalid_line_number_fails(validator, valid_scenario):
    invalid = valid_scenario.copy()
    invalid["query"] = "SELECT id FROM users;"  # 1 line
    invalid["ground_truth"]["issues"][0]["line"] = 99  # Out of bounds
    res = validator.validate_scenario(invalid)
    assert res.valid is False
    assert any("line 99" in err for err in res.errors)


def test_duplicate_scenario_ids_detected(validator, valid_scenario):
    sc1 = valid_scenario.copy()
    sc2 = valid_scenario.copy()  # Same ID: v3-postgres-easy-0001
    dataset_res = validator.validate_dataset([sc1, sc2])
    assert dataset_res.valid is False
    assert any("Duplicate scenario_id detected" in err for err in dataset_res.global_errors)


def test_duplicate_sql_detected(validator, valid_scenario):
    sc1 = valid_scenario.copy()
    sc2 = valid_scenario.copy()
    sc2["scenario_id"] = "v3-postgres-easy-0002"  # Different ID, same query/dialect
    dataset_res = validator.validate_dataset([sc1, sc2])
    assert dataset_res.valid is False
    assert any("Duplicate exact SQL query collision" in err for err in dataset_res.global_errors)


def test_benign_scenario_with_issues_rejected(validator, valid_scenario):
    invalid = valid_scenario.copy()
    invalid["is_benign"] = True  # Declared benign but contains ground truth issue
    res = validator.validate_scenario(invalid)
    assert res.valid is False
    assert any("Benign scenario" in err for err in res.errors)


def test_ground_truth_count_mismatch_rejected(validator, valid_scenario):
    invalid = valid_scenario.copy()
    invalid["ground_truth"]["total_issues_count"] = 5  # Mismatch (array has 1 item)
    res = validator.validate_scenario(invalid)
    assert res.valid is False
    assert any("Ground truth count mismatch" in err for err in res.errors)


def test_sql_analyzer_disagreement_becomes_conflict(validator):
    # Scenario declares SQL Injection ground truth, but query is an unnecessary columns query
    scenario = {
        "scenario_id": "v3-postgres-medium-9999",
        "version": "3.0.0",
        "dialect": "postgres",
        "difficulty": "medium",
        "query": "SELECT * FROM users WHERE id = 1;",
        "schema_context": "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100));",
        "is_benign": False,
        "is_adversarial": False,
        "ground_truth": {
            "total_issues_count": 1,
            "issues": [
                {
                    "issue": "sql_injection",  # Curator truth
                    "severity": "critical",
                    "line": 1,
                    "evidence": "Curator declared injection.",
                    "recommendation": "Fix injection.",
                    "status": "confirmed",
                    "confidence": 1.0
                }
            ]
        },
        "provenance": {
            "author": "curator_test",
            "created_at": "2026-08-15T00:00:00Z",
            "human_verified": True,
            "source": "curated_github"
        }
    }
    res = validator.validate_scenario(scenario)
    assert res.valid is True  # Valid scenario format
    assert len(res.conflicts) > 0  # Disagreement recorded in conflicts!
    assert any(c["type"] == "unconfirmed_declared_issue" for c in res.conflicts)


def test_conflict_does_not_overwrite_ground_truth(validator):
    scenario = {
        "scenario_id": "v3-postgres-medium-8888",
        "version": "3.0.0",
        "dialect": "postgres",
        "difficulty": "medium",
        "query": "SELECT * FROM users WHERE id = 1;",
        "schema_context": "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100));",
        "is_benign": False,
        "is_adversarial": False,
        "ground_truth": {
            "total_issues_count": 1,
            "issues": [
                {
                    "issue": "sql_injection",
                    "severity": "critical",
                    "line": 1,
                    "evidence": "Original curator evidence.",
                    "recommendation": "Original recommendation.",
                    "status": "confirmed",
                    "confidence": 1.0
                }
            ]
        },
        "provenance": {
            "author": "curator_test",
            "created_at": "2026-08-15T00:00:00Z",
            "human_verified": True,
            "source": "curated_github"
        }
    }
    _ = validator.validate_scenario(scenario)
    # Ground truth remains completely unchanged
    assert scenario["ground_truth"]["issues"][0]["issue"] == "sql_injection"
    assert scenario["ground_truth"]["issues"][0]["evidence"] == "Original curator evidence."


def test_synthetic_secrets_accepted_safely(validator, valid_scenario):
    scenario = valid_scenario.copy()
    scenario["query"] = "SELECT * FROM users WHERE pass = 'TEST_PASSWORD_123' AND key = 'TEST_API_KEY_456';"
    res = validator.validate_scenario(scenario)
    assert res.valid is True
    assert any("Synthetic test secret marker detected" in w for w in res.warnings)


def test_actual_secret_like_literals_trigger_privacy_error(validator, valid_scenario):
    scenario = valid_scenario.copy()
    # Real-looking AWS key format
    scenario["query"] = "SELECT * FROM users WHERE aws_key = 'AKIAIOSFODNN7EXAMPLE';"
    res = validator.validate_scenario(scenario)
    assert res.valid is False
    assert any("sensitive credential detected" in err for err in res.errors)
