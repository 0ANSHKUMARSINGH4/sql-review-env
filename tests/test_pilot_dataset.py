from __future__ import annotations

import json
from pathlib import Path
import pytest
from benchmarks.validator import BenchmarkValidator
from benchmarks.pilot_validation import PILOT_DATASET_PATH, compute_canonical_dataset_hash


EXPECTED_PILOT_SHA256 = "fd6b79ea9af65f21dd3e12b5236a3a4e440308fa16d7fd2046206097ecdcb07a"


@pytest.fixture
def pilot_data():
    with open(PILOT_DATASET_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_pilot_dataset_loads_correctly(pilot_data):
    assert isinstance(pilot_data, list)
    assert len(pilot_data) > 0


def test_pilot_dataset_exactly_30_scenarios(pilot_data):
    assert len(pilot_data) == 30


def test_pilot_dataset_10_per_dialect(pilot_data):
    dialects = [sc["dialect"] for sc in pilot_data]
    assert dialects.count("postgres") == 10
    assert dialects.count("mysql") == 10
    assert dialects.count("sqlite") == 10


def test_pilot_dataset_unique_scenario_ids(pilot_data):
    ids = [sc["scenario_id"] for sc in pilot_data]
    assert len(ids) == 30
    assert len(set(ids)) == 30


def test_pilot_dataset_schema_validity(pilot_data):
    validator = BenchmarkValidator()
    dataset_res = validator.validate_dataset(pilot_data)
    assert dataset_res.valid is True
    assert dataset_res.invalid_scenarios == 0
    assert len(dataset_res.global_errors) == 0


def test_pilot_dataset_dialects_parse(pilot_data):
    validator = BenchmarkValidator()
    for sc in pilot_data:
        parse_res = validator.ast_parser.parse(sc["query"], dialect=sc["dialect"])
        assert parse_res.parse_success is True, f"Failed to parse query for scenario {sc['scenario_id']}: {parse_res.error_message}"


def test_pilot_dataset_benign_records_zero_issues(pilot_data):
    benign_scenarios = [sc for sc in pilot_data if sc.get("is_benign")]
    assert len(benign_scenarios) >= 5
    for sc in benign_scenarios:
        gt = sc.get("ground_truth", {})
        assert gt.get("total_issues_count") == 0
        assert len(gt.get("issues", [])) == 0


def test_pilot_dataset_all_issue_categories_represented(pilot_data):
    found_categories = set()
    for sc in pilot_data:
        for issue_item in sc.get("ground_truth", {}).get("issues", []):
            found_categories.add(issue_item["issue"])

    expected = {"sql_injection", "unnecessary_columns", "inefficient_join", "missing_index", "n_plus_one"}
    assert expected.issubset(found_categories)


def test_pilot_dataset_n_plus_one_contextual_metadata(pilot_data):
    n_plus_one_scenarios = []
    for sc in pilot_data:
        issues = [i["issue"] for i in sc.get("ground_truth", {}).get("issues", [])]
        if "n_plus_one" in issues:
            n_plus_one_scenarios.append(sc)

    assert len(n_plus_one_scenarios) > 0
    for sc in n_plus_one_scenarios:
        combined_text = (sc.get("query", "") + "\n" + sc.get("schema_context", "")).lower()
        assert any(term in combined_text for term in ["loop", "orm", "repeat", "trace", "iteration"])


def test_pilot_dataset_no_real_secrets(pilot_data):
    validator = BenchmarkValidator()
    for sc in pilot_data:
        res = validator.validate_scenario(sc)
        # Should not have any real credential errors
        assert not any("sensitive credential detected" in err for err in res.errors)


def test_pilot_dataset_canonical_hash_stable(pilot_data):
    hash_val = compute_canonical_dataset_hash(pilot_data)
    assert hash_val == EXPECTED_PILOT_SHA256
