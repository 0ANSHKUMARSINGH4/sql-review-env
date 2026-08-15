from __future__ import annotations

import json
from pathlib import Path
import pytest
from benchmarks.validator import BenchmarkValidator
from benchmarks.v3_validation import DATASET_PATH, compute_canonical_dataset_hash


EXPECTED_V3_DATASET_SHA256 = "5342c666ce1e774b443ccd6446adecc9d2135d008237681027d393269b295dde"


@pytest.fixture
def v3_data():
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_v3_dataset_exactly_300_records(v3_data):
    assert isinstance(v3_data, list)
    assert len(v3_data) == 300


def test_v3_dataset_dialect_distribution(v3_data):
    dialects = [sc["dialect"] for sc in v3_data]
    assert dialects.count("postgres") == 100
    assert dialects.count("mysql") == 100
    assert dialects.count("sqlite") == 100


def test_v3_dataset_difficulty_distribution(v3_data):
    difficulties = [sc["difficulty"] for sc in v3_data]
    assert difficulties.count("easy") >= 80
    assert difficulties.count("medium") >= 80
    assert difficulties.count("hard") >= 80


def test_v3_dataset_unique_scenario_ids(v3_data):
    ids = [sc["scenario_id"] for sc in v3_data]
    assert len(ids) == 300
    assert len(set(ids)) == 300


def test_v3_dataset_no_exact_query_collisions(v3_data):
    seen = set()
    for sc in v3_data:
        key = f"{sc['dialect']}:{sc['query'].strip()}"
        assert key not in seen, f"Duplicate query collision detected for scenario {sc['scenario_id']}: {key}"
        seen.add(key)


def test_v3_dataset_schema_validity(v3_data):
    validator = BenchmarkValidator()
    dataset_res = validator.validate_dataset(v3_data)
    assert dataset_res.valid is True
    assert dataset_res.invalid_scenarios == 0
    assert len(dataset_res.global_errors) == 0


def test_v3_dataset_dialects_parse(v3_data):
    validator = BenchmarkValidator()
    for sc in v3_data:
        parse_res = validator.ast_parser.parse(sc["query"], dialect=sc["dialect"])
        assert parse_res.parse_success is True, f"Failed to parse query for scenario {sc['scenario_id']}: {parse_res.error_message}"


def test_v3_dataset_issue_category_coverage(v3_data):
    found_categories = set()
    for sc in v3_data:
        for issue_item in sc.get("ground_truth", {}).get("issues", []):
            found_categories.add(issue_item["issue"])

    expected = {"sql_injection", "unnecessary_columns", "inefficient_join", "missing_index", "n_plus_one"}
    assert expected.issubset(found_categories)


def test_v3_dataset_benign_correctness(v3_data):
    benign_scenarios = [sc for sc in v3_data if sc.get("is_benign")]
    assert len(benign_scenarios) >= 60
    for sc in benign_scenarios:
        gt = sc.get("ground_truth", {})
        assert gt.get("total_issues_count") == 0
        assert len(gt.get("issues", [])) == 0


def test_v3_dataset_n_plus_one_contextual_metadata(v3_data):
    n_plus_one_scenarios = []
    for sc in v3_data:
        issues = [i["issue"] for i in sc.get("ground_truth", {}).get("issues", [])]
        if "n_plus_one" in issues:
            n_plus_one_scenarios.append(sc)

    assert len(n_plus_one_scenarios) > 0
    for sc in n_plus_one_scenarios:
        combined_text = (sc.get("query", "") + "\n" + sc.get("schema_context", "")).lower()
        assert any(term in combined_text for term in ["loop", "orm", "repeat", "trace", "iteration"])


def test_v3_dataset_adversarial_coverage(v3_data):
    adversarial_scenarios = [sc for sc in v3_data if sc.get("is_adversarial")]
    assert len(adversarial_scenarios) >= 50


def test_v3_dataset_privacy_safety(v3_data):
    validator = BenchmarkValidator()
    for sc in v3_data:
        res = validator.validate_scenario(sc)
        assert not any("sensitive credential detected" in err for err in res.errors)


def test_v3_dataset_deterministic_canonical_hash(v3_data):
    hash_val = compute_canonical_dataset_hash(v3_data)
    assert hash_val == EXPECTED_V3_DATASET_SHA256
