from __future__ import annotations

import json
from pathlib import Path
import pytest
from benchmarks.runner import V3BenchmarkRunner, BenchmarkConfig, DEFAULT_DATASET_PATH, DEFAULT_OUTPUT_DIR
from privacy import PrivacyGateway
from security import MockModelProvider


EXPECTED_SHA256 = "5342c666ce1e774b443ccd6446adecc9d2135d008237681027d393269b295dde"


def test_invalid_dataset_fails_closed(tmp_path):
    invalid_file = tmp_path / "invalid_dataset.json"
    invalid_file.write_text("[{\"invalid\": \"schema\"}]", encoding="utf-8")
    
    config = BenchmarkConfig(dataset_path=invalid_file, provider="mock", output_dir=tmp_path)
    runner = V3BenchmarkRunner(config)
    
    with pytest.raises(ValueError, match="Benchmark dataset validation failed closed"):
        runner.execute()


def test_nonexistent_dataset_fails_closed(tmp_path):
    nonexistent = tmp_path / "does_not_exist.json"
    config = BenchmarkConfig(dataset_path=nonexistent, provider="mock", output_dir=tmp_path)
    runner = V3BenchmarkRunner(config)
    
    with pytest.raises(FileNotFoundError, match="Benchmark dataset file not found"):
        runner.execute()


def test_declared_ground_truth_never_mutated(tmp_path):
    config = BenchmarkConfig(dataset_path=DEFAULT_DATASET_PATH, provider="mock", max_scenarios=5, output_dir=tmp_path)
    runner = V3BenchmarkRunner(config)
    
    with open(DEFAULT_DATASET_PATH, "r", encoding="utf-8") as f:
        original_dataset = json.load(f)

    original_gt_sample = json.dumps(original_dataset[0]["ground_truth"], sort_keys=True)
    
    _ = runner.execute()
    
    with open(DEFAULT_DATASET_PATH, "r", encoding="utf-8") as f:
        after_dataset = json.load(f)

    after_gt_sample = json.dumps(after_dataset[0]["ground_truth"], sort_keys=True)
    assert original_gt_sample == after_gt_sample


def test_deterministic_scenario_ordering(tmp_path):
    config1 = BenchmarkConfig(dataset_path=DEFAULT_DATASET_PATH, provider="mock", seed=42, max_scenarios=10, output_dir=tmp_path)
    runner1 = V3BenchmarkRunner(config1)
    dataset1, _ = runner1.load_and_validate_dataset()
    filtered1 = runner1.filter_and_sort_scenarios(dataset1)

    config2 = BenchmarkConfig(dataset_path=DEFAULT_DATASET_PATH, provider="mock", seed=42, max_scenarios=10, output_dir=tmp_path)
    runner2 = V3BenchmarkRunner(config2)
    dataset2, _ = runner2.load_and_validate_dataset()
    filtered2 = runner2.filter_and_sort_scenarios(dataset2)

    ids1 = [s["scenario_id"] for s in filtered1]
    ids2 = [s["scenario_id"] for s in filtered2]
    assert ids1 == ids2


def test_dataset_hash_recorded_correctly(tmp_path):
    config = BenchmarkConfig(dataset_path=DEFAULT_DATASET_PATH, provider="mock", max_scenarios=5, output_dir=tmp_path)
    runner = V3BenchmarkRunner(config)
    run_res = runner.execute()
    assert run_res.dataset_canonical_sha256 == EXPECTED_SHA256


def test_config_recorded_correctly(tmp_path):
    config = BenchmarkConfig(
        dataset_path=DEFAULT_DATASET_PATH,
        provider="mock",
        model_name="MockModelProvider",
        seed=123,
        max_scenarios=5,
        dialect="postgres",
        output_dir=tmp_path,
        run_id="test-run-123",
    )
    runner = V3BenchmarkRunner(config)
    run_res = runner.execute()
    assert run_res.run_id == "test-run-123"
    assert run_res.config["seed"] == 123
    assert run_res.config["dialect"] == "postgres"
    assert run_res.config["provider"] == "mock"


def test_filters_work_correctly(tmp_path):
    config = BenchmarkConfig(
        dataset_path=DEFAULT_DATASET_PATH,
        provider="mock",
        dialect="mysql",
        difficulty="hard",
        max_scenarios=5,
        output_dir=tmp_path,
    )
    runner = V3BenchmarkRunner(config)
    run_res = runner.execute()
    assert len(run_res.scenario_results) == 5
    for sc_res in run_res.scenario_results:
        assert sc_res.dialect == "mysql"
        assert sc_res.difficulty == "hard"


def test_failed_model_calls_represented_explicitly(tmp_path):
    class ErrorModelProvider(MockModelProvider):
        def generate(self, system_prompt: str, user_prompt: str) -> str:
            return "INVALID JSON OUTPUT {{{{"

    config = BenchmarkConfig(dataset_path=DEFAULT_DATASET_PATH, provider="mock", max_scenarios=2, output_dir=tmp_path)
    runner = V3BenchmarkRunner(config)
    runner.provider_client = ErrorModelProvider()
    
    run_res = runner.execute()
    assert run_res.metrics.failed_scenarios == 2
    for sc_res in run_res.scenario_results:
        assert sc_res.status == "INVALID_OUTPUT"
        assert sc_res.evaluation["normalized_score"] == 0.01


def test_mock_mode_is_deterministic(tmp_path):
    config1 = BenchmarkConfig(dataset_path=DEFAULT_DATASET_PATH, provider="mock", seed=42, max_scenarios=10, output_dir=tmp_path)
    run1 = V3BenchmarkRunner(config1).execute()

    config2 = BenchmarkConfig(dataset_path=DEFAULT_DATASET_PATH, provider="mock", seed=42, max_scenarios=10, output_dir=tmp_path)
    run2 = V3BenchmarkRunner(config2).execute()

    assert run1.metrics.macro_f1 == run2.metrics.macro_f1
    assert run1.metrics.total_tp == run2.metrics.total_tp


def test_privacy_boundary_remains_intact(tmp_path):
    config = BenchmarkConfig(dataset_path=DEFAULT_DATASET_PATH, provider="mock", max_scenarios=10, output_dir=tmp_path)
    runner = V3BenchmarkRunner(config)
    run_res = runner.execute()

    out_file = tmp_path / f"{run_res.run_id}.json"
    assert out_file.exists()
    out_text = out_file.read_text(encoding="utf-8")

    assert "token_map" not in out_text
    assert "TEST_PASSWORD_123" not in out_text
    assert "TEST_API_KEY_456" not in out_text


def test_persisted_result_json_valid_schema(tmp_path):
    config = BenchmarkConfig(dataset_path=DEFAULT_DATASET_PATH, provider="mock", max_scenarios=3, output_dir=tmp_path, run_id="schema-test-run")
    runner = V3BenchmarkRunner(config)
    _ = runner.execute()

    out_file = tmp_path / "schema-test-run.json"
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["run_id"] == "schema-test-run"
    assert "metrics" in data
    assert "scenario_results" in data
    assert len(data["scenario_results"]) == 3
