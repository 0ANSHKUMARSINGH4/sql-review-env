from __future__ import annotations

import os
import sys
import json
import time
import random
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict

from benchmarks.validator import BenchmarkValidator
from benchmarks.v3_validation import compute_canonical_dataset_hash
from privacy import PrivacyGateway
from security import PromptIsolationManager, ModelProvider, MockModelProvider, OpenAIModelProvider, parse_model_findings_json
from grading import EvidenceBasedEvaluator
from models import SQLReviewAction
from sql_analysis.analyzer import GroundTruthIssue


DEFAULT_DATASET_PATH = Path(__file__).parent / "v3_dataset.json"
DEFAULT_OUTPUT_DIR = Path(__file__).parent / "results"


@dataclass
class BenchmarkConfig:
    dataset_path: Path = DEFAULT_DATASET_PATH
    provider: str = "mock"  # "mock" or "openai"
    model_name: str = "MockModelProvider"
    seed: int = 42
    max_scenarios: Optional[int] = None
    dialect: Optional[str] = None
    difficulty: Optional[str] = None
    issue_category: Optional[str] = None
    output_dir: Path = DEFAULT_OUTPUT_DIR
    no_llm_mode: bool = True
    run_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_path": str(self.dataset_path),
            "provider": self.provider,
            "model_name": self.model_name,
            "seed": self.seed,
            "max_scenarios": self.max_scenarios,
            "dialect": self.dialect,
            "difficulty": self.difficulty,
            "issue_category": self.issue_category,
            "output_dir": str(self.output_dir),
            "no_llm_mode": self.no_llm_mode,
            "run_id": self.run_id,
        }


@dataclass
class ScenarioResult:
    scenario_id: str
    dialect: str
    difficulty: str
    is_benign: bool
    is_adversarial: bool
    declared_issues: List[str]
    status: str  # "SUCCESS", "MODEL_ERROR", "INVALID_OUTPUT", "TIMEOUT", "EVALUATION_ERROR"
    findings: List[Dict[str, Any]]
    evaluation: Dict[str, Any]
    execution_time_ms: float
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AggregateMetrics:
    total_scenarios: int
    executed_scenarios: int
    successful_scenarios: int
    failed_scenarios: int
    macro_precision: float
    macro_recall: float
    macro_f1: float
    micro_precision: float
    micro_recall: float
    micro_f1: float
    location_accuracy: float
    fix_accuracy: float
    total_tp: int
    total_fp: int
    total_fn: int
    total_duplicates: int
    by_dialect: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    by_difficulty: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    by_issue_category: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    by_benign_status: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkRun:
    run_id: str
    timestamp: str
    runner_version: str
    git_commit: str
    dataset_canonical_sha256: str
    dataset_scenario_count: int
    config: Dict[str, Any]
    metrics: AggregateMetrics
    scenario_results: List[ScenarioResult]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "runner_version": self.runner_version,
            "git_commit": self.git_commit,
            "dataset_canonical_sha256": self.dataset_canonical_sha256,
            "dataset_scenario_count": self.dataset_scenario_count,
            "config": self.config,
            "metrics": self.metrics.to_dict(),
            "scenario_results": [sr.to_dict() for sr in self.scenario_results],
        }


class V3BenchmarkRunner:
    """
    Fully reproducible evaluation runner for SQL Review Environment V3.
    Executes models against the independent V3 benchmark dataset and computes
    precision, recall, F1, location accuracy, and fix accuracy metrics.
    """

    RUNNER_VERSION = "1.0.0"

    def __init__(self, config: Optional[BenchmarkConfig] = None):
        self.config = config or BenchmarkConfig()
        self.privacy_gateway = PrivacyGateway()
        self.prompt_manager = PromptIsolationManager()
        self.evaluator = EvidenceBasedEvaluator()
        schema_file = self.config.dataset_path.parent / "v3_dataset.schema.json"
        if not schema_file.exists():
            schema_file = Path(__file__).parent / "v3_dataset.schema.json"
        self.validator = BenchmarkValidator(schema_file=schema_file)
        self.provider_client = self._init_provider()

    def _init_provider(self) -> ModelProvider:
        if self.config.provider.lower() == "mock" or self.config.no_llm_mode:
            return MockModelProvider()
        elif self.config.provider.lower() == "openai":
            return OpenAIModelProvider(model_name=self.config.model_name)
        else:
            raise ValueError(f"Unsupported model provider: '{self.config.provider}'. Must be 'mock' or 'openai'.")

    def load_and_validate_dataset(self) -> Tuple[List[Dict[str, Any]], str]:
        """
        Loads the benchmark dataset and validates it using BenchmarkValidator.
        Fails closed if the dataset structure is invalid.
        """
        if not self.config.dataset_path.exists():
            raise FileNotFoundError(f"Benchmark dataset file not found at: {self.config.dataset_path}")

        with open(self.config.dataset_path, "r", encoding="utf-8") as f:
            dataset = json.load(f)

        dataset_res = self.validator.validate_dataset(dataset)
        if not dataset_res.valid:
            error_msg = "; ".join(dataset_res.global_errors)
            raise ValueError(f"Benchmark dataset validation failed closed. Errors: {error_msg}")

        canonical_hash = compute_canonical_dataset_hash(dataset)
        return dataset, canonical_hash

    def filter_and_sort_scenarios(self, dataset: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filters scenarios by configuration options and orders them deterministically using seed.
        """
        filtered = list(dataset)

        if self.config.dialect:
            target_d = self.config.dialect.lower().strip()
            filtered = [s for s in filtered if s.get("dialect", "").lower() == target_d]

        if self.config.difficulty:
            target_diff = self.config.difficulty.lower().strip()
            filtered = [s for s in filtered if s.get("difficulty", "").lower() == target_diff]

        if self.config.issue_category:
            target_cat = self.config.issue_category.lower().strip()
            filtered = [
                s for s in filtered
                if any(i.get("issue", "").lower() == target_cat for i in s.get("ground_truth", {}).get("issues", []))
            ]

        # Deterministic sorting using seed
        # First sort by scenario_id for stability, then apply seeded shuffle
        filtered.sort(key=lambda s: s.get("scenario_id", ""))
        rng = random.Random(self.config.seed)
        rng.shuffle(filtered)

        if self.config.max_scenarios and self.config.max_scenarios > 0:
            filtered = filtered[: self.config.max_scenarios]

        return filtered

    def run_scenario(self, scenario: Dict[str, Any], provider_client: ModelProvider) -> ScenarioResult:
        """
        Executes a single benchmark scenario through the Privacy Gateway, Prompt Isolation,
        Model Provider, Pydantic Validator, and Evidence-Based Evaluator.
        """
        sc_id = scenario.get("scenario_id", "unknown")
        dialect = scenario.get("dialect", "sqlite")
        difficulty = scenario.get("difficulty", "easy")
        is_benign = scenario.get("is_benign", False)
        is_adversarial = scenario.get("is_adversarial", False)
        
        raw_query = scenario.get("query", "")
        raw_schema = scenario.get("schema_context", "")

        gt_data = scenario.get("ground_truth", {})
        gt_issues_raw = gt_data.get("issues", []) if isinstance(gt_data, dict) else []
        declared_categories = [i.get("issue") for i in gt_issues_raw if isinstance(i, dict)]

        # Reconstruct GroundTruthIssue domain objects for evaluator
        target_gt_objects: List[GroundTruthIssue] = []
        for item in gt_issues_raw:
            if isinstance(item, dict):
                target_gt_objects.append(
                    GroundTruthIssue(
                        issue=item.get("issue", ""),
                        severity=item.get("severity", "medium"),
                        line=item.get("line", 1),
                        evidence=item.get("evidence", ""),
                        status=item.get("status", "confirmed"),
                        recommendation=item.get("recommendation", ""),
                    )
                )

        t0 = time.perf_counter()

        try:
            # 1. Privacy Boundary Pass
            sanitized_ctx = self.privacy_gateway.sanitize_context(raw_query, raw_schema)
            
            # 2. Prompt Isolation Pass
            sys_prompt, user_prompt, _ = self.prompt_manager.build_isolated_prompt(
                sanitized_query=sanitized_ctx.query,
                sanitized_schema=sanitized_ctx.schema_context,
            )

            # 3. Model Provider Generation
            resp_text = provider_client.generate(sys_prompt, user_prompt)
            t1 = time.perf_counter()
            exec_time_ms = round((t1 - t0) * 1000, 2)

            if not resp_text:
                # Empty response failure
                return ScenarioResult(
                    scenario_id=sc_id,
                    dialect=dialect,
                    difficulty=difficulty,
                    is_benign=is_benign,
                    is_adversarial=is_adversarial,
                    declared_issues=declared_categories,
                    status="MODEL_ERROR",
                    findings=[],
                    evaluation={
                        "normalized_score": 0.01,
                        "precision": 0.0,
                        "recall": 0.0,
                        "f1": 0.0,
                        "location_accuracy": 0.0,
                        "fix_accuracy": 0.0,
                        "tp": 0,
                        "fp": 0,
                        "fn": len(target_gt_objects),
                        "duplicates": 0,
                    },
                    execution_time_ms=exec_time_ms,
                    error_message="Model provider returned empty or null response text.",
                )

            # 4. Structured Finding Output Parsing
            findings, parse_error = parse_model_findings_json(resp_text)
            if parse_error or findings is None:
                return ScenarioResult(
                    scenario_id=sc_id,
                    dialect=dialect,
                    difficulty=difficulty,
                    is_benign=is_benign,
                    is_adversarial=is_adversarial,
                    declared_issues=declared_categories,
                    status="INVALID_OUTPUT",
                    findings=[],
                    evaluation={
                        "normalized_score": 0.01,
                        "precision": 0.0,
                        "recall": 0.0,
                        "f1": 0.0,
                        "location_accuracy": 0.0,
                        "fix_accuracy": 0.0,
                        "tp": 0,
                        "fp": 0,
                        "fn": len(target_gt_objects),
                        "duplicates": 0,
                    },
                    execution_time_ms=exec_time_ms,
                    error_message=f"Model output JSON parsing failed: {parse_error}",
                )

            # 5. Evidence-Based Evaluator Pass
            findings_dicts = [f.model_dump() for f in findings]
            action = SQLReviewAction(findings=findings)
            eval_res = self.evaluator.evaluate(action, target_gt_objects)

            eval_dict = {
                "normalized_score": eval_res.normalized_score,
                "precision": eval_res.precision,
                "recall": eval_res.recall,
                "f1": eval_res.f1,
                "location_accuracy": eval_res.location_accuracy,
                "fix_accuracy": eval_res.fix_accuracy,
                "tp": eval_res.true_positives,
                "fp": eval_res.false_positives,
                "fn": eval_res.false_negatives,
                "duplicates": eval_res.duplicates,
            }

            return ScenarioResult(
                scenario_id=sc_id,
                dialect=dialect,
                difficulty=difficulty,
                is_benign=is_benign,
                is_adversarial=is_adversarial,
                declared_issues=declared_categories,
                status="SUCCESS",
                findings=findings_dicts,
                evaluation=eval_dict,
                execution_time_ms=exec_time_ms,
                error_message=None,
            )

        except Exception as exc:
            t1 = time.perf_counter()
            exec_time_ms = round((t1 - t0) * 1000, 2)
            return ScenarioResult(
                scenario_id=sc_id,
                dialect=dialect,
                difficulty=difficulty,
                is_benign=is_benign,
                is_adversarial=is_adversarial,
                declared_issues=declared_categories,
                status="EVALUATION_ERROR",
                findings=[],
                evaluation={
                    "normalized_score": 0.01,
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1": 0.0,
                    "location_accuracy": 0.0,
                    "fix_accuracy": 0.0,
                    "tp": 0,
                    "fp": 0,
                    "fn": len(target_gt_objects),
                    "duplicates": 0,
                },
                execution_time_ms=exec_time_ms,
                error_message=f"Runtime error during scenario evaluation: {str(exc)}",
            )

    def calculate_aggregate_metrics(self, results: List[ScenarioResult], total_dataset_scenarios: int) -> AggregateMetrics:
        """
        Calculates macro and micro aggregate evaluation metrics across all scenario execution results.
        """
        executed = len(results)
        successful = sum(1 for r in results if r.status == "SUCCESS")
        failed = executed - successful

        total_tp = sum(r.evaluation.get("tp", 0) for r in results)
        total_fp = sum(r.evaluation.get("fp", 0) for r in results)
        total_fn = sum(r.evaluation.get("fn", 0) for r in results)
        total_duplicates = sum(r.evaluation.get("duplicates", 0) for r in results)

        # Micro metrics
        micro_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        micro_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        micro_f1 = (2 * micro_precision * micro_recall) / (micro_precision + micro_recall) if (micro_precision + micro_recall) > 0 else 0.0

        # Macro metrics (averaging over scenarios)
        macro_p_sum = sum(r.evaluation.get("precision", 0.0) for r in results)
        macro_r_sum = sum(r.evaluation.get("recall", 0.0) for r in results)
        macro_f1_sum = sum(r.evaluation.get("f1", 0.0) for r in results)
        loc_acc_sum = sum(r.evaluation.get("location_accuracy", 0.0) for r in results)
        fix_acc_sum = sum(r.evaluation.get("fix_accuracy", 0.0) for r in results)

        denom = max(1, executed)
        macro_precision = round(macro_p_sum / denom, 4)
        macro_recall = round(macro_r_sum / denom, 4)
        macro_f1 = round(macro_f1_sum / denom, 4)
        location_accuracy = round(loc_acc_sum / denom, 4)
        fix_accuracy = round(fix_acc_sum / denom, 4)

        # Sub-group breakdowns
        def calc_group_stats(group_results: List[ScenarioResult]) -> Dict[str, Any]:
            g_count = len(group_results)
            if g_count == 0:
                return {"count": 0, "macro_f1": 0.0, "precision": 0.0, "recall": 0.0}
            g_tp = sum(r.evaluation.get("tp", 0) for r in group_results)
            g_fp = sum(r.evaluation.get("fp", 0) for r in group_results)
            g_fn = sum(r.evaluation.get("fn", 0) for r in group_results)
            g_p = g_tp / (g_tp + g_fp) if (g_tp + g_fp) > 0 else 0.0
            g_r = g_tp / (g_tp + g_fn) if (g_tp + g_fn) > 0 else 0.0
            g_f1 = (2 * g_p * g_r) / (g_p + g_r) if (g_p + g_r) > 0 else 0.0
            return {
                "count": g_count,
                "precision": round(g_p, 4),
                "recall": round(g_r, 4),
                "macro_f1": round(g_f1, 4),
            }

        by_dialect = {
            d: calc_group_stats([r for r in results if r.dialect == d])
            for d in ["postgres", "mysql", "sqlite"]
        }
        by_difficulty = {
            diff: calc_group_stats([r for r in results if r.difficulty == diff])
            for diff in ["easy", "medium", "hard", "extreme"]
        }
        by_benign_status = {
            "benign": calc_group_stats([r for r in results if r.is_benign]),
            "non_benign": calc_group_stats([r for r in results if not r.is_benign]),
            "adversarial": calc_group_stats([r for r in results if r.is_adversarial]),
        }

        # Issue category breakdown
        all_categories = ["sql_injection", "unnecessary_columns", "missing_index", "inefficient_join", "n_plus_one"]
        by_category = {
            cat: calc_group_stats([r for r in results if cat in r.declared_issues])
            for cat in all_categories
        }

        return AggregateMetrics(
            total_scenarios=total_dataset_scenarios,
            executed_scenarios=executed,
            successful_scenarios=successful,
            failed_scenarios=failed,
            macro_precision=macro_precision,
            macro_recall=macro_recall,
            macro_f1=macro_f1,
            micro_precision=round(micro_precision, 4),
            micro_recall=round(micro_recall, 4),
            micro_f1=round(micro_f1, 4),
            location_accuracy=location_accuracy,
            fix_accuracy=fix_accuracy,
            total_tp=total_tp,
            total_fp=total_fp,
            total_fn=total_fn,
            total_duplicates=total_duplicates,
            by_dialect=by_dialect,
            by_difficulty=by_difficulty,
            by_issue_category=by_category,
            by_benign_status=by_benign_status,
        )

    def execute(self) -> BenchmarkRun:
        """
        Runs the complete benchmark evaluation pipeline and returns a persisted BenchmarkRun artifact.
        """
        # Load and validate dataset
        raw_dataset, canonical_hash = self.load_and_validate_dataset()
        target_scenarios = self.filter_and_sort_scenarios(raw_dataset)

        run_id = self.config.run_id or f"run-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        timestamp_str = datetime.now(timezone.utc).isoformat()

        # Execute scenarios
        scenario_results: List[ScenarioResult] = []
        for sc in target_scenarios:
            res = self.run_scenario(sc, self.provider_client)
            scenario_results.append(res)

        # Calculate aggregate metrics
        metrics = self.calculate_aggregate_metrics(scenario_results, len(raw_dataset))

        run_obj = BenchmarkRun(
            run_id=run_id,
            timestamp=timestamp_str,
            runner_version=self.RUNNER_VERSION,
            git_commit="3ee01fc",  # Current release HEAD
            dataset_canonical_sha256=canonical_hash,
            dataset_scenario_count=len(raw_dataset),
            config=self.config.to_dict(),
            metrics=metrics,
            scenario_results=scenario_results,
        )

        # Persist machine-readable output JSON
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        out_file = self.config.output_dir / f"{run_id}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(run_obj.to_dict(), f, indent=2, ensure_ascii=False)

        return run_obj


def main() -> None:
    parser = argparse.ArgumentParser(description="SQL Review Environment V3 Benchmark Runner")
    parser.add_argument("--dataset", type=str, default=str(DEFAULT_DATASET_PATH), help="Path to v3_dataset.json")
    parser.add_argument("--provider", type=str, default="mock", choices=["mock", "openai"], help="Model provider type")
    parser.add_argument("--model", type=str, default="MockModelProvider", help="Model name identifier")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic evaluation seed")
    parser.add_argument("--max-scenarios", type=int, default=None, help="Maximum scenarios to evaluate")
    parser.add_argument("--dialect", type=str, default=None, choices=["postgres", "mysql", "sqlite"], help="Filter by dialect")
    parser.add_argument("--difficulty", type=str, default=None, choices=["easy", "medium", "hard", "extreme"], help="Filter by difficulty")
    parser.add_argument("--issue-category", type=str, default=None, help="Filter by issue category")
    parser.add_argument("--output-dir", type=str, default=str(DEFAULT_OUTPUT_DIR), help="Output directory for result JSON")
    parser.add_argument("--no-llm", action="store_true", default=True, help="Force offline deterministic mock mode")
    parser.add_argument("--run-id", type=str, default=None, help="Custom run identifier")

    args = parser.parse_args()

    config = BenchmarkConfig(
        dataset_path=Path(args.dataset),
        provider=args.provider,
        model_name=args.model,
        seed=args.seed,
        max_scenarios=args.max_scenarios,
        dialect=args.dialect,
        difficulty=args.difficulty,
        issue_category=args.issue_category,
        output_dir=Path(args.output_dir),
        no_llm_mode=args.no_llm if args.provider == "mock" else False,
        run_id=args.run_id,
    )

    runner = V3BenchmarkRunner(config)
    run_res = runner.execute()

    print("==================================================")
    print("      SQL REVIEW V3 BENCHMARK RUNNER SUMMARY      ")
    print("==================================================")
    print(f"Run ID               : {run_res.run_id}")
    print(f"Provider / Model     : {config.provider} / {config.model_name}")
    print(f"Dataset SHA-256      : {run_res.dataset_canonical_sha256[:16]}...")
    print(f"Executed / Total     : {run_res.metrics.executed_scenarios} / {run_res.dataset_scenario_count}")
    print(f"Successful / Failed  : {run_res.metrics.successful_scenarios} / {run_res.metrics.failed_scenarios}")
    print("--------------------------------------------------")
    print(f"Macro F1 Score       : {run_res.metrics.macro_f1:.4f}")
    print(f"Macro Precision      : {run_res.metrics.macro_precision:.4f}")
    print(f"Macro Recall         : {run_res.metrics.macro_recall:.4f}")
    print(f"Location Accuracy    : {run_res.metrics.location_accuracy:.4f}")
    print(f"Fix Accuracy         : {run_res.metrics.fix_accuracy:.4f}")
    print("--------------------------------------------------")
    print(f"Result Persisted To  : {config.output_dir / f'{run_res.run_id}.json'}")
    print("==================================================")


if __name__ == "__main__":
    main()
