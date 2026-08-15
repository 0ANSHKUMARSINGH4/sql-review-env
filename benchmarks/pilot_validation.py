from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any, Dict
from benchmarks.validator import BenchmarkValidator


PILOT_DATASET_PATH = Path(__file__).parent / "v3_pilot_dataset.json"


def compute_canonical_dataset_hash(dataset: list[dict[str, Any]]) -> str:
    """
    Computes a deterministic SHA-256 hash of the canonical dataset JSON representation.
    """
    canonical_json_str = json.dumps(dataset, sort_keys=True, indent=None)
    return hashlib.sha256(canonical_json_str.encode("utf-8")).hexdigest()


def validate_pilot_dataset(dataset_path: Path = PILOT_DATASET_PATH) -> Dict[str, Any]:
    """
    Validates the 30-scenario pilot dataset and returns a full summary report.
    """
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    validator = BenchmarkValidator()
    dataset_res = validator.validate_dataset(dataset)
    canonical_hash = compute_canonical_dataset_hash(dataset)

    # Aggregations
    dialects: Dict[str, int] = {}
    difficulties: Dict[str, int] = {}
    issue_categories: Dict[str, int] = {}
    benign_count = 0
    adversarial_count = 0
    multi_issue_count = 0

    for sc in dataset:
        d = sc.get("dialect", "unknown")
        dialects[d] = dialects.get(d, 0) + 1

        diff = sc.get("difficulty", "unknown")
        difficulties[diff] = difficulties.get(diff, 0) + 1

        if sc.get("is_benign"):
            benign_count += 1
        if sc.get("is_adversarial"):
            adversarial_count += 1

        gt_issues = sc.get("ground_truth", {}).get("issues", [])
        if len(gt_issues) > 1:
            multi_issue_count += 1

        for issue_item in gt_issues:
            cat = issue_item.get("issue")
            if cat:
                issue_categories[cat] = issue_categories.get(cat, 0) + 1

    summary = {
        "valid": dataset_res.valid,
        "canonical_sha256": canonical_hash,
        "total_scenarios": dataset_res.total_scenarios,
        "valid_scenarios": dataset_res.valid_scenarios,
        "invalid_scenarios": dataset_res.invalid_scenarios,
        "total_conflicts": dataset_res.total_conflicts,
        "dialects": dialects,
        "difficulties": difficulties,
        "issue_categories": issue_categories,
        "benign_count": benign_count,
        "adversarial_count": adversarial_count,
        "multi_issue_count": multi_issue_count,
        "global_errors": dataset_res.global_errors,
        "global_warnings": dataset_res.global_warnings,
    }

    return summary


def print_pilot_quality_report(summary: Dict[str, Any]) -> None:
    """
    Prints human-readable pilot quality and validation report.
    """
    print("==================================================")
    print("       SQL REVIEW V3 BENCHMARK PILOT REPORT       ")
    print("==================================================")
    print(f"Validation Status    : {'PASSED' if summary['valid'] else 'FAILED'}")
    print(f"Canonical SHA-256    : {summary['canonical_sha256']}")
    print(f"Total Scenarios      : {summary['total_scenarios']}")
    print(f"Valid / Invalid      : {summary['valid_scenarios']} / {summary['invalid_scenarios']}")
    print(f"Secondary Conflicts  : {summary['total_conflicts']}")
    print("--------------------------------------------------")
    print("Dialect Breakdown    :")
    for d, cnt in summary["dialects"].items():
        print(f"  - {d:12s}: {cnt}")
    print("Difficulty Breakdown :")
    for diff, cnt in summary["difficulties"].items():
        print(f"  - {diff:12s}: {cnt}")
    print("Issue Category Counts:")
    for cat, cnt in summary["issue_categories"].items():
        print(f"  - {cat:20s}: {cnt}")
    print("--------------------------------------------------")
    print(f"Benign Scenarios     : {summary['benign_count']}")
    print(f"Adversarial Scenarios: {summary['adversarial_count']}")
    print(f"Multi-Issue Scenarios: {summary['multi_issue_count']}")
    print("==================================================")


if __name__ == "__main__":
    report_summary = validate_pilot_dataset()
    print_pilot_quality_report(report_summary)
