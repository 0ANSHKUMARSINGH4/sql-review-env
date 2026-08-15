from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any, Dict
from benchmarks.validator import BenchmarkValidator


DATASET_PATH = Path(__file__).parent / "v3_dataset.json"
REPORT_PATH = Path(__file__).parent / "V3_DATASET_REPORT.md"


def compute_canonical_dataset_hash(dataset: list[dict[str, Any]]) -> str:
    """
    Computes a deterministic SHA-256 hash of the canonical dataset JSON representation.
    """
    canonical_json_str = json.dumps(dataset, sort_keys=True, indent=None)
    return hashlib.sha256(canonical_json_str.encode("utf-8")).hexdigest()


def validate_v3_dataset(dataset_path: Path = DATASET_PATH) -> Dict[str, Any]:
    """
    Validates the 300-scenario V3 dataset and returns a full summary report.
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
    single_issue_count = 0
    multi_issue_count = 0
    n_plus_one_count = 0
    conflict_categories: Dict[str, int] = {}

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
        if len(gt_issues) == 1:
            single_issue_count += 1
        elif len(gt_issues) > 1:
            multi_issue_count += 1

        for issue_item in gt_issues:
            cat = issue_item.get("issue")
            if cat:
                issue_categories[cat] = issue_categories.get(cat, 0) + 1
                if cat == "n_plus_one":
                    n_plus_one_count += 1

    # Conflict category counts across scenarios
    for sc_res in dataset_res.scenario_results:
        for conf in sc_res.conflicts:
            c_type = conf.get("type", "unknown_conflict")
            conflict_categories[c_type] = conflict_categories.get(c_type, 0) + 1

    summary = {
        "valid": dataset_res.valid,
        "canonical_sha256": canonical_hash,
        "total_scenarios": dataset_res.total_scenarios,
        "valid_scenarios": dataset_res.valid_scenarios,
        "invalid_scenarios": dataset_res.invalid_scenarios,
        "total_conflicts": dataset_res.total_conflicts,
        "conflict_categories": conflict_categories,
        "dialects": dialects,
        "difficulties": difficulties,
        "issue_categories": issue_categories,
        "benign_count": benign_count,
        "adversarial_count": adversarial_count,
        "single_issue_count": single_issue_count,
        "multi_issue_count": multi_issue_count,
        "n_plus_one_count": n_plus_one_count,
        "global_errors": dataset_res.global_errors,
        "global_warnings": dataset_res.global_warnings,
    }

    return summary


def generate_v3_dataset_report_md(summary: Dict[str, Any], output_path: Path = REPORT_PATH) -> str:
    """
    Generates a Markdown validation report file V3_DATASET_REPORT.md.
    """
    md_content = f"""# SQL Review Environment V3 — Benchmark Dataset Quality & Validation Report

## Executive Summary
- **Validation Status**: {"PASSED" if summary["valid"] else "FAILED"}
- **Canonical SHA-256 Hash**: `{summary["canonical_sha256"]}`
- **Total Scenarios**: `{summary["total_scenarios"]}`
- **Valid / Invalid Scenarios**: `{summary["valid_scenarios"]}` / `{summary["invalid_scenarios"]}`
- **Secondary AST Analyzer Conflicts**: `{summary["total_conflicts"]}`

---

## Dataset Distribution

### Dialect Distribution
| Dialect | Count | Percentage |
| :--- | :--- | :--- |
| **PostgreSQL** | `{summary["dialects"].get("postgres", 0)}` | {summary["dialects"].get("postgres", 0) / summary["total_scenarios"] * 100:.1f}% |
| **MySQL** | `{summary["dialects"].get("mysql", 0)}` | {summary["dialects"].get("mysql", 0) / summary["total_scenarios"] * 100:.1f}% |
| **SQLite** | `{summary["dialects"].get("sqlite", 0)}` | {summary["dialects"].get("sqlite", 0) / summary["total_scenarios"] * 100:.1f}% |

### Difficulty Distribution
| Difficulty | Count | Percentage |
| :--- | :--- | :--- |
| **Easy** | `{summary["difficulties"].get("easy", 0)}` | {summary["difficulties"].get("easy", 0) / summary["total_scenarios"] * 100:.1f}% |
| **Medium** | `{summary["difficulties"].get("medium", 0)}` | {summary["difficulties"].get("medium", 0) / summary["total_scenarios"] * 100:.1f}% |
| **Hard** | `{summary["difficulties"].get("hard", 0)}` | {summary["difficulties"].get("hard", 0) / summary["total_scenarios"] * 100:.1f}% |

---

## Category & Structural Metrics

- **Benign Scenarios**: `{summary["benign_count"]}` (queries containing zero vulnerabilities)
- **Adversarial Scenarios**: `{summary["adversarial_count"]}` (prompt injection in comments, fake keys, PII traps)
- **Single-Issue Scenarios**: `{summary["single_issue_count"]}`
- **Multi-Issue Scenarios**: `{summary["multi_issue_count"]}`
- **N+1 Scenarios (with trace metadata)**: `{summary["n_plus_one_count"]}`

### Issue Category Breakdown
| Issue Category | Total Findings Declared |
| :--- | :--- |
| `sql_injection` | `{summary["issue_categories"].get("sql_injection", 0)}` |
| `unnecessary_columns` | `{summary["issue_categories"].get("unnecessary_columns", 0)}` |
| `missing_index` | `{summary["issue_categories"].get("missing_index", 0)}` |
| `inefficient_join` | `{summary["issue_categories"].get("inefficient_join", 0)}` |
| `n_plus_one` | `{summary["issue_categories"].get("n_plus_one", 0)}` |

---

## Secondary AST Analyzer Conflicts
*(Note: Conflicts represent secondary AST parser limitations and do NOT mutate curator-declared ground truth)*

- **Total Secondary Conflicts**: `{summary["total_conflicts"]}`
- **Conflict Types**:
"""
    for c_type, count in summary["conflict_categories"].items():
        md_content += f"  - `{c_type}`: {count}\n"

    md_content += """
---
*Report generated automatically by `benchmarks/v3_validation.py`.*
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    return md_content


if __name__ == "__main__":
    summary_report = validate_v3_dataset()
    generate_v3_dataset_report_md(summary_report)
    print("==================================================")
    print("      SQL REVIEW V3 BENCHMARK DATASET REPORT      ")
    print("==================================================")
    print(f"Validation Status    : {'PASSED' if summary_report['valid'] else 'FAILED'}")
    print(f"Canonical SHA-256    : {summary_report['canonical_sha256']}")
    print(f"Total Scenarios      : {summary_report['total_scenarios']}")
    print(f"Valid / Invalid      : {summary_report['valid_scenarios']} / {summary_report['invalid_scenarios']}")
    print(f"Secondary Conflicts  : {summary_report['total_conflicts']}")
    print("--------------------------------------------------")
    print("Dialect Breakdown    :")
    for d, cnt in summary_report["dialects"].items():
        print(f"  - {d:12s}: {cnt}")
    print("Difficulty Breakdown :")
    for diff, cnt in summary_report["difficulties"].items():
        print(f"  - {diff:12s}: {cnt}")
    print("--------------------------------------------------")
    print(f"Benign Scenarios     : {summary_report['benign_count']}")
    print(f"Adversarial Scenarios: {summary_report['adversarial_count']}")
    print(f"Single-Issue Scenarios: {summary_report['single_issue_count']}")
    print(f"Multi-Issue Scenarios: {summary_report['multi_issue_count']}")
    print(f"N+1 Trace Scenarios  : {summary_report['n_plus_one_count']}")
    print("==================================================")
