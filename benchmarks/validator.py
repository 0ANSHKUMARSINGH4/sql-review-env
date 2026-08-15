from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
import jsonschema

from sql_analysis import SQLASTParser, SQLAnalyzer
from privacy import SecretDetector, PIIDetector


SCHEMA_PATH = Path(__file__).parent / "v3_dataset.schema.json"


@dataclass
class ValidationResult:
    valid: bool
    scenario_id: str
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    analyzer_findings: List[Dict[str, Any]] = field(default_factory=list)
    validation_stages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "scenario_id": self.scenario_id,
            "errors": self.errors,
            "warnings": self.warnings,
            "conflicts": self.conflicts,
            "analyzer_findings": self.analyzer_findings,
            "validation_stages": self.validation_stages,
        }


@dataclass
class DatasetValidationResult:
    valid: bool
    total_scenarios: int
    valid_scenarios: int
    invalid_scenarios: int
    total_conflicts: int
    scenario_results: List[ValidationResult] = field(default_factory=list)
    global_errors: List[str] = field(default_factory=list)
    global_warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "total_scenarios": self.total_scenarios,
            "valid_scenarios": self.valid_scenarios,
            "invalid_scenarios": self.invalid_scenarios,
            "total_conflicts": self.total_conflicts,
            "scenario_results": [r.to_dict() for r in self.scenario_results],
            "global_errors": self.global_errors,
            "global_warnings": self.global_warnings,
        }


class BenchmarkValidator:
    """
    Independent V3 Benchmark Scenario and Dataset Validator.
    Enforces strict ground-truth independence: SQLAnalyzer is used strictly as a
    secondary conflict detector and NEVER mutates declared ground truth.
    """

    def __init__(self, schema_file: Optional[Path] = None):
        self.schema_path = schema_file or SCHEMA_PATH
        with open(self.schema_path, "r", encoding="utf-8") as f:
            self.schema = json.load(f)
        
        self.ast_parser = SQLASTParser()
        self.analyzer = SQLAnalyzer()
        self.secret_detector = SecretDetector()
        self.pii_detector = PIIDetector()

    def validate_scenario(self, scenario: Dict[str, Any]) -> ValidationResult:
        """
        Validates a single benchmark scenario record against all 9 validation stages.
        Does NOT mutate the declared scenario or ground truth.
        """
        scenario_id = str(scenario.get("scenario_id", "unknown_scenario"))
        errors: List[str] = []
        warnings: List[str] = []
        conflicts: List[Dict[str, Any]] = []
        analyzer_findings_dict: List[Dict[str, Any]] = []
        stages: List[str] = []

        # ------------------------------------------------------------------
        # Stage 1: JSON Schema Validation
        # ------------------------------------------------------------------
        stages.append("schema_validation")
        try:
            jsonschema.validate(instance=scenario, schema=self.schema)
        except jsonschema.ValidationError as err:
            errors.append(f"Schema validation error: {err.message} (path: {'/'.join(str(p) for p in err.path)})")
        except jsonschema.SchemaError as err:
            errors.append(f"Invalid JSON Schema file: {err.message}")

        # If scenario structure is fundamentally invalid, return early stage errors
        if not isinstance(scenario, dict):
            return ValidationResult(
                valid=False,
                scenario_id=scenario_id,
                errors=errors,
                warnings=warnings,
                conflicts=conflicts,
                validation_stages=stages,
            )

        query = scenario.get("query", "")
        dialect = scenario.get("dialect", "sqlite")
        schema_context = scenario.get("schema_context", "")

        # ------------------------------------------------------------------
        # Stage 2: SQL Dialect Syntax Validation
        # ------------------------------------------------------------------
        stages.append("dialect_syntax")
        if isinstance(query, str) and query.strip():
            parse_res = self.ast_parser.parse(query, dialect=dialect)
            if not parse_res.parse_success:
                errors.append(f"SQL dialect syntax error for {dialect}: {parse_res.error_message}")

        # ------------------------------------------------------------------
        # Stage 3: Schema & Query Consistency Check
        # ------------------------------------------------------------------
        stages.append("schema_consistency")
        if isinstance(query, str) and not query.strip():
            errors.append("Query text cannot be empty or whitespace only.")

        # ------------------------------------------------------------------
        # Stage 4: Line Number Bounds Validation
        # ------------------------------------------------------------------
        stages.append("line_numbers")
        query_lines_count = len(query.splitlines()) if isinstance(query, str) and query else 1
        gt_data = scenario.get("ground_truth", {})
        issues = gt_data.get("issues", []) if isinstance(gt_data, dict) else []

        if isinstance(issues, list):
            for idx, item in enumerate(issues):
                if isinstance(item, dict):
                    line_no = item.get("line")
                    if isinstance(line_no, int):
                        if line_no < 1 or line_no > max(1, query_lines_count):
                            errors.append(
                                f"Issue #{idx+1} ({item.get('issue')}) specifies line {line_no}, "
                                f"which is out of bounds for query with {query_lines_count} lines."
                            )

        # ------------------------------------------------------------------
        # Stage 5: Ground-Truth Consistency Checks
        # ------------------------------------------------------------------
        stages.append("ground_truth_consistency")
        is_benign = scenario.get("is_benign", False)
        if isinstance(gt_data, dict):
            declared_total = gt_data.get("total_issues_count")
            actual_issues_len = len(issues) if isinstance(issues, list) else 0

            if declared_total != actual_issues_len:
                errors.append(
                    f"Ground truth count mismatch: declared total_issues_count is {declared_total}, "
                    f"but issues array contains {actual_issues_len} items."
                )

            if is_benign and actual_issues_len > 0:
                errors.append(
                    f"Benign scenario '{scenario_id}' declared is_benign=True, "
                    f"but specifies {actual_issues_len} ground-truth issues."
                )

        # ------------------------------------------------------------------
        # Stage 6: SQLAnalyzer Conflict Detection (Secondary Check)
        # ------------------------------------------------------------------
        stages.append("sql_analyzer_conflict")
        if isinstance(query, str) and query.strip():
            ast_issues, _ = self.analyzer.analyze(query, schema_context)
            for ast_issue in ast_issues:
                analyzer_findings_dict.append({
                    "issue": ast_issue.issue,
                    "severity": ast_issue.severity,
                    "line": ast_issue.line,
                    "status": ast_issue.status,
                    "evidence": ast_issue.evidence,
                })

            declared_issue_categories = set(
                item.get("issue") for item in issues if isinstance(item, dict) and item.get("issue")
            )
            analyzer_issue_categories = set(
                f.issue for f in ast_issues
            )

            # Check for categories in ground truth missing from analyzer
            missing_in_analyzer = declared_issue_categories - analyzer_issue_categories
            for issue_cat in missing_in_analyzer:
                conflicts.append({
                    "type": "unconfirmed_declared_issue",
                    "issue": issue_cat,
                    "reason": f"Ground truth declares issue '{issue_cat}', but secondary SQLAnalyzer did not detect it.",
                })

            # Check for confirmed analyzer issues omitted from ground truth
            confirmed_analyzer_issues = set(
                f.issue for f in ast_issues if f.status == "confirmed"
            )
            omitted_in_declared = confirmed_analyzer_issues - declared_issue_categories
            for issue_cat in omitted_in_declared:
                conflicts.append({
                    "type": "omitted_confirmed_issue",
                    "issue": issue_cat,
                    "reason": f"Secondary SQLAnalyzer detected confirmed issue '{issue_cat}', which is omitted from declared ground truth.",
                })

        # ------------------------------------------------------------------
        # Stage 7: Privacy & Secret Safety Validation
        # ------------------------------------------------------------------
        stages.append("privacy_safety")
        combined_text = f"{query}\n{schema_context}"
        
        # Check secrets
        secret_matches = self.secret_detector.detect(combined_text)
        for secret_match in secret_matches:
            val = secret_match.value
            if any(test_marker in val for test_marker in ["TEST_PASSWORD_", "TEST_API_KEY_", "TEST_SECRET_"]):
                warnings.append(f"Synthetic test secret marker detected: {val}")
            else:
                errors.append(f"Potentially real sensitive credential detected in scenario: category={secret_match.category}")

        # Check PII
        pii_matches = self.pii_detector.detect(combined_text)
        for pii_match in pii_matches:
            val = pii_match.value
            if "example.invalid" in val or "555-01" in val or "test@" in val:
                warnings.append(f"Synthetic test PII marker detected: {val}")
            else:
                warnings.append(f"Potential un-sanitized PII detected in scenario: category={pii_match.category}")

        is_valid = len(errors) == 0

        return ValidationResult(
            valid=is_valid,
            scenario_id=scenario_id,
            errors=errors,
            warnings=warnings,
            conflicts=conflicts,
            analyzer_findings=analyzer_findings_dict,
            validation_stages=stages,
        )

    def validate_dataset(self, dataset: List[Dict[str, Any]]) -> DatasetValidationResult:
        """
        Validates a complete list of benchmark scenario records.
        Includes Stages 8 (Duplicate Scenario IDs) & Stage 9 (Exact Query Collisions).
        """
        global_errors: List[str] = []
        global_warnings: List[str] = []
        scenario_results: List[ValidationResult] = []

        if not isinstance(dataset, list):
            global_errors.append("Dataset must be a list of scenario objects.")
            return DatasetValidationResult(
                valid=False,
                total_scenarios=0,
                valid_scenarios=0,
                invalid_scenarios=0,
                total_conflicts=0,
                global_errors=global_errors,
            )

        seen_ids: Dict[str, int] = {}
        seen_queries: Dict[str, str] = {}
        total_conflicts = 0
        valid_count = 0
        invalid_count = 0

        for idx, scenario in enumerate(dataset):
            if not isinstance(scenario, dict):
                global_errors.append(f"Scenario at index {idx} is not a dict object.")
                invalid_count += 1
                continue

            res = self.validate_scenario(scenario)
            scenario_results.append(res)

            if res.valid:
                valid_count += 1
            else:
                invalid_count += 1

            total_conflicts += len(res.conflicts)

            # Stage 8: Duplicate Scenario ID Check
            sc_id = res.scenario_id
            if sc_id in seen_ids:
                global_errors.append(f"Duplicate scenario_id detected: '{sc_id}' (indices {seen_ids[sc_id]} and {idx})")
            else:
                seen_ids[sc_id] = idx

            # Stage 9: Exact Query Collision Check
            query_str = scenario.get("query", "").strip()
            dialect_str = scenario.get("dialect", "").strip()
            query_key = f"{dialect_str}:{query_str}"
            if query_str and query_key in seen_queries:
                global_errors.append(
                    f"Duplicate exact SQL query collision in dialect '{dialect_str}' "
                    f"between scenario '{seen_queries[query_key]}' and '{sc_id}'"
                )
            elif query_str:
                seen_queries[query_key] = sc_id

        overall_valid = len(global_errors) == 0 and invalid_count == 0

        return DatasetValidationResult(
            valid=overall_valid,
            total_scenarios=len(dataset),
            valid_scenarios=valid_count,
            invalid_scenarios=invalid_count,
            total_conflicts=total_conflicts,
            scenario_results=scenario_results,
            global_errors=global_errors,
            global_warnings=global_warnings,
        )
