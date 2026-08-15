from __future__ import annotations
import re
from typing import List, Dict, Any, Optional, Set
from pydantic import BaseModel, Field

from models import SQLReviewAction, StructuredFinding
from sql_analysis.analyzer import GroundTruthIssue


class FindingEvaluation(BaseModel):
    """Evaluation breakdown for an individual agent finding."""
    issue: str = Field(description="Issue category.")
    issue_correct: bool = Field(default=False, description="True if issue category matches ground truth.")
    location_correct: bool = Field(default=False, description="True if line number matches ground truth.")
    evidence_quality: float = Field(default=0.0, ge=0.0, le=1.0, description="Evidence quality score between 0.0 and 1.0.")
    severity_correct: bool = Field(default=False, description="True if severity matches ground truth.")
    recommendation_quality: float = Field(default=0.0, ge=0.0, le=1.0, description="Recommendation quality score between 0.0 and 1.0.")
    score: float = Field(default=0.0, description="Total score awarded for this finding.")


class EvaluationResult(BaseModel):
    """Complete machine-readable benchmark evaluation result."""
    true_positives: int = Field(default=0, description="Count of correctly identified ground-truth issues.")
    false_positives: int = Field(default=0, description="Count of unsupported/hallucinated findings.")
    false_negatives: int = Field(default=0, description="Count of confirmed ground-truth issues missed by agent.")
    duplicates: int = Field(default=0, description="Count of duplicate findings for the same issue category.")
    precision: float = Field(default=0.0, ge=0.0, le=1.0, description="Precision score TP / (TP + FP).")
    recall: float = Field(default=0.0, ge=0.0, le=1.0, description="Recall score TP / (TP + FN).")
    f1: float = Field(default=0.0, ge=0.0, le=1.0, description="F1 harmonic mean score.")
    location_accuracy: float = Field(default=0.0, ge=0.0, le=1.0, description="Ratio of findings with accurate line numbers.")
    fix_accuracy: float = Field(default=0.0, ge=0.0, le=1.0, description="Ratio of findings with effective remediation recommendations.")
    raw_score: float = Field(default=0.0, description="Raw un-clamped total score.")
    normalized_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Normalized score between 0.0 and 1.0.")
    analysis_status: str = Field(default="authoritative", description="Analysis status: 'authoritative', 'candidate_aware', or 'indeterminate'.")
    finding_evaluations: List[FindingEvaluation] = Field(default_factory=list, description="Per-finding evaluation items.")


class EvidenceBasedEvaluator:
    """
    Evidence-based multi-dimensional evaluator for SQL Review Environment V2.
    
    Evaluates structured findings against ground truth across 5 dimensions:
    Issue Correctness, Location Accuracy, Evidence Quality, Severity Accuracy, and Fix Quality.
    Penalizes false positives (-0.75) and duplicates (-0.25) to prevent reward gaming.
    """

    WEIGHT_ISSUE = 1.0
    WEIGHT_LOCATION = 0.5
    WEIGHT_EVIDENCE = 0.5
    WEIGHT_SEVERITY = 0.25
    WEIGHT_RECOMMENDATION = 0.25

    PENALTY_FALSE_POSITIVE = -0.75
    PENALTY_DUPLICATE = -0.25

    RELEVANT_FIX_KEYWORDS = {
        "sql_injection": {"parameter", "bind", "prepared", "sanitize", "escape"},
        "n_plus_one": {"batch", "join", "in clause", "eager", "include"},
        "missing_index": {"index", "key", "create index", "search"},
        "inefficient_join": {"inner", "left", "predicate", "on clause", "join"},
        "unnecessary_columns": {"select list", "explicit", "columns", "avoid star", "specific"},
    }

    def __init__(self):
        pass

    def evaluate(
        self,
        action: SQLReviewAction,
        ground_truth: List[GroundTruthIssue],
        parse_success: bool = True,
    ) -> EvaluationResult:
        """
        Evaluates an agent's action against ground truth issues.
        Returns a serializable EvaluationResult.
        """
        if not parse_success:
            # Handle SQL parse failure gracefully
            return EvaluationResult(
                true_positives=0,
                false_positives=0,
                false_negatives=0,
                duplicates=0,
                precision=0.0,
                recall=0.0,
                f1=0.0,
                location_accuracy=0.0,
                fix_accuracy=0.0,
                raw_score=0.0,
                normalized_score=0.0,
                analysis_status="indeterminate",
                finding_evaluations=[],
            )

        # 1. Extract agent findings (supporting both structured findings and legacy comment adapter)
        agent_findings = self._extract_findings(action)

        seen_issues: Set[str] = set()
        finding_evals: List[FindingEvaluation] = []

        tp = 0
        fp = 0
        dup_count = 0
        correct_locations = 0
        effective_fixes = 0

        total_raw_score = 0.0

        # Build ground truth lookup map
        gt_map: Dict[str, GroundTruthIssue] = {gt.issue: gt for gt in ground_truth}
        matched_gt_issues: Set[str] = set()

        for finding in agent_findings:
            issue_cat = finding.issue

            # Duplicate Check
            if issue_cat in seen_issues:
                dup_count += 1
                total_raw_score += self.PENALTY_DUPLICATE
                finding_evals.append(
                    FindingEvaluation(
                        issue=issue_cat,
                        issue_correct=False,
                        score=self.PENALTY_DUPLICATE,
                    )
                )
                continue

            seen_issues.add(issue_cat)

            # Match against ground truth
            gt_match = gt_map.get(issue_cat)

            if not gt_match:
                # False Positive
                fp += 1
                total_raw_score += self.PENALTY_FALSE_POSITIVE
                finding_evals.append(
                    FindingEvaluation(
                        issue=issue_cat,
                        issue_correct=False,
                        score=self.PENALTY_FALSE_POSITIVE,
                    )
                )
            else:
                # True Positive
                tp += 1
                matched_gt_issues.add(issue_cat)

                item_score = self.WEIGHT_ISSUE

                # Location Scoring
                loc_correct = False
                if finding.line is not None and gt_match.line is not None:
                    diff = abs(finding.line - gt_match.line)
                    if diff == 0:
                        loc_correct = True
                        correct_locations += 1
                        item_score += self.WEIGHT_LOCATION
                    elif diff == 1:
                        item_score += (self.WEIGHT_LOCATION * 0.5)

                # Evidence Quality
                ev_quality = self._score_evidence(finding.evidence, gt_match.evidence)
                item_score += (ev_quality * self.WEIGHT_EVIDENCE)

                # Severity Accuracy
                sev_correct = False
                if finding.severity == gt_match.severity:
                    sev_correct = True
                    item_score += self.WEIGHT_SEVERITY
                elif finding.severity:
                    item_score += (self.WEIGHT_SEVERITY * 0.4)

                # Recommendation / Fix Quality
                rec_quality = self._score_recommendation(finding.issue, finding.recommendation)
                if rec_quality >= 0.7:
                    effective_fixes += 1
                item_score += (rec_quality * self.WEIGHT_RECOMMENDATION)

                total_raw_score += item_score

                finding_evals.append(
                    FindingEvaluation(
                        issue=issue_cat,
                        issue_correct=True,
                        location_correct=loc_correct,
                        evidence_quality=ev_quality,
                        severity_correct=sev_correct,
                        recommendation_quality=rec_quality,
                        score=item_score,
                    )
                )

        # 2. Count False Negatives (Confirmed ground truth issues missed by agent)
        confirmed_gt = [gt for gt in ground_truth if gt.status == "confirmed"]
        candidate_gt = [gt for gt in ground_truth if gt.status == "candidate"]

        fn = 0
        for gt in confirmed_gt:
            if gt.issue not in matched_gt_issues:
                fn += 1

        # 3. Calculate Precision, Recall, F1
        denom_p = tp + fp
        precision = (tp / denom_p) if denom_p > 0 else 0.0

        denom_r = tp + fn
        recall = (tp / denom_r) if denom_r > 0 else 0.0

        denom_f1 = precision + recall
        f1 = (2 * precision * recall / denom_f1) if denom_f1 > 0 else 0.0

        loc_acc = (correct_locations / tp) if tp > 0 else 0.0
        fix_acc = (effective_fixes / tp) if tp > 0 else 0.0

        # 4. Calculate Normalized Score [0.0, 1.0]
        max_possible = sum(
            self.WEIGHT_ISSUE + self.WEIGHT_LOCATION + self.WEIGHT_EVIDENCE + self.WEIGHT_SEVERITY + self.WEIGHT_RECOMMENDATION
            for _ in confirmed_gt
        )
        if max_possible <= 0:
            max_possible = 2.5  # Default baseline max for empty ground truth

        norm_score = max(0.0, min(1.0, total_raw_score / max_possible))

        status_str = "candidate_aware" if candidate_gt else "authoritative"

        return EvaluationResult(
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            duplicates=dup_count,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1=round(f1, 4),
            location_accuracy=round(loc_acc, 4),
            fix_accuracy=round(fix_acc, 4),
            raw_score=round(total_raw_score, 2),
            normalized_score=round(norm_score, 4),
            analysis_status=status_str,
            finding_evaluations=finding_evals,
        )

    def _extract_findings(self, action: SQLReviewAction) -> List[StructuredFinding]:
        """Extracts structured findings, adapting legacy comments if structured findings are missing."""
        if action.findings and len(action.findings) > 0:
            return action.findings

        # Legacy Free-Text Comment Adapter
        comment = (action.review_comment or "").lower()
        extracted: List[StructuredFinding] = []

        patterns = {
            "sql_injection": r"(sql[ -]?injection|unsanitized|parameterized|prepared statement|injection|binding)",
            "n_plus_one": r"(n\+1|n plus one|loop query|multiple queries|batching)",
            "missing_index": r"(missing index|indexing|no index|full table scan)",
            "inefficient_join": r"(inefficient join|nested loop|cross join|cartesian)",
            "unnecessary_columns": r"(select \*|unnecessary columns|column list|star operator)",
        }

        for issue_id, regex in patterns.items():
            if re.search(regex, comment):
                extracted.append(
                    StructuredFinding(
                        issue=issue_id,
                        severity="medium",
                        line=None,
                        evidence=f"Legacy comment keyword match for {issue_id}.",
                        recommendation="Use appropriate remediation.",
                    )
                )

        return extracted

    def _score_evidence(self, evidence: str, gt_evidence: str) -> float:
        """Scores evidence quality deterministically."""
        if not evidence or len(evidence.strip()) < 15:
            return 0.2  # Vague / short evidence

        ev_lower = evidence.lower()
        gt_lower = gt_evidence.lower()

        # Check for substantive words overlapping with ground truth explanation
        gt_words = set(re.findall(r"\w+", gt_lower)) - {"a", "an", "the", "in", "on", "of", "is", "query"}
        ev_words = set(re.findall(r"\w+", ev_lower))

        overlap = len(gt_words.intersection(ev_words))
        if overlap >= 2 or len(evidence.strip()) >= 30:
            return 1.0  # Strong, substantive evidence

        return 0.6

    def _score_recommendation(self, issue: str, recommendation: Optional[str]) -> float:
        """Scores recommendation quality deterministically."""
        if not recommendation or len(recommendation.strip()) < 10:
            return 0.1  # Weak / missing recommendation

        rec_lower = recommendation.lower()
        keywords = self.RELEVANT_FIX_KEYWORDS.get(issue, set())

        if any(kw in rec_lower for kw in keywords) or len(recommendation.strip()) >= 25:
            return 1.0  # Strong remediation recommendation

        return 0.4
