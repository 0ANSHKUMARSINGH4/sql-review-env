from __future__ import annotations
import pytest
from models import SQLReviewAction, StructuredFinding
from sql_analysis.analyzer import GroundTruthIssue
from grading import EvidenceBasedEvaluator, FindingEvaluation, EvaluationResult


def test_correct_finding_all_dimensions():
    evaluator = EvidenceBasedEvaluator()
    
    gt = [
        GroundTruthIssue(
            issue="sql_injection",
            severity="critical",
            line=3,
            evidence="Dynamic concatenation in WHERE clause.",
            recommendation="Use parameterized queries.",
            status="confirmed",
            confidence=0.98,
        )
    ]
    
    action = SQLReviewAction(
        findings=[
            StructuredFinding(
                issue="sql_injection",
                severity="critical",
                line=3,
                evidence="User input is concatenated into the WHERE clause without parameterization.",
                recommendation="Use parameterized query parameters.",
            )
        ]
    )
    
    res = evaluator.evaluate(action, gt)
    
    assert res.true_positives == 1
    assert res.false_positives == 0
    assert res.false_negatives == 0
    assert res.duplicates == 0
    assert res.precision == 1.0
    assert res.recall == 1.0
    assert res.f1 == 1.0
    assert res.location_accuracy == 1.0
    assert res.fix_accuracy == 1.0
    assert res.normalized_score > 0.9


def test_false_positive_penalty():
    evaluator = EvidenceBasedEvaluator()
    
    gt = [
        GroundTruthIssue(
            issue="sql_injection",
            severity="critical",
            line=3,
            evidence="Dynamic string concatenation.",
            status="confirmed",
        )
    ]
    
    action = SQLReviewAction(
        findings=[
            StructuredFinding(issue="sql_injection", severity="critical", line=3, evidence="Concatenation in query."),
            StructuredFinding(issue="unnecessary_columns", severity="low", line=5, evidence="Unsupported claim."),
        ]
    )
    
    res = evaluator.evaluate(action, gt)
    
    assert res.true_positives == 1
    assert res.false_positives == 1
    assert res.precision == 0.5
    # False positive penalty should reduce raw score
    assert res.raw_score < 2.5


def test_false_negative_tracking():
    evaluator = EvidenceBasedEvaluator()
    
    gt = [
        GroundTruthIssue(issue="sql_injection", severity="critical", line=3, evidence="Concat", status="confirmed"),
        GroundTruthIssue(issue="missing_index", severity="medium", line=8, evidence="No index", status="confirmed"),
    ]
    
    action = SQLReviewAction(
        findings=[
            StructuredFinding(issue="sql_injection", severity="critical", line=3, evidence="Concatenation in query.")
        ]
    )
    
    res = evaluator.evaluate(action, gt)
    
    assert res.true_positives == 1
    assert res.false_negatives == 1
    assert res.recall == 0.5


def test_duplicate_finding_penalty():
    evaluator = EvidenceBasedEvaluator()
    
    gt = [
        GroundTruthIssue(issue="sql_injection", severity="critical", line=3, evidence="Concat", status="confirmed")
    ]
    
    action = SQLReviewAction(
        findings=[
            StructuredFinding(issue="sql_injection", severity="critical", line=3, evidence="Concatenation in query 1."),
            StructuredFinding(issue="sql_injection", severity="critical", line=3, evidence="Concatenation in query 2."),
            StructuredFinding(issue="sql_injection", severity="critical", line=3, evidence="Concatenation in query 3."),
        ]
    )
    
    res = evaluator.evaluate(action, gt)
    
    assert res.true_positives == 1
    assert res.duplicates == 2


def test_location_scoring_exact_vs_wrong():
    evaluator = EvidenceBasedEvaluator()
    
    gt = [
        GroundTruthIssue(issue="sql_injection", severity="critical", line=5, evidence="Concat", status="confirmed")
    ]
    
    # Action with wrong line 20
    action_wrong = SQLReviewAction(
        findings=[
            StructuredFinding(issue="sql_injection", severity="critical", line=20, evidence="Concatenation in query.")
        ]
    )
    res_wrong = evaluator.evaluate(action_wrong, gt)
    assert res_wrong.location_accuracy == 0.0
    
    # Action with exact line 5
    action_exact = SQLReviewAction(
        findings=[
            StructuredFinding(issue="sql_injection", severity="critical", line=5, evidence="Concatenation in query.")
        ]
    )
    res_exact = evaluator.evaluate(action_exact, gt)
    assert res_exact.location_accuracy == 1.0
    assert res_exact.raw_score > res_wrong.raw_score


def test_evidence_quality_substantive_vs_vague():
    evaluator = EvidenceBasedEvaluator()
    
    gt = [
        GroundTruthIssue(issue="unnecessary_columns", severity="low", line=1, evidence="Detected SELECT * wildcard projection.", status="confirmed")
    ]
    
    # Vague evidence
    action_vague = SQLReviewAction(
        findings=[StructuredFinding(issue="unnecessary_columns", evidence="Bad query.")]
    )
    res_vague = evaluator.evaluate(action_vague, gt)
    
    # Substantive evidence
    action_substantive = SQLReviewAction(
        findings=[StructuredFinding(issue="unnecessary_columns", evidence="Detected SELECT * wildcard projection fetching all columns.")]
    )
    res_sub = evaluator.evaluate(action_substantive, gt)
    
    assert res_sub.finding_evaluations[0].evidence_quality > res_vague.finding_evaluations[0].evidence_quality


def test_candidate_ground_truth_not_penalized_as_fn():
    evaluator = EvidenceBasedEvaluator()
    
    gt = [
        GroundTruthIssue(issue="missing_index", severity="medium", line=3, evidence="No index stats", status="candidate")
    ]
    
    # Agent misses candidate issue
    action = SQLReviewAction(
        findings=[StructuredFinding(issue="sql_injection", evidence="Other issue.")]
    )
    res = evaluator.evaluate(action, gt)
    
    # Candidate missing item must NOT count as false negative
    assert res.false_negatives == 0
    assert res.analysis_status == "candidate_aware"


def test_parse_failure_indeterminate_status():
    evaluator = EvidenceBasedEvaluator()
    gt = [GroundTruthIssue(issue="sql_injection", severity="critical", line=1, evidence="Concat", status="confirmed")]
    
    action = SQLReviewAction(findings=[StructuredFinding(issue="sql_injection", evidence="Some text.")])
    res = evaluator.evaluate(action, gt, parse_success=False)
    
    assert res.analysis_status == "indeterminate"


def test_adversarial_keyword_gaming_response():
    evaluator = EvidenceBasedEvaluator()
    
    # Ground truth contains only 1 actual issue (sql_injection)
    gt = [
        GroundTruthIssue(issue="sql_injection", severity="critical", line=2, evidence="Concat in query.", status="confirmed")
    ]
    
    # Adversarial agent spams all issue categories without valid evidence or line
    action = SQLReviewAction(
        findings=[
            StructuredFinding(issue="sql_injection", evidence="sql_injection"),
            StructuredFinding(issue="n_plus_one", evidence="n_plus_one"),
            StructuredFinding(issue="missing_index", evidence="missing_index"),
            StructuredFinding(issue="inefficient_join", evidence="inefficient_join"),
            StructuredFinding(issue="unnecessary_columns", evidence="unnecessary_columns"),
        ]
    )
    
    res = evaluator.evaluate(action, gt)
    
    # Should get 1 TP and 4 FPs -> precision 0.2, heavy penalties applied
    assert res.true_positives == 1
    assert res.false_positives == 4
    assert res.precision == 0.2
    assert res.normalized_score < 0.3


def test_legacy_review_comment_compatibility():
    evaluator = EvidenceBasedEvaluator()
    
    gt = [
        GroundTruthIssue(issue="sql_injection", severity="critical", line=1, evidence="Concat", status="confirmed")
    ]
    
    # Legacy client sending only review_comment
    action = SQLReviewAction(review_comment="Query contains SQL injection in parameter.")
    res = evaluator.evaluate(action, gt)
    
    assert res.true_positives == 1
    assert res.false_positives == 0
    assert res.precision == 1.0
