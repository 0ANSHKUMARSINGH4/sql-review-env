from __future__ import annotations
import pytest
from pydantic import ValidationError
from models import SQLReviewAction, StructuredFinding


def test_legacy_review_comment_backward_compatibility():
    # Legacy clients sending only review_comment
    action = SQLReviewAction(review_comment="Query contains SQL injection in id parameter.")
    assert action.review_comment == "Query contains SQL injection in id parameter."
    assert action.findings == []
    assert "SQL injection" in action.get_effective_comment()


def test_valid_structured_findings():
    finding = StructuredFinding(
        issue="sql_injection",
        severity="critical",
        line=3,
        evidence="WHERE id = '" + "user_input" + "'",
        recommendation="Use parameterized queries."
    )
    action = SQLReviewAction(findings=[finding])
    
    assert len(action.findings) == 1
    assert action.findings[0].issue == "sql_injection"
    assert action.findings[0].severity == "critical"
    assert action.findings[0].line == 3
    assert "[CRITICAL] sql_injection at line 3" in action.get_effective_comment()


def test_dual_action_payload_retains_both():
    finding = StructuredFinding(
        issue="n_plus_one",
        severity="high",
        line=10,
        evidence="Loop querying order_items inside orders loop.",
        recommendation="Use JOIN or batch fetch."
    )
    action = SQLReviewAction(
        review_comment="Free text comment about N+1.",
        findings=[finding]
    )
    
    effective = action.get_effective_comment()
    assert "Free text comment about N+1." in effective
    assert "[HIGH] n_plus_one at line 10" in effective


def test_invalid_issue_category_raises_error():
    with pytest.raises(ValidationError) as excinfo:
        StructuredFinding(
            issue="unsupported_custom_issue",
            evidence="Some evidence"
        )
    assert "Invalid issue category" in str(excinfo.value)


def test_invalid_severity_raises_error():
    with pytest.raises(ValidationError) as excinfo:
        StructuredFinding(
            issue="sql_injection",
            severity="extreme_critical",
            evidence="Some evidence"
        )
    assert "Invalid severity" in str(excinfo.value)


def test_invalid_line_number_raises_error():
    with pytest.raises(ValidationError):
        StructuredFinding(
            issue="sql_injection",
            line=-5,
            evidence="Some evidence"
        )


def test_oversized_evidence_payload_raises_error():
    with pytest.raises(ValidationError):
        StructuredFinding(
            issue="sql_injection",
            evidence="A" * 3000
        )


def test_empty_action_raises_error():
    with pytest.raises(ValidationError) as excinfo:
        SQLReviewAction()
    assert "must contain at least a 'review_comment' or non-empty 'findings' array" in str(excinfo.value)
