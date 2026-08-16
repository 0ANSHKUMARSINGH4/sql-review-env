from __future__ import annotations
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator, model_validator


ALLOWED_ISSUES = {
    "sql_injection",
    "n_plus_one",
    "missing_index",
    "inefficient_join",
    "unnecessary_columns",
    "destructive_operation",
}

ALLOWED_SEVERITIES = {
    "critical",
    "high",
    "medium",
    "low",
    "info",
}


class StructuredFinding(BaseModel):
    """Structured review finding emitted by an agent."""
    issue: str = Field(description="Issue category (e.g. sql_injection, n_plus_one, missing_index).")
    severity: str = Field(default="medium", description="Issue severity: critical, high, medium, low, info.")
    line: Optional[int] = Field(default=None, ge=1, description="Line number where issue occurs (1-indexed).")
    evidence: str = Field(description="Evidence or snippet demonstrating the issue.", max_length=2000)
    recommendation: Optional[str] = Field(default=None, description="Suggested remediation or fix.", max_length=2000)

    @field_validator("issue")

    def validate_issue(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Issue category cannot be empty.")
        normalized = v.strip().lower().replace("-", "_").replace(" ", "_")
        if normalized not in ALLOWED_ISSUES:
            raise ValueError(f"Invalid issue category '{v}'. Allowed categories: {sorted(list(ALLOWED_ISSUES))}")
        return normalized

    @field_validator("severity")

    def validate_severity(cls, v: str) -> str:
        if not v or not v.strip():
            return "medium"
        normalized = v.strip().lower()
        if normalized not in ALLOWED_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'. Allowed severities: {sorted(list(ALLOWED_SEVERITIES))}")
        return normalized


class SQLReviewAction(BaseModel):
    """
    Action for the SQL Review environment.
    Supports both legacy free-text `review_comment` and structured `findings`.
    """
    review_comment: Optional[str] = Field(default=None, description="Natural language comment identifying SQL issues.")
    findings: Optional[List[StructuredFinding]] = Field(default_factory=list, description="Structured review findings.")

    @model_validator(mode="after")
    def validate_action_payload(self) -> SQLReviewAction:
        has_comment = bool(self.review_comment and self.review_comment.strip())
        has_findings = bool(self.findings and len(self.findings) > 0)
        
        if not has_comment and not has_findings:
            raise ValueError("SQLReviewAction must contain at least a 'review_comment' or non-empty 'findings' array.")
        return self

    def get_effective_comment(self) -> str:
        """Returns effective natural language comment for legacy rubric grading."""
        parts = []
        if self.review_comment and self.review_comment.strip():
            parts.append(self.review_comment.strip())
        
        if self.findings:
            for f in self.findings:
                line_str = f" at line {f.line}" if f.line else ""
                parts.append(f"[{f.severity.upper()}] {f.issue}{line_str}: {f.evidence}")
        
        return " | ".join(parts)


class SQLReviewObservation(BaseModel):
    """Observation for the SQL Review environment."""
    query: str = Field(description="The SQL query to review.")
    schema_context: Optional[str] = Field(None, description="The database schema associated with the query.")
    feedback_history: List[str] = Field(default_factory=list, description="Previous feedback comments.")
    issues_remaining: int = Field(description="Number of unresolved issues in the current query.")
    done: bool = Field(False, description="Whether the episode is complete.")


class SQLReviewReward(BaseModel):
    """Reward for the SQL Review environment."""
    value: float = Field(0.0, description="The reward value, usually between 0.0 and 1.0.")
