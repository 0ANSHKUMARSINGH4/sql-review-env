from __future__ import annotations
import time
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from privacy.models import PrivacyReport
from security.prompt_injection import SuspiciousInjectionSignal
from models import StructuredFinding
from sql_analysis.analyzer import GroundTruthIssue
from sandbox.models import SandboxResult
from grading.evaluator import EvaluationResult


class BenchmarkReport(BaseModel):
    """Complete, privacy-safe enterprise benchmark report."""
    report_id: str = Field(description="Unique report identifier.")
    scenario_id: str = Field(description="Target scenario ID.")
    dialect: str = Field(default="postgres", description="SQL dialect.")
    difficulty: str = Field(default="medium", description="Difficulty level.")
    timestamp: float = Field(default_factory=time.time, description="Report generation timestamp.")
    privacy_report: Optional[PrivacyReport] = Field(default=None, description="Privacy sanitization report.")
    security_signals: List[Dict[str, Any]] = Field(default_factory=list, description="Advisory injection signals detected.")
    agent_findings: List[StructuredFinding] = Field(default_factory=list, description="Findings submitted by AI agent.")
    ast_evidence: List[GroundTruthIssue] = Field(default_factory=list, description="AST analysis ground truth evidence.")
    sandbox_evidence: Optional[SandboxResult] = Field(default=None, description="Sandbox execution result evidence.")
    evaluation_result: Optional[EvaluationResult] = Field(default=None, description="Multi-dimensional evaluation metrics.")
    overall_score: float = Field(default=0.0, description="Final score strictly clamped to (0.01, 0.99).")
    analysis_status: str = Field(default="authoritative", description="Overall analysis status.")


class AuditSummary(BaseModel):
    """Aggregated metrics summary across multiple benchmark runs."""
    total_episodes: int = Field(default=0, description="Total benchmark evaluation episodes executed.")
    successful_episodes: int = Field(default=0, description="Episodes achieving success threshold.")
    average_score: float = Field(default=0.0, description="Average benchmark score.")
    total_secrets_detected: int = Field(default=0, description="Total secret redaction events.")
    total_pii_detected: int = Field(default=0, description="Total PII redaction events.")
    sandbox_executions: int = Field(default=0, description="Total queries analyzed in sandbox.")
