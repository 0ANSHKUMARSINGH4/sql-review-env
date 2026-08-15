"""
Grading and Evaluation module for SQL Review Environment V2.
Provides evidence-based multi-dimensional evaluation, precision/recall/F1 metrics,
and false-positive/duplicate penalties.
"""

from grading.evaluator import (
    EvidenceBasedEvaluator,
    FindingEvaluation,
    EvaluationResult,
)

__all__ = [
    "EvidenceBasedEvaluator",
    "FindingEvaluation",
    "EvaluationResult",
]
