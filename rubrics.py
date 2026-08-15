from __future__ import annotations
from typing import Any, List, Dict
import re

class Rubric:
    """Base class for rewards (RFC 004 pattern)."""
    def __call__(self, action: Any, observation: Any) -> float:
        return self.forward(action, observation)

    def forward(self, action: Any, observation: Any) -> float:
        raise NotImplementedError

    def reset(self) -> None:
        pass

class SQLReviewRubric(Rubric):
    """
    Evaluates SQL review comments against a set of expected issues.
    Matches keywords in the comment to reward correct findings.
    """
    def __init__(self):
        self.issue_patterns = {
            "sql_injection": r"(sql[ -]?injection|unsanitized|parameterized|prepared statement|injection|binding|concatenation|vulnerable to.*input)",
            "n_plus_one": r"(n\+1|n plus one|loop query|multiple queries|batching|repeatedly.*query|nested call)",
            "missing_index": r"(missing index|indexing|no index|full table scan|search optimization|index hint|add.*index)",
            "inefficient_join": r"(inefficient join|nested loop|cross join|cartesian|join optimization|slow.*join|optimize.*join)",
            "unnecessary_columns": r"(select \*|unnecessary columns|column list|specific columns|star operator|fetch.*all columns)"
        }
        self.found_issues = set()
        self.expected_issues = []

    def set_expected(self, expected_issues: List[str]):
        self.expected_issues = expected_issues

    def forward(self, action: Any, observation: Any) -> float:
        comment = getattr(action, "get_effective_comment", lambda: getattr(action, "review_comment", ""))()
        comment = (comment or "").lower()
        new_findings = []
        
        for issue_id in self.expected_issues:
            if issue_id in self.found_issues:
                continue
                
            pattern = self.issue_patterns.get(issue_id, issue_id.replace("_", " "))
            if re.search(pattern, comment):
                new_findings.append(issue_id)
                self.found_issues.add(issue_id)

        reward = len(new_findings) * 0.5
        return round(reward, 2)

    def reset(self):
        self.found_issues = set()
        self.expected_issues = []


class V2EvidenceRubric(Rubric):
    """V2 Evidence-Based Rubric evaluating structured findings against ground truth."""
    
    def __init__(self):
        from grading.evaluator import EvidenceBasedEvaluator
        self.evaluator = EvidenceBasedEvaluator()
        self.ground_truth = []

    def set_ground_truth(self, ground_truth: List[Any]):
        self.ground_truth = ground_truth

    def forward(self, action: Any, observation: Any) -> float:
        res = self.evaluator.evaluate(action, self.ground_truth)
        return res.normalized_score

class OutcomeRubric(Rubric):
    """Calculates final score (0.0 to 1.0) based on total findings."""
    def forward(self, action: Any, observation: Any) -> float:
        if not getattr(observation, "done", False):
            return 0.0
            
        # This will be used at the end of the episode
        # (Already handled in environment.py step logic for now)
        return 1.0 if observation.issues_remaining == 0 else 0.5
