from __future__ import annotations
import pytest
from scenarios import ScenarioGenerator
from privacy import PrivacyGateway
from security import PromptIsolationManager, MockModelProvider, parse_model_findings_json
from grading import EvidenceBasedEvaluator
from models import SQLReviewAction


def test_end_to_end_evaluation_pipeline():
    """
    Tests the full end-to-end evaluation pipeline:
    Generated Scenario -> Privacy Gateway -> Prompt Isolation -> Mock Provider -> Output Validation -> Evaluator -> Reward.
    """
    # 1. Generate dynamic scenario
    gen = ScenarioGenerator()
    scenario = gen.generate(seed=555, dialect="postgres", difficulty="medium")
    
    # 2. Privacy Gateway
    gateway = PrivacyGateway()
    sanitized_ctx = gateway.sanitize_context(scenario.query, scenario.schema)
    
    # 3. Prompt Isolation
    prompt_mgr = PromptIsolationManager()
    sys_prompt, user_prompt, _ = prompt_mgr.build_isolated_prompt(
        sanitized_query=sanitized_ctx.query,
        sanitized_schema=sanitized_ctx.schema_context,
    )
    
    # 4. Mock Model Provider
    provider = MockModelProvider()
    response_text = provider.generate(sys_prompt, user_prompt)
    
    # 5. Output Validation
    findings, parse_err = parse_model_findings_json(response_text)
    assert len(findings) > 0
    assert parse_err is None
    
    # 6. Evidence-Based Evaluator
    action = SQLReviewAction(findings=findings)
    evaluator = EvidenceBasedEvaluator()
    eval_result = evaluator.evaluate(action, scenario.target_issues)
    
    assert eval_result.normalized_score >= 0.0
    assert eval_result.normalized_score <= 1.0
    assert eval_result.analysis_status in ("authoritative", "candidate_aware")
