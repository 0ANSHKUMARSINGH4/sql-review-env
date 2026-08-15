from __future__ import annotations
import json
import pytest
from scenarios import ScenarioGenerator
from privacy import PrivacyGateway
from security import PromptIsolationManager, MockModelProvider, parse_model_findings_json
from sql_analysis import SQLAnalyzer
from sandbox import SandboxExecutor
from grading import EvidenceBasedEvaluator
from reporting import BenchmarkReport, ReportExporter
from models import SQLReviewAction


def test_full_system_end_to_end_smoke():
    """
    Complete System End-to-End Smoke Test:
    Exercises scenario generation -> privacy gateway -> prompt isolation -> mock provider ->
    Pydantic validation -> AST analysis -> sandbox execution -> evaluator -> report exporter.
    """
    # 1. Scenario Generation
    gen = ScenarioGenerator()
    scenario = gen.generate(seed=777, dialect="postgres", difficulty="medium")
    
    # 2. Privacy Gateway Sanitization
    gateway = PrivacyGateway()
    raw_query = f"{scenario.query} -- User: test@example.invalid Key: TEST_API_KEY_456"
    sanitized_ctx = gateway.sanitize_context(raw_query, scenario.schema)
    
    # 3. Prompt Isolation
    prompt_mgr = PromptIsolationManager()
    sys_prompt, user_prompt, scan_meta = prompt_mgr.build_isolated_prompt(
        sanitized_query=sanitized_ctx.query,
        sanitized_schema=sanitized_ctx.schema_context,
    )
    
    # 4. Mock Provider
    provider = MockModelProvider()
    resp_text = provider.generate(sys_prompt, user_prompt)
    
    # 5. Pydantic Output Validation
    findings, parse_err = parse_model_findings_json(resp_text)
    assert len(findings) > 0
    assert parse_err is None
    
    # 6. AST Analysis & Sandbox Execution
    analyzer = SQLAnalyzer()
    ast_issues, _ = analyzer.analyze(sanitized_ctx.query, sanitized_ctx.schema_context)
    
    sandbox = SandboxExecutor()
    sandbox_res = sandbox.execute(sanitized_ctx.query, sanitized_ctx.schema_context)
    assert sandbox_res.status in ("success", "blocked", "error")
    
    # 7. Evaluator Grading
    action = SQLReviewAction(findings=findings)
    evaluator = EvidenceBasedEvaluator()
    eval_res = evaluator.evaluate(action, scenario.target_issues)
    
    # 8. Report Exporter & Zero Leakage Assertion
    report = BenchmarkReport(
        report_id="smoke-777",
        scenario_id=scenario.scenario_id,
        dialect=scenario.dialect,
        difficulty=scenario.difficulty,
        privacy_report=sanitized_ctx.report,
        agent_findings=findings,
        ast_evidence=ast_issues,
        sandbox_evidence=sandbox_res,
        evaluation_result=eval_res,
        overall_score=eval_res.normalized_score,
    )
    
    exporter = ReportExporter()
    exported_json = exporter.export_json(report)
    
    assert "smoke-777" in exported_json
    assert "TEST_API_KEY_456" not in exported_json
    assert "test@example.invalid" not in exported_json
    assert "token_map" not in exported_json


def test_system_reproducibility():
    """
    Verifies 100% deterministic reproducibility across execution runs.
    """
    gen = ScenarioGenerator()
    sc1 = gen.generate(seed=12345, dialect="postgres", difficulty="hard")
    sc2 = gen.generate(seed=12345, dialect="postgres", difficulty="hard")
    
    assert sc1.scenario_id == sc2.scenario_id
    assert sc1.query == sc2.query
    assert sc1.schema == sc2.schema
    assert [gt.issue for gt in sc1.target_issues] == [gt.issue for gt in sc2.target_issues]
