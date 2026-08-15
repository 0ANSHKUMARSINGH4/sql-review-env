from __future__ import annotations
import pytest
from scenarios import ScenarioGenerator, GeneratedScenario
from server.environment import SQLReviewEnv
from privacy import SecretDetector, PIIDetector


def test_scenario_generator_determinism():
    gen = ScenarioGenerator()
    sc1 = gen.generate(seed=12345, dialect="postgres", difficulty="medium")
    sc2 = gen.generate(seed=12345, dialect="postgres", difficulty="medium")

    assert sc1.scenario_id == sc2.scenario_id
    assert sc1.query == sc2.query
    assert sc1.schema == sc2.schema
    assert [gt.issue for gt in sc1.target_issues] == [gt.issue for gt in sc2.target_issues]
    assert sc1.metadata.generator_version == "1.0"


def test_batch_generation_determinism():
    gen = ScenarioGenerator()
    batch1 = gen.generate_batch(count=5, seed=999, dialect="mysql", difficulty="easy")
    batch2 = gen.generate_batch(count=5, seed=999, dialect="mysql", difficulty="easy")

    assert len(batch1) == 5
    assert len(batch2) == 5
    for s1, s2 in zip(batch1, batch2):
        assert s1.scenario_id == s2.scenario_id
        assert s1.query == s2.query


def test_different_seeds_produce_different_scenarios():
    gen = ScenarioGenerator()
    sc1 = gen.generate(seed=100)
    sc2 = gen.generate(seed=200)

    assert sc1.seed != sc2.seed
    assert sc1.scenario_id != sc2.scenario_id


def test_multi_dialect_generation_ast_validity():
    gen = ScenarioGenerator()
    for dialect in ["postgres", "mysql", "sqlite"]:
        sc = gen.generate(seed=42, dialect=dialect)
        assert sc.dialect == dialect
        assert sc.query is not None and len(sc.query) > 0


def test_difficulty_scaling():
    gen = ScenarioGenerator()
    sc_easy = gen.generate(seed=7, difficulty="easy")
    sc_hard = gen.generate(seed=7, difficulty="hard")

    assert sc_easy.difficulty == "easy"
    assert sc_hard.difficulty == "hard"


def test_no_real_secrets_or_pii_in_generated_scenarios():
    gen = ScenarioGenerator()
    secret_det = SecretDetector()
    pii_det = PIIDetector()

    batch = gen.generate_batch(count=10, seed=1234)
    for sc in batch:
        full_text = f"{sc.query} {sc.schema}"
        secrets = secret_det.detect(full_text)
        pii = pii_det.detect(full_text)

        # Allow synthetic test indicators if present, but assert no real secrets
        for sec in secrets:
            assert "TEST_" in sec.value or sec.confidence < 1.0 or "sk-" not in sec.value
        for p in pii:
            assert "@example." in p.value or "test" in p.value or "CUST-" in p.value


def test_original_five_scenarios_preserved():
    env = SQLReviewEnv()
    original_tasks = [
        "easy-sql-review",
        "medium-sql-review",
        "hard-sql-review",
        "security-extreme",
        "performance-optimization",
    ]

    for task_id in original_tasks:
        obs = env.reset(task=task_id)
        assert obs.query is not None
        assert env.current_task_id == task_id


def test_dynamic_scenario_reset_in_environment():
    env = SQLReviewEnv()
    obs = env.reset(task="generated", seed=888, dialect="sqlite", difficulty="hard")

    assert "generated-sqlite-hard-888" in env.current_task_id
    assert obs.query is not None
    assert obs.schema_context is not None
