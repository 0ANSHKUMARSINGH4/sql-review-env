from __future__ import annotations
import random
from typing import List, Dict, Any, Optional, Set
from scenarios.models import GeneratedScenario, ScenarioMetadata
from sql_analysis.ast_parser import SQLASTParser
from sql_analysis.analyzer import SQLAnalyzer, GroundTruthIssue


class ScenarioGenerator:
    """
    Deterministic, reproducible dynamic scenario generator for SQL Review Environment V2.
    Supports PostgreSQL, MySQL, and SQLite dialects across easy, medium, and hard difficulty levels.
    """

    SUPPORTED_DIALECTS = {"postgres", "postgresql", "mysql", "sqlite"}
    SUPPORTED_DIFFICULTIES = {"easy", "medium", "hard"}

    TABLE_TEMPLATES = {
        "users": ["id", "username", "email", "created_at", "status"],
        "orders": ["id", "user_id", "total_amount", "order_date", "status"],
        "products": ["id", "name", "price", "sku", "category_id"],
        "logs": ["id", "user_id", "action", "timestamp", "ip_address"],
    }

    def __init__(self):
        self.parser = SQLASTParser()
        self.analyzer = SQLAnalyzer()

    def generate(
        self,
        seed: int,
        dialect: str = "postgres",
        difficulty: str = "medium",
        issue_types: Optional[List[str]] = None,
        max_attempts: int = 10,
    ) -> GeneratedScenario:
        """
        Generates a single deterministic scenario for a given seed.
        """
        dialect_norm = "postgres" if dialect.lower() in ("postgres", "postgresql") else dialect.lower()
        if dialect_norm not in self.SUPPORTED_DIALECTS:
            dialect_norm = "postgres"

        diff_norm = difficulty.lower() if difficulty.lower() in self.SUPPORTED_DIFFICULTIES else "medium"

        for attempt in range(max_attempts):
            child_seed = seed + (attempt * 10007)
            rng = random.Random(child_seed)

            scenario = self._build_scenario(child_seed, rng, dialect_norm, diff_norm, issue_types)

            # Validate AST Parsing
            parse_res = self.parser.parse(scenario.query, dialect=dialect_norm)
            if parse_res.parse_success:
                return scenario

        # Fallback guaranteed valid scenario if max_attempts reached
        return self._build_fallback(seed, dialect_norm, diff_norm)

    def generate_batch(
        self,
        count: int,
        seed: int,
        dialect: str = "postgres",
        difficulty: str = "medium",
    ) -> List[GeneratedScenario]:
        """
        Generates a reproducible batch of scenarios from a master seed.
        Guarantees unique scenario IDs within the batch.
        """
        batch: List[GeneratedScenario] = []
        seen_ids: Set[str] = set()

        for idx in range(count):
            child_seed = seed + idx
            scenario = self.generate(child_seed, dialect=dialect, difficulty=difficulty)
            
            if scenario.scenario_id not in seen_ids:
                seen_ids.add(scenario.scenario_id)
                batch.append(scenario)
            else:
                # Disambiguate if collision occurs
                scenario.scenario_id = f"{scenario.scenario_id}-b{idx}"
                seen_ids.add(scenario.scenario_id)
                batch.append(scenario)

        return batch

    def _build_scenario(
        self,
        seed: int,
        rng: random.Random,
        dialect: str,
        difficulty: str,
        requested_issues: Optional[List[str]],
    ) -> GeneratedScenario:
        scenario_id = f"generated-{dialect}-{difficulty}-{seed}"

        # Choose primary issue based on difficulty and requested issues
        possible_issues = ["sql_injection", "unnecessary_columns", "inefficient_join", "missing_index"]
        if difficulty == "medium":
            possible_issues.append("n_plus_one")
        elif difficulty == "hard":
            possible_issues.extend(["sql_injection", "inefficient_join", "missing_index"])

        if requested_issues:
            target_issue_cats = requested_issues
        else:
            k = 1 if difficulty == "easy" else (2 if difficulty == "medium" else 3)
            target_issue_cats = rng.sample(possible_issues, min(k, len(possible_issues)))

        query_parts = []
        schema_parts = []

        # Construct Table Schema
        main_table = rng.choice(list(self.TABLE_TEMPLATES.keys()))
        cols = self.TABLE_TEMPLATES[main_table]
        schema_parts.append(f"Table: {main_table} ({', '.join(cols)})")

        if "missing_index" in target_issue_cats:
            schema_parts.append("Indices: PRIMARY KEY (id)")
        elif difficulty != "easy":
            schema_parts.append(f"Indices: PRIMARY KEY (id), INDEX ({cols[1]})")

        # Build SQL Query based on issues
        if "sql_injection" in target_issue_cats:
            user_var = "TEST_USER_INPUT"
            if dialect == "postgres":
                query_parts.append(f"SELECT id, email FROM {main_table} WHERE status = '\" + {user_var} + \"'")
            else:
                query_parts.append(f"SELECT id, email FROM {main_table} WHERE username = '\" + {user_var} + \"'")
        elif "unnecessary_columns" in target_issue_cats:
            query_parts.append(f"SELECT * FROM {main_table} WHERE status = 'active'")
        elif "inefficient_join" in target_issue_cats and main_table != "logs":
            query_parts.append(f"SELECT * FROM {main_table} CROSS JOIN logs WHERE {main_table}.id > 10")
            schema_parts.append(f"Table: logs ({', '.join(self.TABLE_TEMPLATES['logs'])})")
        else:
            query_parts.append(f"SELECT id, username FROM {main_table} WHERE status = 'pending'")

        # Handle N+1 query trace metadata
        if "n_plus_one" in target_issue_cats:
            query_parts.insert(0, "-- Pattern: for item in items: fetch details")

        full_query = "\n".join(query_parts)
        full_schema = " | ".join(schema_parts)

        # Run SQLAnalyzer to extract verified Ground Truth
        verified_gt, _ = self.analyzer.analyze(full_query, schema_context=full_schema, dialect=dialect)

        metadata = ScenarioMetadata(
            generator_version="1.0",
            categories=[gt.issue for gt in verified_gt],
            schema_complexity=difficulty,
            dialect=dialect,
        )

        return GeneratedScenario(
            scenario_id=scenario_id,
            seed=seed,
            dialect=dialect,
            difficulty=difficulty,
            query=full_query,
            schema_context=full_schema,
            target_issues=verified_gt,
            metadata=metadata,
        )

    def _build_fallback(self, seed: int, dialect: str, difficulty: str) -> GeneratedScenario:
        query = "SELECT id, email FROM users WHERE id = 1;"
        schema = "Table: users (id INT, email VARCHAR); Indices: PRIMARY KEY (id)"
        gt, _ = self.analyzer.analyze(query, schema, dialect=dialect)

        return GeneratedScenario(
            scenario_id=f"generated-{dialect}-{difficulty}-{seed}",
            seed=seed,
            dialect=dialect,
            difficulty=difficulty,
            query=query,
            schema_context=schema,
            target_issues=gt,
            metadata=ScenarioMetadata(
                generator_version="1.0",
                categories=[],
                schema_complexity=difficulty,
                dialect=dialect,
            ),
        )
