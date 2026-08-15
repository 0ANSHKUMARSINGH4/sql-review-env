from __future__ import annotations
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from sql_analysis.analyzer import GroundTruthIssue


class ScenarioMetadata(BaseModel):
    """Metadata describing a generated scenario's version and configuration."""
    generator_version: str = Field(default="1.0", description="Scenario generator version.")
    categories: List[str] = Field(default_factory=list, description="Target issue categories present in scenario.")
    schema_complexity: str = Field(default="medium", description="Schema complexity level.")
    dialect: str = Field(default="postgres", description="Target SQL dialect.")


class GeneratedScenario(BaseModel):
    """Structured representation of a benchmark scenario."""
    scenario_id: str = Field(description="Deterministic benchmark scenario identifier.")
    seed: int = Field(description="RNG seed used for deterministic generation.")
    dialect: str = Field(default="postgres", description="SQL dialect: postgres, mysql, sqlite.")
    difficulty: str = Field(default="medium", description="Difficulty level: easy, medium, hard.")
    query: str = Field(description="Target SQL query string.")
    schema_context: str = Field(description="Database table schema context.")
    target_issues: List[GroundTruthIssue] = Field(default_factory=list, description="Ground-truth issues present in scenario.")
    metadata: ScenarioMetadata = Field(description="Scenario metadata.")

    @property
    def schema(self) -> str:
        return self.schema_context
