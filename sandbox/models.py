from __future__ import annotations
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field


class SandboxPolicy(BaseModel):
    """Execution policy controlling sandbox safety boundaries."""
    read_only: bool = Field(default=True, description="Enforce strict read-only execution.")
    allow_explain: bool = Field(default=True, description="Allow EXPLAIN and EXPLAIN QUERY PLAN statements.")
    allow_select: bool = Field(default=True, description="Allow SELECT queries.")
    allow_ddl: bool = Field(default=False, description="Prohibit DDL statements (DROP, ALTER, etc.).")
    allow_dml: bool = Field(default=False, description="Prohibit DML write operations (INSERT, UPDATE, DELETE).")
    allow_attach: bool = Field(default=False, description="Prohibit ATTACH/DETACH DATABASE operations.")
    allow_pragma: bool = Field(default=False, description="Prohibit PRAGMA statements.")
    allow_extensions: bool = Field(default=False, description="Prohibit extension loading.")
    max_sql_length: int = Field(default=100_000, description="Maximum allowed SQL query string length.")
    max_result_rows: int = Field(default=100, description="Maximum result rows returned.")
    max_execution_steps: int = Field(default=100_000, description="SQLite step limit before interruption.")


class ExplainPlanStep(BaseModel):
    """Normalized representation of an EXPLAIN QUERY PLAN step."""
    id: int = Field(description="Step ID.")
    parent: int = Field(description="Parent step ID.")
    detail: str = Field(description="Raw query planner detail string.")
    operation: Optional[str] = Field(default=None, description="Inferred operation (e.g. SCAN, SEARCH).")
    table: Optional[str] = Field(default=None, description="Target table name if detected.")
    index: Optional[str] = Field(default=None, description="Used index name if detected.")


class SandboxResult(BaseModel):
    """Structured result returned by SandboxExecutor."""
    status: Literal["success", "blocked", "timeout", "error"] = Field(description="Execution outcome status.")
    statement_type: Optional[str] = Field(default=None, description="Primary statement type (e.g. SELECT, EXPLAIN).")
    rows_returned: int = Field(default=0, description="Number of query result rows returned.")
    execution_time_ms: float = Field(default=0.0, description="Execution time duration in milliseconds.")
    plan: List[ExplainPlanStep] = Field(default_factory=list, description="Query execution plan steps if EXPLAIN requested.")
    error: Optional[str] = Field(default=None, description="Sanitized error description.")
    blocked_reason: Optional[str] = Field(default=None, description="Reason SQL was blocked by security policy.")
    truncated: bool = Field(default=False, description="Whether query results were truncated at max_result_rows.")
