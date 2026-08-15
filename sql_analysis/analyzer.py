from __future__ import annotations
import re
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import sqlglot
from sqlglot import expressions as exp
from sql_analysis.ast_parser import SQLASTParser, ParseResult


class GroundTruthIssue(BaseModel):
    """Structured internal ground-truth issue representation."""
    issue: str = Field(description="Issue type: sql_injection, n_plus_one, missing_index, inefficient_join, unnecessary_columns.")
    severity: str = Field(description="Severity: critical, high, medium, low, info.")
    line: Optional[int] = Field(default=None, description="1-indexed line number where issue occurs.")
    evidence: str = Field(description="Deterministic explanation of why this issue was identified.")
    recommendation: Optional[str] = Field(default=None, description="Suggested remediation for the issue.")
    status: str = Field(default="confirmed", description="Issue certainty: 'confirmed' or 'candidate'.")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0.")


def format_numbered_sql(sql: str) -> str:
    """Formats SQL with deterministic line numbers while preserving original boundaries."""
    if not sql:
        return ""
    lines = sql.splitlines()
    width = len(str(len(lines)))
    numbered_lines = [f"{i+1:>{width}} | {line}" for i, line in enumerate(lines)]
    return "\n".join(numbered_lines)


class SQLAnalyzer:
    """
    Analyzes SQL AST structures and schema contexts to produce deterministic
    GroundTruthIssue findings.
    
    Enforces the credibility bar: distinguishes between CONFIRMED structural facts
    and CANDIDATE inferences when evidence is incomplete.
    """

    def __init__(self):
        self.parser = SQLASTParser()

    def analyze(
        self,
        sql: str,
        schema_context: Optional[str] = None,
        dialect: str = "postgres"
    ) -> Tuple[List[GroundTruthIssue], ParseResult]:
        """
        Analyzes a SQL query and optional schema context.
        Returns a tuple of (List[GroundTruthIssue], ParseResult).
        """
        parse_result = self.parser.parse(sql, dialect=dialect)
        issues: List[GroundTruthIssue] = []

        if not parse_result.parse_success:
            # If parsing fails, fall back to robust heuristic analysis
            heuristic_issues = self._analyze_heuristics(sql, schema_context)
            return heuristic_issues, parse_result

        # AST Structural Analysis
        expr = parse_result.expression
        lines = sql.splitlines()

        # 1. SELECT * / Unnecessary Columns Analysis (CONFIRMED)
        for select_expr in expr.find_all(exp.Select):
            for projection in select_expr.expressions:
                if isinstance(projection, exp.Star) or projection.find(exp.Star):
                    line_no = self._find_line_number(lines, "select", "*")
                    issues.append(
                        GroundTruthIssue(
                            issue="unnecessary_columns",
                            severity="low",
                            line=line_no,
                            evidence="Detected 'SELECT *' wildcard projection in query.",
                            recommendation="Explicitly list required columns instead of fetching all columns with '*'.",
                            status="confirmed",
                            confidence=1.0,
                        )
                    )
                    break  # Avoid duplicate finding per select clause

        # 2. Inefficient JOIN Analysis (CONFIRMED for CROSS JOIN, CANDIDATE for Cartesian product)
        for join_expr in expr.find_all(exp.Join):
            join_kind = str(join_expr.args.get("kind", "")).upper()
            join_on = join_expr.args.get("on")
            
            if "CROSS" in join_kind or ("CROSS" in str(join_expr).upper() and not join_on):
                line_no = self._find_line_number(lines, "join", "cross")
                issues.append(
                    GroundTruthIssue(
                        issue="inefficient_join",
                        severity="medium",
                        line=line_no,
                        evidence="Detected explicit 'CROSS JOIN' operation resulting in a Cartesian product.",
                        recommendation="Use an INNER or LEFT JOIN with explicit join predicates.",
                        status="confirmed",
                        confidence=0.95,
                    )
                )

        # 3. SQL Injection Analysis (CONFIRMED for dynamic execution/concat)
        sql_lower = sql.lower()
        if re.search(r"(?i)\bexec(?:ute)?\s*\(", sql) or "'+ " in sql or " + '" in sql or "+\"" in sql or "'\"" in sql or "\"'" in sql:
            line_no = self._find_line_number(lines, "exec", "+", "'\"")
            issues.append(
                GroundTruthIssue(
                    issue="sql_injection",
                    severity="critical",
                    line=line_no,
                    evidence="Dynamic SQL concatenation or unparameterized EXEC construct detected.",
                    recommendation="Use parameterized query parameters or prepared statements.",
                    status="confirmed",
                    confidence=0.98,
                )
            )
        elif "where" in sql_lower and (" + " in sql or " || " in sql or " + " in sql_lower):
            line_no = self._find_line_number(lines, "where")
            issues.append(
                GroundTruthIssue(
                    issue="sql_injection",
                    severity="critical",
                    line=line_no,
                    evidence="String concatenation detected in WHERE clause predicate.",
                    recommendation="Bind input variables using query parameters.",
                    status="confirmed",
                    confidence=0.90,
                )
            )

        # 4. N+1 Query Analysis (CANDIDATE ONLY for standalone queries with loop trace metadata)
        if re.search(r"(?i)(loop|for\s+in\s+|repeatedly|n\+1)", sql) or (schema_context and re.search(r"(?i)n\+1", schema_context)):
            issues.append(
                GroundTruthIssue(
                    issue="n_plus_one",
                    severity="high",
                    line=1,
                    evidence="Application query pattern indicates repeated single-row queries inside an execution loop.",
                    recommendation="Batch queries using IN clauses, JOINs, or eager loading.",
                    status="candidate",
                    confidence=0.75,
                )
            )

        # 5. Missing Index Analysis (CONFIRMED if schema index info present, CANDIDATE if missing)
        if "where" in sql_lower:
            where_match = re.search(r"(?i)where\s+([a-zA-Z0-9_\.]+)", sql)
            where_col = where_match.group(1) if where_match else "filtered_column"
            
            if schema_context and re.search(r"(?i)index|indices", schema_context):
                # Separate table columns from explicit index declaration
                idx_part = schema_context.split("Indices:", 1)[-1] if "Indices:" in schema_context else schema_context
                if where_col.lower() not in idx_part.lower():
                    issues.append(
                        GroundTruthIssue(
                            issue="missing_index",
                            severity="medium",
                            line=self._find_line_number(lines, "where"),
                            evidence=f"WHERE clause filters on column '{where_col}' which is not in configured table indices.",
                            recommendation=f"Add a database index on column '{where_col}'.",
                            status="confirmed",
                            confidence=0.85,
                        )
                    )
            else:
                # Schema lacks index details -> CANDIDATE ONLY
                issues.append(
                    GroundTruthIssue(
                        issue="missing_index",
                        severity="medium",
                        line=self._find_line_number(lines, "where"),
                        evidence=f"Query filters on '{where_col}'. Index availability cannot be verified without schema index statistics.",
                        recommendation=f"Verify if column '{where_col}' has a supporting index.",
                        status="candidate",
                        confidence=0.50,
                    )
                )

        return issues, parse_result

    def _analyze_heuristics(
        self, sql: str, schema_context: Optional[str]
    ) -> List[GroundTruthIssue]:
        """Fallback analysis when AST parsing cannot be completed."""
        issues: List[GroundTruthIssue] = []
        sql_lower = sql.lower()
        lines = sql.splitlines()

        if "select *" in sql_lower:
            issues.append(
                GroundTruthIssue(
                    issue="unnecessary_columns",
                    severity="low",
                    line=self._find_line_number(lines, "select"),
                    evidence="Heuristic match: 'SELECT *' wildcard projection detected.",
                    recommendation="Explicitly list required columns.",
                    status="confirmed",
                    confidence=0.90,
                )
            )

        if "exec(" in sql_lower or "'+ " in sql or " + '" in sql:
            issues.append(
                GroundTruthIssue(
                    issue="sql_injection",
                    severity="critical",
                    line=self._find_line_number(lines, "exec", "+"),
                    evidence="Heuristic match: Dynamic string concatenation or EXEC detected.",
                    recommendation="Use parameterized queries.",
                    status="confirmed",
                    confidence=0.90,
                )
            )

        return issues

    def _find_line_number(self, lines: List[str], *keywords: str) -> Optional[int]:
        for idx, line in enumerate(lines, 1):
            line_lower = line.lower()
            if any(kw.lower() in line_lower for kw in keywords):
                return idx
        return 1 if lines else None
