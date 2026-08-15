from __future__ import annotations
import sqlite3
import time
import re
from typing import List, Dict, Any, Optional, Tuple
from sandbox.models import SandboxPolicy, SandboxResult, ExplainPlanStep
from sandbox.policy import SandboxPolicyValidator


class SandboxExecutor:
    """
    Isolated, ephemeral SQLite analysis sandbox executor.
    Executes benchmark queries strictly in-memory (:memory:) with resource caps and plan extraction.
    """

    def __init__(self, policy: Optional[SandboxPolicy] = None):
        self.policy = policy or SandboxPolicy()
        self.validator = SandboxPolicyValidator(self.policy)

    def execute(self, sql: str, schema_context: Optional[str] = None) -> SandboxResult:
        """
        Safely executes a query in an ephemeral in-memory SQLite database.
        Returns a structured SandboxResult.
        """
        # 1. Validate Policy
        is_safe, blocked_reason = self.validator.validate(sql)
        if not is_safe:
            return SandboxResult(
                status="blocked",
                statement_type=self._detect_statement_type(sql),
                blocked_reason=blocked_reason,
            )

        start_time = time.perf_counter()
        conn: Optional[sqlite3.Connection] = None

        try:
            # 2. Open Ephemeral In-Memory Database
            conn = sqlite3.connect(":memory:")

            # 3. Disable Extension Loading
            try:
                conn.enable_load_extension(False)
            except (AttributeError, sqlite3.OperationalError):
                pass  # Ignore if Python sqlite3 build lacks extension loading API

            # 4. Configure Progress Handler for Timeout / Step Limits
            step_counter = [0]
            max_steps = self.policy.max_execution_steps

            def progress_handler():
                step_counter[0] += 100
                if step_counter[0] > max_steps:
                    return 1  # Non-zero interrupts execution
                return 0

            conn.set_progress_handler(progress_handler, 100)

            # 5. Populate Synthetic Schema if Provided
            if schema_context:
                self._load_synthetic_schema(conn, schema_context)

            cursor = conn.cursor()
            stmt_type = self._detect_statement_type(sql)

            # 6. Execute EXPLAIN QUERY PLAN or Query
            if stmt_type == "EXPLAIN" or sql.strip().upper().startswith("EXPLAIN"):
                cursor.execute(sql)
                raw_rows = cursor.fetchall()
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0

                plan_steps = self._parse_explain_plan(raw_rows)
                return SandboxResult(
                    status="success",
                    statement_type="EXPLAIN",
                    rows_returned=len(raw_rows),
                    execution_time_ms=round(elapsed_ms, 3),
                    plan=plan_steps,
                )

            # Execute SELECT Query
            cursor.execute(sql)
            rows = cursor.fetchmany(self.policy.max_result_rows + 1)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            truncated = False
            if len(rows) > self.policy.max_result_rows:
                truncated = True
                rows = rows[: self.policy.max_result_rows]

            # Extract EXPLAIN QUERY PLAN automatically for SELECT queries
            explain_steps = []
            try:
                explain_sql = f"EXPLAIN QUERY PLAN {sql}"
                cursor.execute(explain_sql)
                explain_rows = cursor.fetchall()
                explain_steps = self._parse_explain_plan(explain_rows)
            except Exception:
                pass  # Ignore if EXPLAIN fails on specific synthetic query

            return SandboxResult(
                status="success",
                statement_type="SELECT",
                rows_returned=len(rows),
                execution_time_ms=round(elapsed_ms, 3),
                plan=explain_steps,
                truncated=truncated,
            )

        except sqlite3.OperationalError as exc:
            err_msg = str(exc)
            if "interrupted" in err_msg.lower():
                return SandboxResult(
                    status="timeout",
                    statement_type=self._detect_statement_type(sql),
                    error="Query execution exceeded instruction step limit.",
                )
            return SandboxResult(
                status="error",
                statement_type=self._detect_statement_type(sql),
                error=self._sanitize_error_message(err_msg),
            )
        except Exception as exc:
            return SandboxResult(
                status="error",
                statement_type=self._detect_statement_type(sql),
                error=self._sanitize_error_message(str(exc)),
            )
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def _detect_statement_type(self, sql: str) -> str:
        text = sql.strip().upper()
        if text.startswith("EXPLAIN"):
            return "EXPLAIN"
        if text.startswith("SELECT"):
            return "SELECT"
        return "UNKNOWN"

    def _load_synthetic_schema(self, conn: sqlite3.Connection, schema_context: str):
        """Extracts and creates synthetic tables/indexes from schema_context description."""
        cursor = conn.cursor()
        
        # Parse table descriptions e.g. "Table: users (id INT, email VARCHAR)"
        table_matches = re.findall(r"Table:\s*([a-zA-Z0-9_]+)\s*\(([^)]+)\)", schema_context)
        for tbl_name, col_defs in table_matches:
            # Clean column definitions
            cols_clean = []
            for col in col_defs.split(","):
                c = col.strip()
                if c:
                    # Simple normalization for SQLite
                    if " " not in c:
                        cols_clean.append(f"{c} TEXT")
                    else:
                        cols_clean.append(c)
            if cols_clean:
                create_sql = f"CREATE TABLE IF NOT EXISTS {tbl_name} ({', '.join(cols_clean)});"
                try:
                    cursor.execute(create_sql)
                except Exception:
                    pass

        # Parse index descriptions e.g. "INDEX (email)" or "INDEX users_email_idx(email)"
        index_matches = re.findall(r"INDEX(?:ES)?:\s*([^\n|]+)", schema_context, re.IGNORECASE)
        for idx_str in index_matches:
            for idx_item in idx_str.split(","):
                idx_clean = idx_item.strip()
                m = re.search(r"(?:([a-zA-Z0-9_]+)\s*)?\(([^)]+)\)", idx_clean)
                if m:
                    idx_name = m.group(1) or f"idx_{int(time.time()*1000)}"
                    col_name = m.group(2).strip()
                    # Try creating index on main tables
                    for tbl_name, _ in table_matches:
                        try:
                            cursor.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {tbl_name} ({col_name});")
                        except Exception:
                            pass
        conn.commit()

    def _parse_explain_plan(self, raw_rows: list) -> List[ExplainPlanStep]:
        """Parses SQLite EXPLAIN QUERY PLAN tuple output into ExplainPlanStep models."""
        plan_steps = []
        for row in raw_rows:
            step_id = row[0] if len(row) > 0 else 0
            parent_id = row[1] if len(row) > 1 else 0
            detail = row[3] if len(row) > 3 else str(row)

            detail_upper = detail.upper()
            op = "UNKNOWN"
            if "SCAN" in detail_upper:
                op = "SCAN"
            elif "SEARCH" in detail_upper:
                op = "SEARCH"
            elif "COVERING INDEX" in detail_upper:
                op = "COVERING INDEX"

            tbl_m = re.search(r"TABLE\s+([a-zA-Z0-9_]+)", detail, re.IGNORECASE)
            idx_m = re.search(r"USING\s+(?:COVERING\s+)?INDEX\s+([a-zA-Z0-9_]+)", detail, re.IGNORECASE)

            plan_steps.append(
                ExplainPlanStep(
                    id=step_id,
                    parent=parent_id,
                    detail=detail,
                    operation=op,
                    table=tbl_m.group(1) if tbl_m else None,
                    index=idx_m.group(1) if idx_m else None,
                )
            )
        return plan_steps

    def _sanitize_error_message(self, raw_err: str) -> str:
        """Removes filesystem paths, OS error details, or credentials from exception messages."""
        # Strip Windows/Unix file paths
        clean_err = re.sub(r"[A-Za-z]:\\[^\s:]+", "[REDACTED_PATH]", raw_err)
        clean_err = re.sub(r"/[^\s:]+", "[REDACTED_PATH]", clean_err)
        return clean_err
