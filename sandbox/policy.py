from __future__ import annotations
import re
from typing import Tuple, Optional
from sandbox.models import SandboxPolicy
from sqlglot import exp, parse, parse_one


class SandboxPolicyValidator:
    """
    Fail-closed security policy validator for isolated SQL analysis sandbox.
    Validates statements before SQLite execution.
    """

    PROHIBITED_KEYWORDS = {
        "DROP", "TRUNCATE", "ALTER", "ATTACH", "DETACH", "VACUUM",
        "PRAGMA", "INSERT", "UPDATE", "DELETE", "REPLACE",
        "LOAD_EXTENSION", "GRANT", "REVOKE", "EXEC", "EXECUTE",
    }

    def __init__(self, policy: Optional[SandboxPolicy] = None):
        self.policy = policy or SandboxPolicy()

    def validate(self, sql: str) -> Tuple[bool, Optional[str]]:
        """
        Validates SQL string against security policy.
        Returns (is_allowed, blocked_reason).
        """
        if not sql or not sql.strip():
            return False, "Empty SQL query string."

        sql_text = sql.strip()

        # 1. Query Length Check
        if len(sql_text) > self.policy.max_sql_length:
            return False, f"SQL query length ({len(sql_text)}) exceeds maximum allowed limit ({self.policy.max_sql_length})."

        # 2. Multi-statement Check
        cleaned_statements = [stmt.strip() for stmt in self._split_statements(sql_text) if stmt.strip()]
        if len(cleaned_statements) > 1:
            return False, "Multi-statement SQL execution is strictly prohibited."

        single_sql = cleaned_statements[0]

        # 3. Keyword / Regex Prohibited Pattern Inspection
        sql_upper = single_sql.upper()
        
        # Remove string literals and comments before checking keywords
        no_literals = re.sub(r"'[^']*'", "''", single_sql)
        no_comments = re.sub(r"--[^\n]*", "", no_literals)
        no_comments = re.sub(r"/\*[\s\S]*?\*/", "", no_comments)
        code_upper = no_comments.upper()

        for kw in self.PROHIBITED_KEYWORDS:
            pattern = r"\b" + re.escape(kw) + r"\b"
            if re.search(pattern, code_upper):
                return False, f"Prohibited SQL operation detected: '{kw}'."

        # Check for extension loading functions
        if "LOAD_EXTENSION" in code_upper:
            return False, "Prohibited function call: load_extension."

        # 4. AST Statement Classification & Read-Only Enforcement
        try:
            expressions = parse(single_sql)
            if not expressions or expressions[0] is None:
                return False, "Unable to parse SQL statement AST."
            
            first_ast = expressions[0]
            if isinstance(first_ast, exp.Select):
                if not self.policy.allow_select:
                    return False, "SELECT statements are not allowed by policy."
            elif isinstance(first_ast, (exp.Explain, exp.Command)):
                if "EXPLAIN" in code_upper and not self.policy.allow_explain:
                    return False, "EXPLAIN statements are not allowed by policy."
            else:
                # Under read-only fail-closed policy, block any non-SELECT / non-EXPLAIN expression
                if not (code_upper.startswith("SELECT") or code_upper.startswith("EXPLAIN")):
                    return False, f"Statement type '{first_ast.__class__.__name__}' is not permitted under read-only policy."
        except Exception:
            # Under fail-closed design, if AST parsing fails or statement is unclassifiable, block if not starting with SELECT/EXPLAIN
            if not (code_upper.startswith("SELECT") or code_upper.startswith("EXPLAIN")):
                return False, "Unclassifiable SQL statement blocked under fail-closed security policy."

        return True, None

    def _split_statements(self, sql: str) -> list[str]:
        """Splits multi-statement SQL strings while ignoring semicolons inside string literals."""
        statements = []
        current = []
        in_string = False
        quote_char = None
        
        i = 0
        while i < len(sql):
            char = sql[i]
            if char in ("'", '"'):
                if not in_string:
                    in_string = True
                    quote_char = char
                elif quote_char == char:
                    in_string = False
                    quote_char = None
            elif char == ";" and not in_string:
                statements.append("".join(current))
                current = []
                i += 1
                continue
            current.append(char)
            i += 1

        if current:
            statements.append("".join(current))

        return statements
