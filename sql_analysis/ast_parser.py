from __future__ import annotations
from typing import Optional, List, Dict, Any
import sqlglot
from sqlglot import parse_one, parse
from sqlglot.expressions import Expression
from sqlglot.errors import ParseError


class ParseResult:
    """Encapsulates the result of a SQL AST parsing operation."""

    def __init__(
        self,
        parse_success: bool,
        expression: Optional[Expression] = None,
        expressions: Optional[List[Expression]] = None,
        error_type: Optional[str] = None,
        error_message: Optional[str] = None,
        dialect: str = "postgres",
    ):
        self.parse_success = parse_success
        self.expression = expression
        self.expressions = expressions or ([expression] if expression else [])
        self.error_type = error_type
        self.error_message = error_message
        self.dialect = dialect


class SQLASTParser:
    """
    Multi-dialect SQL AST Parser wrapping SQLGlot.
    Supports PostgreSQL, MySQL, and SQLite safely without throwing unhandled exceptions.
    """

    DIALECT_MAP = {
        "postgres": "postgres",
        "postgresql": "postgres",
        "mysql": "mysql",
        "sqlite": "sqlite",
    }

    def parse(self, sql: str, dialect: str = "postgres") -> ParseResult:
        if not sql or not sql.strip():
            return ParseResult(
                parse_success=False,
                error_type="EmptySQLError",
                error_message="SQL string is empty.",
                dialect=dialect,
            )

        target_dialect = self.DIALECT_MAP.get(dialect.lower(), "postgres")

        try:
            # Parse multiple statements if semicolon present, or single expression
            parsed_list = parse(sql.strip(), read=target_dialect)
            # Remove None entries if any
            valid_exprs = [e for e in parsed_list if e is not None]

            if not valid_exprs:
                # Try single expression parse_one
                single_expr = parse_one(sql.strip(), read=target_dialect)
                if single_expr:
                    valid_exprs = [single_expr]

            if not valid_exprs:
                return ParseResult(
                    parse_success=False,
                    error_type="SQLParseError",
                    error_message="Could not parse valid AST expressions from SQL string.",
                    dialect=target_dialect,
                )

            return ParseResult(
                parse_success=True,
                expression=valid_exprs[0],
                expressions=valid_exprs,
                dialect=target_dialect,
            )

        except ParseError as pe:
            return ParseResult(
                parse_success=False,
                error_type="SQLParseError",
                error_message=str(pe),
                dialect=target_dialect,
            )
        except Exception as exc:
            return ParseResult(
                parse_success=False,
                error_type=exc.__class__.__name__,
                error_message=str(exc),
                dialect=target_dialect,
            )
