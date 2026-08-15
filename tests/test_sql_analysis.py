from __future__ import annotations
import pytest
from sql_analysis import SQLASTParser, SQLAnalyzer, format_numbered_sql, GroundTruthIssue


def test_sql_ast_parser_dialects():
    parser = SQLASTParser()

    # PostgreSQL
    res_pg = parser.parse("SELECT id, email FROM users WHERE id = 10;", dialect="postgres")
    assert res_pg.parse_success is True
    assert res_pg.dialect == "postgres"

    # MySQL
    res_mysql = parser.parse("SELECT `id`, `email` FROM `users` LIMIT 5;", dialect="mysql")
    assert res_mysql.parse_success is True
    assert res_mysql.dialect == "mysql"

    # SQLite
    res_sqlite = parser.parse("SELECT id FROM users WHERE age >= 18;", dialect="sqlite")
    assert res_sqlite.parse_success is True
    assert res_sqlite.dialect == "sqlite"


def test_sql_ast_parser_malformed_and_empty():
    parser = SQLASTParser()

    # Empty SQL
    res_empty = parser.parse("")
    assert res_empty.parse_success is False
    assert res_empty.error_type == "EmptySQLError"

    # Malformed SQL
    res_malformed = parser.parse("SELECT FROM WHERE WHERE === INVALID !!!")
    assert res_malformed.parse_success is False
    assert res_malformed.error_type == "SQLParseError"


def test_unnecessary_columns_confirmed():
    analyzer = SQLAnalyzer()
    sql = "SELECT * FROM users WHERE status = 'active';"
    issues, parse_res = analyzer.analyze(sql)

    assert parse_res.parse_success is True
    unnecessary = [i for i in issues if i.issue == "unnecessary_columns"]
    assert len(unnecessary) == 1
    assert unnecessary[0].status == "confirmed"
    assert unnecessary[0].confidence == 1.0


def test_cross_join_confirmed():
    analyzer = SQLAnalyzer()
    sql = "SELECT a.name, b.title FROM authors a CROSS JOIN books b;"
    issues, parse_res = analyzer.analyze(sql)

    assert parse_res.parse_success is True
    joins = [i for i in issues if i.issue == "inefficient_join"]
    assert len(joins) == 1
    assert joins[0].status == "confirmed"


def test_sql_injection_confirmed():
    analyzer = SQLAnalyzer()
    sql = "SELECT * FROM users WHERE username = '\" + user_input + \"'"
    issues, parse_res = analyzer.analyze(sql)

    sqli = [i for i in issues if i.issue == "sql_injection"]
    assert len(sqli) == 1
    assert sqli[0].status == "confirmed"
    assert sqli[0].severity == "critical"


def test_candidate_vs_confirmed_missing_index():
    analyzer = SQLAnalyzer()
    sql = "SELECT id, name FROM users WHERE email = 'john@example.com';"
    
    # Scenario A: No schema index info provided -> candidate ONLY
    issues_no_schema, _ = analyzer.analyze(sql, schema_context=None)
    missing_cand = [i for i in issues_no_schema if i.issue == "missing_index"]
    assert len(missing_cand) == 1
    assert missing_cand[0].status == "candidate"

    # Scenario B: Schema lists indices, but email is unindexed -> confirmed
    schema_with_index = "Table: users (id INT, name VARCHAR, email VARCHAR); Indices: PRIMARY KEY (id)"
    issues_schema, _ = analyzer.analyze(sql, schema_context=schema_with_index)
    missing_conf = [i for i in issues_schema if i.issue == "missing_index"]
    assert len(missing_conf) == 1
    assert missing_conf[0].status == "confirmed"


def test_standalone_query_does_not_manufacture_confirmed_n_plus_one():
    analyzer = SQLAnalyzer()
    sql = "SELECT id, title FROM posts WHERE user_id = 10;"
    issues, _ = analyzer.analyze(sql)

    n1_issues = [i for i in issues if i.issue == "n_plus_one"]
    # Single standalone query without loop trace metadata must NOT manufacture a confirmed N+1 finding
    for n1 in n1_issues:
        assert n1.status != "confirmed"


def test_format_numbered_sql():
    sql = "SELECT *\nFROM users\nWHERE id = 1;"
    numbered = format_numbered_sql(sql)
    
    assert "1 | SELECT *" in numbered
    assert "2 | FROM users" in numbered
    assert "3 | WHERE id = 1;" in numbered
