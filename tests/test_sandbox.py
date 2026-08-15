from __future__ import annotations
import pytest
import inspect
from sandbox import SandboxExecutor, SandboxPolicy, SandboxPolicyValidator


def test_sandbox_allowed_select():
    executor = SandboxExecutor()
    schema = "Table: users (id INT, email VARCHAR)"
    res = executor.execute("SELECT id FROM users;", schema_context=schema)

    assert res.status == "success"
    assert res.statement_type == "SELECT"
    assert res.error is None
    assert res.blocked_reason is None


def test_sandbox_explain_query_plan():
    executor = SandboxExecutor()
    schema = "Table: users (id INT, email VARCHAR)"
    res = executor.execute("EXPLAIN QUERY PLAN SELECT id FROM users;", schema_context=schema)

    assert res.status == "success"
    assert res.statement_type == "EXPLAIN"
    assert len(res.plan) > 0


def test_sandbox_blocked_destructive_ddl_dml():
    executor = SandboxExecutor()
    schema = "Table: users (id INT, email VARCHAR)"

    destructive_queries = [
        ("DROP TABLE users;", "DROP"),
        ("TRUNCATE TABLE users;", "TRUNCATE"),
        ("ALTER TABLE users ADD COLUMN age INT;", "ALTER"),
        ("INSERT INTO users (id, email) VALUES (1, 'a');", "INSERT"),
        ("UPDATE users SET email = 'b' WHERE id = 1;", "UPDATE"),
        ("DELETE FROM users WHERE id = 1;", "DELETE"),
        ("REPLACE INTO users (id, email) VALUES (1, 'c');", "REPLACE"),
    ]

    for sql, expected_kw in destructive_queries:
        res = executor.execute(sql, schema_context=schema)
        assert res.status == "blocked", f"Query '{sql}' was not blocked!"
        assert res.blocked_reason is not None
        assert expected_kw in res.blocked_reason


def test_sandbox_blocked_attach_detach():
    executor = SandboxExecutor()
    res_attach = executor.execute("ATTACH DATABASE 'test.db' AS ext;")
    res_detach = executor.execute("DETACH DATABASE ext;")

    assert res_attach.status == "blocked"
    assert "ATTACH" in res_attach.blocked_reason
    assert res_detach.status == "blocked"
    assert "DETACH" in res_detach.blocked_reason


def test_sandbox_blocked_pragma_and_load_extension():
    executor = SandboxExecutor()
    res_pragma = executor.execute("PRAGMA user_version;")
    res_ext = executor.execute("SELECT load_extension('native_lib.so');")

    assert res_pragma.status == "blocked"
    assert "PRAGMA" in res_pragma.blocked_reason
    assert res_ext.status == "blocked"


def test_sandbox_blocked_multi_statement():
    executor = SandboxExecutor()
    sql = "SELECT 1; DROP TABLE users;"
    res = executor.execute(sql)

    assert res.status == "blocked"
    assert "Multi-statement" in res.blocked_reason


def test_sandbox_oversized_sql_length():
    policy = SandboxPolicy(max_sql_length=100)
    executor = SandboxExecutor(policy=policy)
    oversized_sql = "SELECT " + "a, " * 50 + "b FROM users;"
    res = executor.execute(oversized_sql)

    assert res.status == "blocked"
    assert "exceeds maximum allowed limit" in res.blocked_reason


def test_sandbox_result_row_truncation():
    policy = SandboxPolicy(max_result_rows=5)
    executor = SandboxExecutor(policy=policy)
    
    # Create schema with data generator
    schema = "Table: nums (id INT)"
    # Execute query generating sequence using WITH RECURSIVE
    res = executor.execute(
        "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x<20) SELECT x FROM cnt;",
        schema_context=schema,
    )

    assert res.status == "success"
    assert res.rows_returned == 5
    assert res.truncated is True


def test_sandbox_timeout_step_limit():
    policy = SandboxPolicy(max_execution_steps=100)
    executor = SandboxExecutor(policy=policy)
    
    # Heavy recursive query exceeding step limit
    heavy_sql = "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt) SELECT x FROM cnt;"
    res = executor.execute(heavy_sql)

    assert res.status == "timeout"
    assert "instruction step limit" in res.error or "interrupted" in res.error.lower()


def test_sandbox_explain_indexed_vs_unindexed_query():
    executor = SandboxExecutor()
    schema_indexed = "Table: users (id INT, email VARCHAR) | Indices: users_email_idx(email)"
    schema_unindexed = "Table: users (id INT, email VARCHAR)"

    res_idx = executor.execute("SELECT id FROM users WHERE email = 'test@example.invalid';", schema_context=schema_indexed)
    res_unidx = executor.execute("SELECT id FROM users WHERE email = 'test@example.invalid';", schema_context=schema_unindexed)

    assert res_idx.status == "success"
    assert res_unidx.status == "success"
    assert len(res_idx.plan) > 0
    assert len(res_unidx.plan) > 0


def test_sandbox_host_and_network_isolation():
    from sandbox import executor, policy, models
    
    for module in (executor, policy, models):
        src = inspect.getsource(module)
        assert "requests" not in src
        assert "httpx" not in src
        assert "urllib" not in src
        assert "subprocess" not in src
        assert "os.system" not in src


def test_sandbox_sanitized_error_messages():
    executor = SandboxExecutor()
    res = executor.execute("SELECT * FROM non_existent_table_xyz;")

    assert res.status == "error"
    assert res.error is not None
    assert "C:\\Users\\" not in res.error
    assert "/home/" not in res.error
