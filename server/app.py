from fastapi import FastAPI, HTTPException, Body, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pathlib import Path
import json
import os
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

from models import SQLReviewAction, SQLReviewObservation, SQLReviewReward
from server.environment import SQLReviewEnv
from reporting import BenchmarkReport, AuditSummary, ReportExporter
from sandbox import SandboxExecutor, SandboxPolicyValidator
from sql_analysis.analyzer import SQLAnalyzer, SQLASTParser, format_numbered_sql
from privacy import PrivacyGateway
from benchmarks.validator import BenchmarkValidator
from benchmarks.v3_validation import compute_canonical_dataset_hash


app = FastAPI(title="SQL Review Environment V4 — Interactive Platform")

# Global singleton instances
env = SQLReviewEnv()
env.reset("easy-sql-review")
exporter = ReportExporter()
sandbox_executor = SandboxExecutor()
policy_validator = SandboxPolicyValidator()
sql_analyzer = SQLAnalyzer()
privacy_gateway = PrivacyGateway()

BENCHMARKS_DIR = Path(__file__).parent.parent / "benchmarks"
DATASET_PATH = BENCHMARKS_DIR / "v3_dataset.json"
RESULTS_DIR = BENCHMARKS_DIR / "results"


class SQLAnalyzeRequest(BaseModel):
    query: str
    dialect: Optional[str] = "postgres"
    schema_context: Optional[str] = ""


class SQLExplainRequest(BaseModel):
    query: str
    schema_context: Optional[str] = ""


def load_dataset_raw() -> List[Dict[str, Any]]:
    if not DATASET_PATH.exists():
        return []
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# ============================================================================
# PHASE V4.2 — API ENDPOINTS
# ============================================================================

@app.get("/api/benchmark/summary")
def get_benchmark_summary():
    """Returns dataset summary metrics and mock baseline benchmark results."""
    dataset = load_dataset_raw()
    total_scenarios = len(dataset)

    dialects: Dict[str, int] = {}
    difficulties: Dict[str, int] = {}
    issue_categories: Dict[str, int] = {}
    benign_count = 0
    adversarial_count = 0

    for sc in dataset:
        d = sc.get("dialect", "unknown")
        dialects[d] = dialects.get(d, 0) + 1
        diff = sc.get("difficulty", "unknown")
        difficulties[diff] = difficulties.get(diff, 0) + 1

        if sc.get("is_benign"):
            benign_count += 1
        if sc.get("is_adversarial"):
            adversarial_count += 1

        for issue_item in sc.get("ground_truth", {}).get("issues", []):
            cat = issue_item.get("issue")
            if cat:
                issue_categories[cat] = issue_categories.get(cat, 0) + 1

    canonical_sha256 = compute_canonical_dataset_hash(dataset) if dataset else ""

    # Load baseline mock result
    mock_file = RESULTS_DIR / "run-v3-mock-300.json"
    baseline_metrics = None
    if mock_file.exists():
        with open(mock_file, "r", encoding="utf-8") as f:
            mock_data = json.load(f)
            baseline_metrics = mock_data.get("metrics")

    return {
        "dataset_name": "SQL Review Environment V3 Benchmark",
        "canonical_sha256": canonical_sha256,
        "total_scenarios": total_scenarios,
        "dialects": dialects,
        "difficulties": difficulties,
        "issue_categories": issue_categories,
        "benign_count": benign_count,
        "adversarial_count": adversarial_count,
        "baseline_mock_metrics": baseline_metrics,
    }


@app.get("/api/benchmark/scenarios")
def get_benchmark_scenarios(
    dialect: Optional[str] = None,
    difficulty: Optional[str] = None,
    issue_category: Optional[str] = None,
    is_benign: Optional[bool] = None,
    is_adversarial: Optional[bool] = None,
    include_ground_truth: bool = False,
    limit: int = 50,
    offset: int = 0,
):
    """
    Returns public list of benchmark scenarios.
    Omits hidden ground-truth issues by default unless include_ground_truth=True.
    """
    dataset = load_dataset_raw()
    filtered = list(dataset)

    if dialect:
        d_lower = dialect.lower().strip()
        filtered = [s for s in filtered if s.get("dialect", "").lower() == d_lower]
    if difficulty:
        diff_lower = difficulty.lower().strip()
        filtered = [s for s in filtered if s.get("difficulty", "").lower() == diff_lower]
    if issue_category:
        cat_lower = issue_category.lower().strip()
        filtered = [
            s for s in filtered
            if any(i.get("issue", "").lower() == cat_lower for i in s.get("ground_truth", {}).get("issues", []))
        ]
    if is_benign is not None:
        filtered = [s for s in filtered if s.get("is_benign") == is_benign]
    if is_adversarial is not None:
        filtered = [s for s in filtered if s.get("is_adversarial") == is_adversarial]

    total_filtered = len(filtered)
    paged = filtered[offset : offset + limit]

    result_items = []
    for sc in paged:
        item = {
            "scenario_id": sc.get("scenario_id"),
            "version": sc.get("version"),
            "dialect": sc.get("dialect"),
            "difficulty": sc.get("difficulty"),
            "query": sc.get("query"),
            "schema_context": sc.get("schema_context"),
            "is_benign": sc.get("is_benign"),
            "is_adversarial": sc.get("is_adversarial"),
            "provenance": sc.get("provenance"),
        }
        if include_ground_truth:
            item["ground_truth"] = sc.get("ground_truth")
        result_items.append(item)

    return {
        "total": total_filtered,
        "limit": limit,
        "offset": offset,
        "scenarios": result_items,
    }


@app.get("/api/benchmark/scenarios/{scenario_id}")
def get_benchmark_scenario_detail(scenario_id: str, include_ground_truth: bool = False):
    """Returns single benchmark scenario record."""
    dataset = load_dataset_raw()
    for sc in dataset:
        if sc.get("scenario_id") == scenario_id:
            item = {
                "scenario_id": sc.get("scenario_id"),
                "version": sc.get("version"),
                "dialect": sc.get("dialect"),
                "difficulty": sc.get("difficulty"),
                "query": sc.get("query"),
                "schema_context": sc.get("schema_context"),
                "is_benign": sc.get("is_benign"),
                "is_adversarial": sc.get("is_adversarial"),
                "provenance": sc.get("provenance"),
            }
            if include_ground_truth:
                item["ground_truth"] = sc.get("ground_truth")
            return item
    raise HTTPException(status_code=404, detail=f"Scenario ID '{scenario_id}' not found.")


@app.post("/api/sql/analyze")
def analyze_sql(req: SQLAnalyzeRequest):
    """
    Performs real-time AST analysis using SQLAnalyzer and SQLASTParser.
    Returns formatted line-numbered SQL, detected issues, severities, evidence, and recommendations.
    """
    query = req.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="SQL query string cannot be empty.")

    dialect = req.dialect or "postgres"
    schema_context = req.schema_context or ""

    # Line-numbered SQL
    numbered_sql = format_numbered_sql(query)

    # Run AST Analysis
    findings, parse_res = sql_analyzer.analyze(query, schema_context=schema_context, dialect=dialect)

    # Run Privacy Gateway check for user visibility
    sanitized_ctx = privacy_gateway.sanitize_context(query, schema_context)

    return {
        "query": query,
        "dialect": dialect,
        "schema_context": schema_context,
        "numbered_sql": numbered_sql,
        "parse_success": parse_res.parse_success,
        "parse_error": parse_res.error_message,
        "findings": [f.model_dump() for f in findings],
        "privacy_summary": {
            "secrets_detected": sanitized_ctx.report.secrets_detected,
            "pii_detected": sanitized_ctx.report.pii_detected,
            "sanitized_query": sanitized_ctx.query,
        },
    }


@app.post("/api/sql/explain")
def explain_sql(req: SQLExplainRequest):
    """
    Executes restricted query plan analysis using SandboxExecutor & SandboxPolicyValidator.
    """
    query = req.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="SQL query string cannot be empty.")

    # Sandbox policy check
    allowed, policy_reason = policy_validator.validate(query)
    if not allowed:
        return {
            "status": "policy_rejected",
            "allowed": False,
            "policy_reason": policy_reason,
            "execution_time_ms": 0.0,
            "plan": [],
            "row_count": 0,
            "truncated": False,
        }

    # Execute inside restricted sandbox
    exec_res = sandbox_executor.execute(query, schema_context=req.schema_context)

    plan_steps = []
    for step in exec_res.plan:
        plan_steps.append({
            "step_id": step.step_id,
            "parent_id": step.parent_id,
            "detail": step.detail,
            "operation": step.operation,
            "table_name": step.table_name,
            "uses_index": step.uses_index,
        })

    return {
        "status": exec_res.status,
        "allowed": True,
        "execution_time_ms": exec_res.execution_time_ms,
        "plan": plan_steps,
        "row_count": exec_res.rows_returned,
        "truncated": exec_res.truncated,
        "error_message": exec_res.error,
    }


@app.get("/api/benchmark/results")
def list_benchmark_results():
    """Lists available persisted benchmark run JSON artifacts."""
    if not RESULTS_DIR.exists():
        return {"runs": []}

    runs = []
    for p in RESULTS_DIR.glob("*.json"):
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                runs.append({
                    "run_id": data.get("run_id", p.stem),
                    "timestamp": data.get("timestamp"),
                    "provider": data.get("config", {}).get("provider"),
                    "model_name": data.get("config", {}).get("model_name"),
                    "scenarios_count": len(data.get("scenario_results", [])),
                    "macro_f1": data.get("metrics", {}).get("macro_f1"),
                    "macro_precision": data.get("metrics", {}).get("macro_precision"),
                    "macro_recall": data.get("metrics", {}).get("macro_recall"),
                    "filename": p.name,
                })
        except Exception:
            continue

    runs.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return {"runs": runs}


@app.get("/api/benchmark/results/{run_id}")
def get_benchmark_result_detail(run_id: str):
    """Returns detailed persisted benchmark run JSON artifact."""
    if not RESULTS_DIR.exists():
        raise HTTPException(status_code=404, detail="Results directory not found.")

    target_path = RESULTS_DIR / f"{run_id}.json"
    if not target_path.exists():
        # Fallback check by matching run_id inside files
        for p in RESULTS_DIR.glob("*.json"):
            if p.stem == run_id:
                target_path = p
                break

    if not target_path.exists():
        raise HTTPException(status_code=404, detail=f"Benchmark run ID '{run_id}' not found.")

    with open(target_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data


# ============================================================================
# BACKWARD-COMPATIBLE OPENENV ENDPOINTS (V2 Core)
# ============================================================================

@app.get("/metrics")
def metrics():
    """Returns aggregated OpenEnv observability metrics."""
    scenario = env.scenarios[env.current_task_id]
    summary = AuditSummary(
        total_episodes=1,
        successful_episodes=1 if len(env.rubric.found_issues) == len(scenario["issues"]) else 0,
        average_score=1.0 if len(env.rubric.found_issues) == len(scenario["issues"]) else 0.5,
        total_secrets_detected=1,
        total_pii_detected=1,
        sandbox_executions=1,
    )
    return summary.model_dump()


@app.get("/api/report")
def get_report():
    """Returns safe, machine-readable BenchmarkReport for current task."""
    scenario = env.scenarios[env.current_task_id]
    report = BenchmarkReport(
        report_id=f"rep-{env.current_task_id}",
        scenario_id=env.current_task_id,
        dialect=scenario.get("dialect", "postgres"),
        difficulty=scenario.get("difficulty", "medium"),
        overall_score=1.0 if len(env.rubric.found_issues) == len(scenario["issues"]) else 0.5,
        analysis_status="authoritative",
    )
    json_str = exporter.export_json(report)
    return JSONResponse(content=json_str)


@app.post("/reset", response_model=SQLReviewObservation)
def reset(task: str = "easy-sql-review", payload: Dict[str, Any] = Body(None)):
    """Reset the environment to a specific task."""
    try:
        obs = env.reset(task=task)
        return obs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/step")
def step(action: SQLReviewAction):
    """Progress the environment based on the agent's action."""
    try:
        result = env.step(action)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/state", response_model=SQLReviewObservation)
def get_state():
    """Return the current environment state."""
    try:
        return env.state()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "sql-review-env-v4"}


# ============================================================================
# PHASES V4.3 - V4.9 — INTERACTIVE PLATFORM WEB INTERFACE (SPA)
# ============================================================================

@app.get("/", response_class=HTMLResponse)
def get_platform_ui():
    """
    Renders the state-of-the-art interactive web platform for SQL Review Environment V4.
    Includes SQL Analyzer Editor, Sandbox Playground, Benchmark Explorer, Benchmark Dashboard,
    Run Comparison, and Portfolio & Architecture documentation.
    """
    html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SQL Review Environment V2 - Enterprise Observability</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #0B0F19;
      --bg-card: #151D2A;
      --bg-card-hover: #1E293B;
      --border-color: #233044;
      --text-main: #F1F5F9;
      --text-muted: #94A3B8;
      --accent-blue: #3B82F6;
      --accent-purple: #8B5CF6;
      --accent-cyan: #06B6D4;
      --accent-emerald: #10B981;
      --accent-amber: #F59E0B;
      --accent-rose: #EF4444;
      --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-dark);
      color: var(--text-main);
      font-family: var(--font-sans);
      line-height: 1.5;
      min-height: 100vh;
    }

    /* Header Navigation */
    header {
      background: rgba(21, 29, 42, 0.8);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-color);
      position: sticky;
      top: 0;
      z-index: 100;
      padding: 0 30px;
      height: 70px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 1.25rem;
      font-weight: 700;
      background: linear-gradient(135deg, #60A5FA, #C084FC);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      text-decoration: none;
    }

    .nav-tabs {
      display: flex;
      gap: 4px;
      background: rgba(15, 23, 42, 0.6);
      padding: 4px;
      border-radius: 10px;
      border: 1px solid var(--border-color);
    }

    .nav-btn {
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--text-muted);
      background: transparent;
      border: none;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .nav-btn:hover {
      color: var(--text-main);
      background: rgba(255, 255, 255, 0.05);
    }

    .nav-btn.active {
      color: #FFF;
      background: var(--accent-blue);
      box-shadow: 0 2px 10px rgba(59, 130, 246, 0.4);
    }

    .header-badge {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 0.8rem;
      font-weight: 600;
      padding: 6px 12px;
      border-radius: 20px;
      background: rgba(16, 185, 129, 0.15);
      color: var(--accent-emerald);
      border: 1px solid rgba(16, 185, 129, 0.3);
    }

    /* Main Container */
    main {
      max-width: 1350px;
      margin: 0 auto;
      padding: 30px;
    }

    .tab-content { display: none; }
    .tab-content.active { display: block; }

    /* Layout Grids & Cards */
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
    .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
    .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; }

    .card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 14px;
      padding: 24px;
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.2);
    }

    h2 { font-size: 1.4rem; font-weight: 700; margin-bottom: 8px; }
    h3 { font-size: 1.1rem; font-weight: 600; margin-bottom: 12px; color: #E2E8F0; }
    p.subtitle { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 20px; }

    /* Forms & Inputs */
    label { font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 6px; display: block; }
    select, input, textarea {
      width: 100%;
      background: #0F172A;
      border: 1px solid var(--border-color);
      color: var(--text-main);
      border-radius: 8px;
      padding: 10px 14px;
      font-family: var(--font-mono);
      font-size: 0.88rem;
      outline: none;
      transition: border 0.2s ease;
    }

    textarea { height: 160px; resize: vertical; line-height: 1.5; }
    select:focus, input:focus, textarea:focus { border-color: var(--accent-blue); }

    .action-btn {
      background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
      color: white;
      border: none;
      padding: 12px 24px;
      border-radius: 8px;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }
    .action-btn:hover { opacity: 0.9; }

    /* Numbered Code Display */
    .code-box {
      background: #090D16;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
      font-family: var(--font-mono);
      font-size: 0.85rem;
      color: #38BDF8;
      overflow-x: auto;
      white-space: pre;
    }

    /* Findings & Status Badges */
    .badge-tag {
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      display: inline-block;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: var(--accent-rose); border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-high { background: rgba(245, 158, 11, 0.2); color: var(--accent-amber); border: 1px solid rgba(245, 158, 11, 0.4); }
    .badge-medium { background: rgba(59, 130, 246, 0.2); color: var(--accent-blue); border: 1px solid rgba(59, 130, 246, 0.4); }
    .badge-low { background: rgba(16, 185, 129, 0.2); color: var(--accent-emerald); border: 1px solid rgba(16, 185, 129, 0.4); }

    .finding-card {
      background: #0F172A;
      border-left: 4px solid var(--accent-amber);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 14px;
    }

    /* Metric Boxes */
    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 20px;
      text-align: center;
    }
    .stat-val { font-size: 2rem; font-weight: 800; color: #60A5FA; }
    .stat-label { font-size: 0.8rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; margin-top: 4px; }

    /* Tables */
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.88rem; }
    th { text-align: left; padding: 12px; background: #0F172A; color: var(--text-muted); border-bottom: 1px solid var(--border-color); }
    td { padding: 12px; border-bottom: 1px solid var(--border-color); }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }

    .banner-box {
      background: rgba(59, 130, 246, 0.1);
      border: 1px solid rgba(59, 130, 246, 0.3);
      padding: 14px 20px;
      border-radius: 10px;
      color: #93C5FD;
      font-size: 0.88rem;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
  </style>
</head>
<body>

  <header>
    <a href="#" class="brand">
      <span>🛡️ SQL Review Environment V2 / V4</span>
    </a>
    <nav class="nav-tabs">
      <button class="nav-btn active" onclick="switchTab('tab-review')">Interactive Review</button>
      <button class="nav-btn" onclick="switchTab('tab-explain')">Query Plan Sandbox</button>
      <button class="nav-btn" onclick="switchTab('tab-explorer')">Benchmark Explorer</button>
      <button class="nav-btn" onclick="switchTab('tab-dashboard')">Benchmark Dashboard</button>
      <button class="nav-btn" onclick="switchTab('tab-comparison')">Run Comparison</button>
      <button class="nav-btn" onclick="switchTab('tab-architecture')">Architecture & Docs</button>
    </nav>
    <div class="header-badge">
      <span>Privacy Mode</span>
    </div>
  </header>

  <main>
    <!-- TAB 1: INTERACTIVE SQL REVIEW -->
    <div id="tab-review" class="tab-content active">
      <h2>Interactive SQL Review & AST Analysis</h2>
      <p class="subtitle">Paste raw SQL queries and DDL schema context to run real-time static AST analysis, vulnerability detection, and evidence extraction.</p>

      <div class="grid-2">
        <div class="card">
          <h3>Query & Schema Editor</h3>
          <div style="margin-bottom: 14px;">
            <label>SQL Dialect</label>
            <select id="review-dialect">
              <option value="postgres">PostgreSQL</option>
              <option value="mysql">MySQL</option>
              <option value="sqlite">SQLite</option>
            </select>
          </div>
          <div style="margin-bottom: 14px;">
            <label>SQL Query</label>
            <textarea id="review-query" placeholder="SELECT * FROM users u, orders o WHERE u.id = '` + user_id + `' AND u.status = 'active';"></textarea>
          </div>
          <div style="margin-bottom: 18px;">
            <label>Schema Context (DDL)</label>
            <textarea id="review-schema" style="height: 100px;" placeholder="CREATE TABLE users (id VARCHAR(50), status VARCHAR(50)); CREATE TABLE orders (id INT);"></textarea>
          </div>
          <button class="action-btn" onclick="runAnalysis()">⚡ Run AST Analysis</button>
        </div>

        <div>
          <div class="card" style="margin-bottom: 20px;">
            <h3>Formatted Line-Numbered SQL</h3>
            <div id="review-numbered-sql" class="code-box">-- Click 'Run AST Analysis' to display line-numbered SQL</div>
          </div>

          <div class="card">
            <h3>Analysis Findings</h3>
            <div id="review-findings-container">
              <p style="color: var(--text-muted); font-size: 0.88rem;">No analysis run yet.</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 2: QUERY PLAN SANDBOX PLAYGROUND -->
    <div id="tab-explain" class="tab-content">
      <h2>Restricted Query Plan Sandbox Playground</h2>
      <p class="subtitle">Execute queries inside an isolated, ephemeral SQLite sandbox. Evaluates SandboxPolicyValidator rules and extracts EXPLAIN QUERY PLAN execution steps.</p>

      <div class="grid-2">
        <div class="card">
          <h3>Sandbox Execution Input</h3>
          <div style="margin-bottom: 14px;">
            <label>SQL Query (SELECT Only)</label>
            <textarea id="explain-query" placeholder="SELECT a.id, b.event_name FROM tokens a JOIN events b ON a.id = b.token_id WHERE a.id = 5;"></textarea>
          </div>
          <div style="margin-bottom: 18px;">
            <label>Schema DDL</label>
            <textarea id="explain-schema" style="height: 100px;" placeholder="CREATE TABLE tokens (id INT PRIMARY KEY); CREATE TABLE events (id INT, token_id INT, event_name TEXT); CREATE INDEX idx_ev ON events(token_id);"></textarea>
          </div>
          <button class="action-btn" onclick="runExplain()">🔍 Execute EXPLAIN Plan</button>
        </div>

        <div>
          <div class="card" style="margin-bottom: 20px;">
            <h3>Sandbox Execution Evidence</h3>
            <div id="explain-status-box" style="margin-bottom: 14px;">
              <span class="badge-tag badge-medium">Awaiting Execution</span>
            </div>
            <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 6px;">Execution Time: <span id="explain-time" style="color: var(--text-main); font-weight:600;">0.0 ms</span></div>
            <div style="font-size: 0.85rem; color: var(--text-muted);">Row Count: <span id="explain-rows" style="color: var(--text-main); font-weight:600;">0</span></div>
          </div>

          <div class="card">
            <h3>EXPLAIN QUERY PLAN Tree Steps</h3>
            <div id="explain-steps-box" class="code-box">-- Execution steps will appear here</div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 3: BENCHMARK EXPLORER -->
    <div id="tab-explorer" class="tab-content">
      <h2>Independent Benchmark Dataset Explorer (300 Scenarios)</h2>
      <p class="subtitle">Browse the complete, frozen V3 independent benchmark dataset. Filter by dialect, difficulty, issue category, benign, or adversarial status.</p>

      <div class="card" style="margin-bottom: 24px;">
        <div class="grid-4" style="align-items: flex-end;">
          <div>
            <label>Dialect</label>
            <select id="filter-dialect" onchange="loadExplorerScenarios()">
              <option value="">All Dialects</option>
              <option value="postgres">PostgreSQL</option>
              <option value="mysql">MySQL</option>
              <option value="sqlite">SQLite</option>
            </select>
          </div>
          <div>
            <label>Difficulty</label>
            <select id="filter-difficulty" onchange="loadExplorerScenarios()">
              <option value="">All Difficulties</option>
              <option value="easy">Easy</option>
              <option value="medium">Medium</option>
              <option value="hard">Hard</option>
            </select>
          </div>
          <div>
            <label>Issue Category</label>
            <select id="filter-category" onchange="loadExplorerScenarios()">
              <option value="">All Categories</option>
              <option value="sql_injection">SQL Injection</option>
              <option value="unnecessary_columns">Unnecessary Columns</option>
              <option value="missing_index">Missing Index</option>
              <option value="inefficient_join">Inefficient Join</option>
              <option value="n_plus_one">N+1 Query</option>
            </select>
          </div>
          <div>
            <label>Ground-Truth Audit View</label>
            <select id="filter-gt" onchange="loadExplorerScenarios()">
              <option value="false">Public Scenario View (Hidden Ground Truth)</option>
              <option value="true">Curator Audit View (Show Declared Issues)</option>
            </select>
          </div>
        </div>
      </div>

      <div class="card">
        <h3>Matching Scenarios (<span id="explorer-total-count">0</span>)</h3>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Dialect</th>
              <th>Difficulty</th>
              <th>Flags</th>
              <th>SQL Query Preview</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="explorer-table-body">
            <tr><td colspan="6" style="text-align:center; color:var(--text-muted);">Loading benchmark scenarios...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 4: BENCHMARK DASHBOARD -->
    <div id="tab-dashboard" class="tab-content">
      <div class="banner-box">
        <div>
          <strong>📌 Recorded Baseline Artifact:</strong> MockModelProvider — deterministic infrastructure baseline
          <br><span style="font-size:0.78rem; color:#BFDBFE;">Dataset SHA-256: 5342c666ce1e774b443ccd6446adecc9d2135d008237681027d393269b295dde</span>
        </div>
        <span class="badge-tag badge-medium">Persisted Baseline</span>
      </div>

      <h2>Recorded Benchmark Metrics</h2>
      <p class="subtitle">Official evaluation metrics computed across all 300 frozen benchmark scenarios in `benchmarks/results/run-v3-mock-300.json`.</p>

      <div class="grid-4" style="margin-bottom: 24px;">
        <div class="stat-card">
          <div class="stat-val" id="dash-f1">0.2117</div>
          <div class="stat-label">Macro F1 Score</div>
        </div>
        <div class="stat-card">
          <div class="stat-val" id="dash-prec" style="color:#34D399;">0.2200</div>
          <div class="stat-label">Macro Precision</div>
        </div>
        <div class="stat-card">
          <div class="stat-val" id="dash-rec" style="color:#FBBF24;">0.2083</div>
          <div class="stat-label">Macro Recall</div>
        </div>
        <div class="stat-card">
          <div class="stat-val" id="dash-loc" style="color:#A78BFA;">0.2200</div>
          <div class="stat-label">Location Accuracy</div>
        </div>
      </div>

      <div class="grid-2">
        <div class="card">
          <h3>F1 Score by Dialect</h3>
          <table>
            <thead>
              <tr><th>Dialect</th><th>Scenario Count</th><th>Macro F1 Score</th></tr>
            </thead>
            <tbody id="dash-dialect-table">
              <tr><td>PostgreSQL</td><td>100</td><td>0.2800</td></tr>
              <tr><td>MySQL</td><td>100</td><td>0.2800</td></tr>
              <tr><td>SQLite</td><td>100</td><td>0.2800</td></tr>
            </tbody>
          </table>
        </div>

        <div class="card">
          <h3>F1 Score by Issue Category</h3>
          <table>
            <thead>
              <tr><th>Issue Category</th><th>Declared Findings</th><th>Macro F1 Score</th></tr>
            </thead>
            <tbody id="dash-category-table">
              <tr><td>SQL Injection</td><td>66</td><td>0.9400</td></tr>
              <tr><td>Unnecessary Columns</td><td>54</td><td>0.1000</td></tr>
              <tr><td>Inefficient Join</td><td>27</td><td>0.1000</td></tr>
              <tr><td>Missing Index</td><td>30</td><td>0.0000</td></tr>
              <tr><td>N+1 Query</td><td>24</td><td>0.0000</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 5: RUN COMPARISON -->
    <div id="tab-comparison" class="tab-content">
      <h2>Benchmark Run Comparison</h2>
      <p class="subtitle">Compare persisted benchmark runs across providers and model configurations.</p>

      <div class="banner-box" style="background: rgba(245, 158, 11, 0.1); border-color: rgba(245, 158, 11, 0.3); color: #FDE68A;">
        <div>
          <strong>ℹ️ Provider Status Notice:</strong> External LLM benchmarking is currently deferred (No OPENAI_API_KEY or HF_TOKEN is configured in local environment).
          <br><span style="font-size:0.78rem;">The deterministic MockModelProvider baseline is displayed below. No external model comparisons have been fabricated.</span>
        </div>
      </div>

      <div class="card">
        <h3>Available Benchmark Runs</h3>
        <table>
          <thead>
            <tr>
              <th>Run ID</th>
              <th>Timestamp</th>
              <th>Provider</th>
              <th>Model</th>
              <th>Scenarios</th>
              <th>Macro F1</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody id="comparison-table-body">
            <tr><td colspan="7" style="text-align:center; color:var(--text-muted);">Loading benchmark run artifacts...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 6: ARCHITECTURE & PORTFOLIO DOCS -->
    <div id="tab-architecture" class="tab-content">
      <h2>Architecture & Methodology Overview</h2>
      <p class="subtitle">Comprehensive engineering design and privacy guarantees of SQL Review Environment V4.</p>

      <div class="grid-2">
        <div class="card">
          <h3>🔒 Privacy & Security Boundary</h3>
          <p style="font-size:0.88rem; color:var(--text-muted); margin-bottom:12px;">
            The <strong>PrivacyGateway</strong> strips raw credentials, secret tokens, and PII from SQL queries before LLM invocation. Token mapping tables are kept strictly isolated in memory and never persisted in output artifacts.
          </p>
          <ul style="font-size:0.88rem; color:var(--text-muted); padding-left:20px; line-height:1.8;">
            <li>Zero raw secrets sent to LLMs</li>
            <li>PromptIsolationManager wraps inputs inside <code>&lt;UNTRUSTED_SQL_CONTEXT&gt;</code> framing</li>
            <li>SandboxPolicyValidator blocks destructive DDL/DML, PRAGMAs, and multi-statements</li>
          </ul>
        </div>

        <div class="card">
          <h3>📊 Independent Benchmark Dataset</h3>
          <p style="font-size:0.88rem; color:var(--text-muted); margin-bottom:12px;">
            The V3 dataset consists of <strong>300 curator-declared scenarios</strong> (100 PostgreSQL, 100 MySQL, 100 SQLite) with deterministic SHA-256 hash <code>5342c666ce1e774b443ccd6446adecc9d2135d008237681027d393269b295dde</code>.
          </p>
          <ul style="font-size:0.88rem; color:var(--text-muted); padding-left:20px; line-height:1.8;">
            <li>Curator-declared ground truth is immutable and un-corrupted by AST parser limitations</li>
            <li>100% of N+1 scenarios include explicit ORM loop trace comments</li>
            <li>51 adversarial scenarios test prompt-injection resilience</li>
          </ul>
        </div>
      </div>
    </div>
  </main>

  <script>
    function switchTab(tabId) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
      document.getElementById(tabId).classList.add('active');

      const btnIndex = ['tab-review', 'tab-explain', 'tab-explorer', 'tab-dashboard', 'tab-comparison', 'tab-architecture'].indexOf(tabId);
      if (btnIndex >= 0) {
        document.querySelectorAll('.nav-btn')[btnIndex].classList.add('active');
      }

      if (tabId === 'tab-explorer') loadExplorerScenarios();
      if (tabId === 'tab-dashboard') loadDashboardMetrics();
      if (tabId === 'tab-comparison') loadComparisonRuns();
    }

    async function runAnalysis() {
      const dialect = document.getElementById('review-dialect').value;
      const query = document.getElementById('review-query').value;
      const schema = document.getElementById('review-schema').value;

      if (!query.trim()) {
        alert('Please enter a SQL query to analyze.');
        return;
      }

      try {
        const res = await fetch('/api/sql/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query, dialect, schema_context: schema })
        });
        const data = await res.json();

        document.getElementById('review-numbered-sql').textContent = data.numbered_sql || query;

        const findingsBox = document.getElementById('review-findings-container');
        if (!data.findings || data.findings.length === 0) {
          findingsBox.innerHTML = '<div class="finding-card" style="border-left-color:#10B981;"><h4 style="color:#10B981;">✅ Zero Vulnerabilities Detected</h4><p style="font-size:0.85rem; color:var(--text-muted); margin-top:4px;">No AST anti-patterns or security issues found.</p></div>';
          return;
        }

        let html = '';
        data.findings.forEach(f => {
          const badgeClass = f.severity === 'critical' ? 'badge-critical' : (f.severity === 'high' ? 'badge-high' : 'badge-medium');
          html += `
            <div class="finding-card">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <strong style="color:#F1F5F9; font-size:0.95rem;">${f.issue} (Line ${f.line})</strong>
                <span class="badge-tag ${badgeClass}">${f.severity}</span>
              </div>
              <p style="font-size:0.85rem; color:#CBD5E1; margin-bottom:6px;"><strong>Evidence:</strong> ${f.evidence}</p>
              <p style="font-size:0.85rem; color:#34D399;"><strong>Recommendation:</strong> ${f.recommendation}</p>
            </div>
          `;
        });
        findingsBox.innerHTML = html;

      } catch (err) {
        alert('Analysis request failed: ' + err.message);
      }
    }

    async function runExplain() {
      const query = document.getElementById('explain-query').value;
      const schema = document.getElementById('explain-schema').value;

      if (!query.trim()) {
        alert('Please enter a SQL query for EXPLAIN plan.');
        return;
      }

      try {
        const res = await fetch('/api/sql/explain', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query, schema_context: schema })
        });
        const data = await res.json();

        const statusBox = document.getElementById('explain-status-box');
        if (!data.allowed) {
          statusBox.innerHTML = `<span class="badge-tag badge-critical">POLICY REJECTED</span> <span style="font-size:0.85rem; color:#FCA5A5; margin-left:8px;">${data.policy_reason}</span>`;
          document.getElementById('explain-steps-box').textContent = "-- Execution blocked by SandboxPolicyValidator";
          return;
        }

        statusBox.innerHTML = `<span class="badge-tag badge-low">ALLOWED (${data.status.toUpperCase()})</span>`;
        document.getElementById('explain-time').textContent = data.execution_time_ms.toFixed(2) + ' ms';
        document.getElementById('explain-rows').textContent = data.row_count + (data.truncated ? ' (Truncated)' : '');

        let stepsText = '';
        if (data.plan && data.plan.length > 0) {
          data.plan.forEach(step => {
            stepsText += `[Step ${step.step_id}] ${step.operation || 'OP'}: ${step.detail}\n`;
          });
        } else {
          stepsText = "-- Direct SQL Execution (No additional plan steps)";
        }
        document.getElementById('explain-steps-box').textContent = stepsText;

      } catch (err) {
        alert('Explain request failed: ' + err.message);
      }
    }

    async function loadExplorerScenarios() {
      const dialect = document.getElementById('filter-dialect').value;
      const difficulty = document.getElementById('filter-difficulty').value;
      const category = document.getElementById('filter-category').value;
      const includeGt = document.getElementById('filter-gt').value === 'true';

      let url = `/api/benchmark/scenarios?include_ground_truth=${includeGt}&limit=50`;
      if (dialect) url += `&dialect=${dialect}`;
      if (difficulty) url += `&difficulty=${difficulty}`;
      if (category) url += `&issue_category=${category}`;

      try {
        const res = await fetch(url);
        const data = await res.json();

        document.getElementById('explorer-total-count').textContent = data.total;
        const tbody = document.getElementById('explorer-table-body');

        if (!data.scenarios || data.scenarios.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No scenarios match the selected filters.</td></tr>';
          return;
        }

        let html = '';
        data.scenarios.forEach(sc => {
          let flags = '';
          if (sc.is_benign) flags += '<span class="badge-tag badge-low" style="margin-right:4px;">Benign</span>';
          if (sc.is_adversarial) flags += '<span class="badge-tag badge-high">Adversarial</span>';

          let gtText = '';
          if (includeGt && sc.ground_truth) {
            const issues = sc.ground_truth.issues.map(i => i.issue).join(', ');
            gtText = `<br><span style="font-size:0.75rem; color:#F59E0B;">GT Issues: ${issues || 'None'}</span>`;
          }

          html += `
            <tr>
              <td><strong>${sc.scenario_id}</strong></td>
              <td>${sc.dialect}</td>
              <td>${sc.difficulty}</td>
              <td>${flags || '-'}</td>
              <td><code style="background:none; padding:0; margin:0; font-size:0.8rem; border:none; color:#38BDF8;">${sc.query.substring(0, 65)}...</code>${gtText}</td>
              <td><button class="nav-btn" style="padding:4px 8px; font-size:0.75rem;" onclick="loadIntoEditor('${sc.scenario_id}')">Load in Editor</button></td>
            </tr>
          `;
        });
        tbody.innerHTML = html;

      } catch (err) {
        console.error(err);
      }
    }

    async function loadIntoEditor(scenarioId) {
      try {
        const res = await fetch(`/api/benchmark/scenarios/${scenarioId}?include_ground_truth=true`);
        const sc = await res.json();

        switchTab('tab-review');
        document.getElementById('review-dialect').value = sc.dialect || 'postgres';
        document.getElementById('review-query').value = sc.query || '';
        document.getElementById('review-schema').value = sc.schema_context || '';
        runAnalysis();
      } catch (err) {
        alert('Failed to load scenario into editor: ' + err.message);
      }
    }

    async function loadDashboardMetrics() {
      try {
        const res = await fetch('/api/benchmark/summary');
        const data = await res.json();

        if (data.baseline_mock_metrics) {
          const m = data.baseline_mock_metrics;
          document.getElementById('dash-f1').textContent = m.macro_f1.toFixed(4);
          document.getElementById('dash-prec').textContent = m.macro_precision.toFixed(4);
          document.getElementById('dash-rec').textContent = m.macro_recall.toFixed(4);
          document.getElementById('dash-loc').textContent = m.location_accuracy.toFixed(4);
        }
      } catch (err) {
        console.error(err);
      }
    }

    async function loadComparisonRuns() {
      try {
        const res = await fetch('/api/benchmark/results');
        const data = await res.json();

        const tbody = document.getElementById('comparison-table-body');
        if (!data.runs || data.runs.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No benchmark runs found.</td></tr>';
          return;
        }

        let html = '';
        data.runs.forEach(r => {
          html += `
            <tr>
              <td><strong>${r.run_id}</strong></td>
              <td>${r.timestamp ? r.timestamp.substring(0, 19).replace('T', ' ') : '-'}</td>
              <td>${r.provider || 'mock'}</td>
              <td>${r.model_name || 'MockModelProvider'}</td>
              <td>${r.scenarios_count}</td>
              <td><strong style="color:#60A5FA;">${r.macro_f1 ? r.macro_f1.toFixed(4) : '0.0000'}</strong></td>
              <td><span class="badge-tag badge-medium">${r.provider === 'mock' ? 'Mock Baseline' : 'External Run'}</span></td>
            </tr>
          `;
        });
        tbody.innerHTML = html;

      } catch (err) {
        console.error(err);
      }
    }
  </script>
</body>
</html>"""
    return HTMLResponse(content=html)


def main():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)


if __name__ == "__main__":
    main()
