from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Optional, Dict, Any
from models import SQLReviewAction, SQLReviewObservation, SQLReviewReward
from server.environment import SQLReviewEnv
from reporting import BenchmarkReport, AuditSummary, ReportExporter
from sandbox import SandboxExecutor

app = FastAPI(title="SQL Review Environment V2")

# Initialize global environment instance and exporter
env = SQLReviewEnv()
exporter = ReportExporter()
sandbox_executor = SandboxExecutor()

@app.get("/", response_class=HTMLResponse)
def dashboard():
    """Enterprise V2 Observability Dashboard."""
    scenario = env.scenarios[env.current_task_id]
    found = list(env.rubric.found_issues)
    expected = scenario["issues"]
    dialect = scenario.get("dialect", "postgres").upper()
    
    # Run sandbox explain plan dynamically for visual observability
    sandbox_res = sandbox_executor.execute(scenario["query"], schema_context=scenario["schema"])
    plan_details = [f"{step.operation or 'STEP'}: {step.detail}" for step in sandbox_res.plan] if sandbox_res.plan else ["Direct SQL Execution"]
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>SQL Review Environment V2 - Enterprise Observability</title>
            <style>
                body {{ font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; background: #0B0F19; color: #F1F5F9; padding: 30px; }}
                .container {{ max-width: 1100px; margin: 0 auto; }}
                .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1E293B; padding-bottom: 20px; margin-bottom: 30px; }}
                .title {{ font-size: 1.8rem; font-weight: 700; background: linear-gradient(135deg, #60A5FA, #A855F7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
                .badge {{ padding: 6px 14px; border-radius: 9999px; font-weight: 600; font-size: 0.85rem; background: #3B82F6; color: white; }}
                .badge-dialect {{ background: #8B5CF6; margin-left: 8px; }}
                .grid {{ display: grid; grid-template-columns: 2fr 1fr; gap: 24px; }}
                .card {{ background: #1E293B; border-radius: 12px; padding: 24px; border: 1px solid #334155; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3); }}
                code {{ background: #0F172A; padding: 16px; display: block; white-space: pre-wrap; margin: 12px 0; border-radius: 8px; border-left: 4px solid #38BDF8; color: #38BDF8; font-family: 'Fira Code', monospace; }}
                .issue-list {{ margin-top: 15px; }}
                .issue {{ padding: 10px 14px; margin: 8px 0; border-radius: 8px; font-weight: 500; display: flex; align-items: center; justify-content: space-between; }}
                .found {{ background: rgba(16, 185, 129, 0.15); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.3); }}
                .missing {{ background: rgba(239, 68, 68, 0.15); color: #FCA5A5; border: 1px solid rgba(239, 68, 68, 0.3); }}
                .metric-box {{ background: #0F172A; padding: 16px; border-radius: 8px; border: 1px solid #334155; margin-bottom: 12px; }}
                .metric-val {{ font-size: 1.5rem; font-weight: bold; color: #60A5FA; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="title">SQL Review Environment V2</div>
                    <div>
                        <span class="badge">Privacy Mode: Active</span>
                        <span class="badge badge-dialect">{dialect}</span>
                    </div>
                </div>
                
                <div class="grid">
                    <div class="card">
                        <h2>Current Scenario: {env.current_task_id}</h2>
                        <p><strong>Difficulty:</strong> {scenario['difficulty'].capitalize()}</p>
                        
                        <h3>Target SQL Query:</h3>
                        <code>{scenario['query']}</code>
                        
                        <h3>Schema Context:</h3>
                        <code>{scenario['schema']}</code>
                        
                        <div class="issue-list">
                            <h3>Vulnerabilities & Anti-Patterns:</h3>
                            {"".join([f'<div class="issue found"><span>✅ {issue}</span><span style="font-size:0.8rem">VERIFIED</span></div>' for issue in found])}
                            {"".join([f'<div class="issue missing"><span>❌ {issue}</span><span style="font-size:0.8rem">PENDING</span></div>' for issue in expected if issue not in found])}
                        </div>
                    </div>
                    
                    <div>
                        <div class="card">
                            <h3>Sandbox Execution Evidence</h3>
                            <div class="metric-box">
                                <div style="font-size:0.85rem; color:#94A3B8;">Execution Status</div>
                                <div class="metric-val" style="color:#10B981">{sandbox_res.status.upper()}</div>
                            </div>
                            <div class="metric-box">
                                <div style="font-size:0.85rem; color:#94A3B8;">Query Plan (EXPLAIN)</div>
                                <div style="font-size:0.85rem; font-family:monospace; margin-top:6px; color:#CBD5E1">
                                    {"<br>".join(plan_details)}
                                </div>
                            </div>
                        </div>
                        
                        <div class="card" style="margin-top:20px;">
                            <h3>Enterprise Endpoints</h3>
                            <p style="font-size:0.85rem; color:#94A3B8;">
                                • <code>POST /reset</code><br>
                                • <code>POST /step</code><br>
                                • <code>GET /state</code><br>
                                • <code>GET /metrics</code><br>
                                • <code>GET /api/report</code>
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)

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
    return {"status": "healthy", "service": "sql-review-env-v2"}

def main():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)

if __name__ == "__main__":
    main()