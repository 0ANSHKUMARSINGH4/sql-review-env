from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import HTMLResponse
from typing import Optional, Dict, Any
from models import SQLReviewAction, SQLReviewObservation, SQLReviewReward
from server.environment import SQLReviewEnv

app = FastAPI(title="SQL Review Environment (Round 1)")

# Initialize the global environment instance
env = SQLReviewEnv()

@app.get("/", response_class=HTMLResponse)
def dashboard():
    """Simple web dashboard for the environment."""
    scenario = env.scenarios[env.current_task_id]
    found = list(env.rubric.found_issues)
    expected = scenario["issues"]
    
    html_content = f"""
    <html>
        <head>
            <title>SQL Review Env Dashboard</title>
            <style>
                body {{ font-family: sans-serif; margin: 40px; background: #f4f4f9; color: #333; }}
                .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                code {{ background: #eee; padding: 10px; display: block; white-space: pre-wrap; margin: 10px 0; border-radius: 4px; border-left: 4px solid #4a90e2; }}
                .status-badge {{ padding: 5px 10px; border-radius: 20px; font-weight: bold; background: #4a90e2; color: white; }}
                .issue-list {{ margin-top: 20px; }}
                .issue {{ padding: 5px; margin: 5px 0; border-radius: 4px; }}
                .found {{ background: #d4edda; color: #155724; }}
                .missing {{ background: #f8d7da; color: #721c24; }}
            </style>
        </head>
        <body>
            <h1>SQL Review Environment <span class="status-badge">Live</span></h1>
            <div class="card">
                <h2>Current Task: {env.current_task_id}</h2>
                <p><strong>Difficulty:</strong> {scenario['difficulty']}</p>
                <h3>Query to Review:</h3>
                <code>{scenario['query']}</code>
                
                <div class="issue-list">
                    <h3>Vulnerabilities Found:</h3>
                    {"".join([f'<div class="issue found">✅ {issue}</div>' for issue in found])}
                    {"".join([f'<div class="issue missing">❌ {issue} (Not identified yet)</div>' for issue in expected if issue not in found])}
                </div>
                
                <p style="margin-top: 30px; font-size: 0.8em; color: #666;">
                    API Endpoints: <code>/reset</code>, <code>/step</code>, <code>/state</code>
                </p>
            </div>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)

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
    return {"status": "healthy", "service": "sql-review-env"}

def main():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)

if __name__ == "__main__":
    main()