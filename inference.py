from __future__ import annotations
import os
import textwrap
from typing import List, Optional, Dict, Any
import requests

from privacy import PrivacyGateway, SanitizedLogger
from security import (
    PromptIsolationManager,
    ModelProvider,
    MockModelProvider,
    get_model_provider,
    parse_model_findings_json,
)
from models import SQLReviewAction, StructuredFinding

# =========================
# Mandatory Env Variables
# =========================
API_BASE_URL = os.getenv("API_BASE_URL", "https://api-inference.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "mistralai/Mistral-7B-Instruct-v0.3")
HF_TOKEN = os.getenv("HF_TOKEN")
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://0.0.0.0:7860")  # Local default for testing

# =========================
# Configuration
# =========================
MAX_STEPS = 10
SUCCESS_THRESHOLD = 0.7

privacy_gateway = PrivacyGateway()
prompt_manager = PromptIsolationManager()
sanitized_logger = SanitizedLogger("inference-logger")


# =========================
# Logging Functions
# =========================
def log_start(task: str, env: str, model: str) -> None:
    sanitized_logger.info(f"[START] task={task} env={env} model={model}")


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    sanitized_logger.info(f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}")


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    sanitized_logger.info(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}")


# =========================
# Core Logic
# =========================
def get_model_review(
    provider: ModelProvider,
    query: str,
    schema: str,
    history: List[str]
) -> Tuple[Dict[str, Any], str]:
    """
    Sanitizes raw SQL/Schema via PrivacyGateway, builds isolated prompts,
    executes provider generation, and returns (action_payload, raw_response).
    """
    # 1. Privacy Gateway Sanitization Boundary
    sanitized_ctx = privacy_gateway.sanitize_context(query, schema)

    # 2. Prompt Isolation Boundary
    sys_prompt, user_prompt, _ = prompt_manager.build_isolated_prompt(
        sanitized_query=sanitized_ctx.query,
        sanitized_schema=sanitized_ctx.schema_context,
        feedback_history=history,
    )

    # 3. Provider Generation
    response_text = provider.generate(sys_prompt, user_prompt)

    # 4. Parse & Validate Structured Output
    findings, parse_err = parse_model_findings_json(response_text)

    if findings:
        action = SQLReviewAction(
            review_comment=f"AI Agent identified {len(findings)} structured issues.",
            findings=findings,
        )
        return action.model_dump(), response_text
    
    # Fallback to free-text review comment
    action = SQLReviewAction(review_comment=response_text if response_text.strip() else "No issues identified.")
    return action.model_dump(), response_text


def run_task(task_id: str, provider: ModelProvider):
    rewards = []
    steps_taken = 0
    success = False
    history = []
    
    log_start(task=task_id, env="sql-review-env", model=MODEL_NAME)
    
    try:
        res = requests.post(f"{ENV_BASE_URL}/reset", params={"task": task_id})
        obs = res.json()
        
        for step in range(1, MAX_STEPS + 1):
            if obs.get("done", False):
                break
                
            query = obs["query"]
            schema = obs.get("schema_context", "N/A")
            
            action_payload, raw_resp = get_model_review(provider, query, schema, history)
            
            step_res = requests.post(f"{ENV_BASE_URL}/step", json=action_payload)
            data = step_res.json()
            
            obs = data["observation"]
            reward = data["reward"]["value"]
            done = data["done"]
            
            rewards.append(reward)
            steps_taken = step
            log_step(step, raw_resp.replace("\n", " "), reward, done, None)
            
            history.append(f"Step {step}: {raw_resp}")
            
            if done:
                break

        total_reward = sum(rewards)
        if "easy" in task_id or "medium" in task_id:
            max_possible = 0.5
        elif "hard" in task_id:
            max_possible = 1.5
        elif "performance" in task_id:
            max_possible = 1.0
        else:
            max_possible = 0.5 
            
        unclamped_score = (total_reward / max_possible) if max_possible > 0 else 0.0
        score = max(0.01, min(0.99, unclamped_score))
        success = score >= SUCCESS_THRESHOLD
        
    except Exception as e:
        log_end(False, steps_taken, 0.0, rewards)
        sanitized_logger.error(f"[DEBUG] Fatal error in task {task_id}: {e}")
        return

    log_end(success, steps_taken, score, rewards)


def main():
    provider = get_model_provider()
    tasks = [
        "easy-sql-review",
        "medium-sql-review",
        "hard-sql-review",
        "security-extreme",
        "performance-optimization"
    ]
    for task_id in tasks:
        run_task(task_id, provider)


if __name__ == "__main__":
    main()