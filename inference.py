import os
import textwrap
from typing import List, Optional
from openai import OpenAI
import requests

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
TEMPERATURE = 0.2
MAX_TOKENS = 150
SUCCESS_THRESHOLD = 0.7

SYSTEM_PROMPT = textwrap.dedent(
    """
    You are an expert SQL reviewer. Your task is to analyze the provided SQL query and identify security vulnerabilities (like SQL Injection) or performance issues (like N+1 queries, missing indexes).
    
    Format your response as a concise review comment. Mention the issue name clearly if you find one.
    """
).strip()

# =========================
# Logging Functions (STRICT)
# =========================
def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )

def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)

# =========================
# Core Logic
# =========================
def get_model_review(client: OpenAI, query: str, schema: str, history: List[str]) -> str:
    history_block = "\n".join(history[-3:]) if history else "None"
    user_prompt = textwrap.dedent(
        f"""
        SQL Query: {query}
        Table Schema: {schema}
        
        Previous Feedback:
        {history_block}
        
        Provide your concise review comment:
        """
    ).strip()
    
    # Retry logic for robustness during evaluation
    for attempt in range(3):
        try:
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
            )
            return (completion.choices[0].message.content or "").strip()
        except Exception as exc:
            if attempt == 2:
                return f"Error calling model after multiple attempts: {exc}"
            continue
    return "Error: Unexpected flow in model calling."

def run_task(task_id: str, client: OpenAI):
    rewards = []
    steps_taken = 0
    success = False
    history = []
    
    log_start(task=task_id, env="sql-review-env", model=MODEL_NAME)
    
    try:
        # Reset relative to the environment URL
        res = requests.post(f"{ENV_BASE_URL}/reset", params={"task": task_id})
        obs = res.json()
        
        for step in range(1, MAX_STEPS + 1):
            if obs.get("done", False):
                break
                
            query = obs["query"]
            schema = obs.get("schema_context", "N/A")
            
            review_comment = get_model_review(client, query, schema, history)
            action = {"review_comment": review_comment}
            
            # Step
            step_res = requests.post(f"{ENV_BASE_URL}/step", json=action)
            data = step_res.json()
            
            obs = data["observation"]
            reward = data["reward"]["value"]
            done = data["done"]
            
            rewards.append(reward)
            steps_taken = step
            log_step(step, review_comment.replace("\n", " "), reward, done, None)
            
            history.append(f"Step {step}: {review_comment}")
            
            if done:
                break

        # Calculate final score (normalized strictly between 0 and 1)
        total_reward = sum(rewards)
        # Dynamic max based on task
        if "easy" in task_id or "medium" in task_id:
            max_possible = 0.5
        elif "hard" in task_id:
            max_possible = 1.5
        elif "performance" in task_id:
            max_possible = 1.0
        else:
            max_possible = 0.5 
            
        unclamped_score = (total_reward / max_possible) if max_possible > 0 else 0.0
        # Phase 2 requirement: score must be strictly between 0 and 1
        score = max(0.01, min(0.99, unclamped_score))
        success = score >= SUCCESS_THRESHOLD
        
    except Exception as e:
        log_end(False, steps_taken, 0.0, rewards)
        print(f"[DEBUG] Fatal error in task {task_id}: {e}")
        return

    log_end(success, steps_taken, score, rewards)

def main():
    client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)
    tasks = [
        "easy-sql-review",
        "medium-sql-review",
        "hard-sql-review",
        "security-extreme",
        "performance-optimization"
    ]
    for task_id in tasks:
        run_task(task_id, client)

if __name__ == "__main__":
    main()