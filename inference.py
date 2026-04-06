import os
import requests
from openai import OpenAI

# =========================
# Env Variables (with defaults)
# =========================
API_BASE_URL = os.getenv("API_BASE_URL", "https://api-inference.huggingface.co/v1")
HF_TOKEN = os.getenv("HF_TOKEN")
MODEL_NAME = os.getenv("MODEL_NAME", "mistralai/Mistral-7B-Instruct-v0.3")
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "https://rnr046-sql-review-env.hf.space")

# =========================
# OpenAI Client (SYNC)
# =========================
client = OpenAI(
    base_url=API_BASE_URL,
    api_key=HF_TOKEN
)

# =========================
# Logging Functions (STRICT FORMAT)
# =========================
def log_start(task, env, model):
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step, action, reward, done, error):
    print(f"[STEP] step={step} action={action} reward={reward} done={done} error={error}", flush=True)

def log_end(success, steps, score, rewards):
    print(f"[END] success={success} steps={steps} score={score} rewards={rewards}", flush=True)

# =========================
# LLM Call (SYNC)
# =========================
def generate_review(query, history):
    prompt = f"""
You are an expert SQL reviewer.

Analyze the following SQL query and identify issues like:
- SQL Injection
- N+1 queries
- Missing indexes
- Inefficient joins

Be concise. Mention the exact issue name clearly.

Query:
{query}

Previous feedback:
{history}

Give only a short review comment.
"""
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "You are a SQL expert."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2
    )
    return response.choices[0].message.content.strip()

# =========================
# Run Single Task
# =========================
def run_task(task_name):
    max_steps = 10
    rewards = []
    max_total_reward = 3.0

    task_slug = task_name.split("-")[0]  # "easy", "medium", "hard"

    log_start(task_name, ENV_BASE_URL, MODEL_NAME)

    try:
        # RESET with task parameter
        res = requests.post(f"{ENV_BASE_URL}/reset", params={"task": task_slug})
        state = res.json()

        for step in range(1, max_steps + 1):
            try:
                query = state["query"]
                history = state["feedback_history"]

                review_comment = generate_review(query, history)
                action = {"review_comment": review_comment}

                res = requests.post(f"{ENV_BASE_URL}/step", json=action)
                data = res.json()

                reward = data["reward"]["value"]
                done = data["done"]
                rewards.append(reward)

                log_step(step, action, reward, done, None)

                state = data["observation"]

                if done:
                    break

            except Exception as e:
                log_step(step, None, 0.0, True, str(e))
                break

        score = sum(rewards) / max_total_reward
        score = max(0.01, min(0.99, score))
        success = score >= 0.7

        log_end(success, len(rewards), score, rewards)

    except Exception as e:
        log_end(False, 0, 0.0, [])
        print(f"[FATAL] task={task_name} error={str(e)}", flush=True)

# =========================
# Main Runner
# =========================
def run():
    tasks = [
        "easy-sql-review",
        "medium-sql-review",
        "hard-sql-review"
    ]
    for task in tasks:
        run_task(task)

# =========================
# Entry
# =========================
if __name__ == "__main__":
    run()