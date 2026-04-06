from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
import re

app = FastAPI()


# =========================
# Models
# =========================

class Observation(BaseModel):
    query: str
    feedback_history: List[str]
    issues_remaining: int


class Action(BaseModel):
    review_comment: str


class Reward(BaseModel):
    value: float


# =========================
# Environment
# =========================

class SQLReviewEnv:
    def __init__(self):
        self.queries = [
            {
                "level": "easy",
                "query": "SELECT * FROM users WHERE username = '" + "' + user_input + '",
                "issues": ["sql injection"]
            },
            {
                "level": "medium",
                "query": "SELECT * FROM orders; SELECT * FROM order_items WHERE order_id = ?",
                "issues": ["n+1 query"]
            },
            {
                "level": "hard",
                "query": """
                    SELECT * FROM users u
                    JOIN orders o ON u.id = o.user_id
                    WHERE u.name = '" + user_input + "'
                """,
                "issues": ["sql injection", "missing index", "inefficient join"]
            }
        ]

        self.current_index = 0
        self.feedback_history = []
        self.found_issues = set()
        self.max_steps = 10
        self.steps = 0

    def reset(self):
        self.current_index = 0
        self.feedback_history = []
        self.found_issues = set()
        self.steps = 0
        return self.state()

    def state(self):
        current = self.queries[self.current_index]
        remaining = len(current["issues"]) - len(self.found_issues)
        return Observation(
            query=current["query"],
            feedback_history=self.feedback_history,
            issues_remaining=remaining
        )

    def step(self, action: Action):
        self.steps += 1
        comment = action.review_comment.lower()
        self.feedback_history.append(comment)

        current = self.queries[self.current_index]
        true_issues = set(current["issues"])

        detected = set()
        for issue in true_issues:
            if self._match_issue(issue, comment):
                detected.add(issue)

        correct = detected - self.found_issues
        false_positive = detected - true_issues
        missed = true_issues - detected - self.found_issues

        reward = 0.0

        # Reward correct findings
        reward += len(correct) * 0.8

        # Penalize hallucinations
        reward -= len(false_positive) * 0.4

        # Small penalty for missing issues
        reward -= len(missed) * 0.15

        # Bonus for finishing all
        if correct and len(self.found_issues | correct) == len(true_issues):
            reward += 0.5

        # Update found issues
        self.found_issues.update(correct)

        # Clamp strictly between 0.01 and 0.99 (never 0.0 or 1.0)
        reward = round(max(0.01, min(0.99, reward)), 2)

        done = (
            len(self.found_issues) == len(true_issues)
            or self.steps >= self.max_steps
        )

        return {
            "observation": self.state(),
            "reward": Reward(value=reward),
            "done": done,
            "debug": {
                "correct": list(correct),
                "missed": list(missed),
                "false_positive": list(false_positive)
            }
        }

    def _match_issue(self, issue, comment):
        patterns = {
            "sql injection": r"(sql injection|unsanitized|user input|concatenation|injection)",
            "n+1 query": r"(n\+1|multiple queries|loop query|n plus 1)",
            "missing index": r"(missing index|no index|index hint|add index)",
            "inefficient join": r"(inefficient join|wrong join|nested loop|join type|cross join)"
        }
        pattern = patterns.get(issue, issue)
        return re.search(pattern, comment) is not None


# =========================
# Initialize
# =========================

env = SQLReviewEnv()


# =========================
# API Routes
# =========================

@app.post("/reset")
def reset(task: str = "easy"):
    if task == "easy":
        env.current_index = 0
    elif task == "medium":
        env.current_index = 1
    elif task == "hard":
        env.current_index = 2

    env.feedback_history = []
    env.found_issues = set()
    env.steps = 0

    return env.state()


@app.post("/step")
def step(action: Action):
    return env.step(action)


@app.get("/state")
def get_state():
    return env.state()