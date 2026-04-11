# SQL Review Environment (OpenEnv)

**Author:** Ansh Kumar Singh
**Status:** Round 1 - Meta PyTorch OpenEnv Hackathon

`sql-review-env` is an RL environment designed to train and evaluate AI agents on the real-world task of **SQL Code Review**. It simulates the process of identifying security vulnerabilities (like SQL Injection) and performance bottlenecks (like N+1 queries) in database interactions.

## Motivation
In modern development, AI agents are increasingly used to automate code reviews. This environment provides a structured, reproducible way to measure an agent's ability to "think" about SQL safety and performance using the OpenEnv framework.

---

## Observation Space

The observation is a typed Pydantic model (`SQLReviewObservation`):

- `query` *(string)*: The SQL query (or ORM pattern) to review.
- `schema_context` *(string)*: Information about the relevant tables and indices.
- `feedback_history` *(List[string])*: A list of reviews already provided in the current episode.
- `issues_remaining` *(int)*: Count of unique issues still present in the query.
- `done` *(boolean)*: Whether the review process for this query is complete.

## Action Space

The action is a typed Pydantic model (`SQLReviewAction`):

- `review_comment` *(string)*: A natural language comment describing the identified issues.

## Reward & Rubric System

This environment follows **OpenEnv RFC 004** for reward calculation:
- **Partial Progress**: Agents receive `+0.5` reward for each unique, valid issue identified via keyword matching.
- **Episodic Done**: The episode ends when all issues are found or the step limit (10) is reached.
- **Programmatic Grader**: A deterministic keyword-based mapping ensures scores are reproducible and fair.

---
## Web Dashboard
The environment now includes a real-time **Vulnerability Dashboard** at the root URL (`/`). This provides a visual overview of the current query, table schema, and identified issues, which is helpful for debugging and manual verification.

---
## Benchmark Tasks

| Task ID | Difficulty | Description | Issues to Find |
|---------|------------|-------------|----------------|
| `easy-sql-review` | Easy | Single Table SQL Injection | `sql_injection` |
| `medium-sql-review` | Medium | ORM pattern causing N+1 | `n_plus_one` |
| `hard-sql-review` | Hard | Multi-issue Join query | `sql_injection`, `missing_index`, `inefficient_join` |
| `security-extreme` | Hard | Nested Dynamic SQL Injection | `sql_injection` |
| `performance-review` | Medium | Redundant Subqueries & Stars | `unnecessary_columns`, `inefficient_join` |

---
## Setup & Usage

### Local Development
```bash
pip install -r requirements.txt
uvicorn server.app:app --host 0.0.0.0 --port 7860
```

### Baseline Inference
The baseline `inference.py` has been upgraded with **retry logic** and **fuzzy matching support** to handle transient API errors.
```bash
export HF_TOKEN="your_key"
export MODEL_NAME="mistralai/Mistral-7B-Instruct-v0.3"
python inference.py
```

### Docker
```bash
docker build -t sql-review-env .
docker run -p 7860:7860 sql-review-env
```

## Baseline Scores

| Task | Score (0.0 - 1.0) |
|------|-------|
| Easy | 1.00  |
| Medium | 1.00 |
| Hard | 0.85  |

*Scores obtained using Mistral-7B-Instruct-v0.3.*