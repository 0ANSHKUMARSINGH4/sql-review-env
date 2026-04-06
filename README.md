---
title: Sql Review Env
emoji: 💻
colorFrom: green
colorTo: yellow
sdk: docker
pinned: false
license: mit
---

# sql-review-env

**Author:** Ansh Kumar Singh

`sql-review-env` is an OpenEnv-based Reinforcement Learning (RL) environment where an AI agent reviews SQL queries for common issues such as **SQL injection vulnerabilities**, **N+1 query patterns**, and **inefficient joins**.

---

## Observation Space

- `query` *(string)*: The SQL query to review
- `feedback_history` *(List[string])*: Previous feedback comments
- `issues_remaining` *(int)*: Number of unresolved issues

## Action Space

- `review_comment` *(string)*: Natural language comment identifying issues

## Tasks

- **Easy**: SQL injection via string concatenation
- **Medium**: N+1 query pattern detection
- **Hard**: Three combined issues — SQL injection, missing index, inefficient join

## Setup
```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 7860
```

## Baseline Scores

| Difficulty | Score |
|------------|-------|
| Easy       | 0.85  |
| Medium     | 0.60  |
| Hard       | 0.45  |