---
title: SQL Review Environment V2
emoji: 🔍
colorFrom: blue
colorTo: gray
sdk: docker
app_port: 7860
tags:
  - openenv
---

# SQL Review Environment V2 — Privacy-Preserving Enterprise AI SQL Review & Agent Evaluation

**Author:** Ansh Kumar Singh  
**Status:** Round 1 - Meta PyTorch OpenEnv Hackathon (Upgraded to V2 Enterprise Benchmark)

`sql-review-env` V2 is an open, privacy-preserving, enterprise-oriented RL environment designed to train and evaluate AI agents on **SQL Code Review**, **Database Security**, and **Query Performance Optimization**.

---

## Key Architecture & Data Flow

```text
               Raw SQL / Schema
                      │
                      ▼
               Privacy Gateway
            (Redaction & Tokenization)
                      │
                      ▼
            Prompt Isolation Boundary
         (System vs Untrusted SQL framing)
                      │
                      ▼
                Model Provider
          (Mock / OpenAI-compatible)
                      │
                      ▼
           Structured Findings (JSON)
                      │
                      ▼
            Evidence-Based Evaluator
      (Precision, Recall, F1, Location, Fix)
                      │
                      ▼
              Reward + Metrics State
```

---

## V2 Highlights

1. **Privacy Foundation (`privacy/`)**: Ephemeral tokenization (`<EMAIL_001>`, `<PASSWORD_001>`) redacting credentials, API keys, PII, and infrastructure tokens before LLM submission. Fail-closed `ENTERPRISE_PRIVACY_MODE=true` enforcement.
2. **Prompt-Injection Isolation (`security/`)**: Structural delimiter framing ensuring untrusted SQL queries, comments, and schemas cannot override system instructions. Advisory injection scanner for prompt override signals.
3. **Multi-Dialect AST SQL Analysis (`sql_analysis/`)**: Multi-dialect (`PostgreSQL`, `MySQL`, `SQLite`) AST parsing via `sqlglot` producing verified ground truth issues while distinguishing between *confirmed* facts and *candidate* inferences.
4. **Evidence-Based Multi-Dimensional Grading (`grading/`)**: Five-dimensional evaluation scoring issue classification, line location, evidence quality, severity, and remediation recommendations with precision, recall, F1 metrics and strict false-positive penalties (-0.75).
5. **Deterministic Dynamic Scenario Generation (`scenarios/`)**: Seed-reproducible dynamic scenario generation across dialects and difficulty levels (`easy`, `medium`, `hard`).
6. **Restricted Ephemeral SQL Sandbox (`sandbox/`)**: Ephemeral in-memory SQLite (`:memory:`) analysis sandbox executing `EXPLAIN QUERY PLAN` with application-level security policies blocking `DROP`, `TRUNCATE`, `ALTER`, `ATTACH`, `DETACH`, `PRAGMA`, `INSERT`, `UPDATE`, `DELETE`, `REPLACE`, `load_extension`, and multi-statement SQL.
7. **Enterprise Observability & Reporting (`reporting/`)**: Machine-readable `/metrics` and `/api/report` endpoints with zero secret/PII leakage guarantees.
8. **No-LLM Deterministic Mode**: Offline benchmark evaluation mode using `NO_LLM_MODE=true` or `LLM_ENABLED=false`.

---

## OpenEnv API Endpoints

- `POST /reset`: Reset environment to baseline task (`easy-sql-review`, `medium-sql-review`, `hard-sql-review`, `security-extreme`, `performance-optimization`) or dynamic scenario (`/reset?task=generated&seed=12345&dialect=postgres&difficulty=hard`).
- `POST /step`: Progress environment using structured `SQLReviewAction` or legacy `review_comment`.
- `GET /state`: Fetch current observation state.
- `GET /metrics`: Aggregated OpenEnv observability metrics.
- `GET /api/report`: Machine-readable `BenchmarkReport` JSON.
- `GET /`: Real-time V2 Enterprise Observability Dashboard.

---

## Setup & Execution

### Local Development
```bash
pip install -r requirements.txt
python -m pytest tests/ -v
uvicorn server.app:app --host 0.0.0.0 --port 7860
```

### Reproducible Baseline Benchmark
```bash
export MODEL_PROVIDER=mock
export LLM_ENABLED=false
python inference.py
```

---

## Important Disclaimers

- **Security & Privacy Boundary**: The privacy gateway and prompt isolation manager provide application-level safeguards for benchmark evaluation. They do NOT constitute formal enterprise compliance certification or a guarantee of perfect privacy against all novel attacks.
- **Database Sandbox**: The analysis sandbox operates in an ephemeral in-memory SQLite container with read-only application controls. It is designed for benchmark query plan inspection and does not connect to production databases.