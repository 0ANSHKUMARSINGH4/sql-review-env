# Security & Threat Model Policy — SQL Review Environment

## Overview
`sql-review-env` is an open, privacy-preserving AI SQL review and evaluation environment. It provides structured safeguards for evaluating code review models and agents on SQL security and performance tasks.

---

## Security Architecture & Data Boundaries

```text
                 TRUSTED ENVIRONMENT
                          │
                          ▼
                ┌──────────────────┐
                │ Environment State│
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │ Privacy Gateway  │
                └────────┬─────────┘
                         │
                  SANITIZED DATA
                         │
                         ▼
                ┌──────────────────┐
                │ Prompt Isolation │
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │ Model Provider   │
                │   UNTRUSTED      │
                └────────┬─────────┘
                         │
                  STRUCTURED OUTPUT
                         │
                         ▼
                ┌──────────────────┐
                │ Pydantic         │
                │ Validation       │
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │ Deterministic    │
                │ Evaluator        │
                └──────────────────┘
```

---

## Threat Model (T1 – T10)

| Threat ID | Threat Description | Mitigation Strategy | Residual Risk |
| :--- | :--- | :--- | :--- |
| **T1** | Secret Leakage to LLM | Ephemeral tokenization (`<PASSWORD_001>`) via heuristic & regex secret detectors before provider submission. | Novel credential formats not matching configured regexes may require custom rules. |
| **T2** | PII Leakage | High-confidence PII detector replacing emails, phone numbers, and financial IDs with safe placeholders. | Heuristic PII detection is non-exhaustive; non-standard PII formats may bypass. |
| **T3** | Prompt Injection via SQL | Structural delimiter isolation framing untrusted SQL/schema separate from System Instructions. | Sophisticated jailbreaks targeting LLM reasoning limits cannot be 100% prevented at prompt level. |
| **T4** | Model Output Manipulation | Model output is validated through Pydantic `StructuredFinding` models before evaluation. | Model can still return invalid JSON resulting in `model_error` zero reward. |
| **T5** | SQL Sandbox Escape | Ephemeral SQLite in-memory execution (`:memory:`) with extension loading disabled (`enable_load_extension(False)`). | Application-level controls are enforced inside Python SQLite process, not OS container isolation. |
| **T6** | Destructive SQL Execution | Fail-closed validator blocking `DROP`, `TRUNCATE`, `ALTER`, `INSERT`, `UPDATE`, `DELETE`, `REPLACE`. | Only read-only `SELECT` and `EXPLAIN` queries are permitted. |
| **T7** | Host Filesystem Access | Prohibiting `ATTACH`/`DETACH` DATABASE and sanitizing exception messages (`[REDACTED_PATH]`). | File paths are redacted from log outputs. |
| **T8** | Network / DB Access | Zero network libraries in sandbox; execution runs strictly offline in memory. | None for sandbox execution. |
| **T9** | Benchmark Gaming | Multi-dimensional evaluator penalizing keyword spam without substantive evidence (-0.75 FP penalty). | Adversarial agents attempting gaming suffer precision/score drops. |
| **T10** | Report Data Leakage | `ReportExporter` strips token maps and redacts sensitive tokens before JSON/HTML output. | None in public report endpoints. |

---

## Responsible Disclosure
If you discover a security vulnerability or bypass in the privacy gateway, prompt isolation boundary, or analysis sandbox, please file an issue or contact the maintainer responsibly.
