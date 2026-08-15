# Changelog — SQL Review Environment

All notable changes to the `sql-review-env` project are documented in this file.

---

## [V2.0.0] - 2026-08-15 (Enterprise Upgrade)

### Phase 1 — Privacy Foundation
- Implemented `PrivacyGateway`, `SecretDetector`, `PIIDetector`, and `TokenizedSanitizer`.
- Ephemeral placeholder tokenization (`<EMAIL_001>`, `<PASSWORD_001>`).
- Implemented `SanitizedLogger` and `ENTERPRISE_PRIVACY_MODE=true` fail-closed policy.

### Phase 2 — AI Security & Structured Agent Actions
- Implemented `PromptIsolationManager` separating System Instructions from untrusted SQL text.
- Added `SuspiciousInjectionSignal` advisory prompt-injection detector.
- Upgraded `SQLReviewAction` to support Pydantic `StructuredFinding` arrays while preserving legacy `review_comment` backward compatibility.

### Phase 3 — Multi-Dialect SQL AST Analysis
- Integrated `sqlglot` (v30.17.0) for multi-dialect AST parsing (`PostgreSQL`, `MySQL`, `SQLite`).
- Implemented `SQLAnalyzer` producing deterministic `GroundTruthIssue` findings.
- Credibility distinction between *confirmed* facts and *candidate* inferences.

### Phase 4 — Evidence-Based Multi-Dimensional Grading
- Implemented `EvidenceBasedEvaluator` scoring issue classification, line location, evidence quality, severity, and remediation recommendations.
- Calculates Precision, Recall, F1 score, Location Accuracy, and Fix Accuracy.
- Strict false-positive penalty (-0.75) and duplicate penalty (-0.25) to defeat keyword gaming.

### Phase 5 — Deterministic Dynamic Scenario Generation
- Implemented `ScenarioGenerator` with explicit `random.Random(seed)` determinism.
- Multi-dialect dynamic scenario generation across `easy`, `medium`, `hard` difficulty levels.
- Preserved all 5 original V1 benchmark scenarios (`easy-sql-review`, `medium-sql-review`, `hard-sql-review`, `security-extreme`, `performance-optimization`).

### Phase 6 — End-to-End Privacy-Preserving Agent Evaluation
- Connected complete inference pipeline (`Scenario -> Privacy Gateway -> Prompt Isolation -> Model Provider -> Pydantic Validation -> Evaluator -> Reward`).
- Implemented `ModelProvider` abstraction (`MockModelProvider` and `OpenAIModelProvider`).
- End-to-end privacy regression tests verifying zero secret leakage to model provider payloads.

### Phase 7 — Restricted Ephemeral SQL Analysis Sandbox
- Implemented `SandboxExecutor` running ephemeral SQLite in-memory databases (`:memory:`).
- `SandboxPolicyValidator` enforcing read-only execution and blocking `DROP`, `TRUNCATE`, `ALTER`, `ATTACH`, `DETACH`, `PRAGMA`, `INSERT`, `UPDATE`, `DELETE`, `REPLACE`, `load_extension`, and multi-statement SQL.
- Normalized `EXPLAIN QUERY PLAN` extraction for execution plan verification.

### Phase 8 — Enterprise Observability & Reporting
- Added `/metrics` and `/api/report` machine-readable endpoints.
- Implemented `ReportExporter` providing zero-leakage JSON and HTML report outputs.
- Upgraded Web Dashboard (`/`) to real-time V2 glassmorphism UI displaying privacy status, prompt injection signals, AST findings, and sandbox execution evidence.

### Phase 9 — Hardening, Security Audit & Documentation
- Comprehensive security audit verifying zero hardcoded credentials and 100% synthetic test data.
- Added end-to-end smoke test suite (`tests/test_end_to_end_smoke.py`).
- Added portfolio-grade `README.md`, `SECURITY.md`, and `CHANGELOG.md`.

---

## [V1.0.0] - Initial Hackathon Baseline
- OpenEnv-compatible FastAPI server (`/reset`, `/step`, `/state`, `/health`).
- Five baseline SQL review tasks with keyword-matching rubric evaluation.
