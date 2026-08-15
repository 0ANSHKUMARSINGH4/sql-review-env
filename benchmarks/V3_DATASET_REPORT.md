# SQL Review Environment V3 — Benchmark Dataset Quality & Validation Report

## Executive Summary
- **Validation Status**: PASSED
- **Canonical SHA-256 Hash**: `5342c666ce1e774b443ccd6446adecc9d2135d008237681027d393269b295dde`
- **Total Scenarios**: `300`
- **Valid / Invalid Scenarios**: `300` / `0`
- **Secondary AST Analyzer Conflicts**: `21`

---

## Dataset Distribution

### Dialect Distribution
| Dialect | Count | Percentage |
| :--- | :--- | :--- |
| **PostgreSQL** | `100` | 33.3% |
| **MySQL** | `100` | 33.3% |
| **SQLite** | `100` | 33.3% |

### Difficulty Distribution
| Difficulty | Count | Percentage |
| :--- | :--- | :--- |
| **Easy** | `102` | 34.0% |
| **Medium** | `108` | 36.0% |
| **Hard** | `90` | 30.0% |

---

## Category & Structural Metrics

- **Benign Scenarios**: `111` (queries containing zero vulnerabilities)
- **Adversarial Scenarios**: `51` (prompt injection in comments, fake keys, PII traps)
- **Single-Issue Scenarios**: `180`
- **Multi-Issue Scenarios**: `9`
- **N+1 Scenarios (with trace metadata)**: `24`

### Issue Category Breakdown
| Issue Category | Total Findings Declared |
| :--- | :--- |
| `sql_injection` | `66` |
| `unnecessary_columns` | `54` |
| `missing_index` | `30` |
| `inefficient_join` | `27` |
| `n_plus_one` | `24` |

---

## Secondary AST Analyzer Conflicts
*(Note: Conflicts represent secondary AST parser limitations and do NOT mutate curator-declared ground truth)*

- **Total Secondary Conflicts**: `21`
- **Conflict Types**:
  - `omitted_confirmed_issue`: 18
  - `unconfirmed_declared_issue`: 3

---
*Report generated automatically by `benchmarks/v3_validation.py`.*
