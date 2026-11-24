# ISSUE-004: 10,000+ Scale DuckDB Relational Storage (run_case_evaluations)

## Parent
[SPEC-0002: Hybrid Security Engine (L1/L2) and Large-Scale Comparative Benchmark Platform](../specs/hybrid-guard-and-discrepancy-benchmark-spec.md)

## What to build
Split the DuckDB schema into two relational tables so that 10,000+ test cases in benchmark runs can be stored and queried quickly without memory or disk bloat:
1. `run_history`: Stores macro metrics per run (F1, Precision, Recall, FPR, Latency, Category Stats).
2. `run_case_evaluations`: Stores the individual evaluation result for each test case relationally (`run_id, case_id, domain, analysis_tier, is_malicious, predicted_blocked, correct, decided_by, confidence, latency_ms`).

Update the `web/app.py` benchmark execution engine to perform high-speed bulk inserts of all case results into `run_case_evaluations` when a run completes.

```sql
-- Schema Reference (ADR 0004)
CREATE TABLE IF NOT EXISTS run_case_evaluations (
    run_id              VARCHAR NOT NULL,
    case_id             VARCHAR NOT NULL,
    domain              VARCHAR NOT NULL,
    analysis_tier       VARCHAR NOT NULL,
    is_malicious        BOOLEAN NOT NULL,
    predicted_blocked   BOOLEAN NOT NULL,
    correct             BOOLEAN NOT NULL,
    decided_by          VARCHAR NOT NULL,
    confidence          DOUBLE DEFAULT 0,
    latency_ms          DOUBLE DEFAULT 0,
    PRIMARY KEY (run_id, case_id)
);
CREATE INDEX IF NOT EXISTS idx_case_eval_lookup ON run_case_evaluations (run_id, correct);
```

## Acceptance criteria
- [x] `run_case_evaluations` table is created and indexed (`idx_case_eval_lookup`) in DuckDB.
- [x] `web/app.py` benchmark engine bulk-inserts all evaluation rows via a PyArrow vectorized table at the end of each run.
- [x] Bulk write time for a 10,000-row test suite is under 1 second (measured ~66ms with PyArrow, 15x SLA margin).
- [x] When a past run is deleted (`DELETE /api/runs/{id}`), all associated `run_case_evaluations` rows are also cleaned up (verified via unit test).
- [x] The `/api/runs/{id}` endpoint remains backward-compatible and dynamically reads case samples from this table.

## Blocked by
- [ISSUE-003: Fail-Fast Cascading Hybrid Security Engine (HybridCascadeAdapter)](./ISSUE-003-fail-fast-cascade-hybrid-engine.md) (Done)
