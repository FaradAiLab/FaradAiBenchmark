# ISSUE-005: Discrepancy API and Web UI "Compare Runs" View

## Parent
[SPEC-0002: Hybrid Security Engine (L1/L2) and Large-Scale Comparative Benchmark Platform](../specs/hybrid-guard-and-discrepancy-benchmark-spec.md)

## What to build
Develop a SQL-based discrepancy engine to compare two different benchmark runs (e.g., Run-L1 vs Run-Laya or Run-Laya vs Run-Hybrid) at the micro level. Create a REST endpoint (`GET /api/runs/{run_a}/compare/{run_b}`) that filters out rows where all 10,000 cases agreed and returns only the discrepant cases where the two models diverged.

Add a **"⚖️ Compare Runs"** tab to the Web UI:
1. Dynamic dropdowns for selecting two runs.
2. Macro comparison cards: Latency savings radar, F1 and FPR deltas, Agreement Rate (`Agreement Rate %`).
3. Discrepancy Diff Table: Paginated (25 per page) interactive component listing conflicting verdicts and opening the right-hand Case Detail Drawer with the submitted payload on row click.

```sql
-- Core Discrepancy Query Pattern (ADR 0004)
SELECT 
    a.case_id, a.domain, a.analysis_tier, a.expected,
    a.predicted_blocked AS run_a_blocked, a.latency_ms AS run_a_latency,
    b.predicted_blocked AS run_b_blocked, b.latency_ms AS run_b_latency
FROM run_case_evaluations a
JOIN run_case_evaluations b ON a.case_id = b.case_id
WHERE a.run_id = ? AND b.run_id = ?
  AND a.predicted_blocked != b.predicted_blocked
LIMIT ? OFFSET ?;
```

## Acceptance criteria
- [x] `GET /api/runs/{run_a}/compare/{run_b}` compares two runs via SQL JOIN in milliseconds and returns a paginated discrepancy list and agreement percentage.
- [x] The **"⚖️ Compare Runs"** tab is active in the Web UI top navigation.
- [x] Based on the dataset selected in the first dropdown, the second dropdown (Run B) is dynamically filtered to list only other models using the **same dataset** (guaranteeing intersection).
- [x] When two runs are selected, macro metric cards (F1 delta, average latency delta, agreement rate, A missed / B caught) are immediately computed and displayed.
- [x] Filtering in the Discrepancy table (All Discrepancies / A missed & B caught / B missed & A caught / FP Divergence) works.
- [x] Clicking a row in the Discrepancy table opens the right-hand Case Detail Drawer showing both models' verdicts side-by-side along with syntax-highlighted payload contents.

## Blocked by
- [ISSUE-004: 10,000+ Scale DuckDB Relational Storage (run_case_evaluations)](./ISSUE-004-scalable-duckdb-relational-storage.md) (Done)
