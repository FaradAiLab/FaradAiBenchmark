# Implementation Plan: Generic Cloud Decision Model Benchmarking (Phase 8)

* **Feature:** Generic Cloud System One Decision Model Benchmarking (`typesafe/jev-1.14` & multi-provider support)
* **Governing Specification:** [SPEC.md](../../SPEC.md)
* **Related ADR:** [ADR 0011: Generic Cloud Decision Model Architecture & System One Wire Parity](../adr/0011-generic-cloud-decision-model-architecture.md)
* **Canonical Plan:** [tasks/plan.md](../../tasks/plan.md)
* **Status:** Awaiting Human Approval

---

## 1. Overview & Architecture
Decomposes Phase 8 into 9 atomic vertical slices across 4 modules (`eval-status-and-state-parity`, `cloud-provider-registry`, `systemone-cloud-adapter`, `cloud-matrix-execution`) so any cloud System One model can be registered in DuckDB/YAML without Python edits, benchmarked with scientific parity against local Apple Silicon runs, and bounded by atomic budget caps and deterministic `--resume-run-id`.

---

## 2. Dependency Graph & Implementation Order

```text
[Task 1: Runtime Deps (pyproject.toml) + WF-005 Live OpenRouter Wire Check]
        │
        ├──────────────────────────────┐
        ▼                              ▼
[Task 2: EvalStatus &           [Task 4: DuckDB Cloud Registry,
 format_decision_state()]        Secret Hygiene & Seed YAML]
        │                              │
        ▼                              ▼
[Task 3: Refusal & State        [Task 5: manage_cloud_models.py CLI &
 Parity in Local/MCP]            Unified resolve_adapter()]
        │                              │
        ▼                              ▼
[🛑 Checkpoint 1]              [🛑 Checkpoint 2]
                                       │
                                       ▼
                               [Task 6: TDD RED - SystemOneCloudAdapter]
                                       │
                                       ▼
                               [Task 7: TDD GREEN - SystemOneCloudAdapter]
                                       │
                                       ▼
                               [🛑 Checkpoint 3]
                                       │
                                       ▼
[Task 8: Cloud Matrix Concurrency, Budget Cap, Single Writer & --resume-run-id]
                                       │
                                       ▼
[Task 9: Web Schema Parity, Explicit-Column INSERT & asyncio.to_thread]
                                       │
                                       ▼
                               [🛑 Checkpoint 4: Full Regression & Smoke Run]
```

See [tasks/plan.md](../../tasks/plan.md) and [tasks/todo.md](../../tasks/todo.md) for full risk table, acceptance criteria, and verification commands.
