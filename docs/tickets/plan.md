# Implementation Plan: Web Studio Redesign — Models Dashboard & Periodic AI-Ready Report Studio (Phase 9)

* **Feature:** Unified `Models` Tab (Local Read-Only + Cloud CRUD) & Read-Only Periodic `Report Studio` (Replacing `Matrix Studio` Web UI)
* **Governing Specification:** [SPEC.md](../../SPEC.md)
* **Related ADR:** [ADR 0012: Web Studio Redesign — Models CRUD Dashboard & Periodic AI-Ready Report Studio](../adr/0012-web-studio-models-crud-and-periodic-report-studio.md)
* **Canonical Plan:** [tasks/plan.md](../../tasks/plan.md)
* **Status:** Implemented & Verified

---

## 1. Overview & Architecture
Decomposes Phase 9 into **7 atomic vertical tasks** across 4 modules (`db-hardening-and-parity-schema`, `cloud-models-crud-api`, `report-studio-backend-and-bundle`, `web-studio-ui-redesign`) to deliver a DuckDB-backed Cloud Models CRUD dashboard and a read-only periodic `Report Studio` (`draft` → `published` sealed snapshots + metadata-only AI-Ready Markdown & JSON Bundle) while retiring `Matrix Studio` from the Web UI and keeping `benchmark_matrix.py` CLI intact.

---

## 2. Dependency Graph & Implementation Order

```text
[Task 1: Cloud Registry Hardening & run_history Parity Columns]
        │
        ▼
[Task 2: web/app.py load_dotenv, DB_WRITE_LOCK & Paginated /api/runs]
        │
        ▼
[🛑 Checkpoint 1: Core DB & History Parity Verified]
        │
        ├──────────────────────────────────────┐
        ▼                                      ▼
[Task 3: FastAPI Cloud Providers       [Task 4: adapters/report_registry.py
 & Cloud Models CRUD API + Tests]       Lifecycle, Parity Guard & Bundle]
        │                                      │
        ▼                                      ▼
[🛑 Checkpoint 2: Cloud CRUD API]      [Task 5: FastAPI /api/reports*
        │                               Endpoints & Export Tests]
        │                                      │
        │                                      ▼
        │                              [🛑 Checkpoint 3: Report API]
        │                                      │
        ▼                                      ▼
[Task 6: Models Tab UI (Local          [Task 7: Retire Matrix Studio UI ->
 Read-Only + Cloud CRUD Modals)]        Report Studio + Paginated History]
        │                                      │
        └──────────────────┬───────────────────┘
                           ▼
        [🛑 Checkpoint 4: Full make test-unit & ruff check]
```

See [tasks/plan.md](../../tasks/plan.md) and [tasks/todo.md](../../tasks/todo.md) for full risk table, acceptance criteria, and verification commands.
