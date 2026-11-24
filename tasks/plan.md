# Implementation Plan: Web Studio Redesign — Models Dashboard & Periodic AI-Ready Report Studio (Phase 9)

* **Feature:** Unified `Models` Tab (Local Read-Only + Cloud CRUD) & Read-Only Periodic `Report Studio` (Replacing `Matrix Studio` Web UI)
* **Governing Specification:** [SPEC.md](../SPEC.md) (mirrored in [web-studio-models-and-report-studio-spec.md](../docs/specs/web-studio-models-and-report-studio-spec.md))
* **Related ADR:** [ADR 0012: Web Studio Redesign — Models CRUD Dashboard & Periodic AI-Ready Report Studio](../docs/adr/0012-web-studio-models-crud-and-periodic-report-studio.md)
* **Domain Model:** [CONTEXT.md](../CONTEXT.md)
* **Wayfinder Map:** [MAP.md](../docs/wayfinder/web-studio-models-and-reports/MAP.md)
* **Status:** Implemented & Verified

---

## 1. Overview & Architecture

This plan decomposes Phase 9 into **7 atomic, verifiable tasks** grouped across 4 capability modules (`db-hardening-and-parity-schema`, `cloud-models-crud-api`, `report-studio-backend-and-bundle`, `web-studio-ui-redesign`). It delivers:
1. A hardened DuckDB Cloud Registry & process-wide write lock powering a new **`Models`** tab (read-only local adapters + full Cloud Provider/Model CRUD with `.env` boolean badges).
2. A read-only **`Report Studio`** tab replacing `Matrix Studio` in the Web UI (while keeping `benchmark_matrix.py` CLI and `experiment_templates` intact), fed by a paginated, filterable **`History`** tab with multi-page selection, a two-state **`draft` → `published` (sealed snapshot)** lifecycle, automatic **Parity Guards**, and a metadata-only **AI-Ready Markdown & JSON Bundle**.

---

## 2. Key Architecture Decisions (ADR 0012)

- **DuckDB Single Source of Truth for Cloud CRUD:** Web UI manages `cloud_providers` and `cloud_models` directly in DuckDB (lowercase IDs, static `ADAPTER_REGISTRY` collision guard, `base_url` query-string/credential guard, FK delete protection on providers). YAML import/export remains CLI-only (`scripts/manage_cloud_models.py`) with optional read-only YAML download in UI.
- **Process-Wide `DB_WRITE_LOCK` & `load_dotenv`:** `web/app.py` calls `load_dotenv(override=False)` on lifespan startup and serializes every DuckDB write (`execute_benchmark`, cloud CRUD, report CRUD/publish, run delete) through one module-level `threading.Lock`.
- **Backwards-Compatible Paginated `GET /api/runs`:** Existing `tests/test_multi_model_discrepancy.py` expects `GET /api/runs` to return `List[RunSummary]`. Therefore `GET /api/runs` keeps returning `List[RunSummary]` while adding `limit` (default 50, max 200), `offset`, `dataset`, `model`, `status` query params and an `X-Total-Count` response header.
- **Structured `run_history` Parity Columns:** `tier_scope`, `enable_l1`, and `limit_cases` are added to `run_history` and populated by both `web/app.py` and `benchmark_matrix.py` (with legacy string fallback for older rows).
- **Two-State Sealed Report Lifecycle (`draft` → `published`):** Drafts are editable (warning & pruning if a referenced run was deleted); published reports freeze `snapshot_json` permanently (`409 Conflict` on edit, immune to `History` deletes, supporting only Delete or Duplicate as Draft).
- **Metadata-Only AI-Ready Bundle:** Excludes raw `tool_arguments` and `context` payloads in v1 to eliminate prompt-injection and context-bloat risks.
- **Clean `Matrix Studio` Retirement:** Removes `page-matrix` HTML and ~400 lines of dead JS from `web/static/app.js` while keeping `benchmark_matrix.py` CLI and `experiment_registry.py` intact.

---

## 3. Dependency Graph & Implementation Order

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

*(Tasks 3 and 4–5 can run independently after Checkpoint 1; Tasks 6 and 7 converge into final UI & regression verification.)*

---

## 4. Risks and Mitigations

| Risk | Impact | Mitigation |
| :--- | :---: | :--- |
| **`GET /api/runs` shape change breaks `tests/test_multi_model_discrepancy.py`** | Medium | Keep JSON body as `List[RunSummary]` and return pagination total via `X-Total-Count` header. |
| **DuckDB write-write conflicts while background benchmark runs** | High | Guard every write path in `web/app.py` with one shared `DB_WRITE_LOCK`. |
| **Legacy `run_history` rows have `NULL` in `tier_scope`/`enable_l1`/`limit_cases`** | Medium | Implement safe fallback parser in `report_registry.py` reading legacy `(static)`/`(semantik)` and `+ L1`/`(Saf)` markers when structured columns are `NULL`. |
| **Removing `Matrix Studio` breaks `tests/test_experiment_api.py`** | Low | Task 7 updates UI assertions in `tests/test_experiment_api.py` to check `Models` and `Report Studio` while preserving `/api/experiments` backend assertions. |
| **Cloud model ID shadows local adapter (`laya-mlx`, `mock`)** | High | Task 1 enforces explicit collision check against `ADAPTER_REGISTRY` keys on `save_cloud_model()`. |

---

## 5. Open Questions

- **None.** Ready for human approval before `/build`.
