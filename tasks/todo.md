# Task Checklist: Web Studio Redesign — Models Dashboard & Periodic AI-Ready Report Studio (Phase 9)

* **Governing Specification:** [SPEC.md](../SPEC.md)
* **Implementation Plan:** [plan.md](plan.md)
* **Related ADR:** [ADR 0012: Web Studio Redesign — Models CRUD Dashboard & Periodic AI-Ready Report Studio](../docs/adr/0012-web-studio-models-crud-and-periodic-report-studio.md)
* **Status:** Implemented & Verified

---

## Phase 1: DB Hardening, Parity Schema & Write Serialization (`db-hardening-and-parity-schema`)

- [x] **Task 1: Cloud Registry Hardening & `run_history` Parity Columns**
  - **Description:** Harden `adapters/cloud_registry.py` with lowercase ID normalization (`provider_id`, `model_id`), static `ADAPTER_REGISTRY` collision guard, `base_url` query-string/credential guard, `delete_cloud_model()`, `delete_cloud_provider()` (blocking delete when child models exist), and `is_api_key_configured(env_name)`. Extend `ensure_run_history_schema()` with `tier_scope`, `enable_l1`, and `limit_cases` columns, and update `benchmark_matrix.py` to populate them.
  - **Acceptance Criteria:**
    - [x] Saving `OR-Jev-1.14` normalizes to `or-jev-1.14` and updates the existing row instead of duplicating PKs.
    - [x] Saving a cloud model named `laya-mlx` or `mock` raises `ValueError`.
    - [x] `base_url` with `?key=123` or `user:pass@` raises `ValueError`.
    - [x] `delete_cloud_provider` raises `ValueError` while child models reference it, and succeeds once children are deleted.
    - [x] `run_history` includes `tier_scope`, `enable_l1`, `limit_cases` populated by `benchmark_matrix.py`.
  - **Verification:** `.venv/bin/python -m pytest tests/test_cloud_registry.py tests/test_benchmark_matrix.py -v`
  - **Dependencies:** None
  - **Files:** `adapters/cloud_registry.py`, `benchmark_matrix.py`, `tests/test_cloud_registry.py`
  - **Estimated Scope:** Medium (3 files)

- [x] **Task 2: `web/app.py` Boot Hygiene (`load_dotenv`), `DB_WRITE_LOCK` & Paginated `/api/runs`**
  - **Description:** Call `load_dotenv(override=False)` in `web/app.py` lifespan, introduce module-level `DB_WRITE_LOCK = threading.Lock()` around all DuckDB writes (`execute_benchmark`, `DELETE /api/runs/{run_id}`, and upcoming endpoints), populate `tier_scope`, `enable_l1`, and `limit_cases` on new Web runs, and upgrade `GET /api/runs` with `limit` (default 50, max 200), `offset`, `dataset`, `model`, `status` query params plus `X-Total-Count` response header (preserving `List[RunSummary]` body).
  - **Acceptance Criteria:**
    - [x] `load_dotenv(override=False)` executes at FastAPI lifespan startup.
    - [x] All DuckDB writes in `web/app.py` acquire `DB_WRITE_LOCK`.
    - [x] `GET /api/runs?limit=25&offset=0&status=completed` returns filtered `List[RunSummary]` and accurate `X-Total-Count` header.
    - [x] Existing `tests/test_multi_model_discrepancy.py` and `tests/test_relational_storage.py` pass unchanged.
  - **Verification:** `.venv/bin/python -m pytest tests/test_multi_model_discrepancy.py tests/test_relational_storage.py -v`
  - **Dependencies:** Task 1
  - **Files:** `web/app.py`, `web/schemas.py`
  - **Estimated Scope:** Small (2 files)

### 🛑 Checkpoint 1: After Tasks 1–2 (`db-hardening-and-parity-schema`)
- [x] `tests/test_cloud_registry.py`, `tests/test_multi_model_discrepancy.py`, and `tests/test_relational_storage.py` pass 100%.

---

## Phase 2: Cloud Models CRUD API (`cloud-models-crud-api`)

- [x] **Task 3: FastAPI Cloud Providers & Cloud Models CRUD Endpoints + Tests**
  - **Description:** Add Pydantic request/response schemas in `web/schemas.py` and implement `/api/cloud-providers` (`GET/POST/PUT/DELETE`), `/api/cloud-models` (`GET/POST/PUT/DELETE`), and read-only `GET /api/cloud-config/export-yaml` in `web/app.py` (guarded by `DB_WRITE_LOCK`), exposing only boolean `api_key_configured` (never raw secrets). Write comprehensive API tests in `tests/test_cloud_models_api.py`.
  - **Acceptance Criteria:**
    - [x] Full CRUD round-trip succeeds for both providers and models via FastAPI `TestClient`.
    - [x] Deleting a provider with linked models returns `409 Conflict`; deleting after removing models returns `200`.
    - [x] `api_key_configured` accurately reflects env presence while raw API key strings never appear in any response payload.
    - [x] Creating a cloud model with a static local adapter name returns `422` / `400`.
  - **Verification:** `.venv/bin/python -m pytest tests/test_cloud_models_api.py -v`
  - **Dependencies:** Task 2
  - **Files:** `web/schemas.py`, `web/app.py`, `tests/test_cloud_models_api.py`
  - **Estimated Scope:** Medium (3 files)

### 🛑 Checkpoint 2: After Task 3 (`cloud-models-crud-api`)
- [x] `tests/test_cloud_models_api.py` passes 100% with zero secret leakage.

---

## Phase 3: Report Studio Backend & AI-Ready Bundle (`report-studio-backend-and-bundle`)

- [x] **Task 4: `adapters/report_registry.py` — `benchmark_reports` Schema, Lifecycle (`draft` → `published`), Parity Guard & Metadata-Only AI-Ready Bundle**
  - **Description:** Implement `adapters/report_registry.py` with `benchmark_reports` DuckDB schema, `ReportStatus` (`draft | published`), `ReportImmutableError`, `draft` create/get/update (accepting only `completed` and `budget_stopped` runs; warning & pruning deleted runs on draft read), `publish_report()` (freezing `snapshot_json` immutably), `duplicate_report()` (cloning to new `draft`), `delete_report()`, `Parity Guard` (`dataset`, `tier_scope`, `enable_l1`, `limit_cases`, `budget_stopped` caveats), `run_case_evaluations` slice aggregation (`threat_domain`, `analysis_tier`, `inference_rtt_ms`, `retry_wait_ms`), and metadata-only `JSON` + `<benchmark_report>` `Markdown` bundle builder (max 5 FN + 5 FP per run, max 10 common-dataset disagreements, zero raw `tool_arguments`/`context` payloads).
  - **Acceptance Criteria:**
    - [x] `benchmark_reports` initializes idempotently in DuckDB.
    - [x] `draft` rejects `failed`/`running`/`pending` runs and accepts `completed`/`budget_stopped`.
    - [x] `publish_report()` freezes `snapshot_json`; subsequent `update_draft_report()` raises `ReportImmutableError`, and deleting an underlying run from `run_history` does not alter the published report.
    - [x] `Parity Guard` detects dataset, `tier_scope`, `enable_l1`, `limit_cases`, and `budget_stopped` mismatches.
    - [x] Exported `JSON` and `Markdown` contain exact `0–100%` metrics, `EvalStatus` counts, domain/tier slices, and metadata-only failure/discrepancy lists with zero raw payloads.
  - **Verification:** `.venv/bin/python -m pytest tests/test_reports_api.py -k "registry" -v`
  - **Dependencies:** Task 2
  - **Files:** `adapters/report_registry.py`, `tests/test_reports_api.py`
  - **Estimated Scope:** Medium (2 files)

- [x] **Task 5: FastAPI `/api/reports*` Endpoints & Export Integration Tests**
  - **Description:** Add report Pydantic schemas in `web/schemas.py` and expose `GET/POST /api/reports`, `GET/PUT/DELETE /api/reports/{report_id}`, `POST /api/reports/{report_id}/publish`, `POST /api/reports/{report_id}/duplicate`, and `GET /api/reports/{report_id}/export?format=md|json` in `web/app.py` under `DB_WRITE_LOCK`. Complete full API test coverage in `tests/test_reports_api.py`.
  - **Acceptance Criteria:**
    - [x] All `/api/reports*` endpoints work end-to-end; `PUT` on a `published` report returns `409 Conflict`.
    - [x] `/export?format=md` returns `text/markdown` wrapped in `<benchmark_report>` and `/export?format=json` returns valid JSON dossier.
    - [x] Full `tests/test_reports_api.py` passes including pagination, filtering, draft pruning, publish sealing, duplicate, delete, and export checks.
  - **Verification:** `.venv/bin/python -m pytest tests/test_reports_api.py -v`
  - **Dependencies:** Task 4
  - **Files:** `web/schemas.py`, `web/app.py`, `tests/test_reports_api.py`
  - **Estimated Scope:** Medium (3 files)

### 🛑 Checkpoint 3: After Tasks 4–5 (`report-studio-backend-and-bundle`)
- [x] `tests/test_reports_api.py` passes 100%.

---

## Phase 4: Web Studio UI Redesign & `Matrix Studio` Retirement (`web-studio-ui-redesign`)

- [x] **Task 6: `Models` Tab UI (Local Read-Only + Cloud Provider/Model CRUD Modals)**
  - **Description:** Add the `Models` navigation button and page in `web/templates/index.html`, styles in `web/static/index.css`, and frontend CRUD logic in `web/static/app.js`: read-only Local Adapters table, Cloud Providers table (`.env` presence badge + Add/Edit/Delete modal), Cloud Models table (`enabled` toggle + Add/Edit/Delete modal + read-only YAML download), refreshing the `Dashboard` Model Adapter selector whenever cloud models change.
  - **Acceptance Criteria:**
    - [x] `Models` tab renders local code-first adapters read-only and Cloud Providers/Models with full create/edit/toggle/delete controls.
    - [x] `.env` status displays as a clear boolean badge ("Configured" / "Missing") without exposing secrets.
    - [x] Adding or toggling a cloud model immediately updates the `Dashboard` Model Adapter dropdown.
  - **Verification:** Manual check via `uvicorn web.app:app` + `GET /` HTML assertions in `tests/test_experiment_api.py`
  - **Dependencies:** Task 3
  - **Files:** `web/templates/index.html`, `web/static/app.js`, `web/static/index.css`
  - **Estimated Scope:** Medium (3 files)

- [x] **Task 7: Retire `Matrix Studio` UI → Build `Report Studio` & Paginated Multi-Select `History` + Update Tests**
  - **Description:** Remove `Matrix Studio` nav button, `page-matrix` HTML, and ~400 lines of dead Matrix Studio JS from `web/templates/index.html` and `web/static/app.js`. Upgrade `History` with pagination (`25/50/100`), dataset/model/status filters, persistent multi-page checkboxes (`Set<run_id>`) for `completed`/`budget_stopped` runs, and a sticky action bar (*"N selected → Create Draft Report / Add to Draft"*). Build read-only `Report Studio` UI (saved reports sidebar, draft editor, parity warning banner, Publish/Seal confirmation, Duplicate as Draft, Delete, one-click Copy Markdown / Download `.md` / Download `.json`). Update `tests/test_experiment_api.py` to assert `Models` + `Report Studio` tabs while keeping `/api/experiments` backend tests passing.
  - **Acceptance Criteria:**
    - [x] `GET /` contains `page-models` and `page-reports` and no longer contains `Matrix Studio` or `page-matrix`.
    - [x] `History` paginates via `X-Total-Count` and preserves checked `run_id`s across page changes.
    - [x] `Report Studio` enforces read-only view on `published` reports (hides/disables edit controls, shows Sealed badge) and provides working Copy Markdown + Download `.md`/`.json`.
    - [x] `tests/test_experiment_api.py` and full `make test-unit` pass with zero regressions.
  - **Verification:** `.venv/bin/python -m pytest tests/test_experiment_api.py tests/test_reports_api.py tests/test_cloud_models_api.py -v && make test-unit && .venv/bin/ruff check adapters/ web/ tests/`
  - **Dependencies:** Task 5, Task 6
  - **Files:** `web/templates/index.html`, `web/static/app.js`, `web/static/index.css`, `tests/test_experiment_api.py`
  - **Estimated Scope:** Medium (4 files)

### 🛑 Checkpoint 4: Final Verification
- [x] `make test-unit` passes 100% with zero regressions.
- [x] `.venv/bin/ruff check adapters/ web/ tests/` passes cleanly.
- [x] `benchmark_matrix.py --help` still works intact.
