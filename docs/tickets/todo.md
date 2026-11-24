# Task Checklist: Web Studio Redesign — Models Dashboard & Periodic AI-Ready Report Studio (Phase 9)

* **Governing Specification:** [SPEC.md](../../SPEC.md)
* **Canonical Checklist:** [tasks/todo.md](../../tasks/todo.md)
* **Implementation Plan:** [plan.md](plan.md)
* **Status:** Implemented & Verified

---

## Phase 1: DB Hardening, Parity Schema & Write Serialization (`db-hardening-and-parity-schema`)

- [x] **Task 1: Cloud Registry Hardening & `run_history` Parity Columns** (`adapters/cloud_registry.py`, `benchmark_matrix.py`, `tests/test_cloud_registry.py`)
- [x] **Task 2: `web/app.py` Boot Hygiene (`load_dotenv`), `DB_WRITE_LOCK` & Paginated `/api/runs`** (`web/app.py`, `web/schemas.py`)
- [x] **🛑 Checkpoint 1: Core DB & History Parity Verified**

## Phase 2: Cloud Models CRUD API (`cloud-models-crud-api`)

- [x] **Task 3: FastAPI Cloud Providers & Cloud Models CRUD Endpoints + Tests** (`web/schemas.py`, `web/app.py`, `tests/test_cloud_models_api.py`)
- [x] **🛑 Checkpoint 2: Cloud CRUD API Verified**

## Phase 3: Report Studio Backend & AI-Ready Bundle (`report-studio-backend-and-bundle`)

- [x] **Task 4: `adapters/report_registry.py` — `benchmark_reports` Schema, Lifecycle (`draft` → `published`), Parity Guard & Metadata-Only AI-Ready Bundle** (`adapters/report_registry.py`, `tests/test_reports_api.py`)
- [x] **Task 5: FastAPI `/api/reports*` Endpoints & Export Integration Tests** (`web/schemas.py`, `web/app.py`, `tests/test_reports_api.py`)
- [x] **🛑 Checkpoint 3: Report Studio API & Export Verified**

## Phase 4: Web Studio UI Redesign & `Matrix Studio` Retirement (`web-studio-ui-redesign`)

- [x] **Task 6: `Models` Tab UI (Local Read-Only + Cloud Provider/Model CRUD Modals)** (`web/templates/index.html`, `web/static/app.js`, `web/static/index.css`)
- [x] **Task 7: Retire `Matrix Studio` UI → Build `Report Studio` & Paginated Multi-Select `History` + Update Tests** (`web/templates/index.html`, `web/static/app.js`, `web/static/index.css`, `tests/test_experiment_api.py`)
- [x] **🛑 Checkpoint 4: Full `make test-unit` Regression & `ruff check` Verification**
