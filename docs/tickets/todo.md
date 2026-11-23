# Task Checklist: Generic Cloud Decision Model Benchmarking (Phase 8)

* **Governing Specification:** [SPEC.md](../../SPEC.md)
* **Canonical Checklist:** [tasks/todo.md](../../tasks/todo.md)
* **Implementation Plan:** [plan.md](plan.md)
* **Status:** Implemented (Offline Complete; Live OpenRouter `WF-005` & Smoke Run Gated on `OPENROUTER_API_KEY` + Parquet Datasets)

---

## Phase 1: Pre-Flight Dependencies, Live Wire Check & Core Parity

- [ ] **Task 1: Runtime Dependencies & Live OpenRouter Jev Verification (`WF-005`)** (`pyproject.toml` done; `WF-005` live capture gated on `OPENROUTER_API_KEY`, `MAP.md`)
- [x] **Task 2: `EvalStatus`, `EvaluationResult` & `BaseModelAdapter.format_decision_state()` Core** (`adapters/base.py`, `tests/test_eval_status_parity.py`)
- [x] **Task 3: Refusal & State Parity Fixes in Local Adapters and MCP Factory** (`adapters/ollama_decision_adapter.py`, `adapters/kev_adapter.py`, `laya_security_guard_mcp.py`, `guard_mcp_factory.py`, `tests/test_ollama_decision_adapter.py`)
- [x] **🛑 Checkpoint 1: `eval-status-and-state-parity` Verified**

## Phase 2: DuckDB Cloud Registry, Secret Hygiene & Unified Resolution

- [x] **Task 4: DuckDB `cloud_providers` / `cloud_models` Registry, Secret Hygiene & Seed YAML** (`adapters/cloud_registry.py`, `config/cloud_models/default_systemone.yaml`, `tests/test_cloud_registry.py`)
- [x] **Task 5: `manage_cloud_models.py` CLI & Unified `resolve_adapter()` in `benchmark_runner.py`** (`scripts/manage_cloud_models.py`, `adapters/cloud_registry.py`, `benchmark_runner.py`, `tests/test_cloud_registry.py`)
- [x] **🛑 Checkpoint 2: `cloud-provider-registry` Verified**

## Phase 3: `SystemOneCloudAdapter` (TDD Cycle)

- [x] **Task 6: `SystemOneCloudAdapter` Unit Test Suite (TDD RED)** (`tests/test_systemone_cloud_adapter.py`)
- [x] **Task 7: `SystemOneCloudAdapter` & `QuestionProfile` Implementation (TDD GREEN)** (`adapters/systemone_cloud_adapter.py`, `adapters/cloud_registry.py`, `adapters/__init__.py`)
- [x] **🛑 Checkpoint 3: `systemone-cloud-adapter` Verified**

## Phase 4: Cloud Matrix Execution, Resume & Web Parity

- [x] **Task 8: Cloud Matrix Concurrency, Single DuckDB Writer, Atomic Budget Cap & `--resume-run-id`** (`benchmark_matrix.py`, `benchmark_runner.py`, `tests/test_cloud_execution_resume.py`, `tests/test_benchmark_matrix.py`)
- [x] **Task 9: Web Backend Schema Parity, Explicit-Column Insert & `asyncio.to_thread` Safety** (`web/schemas.py`, `web/app.py`, `tests/test_relational_storage.py`, `tests/test_experiment_api.py`)
- [ ] **🛑 Checkpoint 4: Full `make test-unit` Regression & Live Smoke Verification** (68/68 Phase 8 + core unit tests passed; YAML seeded to DuckDB; live smoke run gated on `OPENROUTER_API_KEY` + parquet datasets)
