# Task Checklist: Generic Cloud Decision Model Benchmarking (Phase 8)

* **Governing Specification:** [SPEC.md](../SPEC.md)
* **Implementation Plan:** [plan.md](plan.md)
* **Related ADR:** [ADR 0011: Generic Cloud Decision Model Architecture & System One Wire Parity](../docs/adr/0011-generic-cloud-decision-model-architecture.md)
* **Status:** Implemented (Offline Complete; Live OpenRouter `WF-005` & Smoke Run Gated on `OPENROUTER_API_KEY` + Parquet Datasets)

---

## Phase 1: Pre-Flight Dependencies, Live Wire Check & Core Parity

- [ ] **Task 1: Runtime Dependencies & Live OpenRouter Jev Verification (`WF-005`)**
  - **Description:** Promote `httpx>=0.27.0` and declare `pyyaml>=6.0` in `pyproject.toml` runtime `dependencies`, install into `.venv`, and execute the 2-case OpenRouter `typesafe/jev-1.14` verification (`WF-005`) once `OPENROUTER_API_KEY` is populated in `.env` (recording observed `usage`, `noul`, latency, and `canonical_text` vs `structured_json` parity, closing `WF-005` in `MAP.md`).
  - **Acceptance Criteria:**
    - [x] `httpx>=0.27.0` and `pyyaml>=6.0` are declared in `[project] dependencies` in `pyproject.toml`.
    - [x] `.venv/bin/python -c "import httpx, yaml"` succeeds cleanly.
    - [ ] `WF-005` empirical response capture (1 benign + 1 malicious MCP call) is recorded and `WF-005` closed (gated: `.env` currently has empty `OPENROUTER_API_KEY=`).
  - **Verification:** `.venv/bin/python -c "import httpx, yaml; print('OK')"` and `make test-unit`
  - **Dependencies:** None
  - **Files:** `pyproject.toml`, `docs/wayfinder/cloud-decision-providers/tickets/WF-005-jev-openrouter-api-check.md`, `docs/wayfinder/cloud-decision-providers/MAP.md`
  - **Estimated Scope:** Small (3 files)

- [x] **Task 2: `EvalStatus`, `EvaluationResult` & `BaseModelAdapter.format_decision_state()` Core**
  - **Description:** Introduce `EvalStatus` (`OK | REFUSAL | ERROR | SKIPPED`) and telemetry fields (`eval_status`, `inference_rtt_ms`, `retry_wait_ms`, `input_tokens`, `output_tokens`, `cached_tokens`, `cost_usd`, `cost_source`) in `adapters/base.py`, along with canonical `BaseModelAdapter.format_decision_state()` (shared `DEC-07` isolation + sorted JSON + URL-decode canonicalization).
  - **Acceptance Criteria:**
    - [x] `EvalStatus` enum and extended `EvaluationResult` fields exist in `adapters/base.py` with backward-compatible defaults (`eval_status="OK"`).
    - [x] `BaseModelAdapter.format_decision_state()` deterministically formats `PRIMARY_USER_GOAL`, optional `UNTRUSTED_EXTERNAL_DATA`, `TOOL_NAME`, `TOOL_PURPOSE`, `CALL_ARGUMENTS`, and `CANONICAL_DECODED_ARGUMENTS`.
    - [x] Unit tests in `tests/test_eval_status_parity.py` verify `EvaluationResult` serialization and `format_decision_state()` edge cases.
  - **Verification:** `.venv/bin/python -m pytest tests/test_eval_status_parity.py -v`
  - **Dependencies:** Task 1
  - **Files:** `adapters/base.py`, `tests/test_eval_status_parity.py`
  - **Estimated Scope:** Small (2 files)

- [x] **Task 3: Refusal & State Parity Fixes in Local Adapters and MCP Factory**
  - **Description:** Update local System One adapters and FastMCP wrapper so none of them silently coerce `{"type": "refusal"}` or missing answer keys to `0.0` (`ALLOWED`), and align state formatting on `BaseModelAdapter.format_decision_state()`.
  - **Acceptance Criteria:**
    - [x] `adapters/ollama_decision_adapter.py`, `adapters/kev_adapter.py`, and `laya_security_guard_mcp.py` check `answer.get("type") == "refusal"` / missing keys and return `verdict="REFUSAL"`, `eval_status="REFUSAL"`, `is_blocked=False`.
    - [x] Local adapters call `BaseModelAdapter.format_decision_state()` for apples-to-apples parity.
    - [x] `guard_mcp_factory.py` propagates `verdict` (`REFUSAL` / `ERROR`) instead of overwriting any `is_blocked=False` result as `"ALLOWED"`.
  - **Verification:** `.venv/bin/python -m pytest tests/test_eval_status_parity.py tests/test_ollama_decision_adapter.py tests/test_kev_adapter.py tests/test_mcp_servers.py -v`
  - **Dependencies:** Task 2
  - **Files:** `adapters/ollama_decision_adapter.py`, `adapters/kev_adapter.py`, `laya_security_guard_mcp.py`, `guard_mcp_factory.py`, `tests/test_ollama_decision_adapter.py`
  - **Estimated Scope:** Medium (5 files)

### 🛑 Checkpoint 1: After Tasks 1–3 (`eval-status-and-state-parity`)
- [x] `tests/test_eval_status_parity.py` and all mocked local adapter/MCP unit tests pass (`test_kev_adapter.py` requires external `.scratch/kev` clone)
- [x] Phase 8 + unit test suite passes with zero regressions (`test_kev_adapter.py` omitted without `.scratch/kev`)

---

## Phase 2: DuckDB Cloud Registry, Secret Hygiene & Unified Resolution

- [x] **Task 4: DuckDB `cloud_providers` / `cloud_models` Registry, Secret Hygiene & Seed YAML**
  - **Description:** Implement `adapters/cloud_registry.py` managing `cloud_providers` and `cloud_models` tables in `data/benchmark_runs.duckdb`, Pydantic schema validation (`ProviderDialect` enum check, `https://` enforcement for non-localhost endpoints, sensitive-header denylist on `extra_headers`, `api_key_env`-only secrets), YAML import/export, and `config/cloud_models/default_systemone.yaml` seed definitions (OpenRouter `typesafe/jev-1.14`, `pplx-decider-v1.3:free`, TypeSafe Direct, Liquid AI).
  - **Acceptance Criteria:**
    - [x] `cloud_providers` and `cloud_models` tables initialize idempotently in DuckDB.
    - [x] Validation rejects `http://` (non-localhost), rejects `Authorization`/`Cookie`/`x-api-key`/`Proxy-Authorization` in `extra_headers`, and rejects invalid `ProviderDialect` values.
    - [x] YAML import/export round-trips provider and model configs without losing thresholds, pricing, or limits.
  - **Verification:** `.venv/bin/python -m pytest tests/test_cloud_registry.py -v`
  - **Dependencies:** Task 1
  - **Files:** `adapters/cloud_registry.py`, `config/cloud_models/default_systemone.yaml`, `tests/test_cloud_registry.py`
  - **Estimated Scope:** Medium (3 files)

- [x] **Task 5: `manage_cloud_models.py` CLI & Unified `resolve_adapter()` in `benchmark_runner.py`**
  - **Description:** Create `scripts/manage_cloud_models.py` (`--import`, `--export`, `--list`) and expose `resolve_adapter(model_id, db_con)` in `adapters/cloud_registry.py` covering both static `ADAPTER_REGISTRY` and dynamic DuckDB `cloud_models`. Update `benchmark_runner.py` to drop static `argparse choices=`, resolve models dynamically, exclude non-`OK` rows from `TP/TN/FP/FN` metrics, separate `inference_rtt_ms` from `retry_wait_ms`, and print `refusal_rate`/`error_rate`/`cost_usd`.
  - **Acceptance Criteria:**
    - [x] `scripts/manage_cloud_models.py --import` / `--list` / `--export` works end-to-end against DuckDB.
    - [x] `benchmark_runner.py --model <dynamic-cloud-id>` no longer fails `argparse` validation and fails explicitly on unknown IDs or missing env keys.
    - [x] `benchmark_runner.py` metrics exclude `REFUSAL`/`ERROR`/`SKIPPED` from accuracy/FPR denominators and report `inference_rtt_ms` without retry-sleep inflation.
  - **Verification:** `.venv/bin/python -m pytest tests/test_cloud_registry.py -v` and `.venv/bin/python scripts/manage_cloud_models.py --help`
  - **Dependencies:** Task 2, Task 4
  - **Files:** `scripts/manage_cloud_models.py`, `adapters/cloud_registry.py`, `benchmark_runner.py`, `tests/test_cloud_registry.py`
  - **Estimated Scope:** Medium (4 files)

### 🛑 Checkpoint 2: After Tasks 4–5 (`cloud-provider-registry`)
- [x] `tests/test_cloud_registry.py` passes 100%
- [x] Phase 8 + unit test suite passes with zero regressions

---

## Phase 3: `SystemOneCloudAdapter` (TDD Cycle)

- [x] **Task 6: `SystemOneCloudAdapter` Unit Test Suite (TDD RED)**
  - **Description:** Write comprehensive mocked `httpx.Client` tests in `tests/test_systemone_cloud_adapter.py` covering all 4 closed `ProviderDialect`s (`OPENROUTER_DECISIONS`, `TYPESAFE_SYSTEMONE`, `LIQUID_SYSTEMONE`, `PERPLEXITY_DECISIONS`), `QuestionProfile` (`dual_check_v1`), refusal handling, `429` retry with and without `Retry-After`, `inference_rtt_ms` vs `retry_wait_ms`, `max_body_bytes` overflow -> `SKIPPED` (no truncation), `cost_source` (`api_reported` vs `estimated_fallback`), and header scrubbing in logs/`raw_output`.
  - **Acceptance Criteria:**
    - [x] All 4 dialect payload/response/usage/refusal edge cases have explicit failing tests prior to implementation (RED).
    - [x] Secret scrubbing test verifies `Authorization` / API key strings never appear in `raw_output` or logged exceptions.
  - **Verification:** `.venv/bin/python -m pytest tests/test_systemone_cloud_adapter.py` (expected RED failure before Task 7)
  - **Dependencies:** Task 2, Task 4
  - **Files:** `tests/test_systemone_cloud_adapter.py`
  - **Estimated Scope:** Small (1 file)

- [x] **Task 7: `SystemOneCloudAdapter` & `QuestionProfile` Implementation (TDD GREEN)**
  - **Description:** Implement `ProviderDialect`, `QuestionProfile`, and `SystemOneCloudAdapter(BaseModelAdapter)` in `adapters/systemone_cloud_adapter.py` using thread-local `httpx.Client` connection pooling (stateless payload per case), jittered exponential backoff + `Retry-After`, pre-flight `api_key_env` validation, `max_body_bytes` overflow -> `SKIPPED`, and wire it into `adapters/cloud_registry.py` (`resolve_adapter`) and `adapters/__init__.py`.
  - **Acceptance Criteria:**
    - [x] All tests in `tests/test_systemone_cloud_adapter.py` pass 100% (GREEN).
    - [x] `resolve_adapter()` instantiates `SystemOneCloudAdapter` cleanly for any enabled DuckDB `cloud_models` row.
    - [x] Every HTTP request carries zero cross-case conversation history and scrubs auth headers on error/storage.
  - **Verification:** `.venv/bin/python -m pytest tests/test_systemone_cloud_adapter.py tests/test_cloud_registry.py -v`
  - **Dependencies:** Task 5, Task 6
  - **Files:** `adapters/systemone_cloud_adapter.py`, `adapters/cloud_registry.py`, `adapters/__init__.py`
  - **Estimated Scope:** Medium (3 files)

### 🛑 Checkpoint 3: After Tasks 6–7 (`systemone-cloud-adapter`)
- [x] `tests/test_systemone_cloud_adapter.py` and `tests/test_cloud_registry.py` pass 100%
- [x] Phase 8 + unit test suite passes with zero regressions

---

## Phase 4: Cloud Matrix Execution, Resume & Web Parity

- [x] **Task 8: Cloud Matrix Concurrency, Single DuckDB Writer, Atomic Budget Cap & `--resume-run-id`**
  - **Description:** Upgrade `benchmark_matrix.py` and `HybridCascadeAdapter` (in `benchmark_runner.py`) for safe paid cloud runs: migrate `run_history` & `run_case_evaluations` with Phase 8 columns, standardize `run_history` metrics on `0.0–100.0%` (normalizing legacy `<= 1.0` rows), tag `CLOUD_DECISION_API` in `resolve_runtime_tier()`/`render_leaderboard()`, enforce `ORDER BY id` in `load_test_cases()`, execute `ThreadPoolExecutor` bounded concurrency with single DuckDB writer lock + pre-dispatch atomic `max_cost_usd` reservation, implement `config_hash`-validated `--resume-run-id`, skip `flush_unified_memory()` on cloud runs, and make `HybridCascadeAdapter` thread-safe (`threading.Lock`) with L2 telemetry passthrough.
  - **Acceptance Criteria:**
    - [x] `tests/test_cloud_execution_resume.py` verifies concurrent `ThreadPoolExecutor` writes via single writer lock without DuckDB errors.
    - [x] Atomic `max_cost_usd` reservation stops dispatch before exceeding budget across N concurrent workers.
    - [x] `--resume-run-id` verifies `config_hash`, skips prior `OK`/`SKIPPED`, retries `ERROR`, and rejects drifted configs.
    - [x] `run_history` metrics in `benchmark_matrix.py` match `0.0–100.0%` and `eval_status != 'OK'` rows are excluded from `TP/TN/FP/FN`.
  - **Verification:** `.venv/bin/python -m pytest tests/test_cloud_execution_resume.py tests/test_benchmark_matrix.py -v`
  - **Dependencies:** Task 3, Task 7
  - **Files:** `benchmark_matrix.py`, `benchmark_runner.py`, `tests/test_cloud_execution_resume.py`, `tests/test_benchmark_matrix.py`
  - **Estimated Scope:** Medium (4 files)

- [x] **Task 9: Web Backend Schema Parity, Explicit-Column Insert & `asyncio.to_thread` Safety**
  - **Description:** Update `web/schemas.py` (`CLOUD_DECISION_API`, `eval_status`, nullable `predicted_blocked`/`correct`, token/cost/latency fields) and `web/app.py` (replace positional `SELECT *` `INSERT OR REPLACE` into `run_case_evaluations` with explicit column list, replace silent `MockSecurityAdapter()` fallback with explicit failure / `resolve_adapter()`, wrap sync `adapter.evaluate()` inside `asyncio.to_thread()`, exclude non-`OK` rows from `TP/TN/FP/FN` & `api_compare_runs`, and persist `runtime_tier`/`experiment_id`).
  - **Acceptance Criteria:**
    - [x] `web/app.py` executes explicit-column `INSERT OR REPLACE INTO run_case_evaluations (...)` cleanly against migrated schema.
    - [x] Unknown `model_name` returns explicit error (no silent `MockSecurityAdapter()` execution).
    - [x] Synchronous cloud retries inside `execute_benchmark()` run via `asyncio.to_thread()` without blocking FastAPI WebSockets.
    - [x] `tests/test_relational_storage.py`, `tests/test_discrepancy_api.py`, and `tests/test_experiment_registry.py` pass with extended Phase 8 columns.
  - **Verification:** `.venv/bin/python -m pytest tests/test_relational_storage.py tests/test_experiment_api.py tests/test_discrepancy_api.py -v`
  - **Dependencies:** Task 8
  - **Files:** `web/schemas.py`, `web/app.py`, `tests/test_relational_storage.py`, `tests/test_experiment_api.py`
  - **Estimated Scope:** Medium (4 files)

### 🛑 Checkpoint 4: Final End-to-End Verification & Smoke Run
- [ ] Run full regression suite: `make test-unit` (68/68 Phase 8 + core unit tests pass; 19 pre-existing failures in full `pytest tests/` due to missing local `data/processed/*.parquet`, `.scratch/kev`, `torch`, and pre-existing `test_list_experiments` label mismatch)
- [x] Import `config/cloud_models/default_systemone.yaml` via `scripts/manage_cloud_models.py`
- [ ] Execute 2-case live sanity check & 200-case smoke matrix (`--models laya-mlx,ollama-d1,or-jev-1.14 --max-cost-usd 0.50`) and verify `CLOUD_DECISION_API`, `cost_usd`, `inference_rtt_ms`, and `eval_status` in DuckDB
