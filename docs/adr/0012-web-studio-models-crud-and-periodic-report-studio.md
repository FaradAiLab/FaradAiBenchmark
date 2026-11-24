# ADR 0012: Web Studio Redesign — Models CRUD Dashboard & Periodic AI-Ready Report Studio

* **Date:** 2026-11-24
* **Status:** Accepted
* **Scope:** Farad Ai Benchmark / Web Dashboard (`Models` Tab, `Report Studio`, `History` Pagination, DuckDB Write Serialization & `run_history` Parity)
* **Supersedes / Extends:** Extends [ADR 0010](0010-code-first-adapters-duckdb-matrix-and-dual-track-serving.md) and [ADR 0011](0011-generic-cloud-decision-model-architecture.md); supersedes the Web UI `Matrix Studio` tab from Phase 7 while preserving CLI `benchmark_matrix.py`.

---

## 1. Context and Problem Statement

After Phase 8 introduced DuckDB-backed cloud System One models (`cloud_providers`, `cloud_models`), two gaps emerged in the Web Dashboard (`web/app.py`, `web/templates/index.html`, `web/static/app.js`):

1. **No Cloud Model Management UI:** Cloud providers and models could only be inspected or edited via CLI (`scripts/manage_cloud_models.py`) and YAML files. Users had no Web UI screen to view local/cloud adapters or create, edit, disable, or delete cloud model definitions.
2. **Misaligned `Matrix Studio` UI:** The Phase 7 `Matrix Studio` tab focused on configuring and executing multi-model templates from the browser, whereas the researcher's actual workflow is:
   - Execute individual benchmarks from `Dashboard` (or batch matrices via `benchmark_matrix.py` CLI),
   - Select approved completed runs from `History`, and
   - Compose a **read-only periodic benchmark report** that exports cleanly into an **AI-Ready Bundle** so an external LLM can write accurate executive and technical reports.

An adversarial review (`/doubt-driven-development`) and design interview (`/grill-with-docs`) also uncovered concrete codebase hazards that must be resolved alongside the UI redesign:
- `run_history` lacks structured `tier_scope`, `enable_l1`, and `limit_cases` columns (`web/app.py` encodes them inside display strings while `benchmark_matrix.py` omits them).
- `adapters/cloud_registry.py` lacks delete operations, has a case-sensitivity primary key bug (`save_cloud_model` vs `LOWER(model_id)` lookup), and allows cloud model IDs to silently shadow static `ADAPTER_REGISTRY` keys (`laya-mlx`, `mock`, etc.).
- `web/app.py` never calls `load_dotenv()`, causing `.env` presence badges to report false negatives on fresh startup, and opens unlocked `duckdb.connect()` handles across concurrent requests and background benchmark tasks.
- `GET /api/runs` is capped at 20 rows without pagination or filters, and embedding raw security-benchmark payloads in an AI-Ready Markdown brief introduces direct prompt-injection risk against the report-writing LLM.

---

## 2. Decision Log

### Decision 1: Unified `Models` Tab & DuckDB Single Source of Truth
* **Decision:** Add a `Models` tab showing:
  1. **Local Code-First Adapters (Read-Only):** Static list of local MLX, Ollama, MPS, L1, and Mock adapters with backend, runtime tier, quantization, and availability status—preserving ADR 0010's code-first boundary (no UI editing of local Python adapters, no Ollama network health probes).
  2. **Cloud Providers & Cloud Models (Full DuckDB CRUD):** Backed by `/api/cloud-providers` and `/api/cloud-models` endpoints over `adapters/cloud_registry.py`. DuckDB is the **Single Source of Truth** for Web UI edits; YAML import/export stays in `scripts/manage_cloud_models.py` (with an optional read-only YAML download in UI, zero path-based upload/import).
* **Hardening in `adapters/cloud_registry.py` & `web/app.py`:**
  * Add `delete_cloud_model()` and `delete_cloud_provider()` (blocking provider deletion while child `cloud_models` reference it).
  * Normalize `provider_id` and `model_id` to lowercase on save/lookup to eliminate case-sensitivity PK collisions.
  * Reject cloud `model_id` values colliding with static `ADAPTER_REGISTRY` keys.
  * Reject credentials/query strings embedded in `base_url` in addition to existing `https://` (non-localhost) and `extra_headers` denylist checks.
  * Call `load_dotenv(override=False)` during `web/app.py` lifespan startup and expose only a boolean `api_key_configured` indicator (never raw secret values).

### Decision 2: Retire `Matrix Studio` Web UI Tab in Favor of Read-Only `Report Studio`
* **Decision:** Remove the `Matrix Studio` tab (`page-matrix`, nav button) and its ~400 lines of unused frontend JS from `web/templates/index.html` and `web/static/app.js`, updating `tests/test_experiment_api.py` accordingly. Preserve `benchmark_matrix.py` CLI and `adapters/experiment_registry.py` (`experiment_templates`) intact for terminal batch runs.
* **Rationale:** Eliminates UI dead weight and matches the real workflow—`Dashboard` runs tests, `Report Studio` strictly curates completed runs without executing anything.

### Decision 3: Two-State Report Lifecycle (`draft` → `published` Sealed Snapshot)
* **Decision:** Persist periodic reports in a new DuckDB `benchmark_reports` table with a strict two-state lifecycle:
  * **`draft`:** Editable metadata (`title`, `period_label`, `researcher_notes`) and mutable `selected_run_ids`. If a run referenced by a draft is later deleted from `History`, opening the draft surfaces a warning and prunes the missing `run_id`.
  * **`published` (Sealed Snapshot):** Publishing computes and freezes the complete report payload (`snapshot_json`: normalized run metrics, `threat_domain`/`analysis_tier` slices, parity caveats, metadata-only failure/discrepancy summaries) and permanently seals the record. A published report **cannot be edited** (`409 Conflict` on mutation), remains intact even if underlying `run_history` rows are later deleted, and supports only **Duplicate as Draft** or **Delete** (with confirmation).
* **Rationale:** Gives researchers freedom to iterate while assembling a periodic report, while guaranteeing historical immutability once published—without the failure modes of a "Refresh Snapshot" feature.

### Decision 4: Structured `run_history` Parity Columns & Paginated `History`
* **Decision:**
  * Extend `run_history` (`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`) with `tier_scope VARCHAR`, `enable_l1 BOOLEAN`, and `limit_cases INTEGER`, populated consistently by both `web/app.py` and `benchmark_matrix.py` (with safe fallback parsing for legacy rows).
  * Aggregate `threat_domain`, `analysis_tier`, `inference_rtt_ms`, and `retry_wait_ms` slices directly from `run_case_evaluations` (falling back to `category_stats` JSON for legacy rows).
  * Upgrade `GET /api/runs` with pagination (`limit` default 50, max 200; `offset`; `total_count`) and filters (`dataset`, `model`, `status`). Allow selecting both `completed` and `budget_stopped` runs across pages via persistent frontend selection state (`Set<run_id>`), flagging `budget_stopped` runs explicitly in `parity_warnings`.

### Decision 5: Metadata-Only AI-Ready Report Bundle (Zero Raw Payloads)
* **Decision:** `Report Studio` exports a dual-format **AI-Ready Report Bundle** (`Copy Markdown`, `Download .md`, `Download .json`):
  * Contains exact `0–100%` metrics (`Accuracy`, `Precision`, `Recall`, `F1`, `FPR`, `TP/FP/FN/TN`), `EvalStatus` counts (`OK/REFUSAL/ERROR/SKIPPED`), latency (`avg_latency_ms`, `inference_rtt_ms`, `retry_wait_ms`), token/cost provenance (`total_cost_usd`, `cost_source`), `runtime_tier`, `enable_l1`, `parity_warnings`, `threat_domain` & `analysis_tier` breakdowns, and metadata-only failure/discrepancy summaries (`case_id`, `threat_domain`, `tool_name`, `expected`, `predicted` — capped at top 5 FN + 5 FP per run and top 10 common-dataset disagreements).
  * **Explicitly excludes raw `tool_arguments` and `context` payloads** in v1.
* **Rationale:** Eliminates prompt-injection risk against external report-writing LLMs, avoids context-window bloat, and removes Parquet re-read overhead during report export.

### Decision 6: Process-Wide `DB_WRITE_LOCK` in `web/app.py`
* **Decision:** Introduce a shared module-level `DB_WRITE_LOCK = threading.Lock()` in `web/app.py` guarding all DuckDB write paths (`execute_benchmark`, `/api/cloud-providers`, `/api/cloud-models`, `/api/reports`, `DELETE /api/runs/{run_id}`).
* **Rationale:** Prevents DuckDB write-write transaction conflicts when users edit cloud models or save/publish reports while a background benchmark run is writing checkpoints.

---

## 3. Consequences

* [CONTEXT.md](../../CONTEXT.md) is updated with the canonical domain glossary terms for periodic reporting and cloud registry UI governance.
* [docs/specs/web-studio-models-and-report-studio-spec.md](../specs/web-studio-models-and-report-studio-spec.md) (mirrored in [SPEC.md](../../SPEC.md)) specifies exact schemas, endpoints, UI flows, and verification tests for Phase 9.
* In-app LLM auto-drafting, raw attack-payload embedding in reports, and UI editing of local code-first adapters remain explicitly out of scope.
