# Spec: Web Studio Redesign — Models Dashboard & Periodic AI-Ready Report Studio (Phase 9)

* **Spec Document:** `SPEC.md` (mirrored in [docs/specs/web-studio-models-and-report-studio-spec.md](docs/specs/web-studio-models-and-report-studio-spec.md))
* **Related ADR:** [ADR 0012: Web Studio Redesign — Models CRUD Dashboard & Periodic AI-Ready Report Studio](docs/adr/0012-web-studio-models-crud-and-periodic-report-studio.md)
* **Prior ADRs & Specs:** [ADR 0010](docs/adr/0010-code-first-adapters-duckdb-matrix-and-dual-track-serving.md), [ADR 0011](docs/adr/0011-generic-cloud-decision-model-architecture.md), [Phase 8 Spec](docs/specs/cloud-decision-model-benchmarking-spec.md)
* **Domain Model:** [CONTEXT.md](CONTEXT.md)
* **Wayfinder Map:** [MAP.md](docs/wayfinder/web-studio-models-and-reports/MAP.md)
* **Status:** Draft — Pending Human Review & Approval

---

## 0. Capability Map & Explicit Assumptions

### Explicit Assumptions
1. **Single-User Local Workstation Dashboard:** No login/auth layer is added; FastAPI binds to localhost (`127.0.0.1:8000`) and talks to local `data/benchmark_runs.duckdb`.
2. **DuckDB Single Source of Truth for Cloud CRUD:** Web UI creates, edits, disables, and deletes `cloud_providers` and `cloud_models` directly in DuckDB. YAML import/export remains a CLI operation (`scripts/manage_cloud_models.py`), with an optional read-only YAML download endpoint in the UI.
3. **Zero Raw Attack Payloads in Reports (v1):** AI-Ready Report Bundles (`JSON` + `Markdown`) exclude raw `tool_arguments` and `context` fields by design (Q5 Option B), preventing prompt injection against downstream LLMs and avoiding Parquet re-reads.
4. **No New Third-Party Dependencies:** Everything runs on existing `pyproject.toml` dependencies (`fastapi`, `uvicorn`, `jinja2`, `duckdb`, `pydantic`, `pyyaml`, `python-dotenv`, `pytest`, `httpx`).
5. **CLI Preservation:** Retiring `Matrix Studio` applies strictly to the Web UI (`index.html`, `app.js`); `benchmark_matrix.py` CLI and `adapters/experiment_registry.py` (`experiment_templates`) remain untouched and operational.

### Capability Map (Module Decomposition)

| Module ID | Responsibility | Depends On |
|---|---|---|
| **`db-hardening-and-parity-schema`** | `adapters/cloud_registry.py` hardening (delete + FK guard, lowercase IDs, static adapter collision guard, `base_url` query-string guard, `is_api_key_configured()`), `run_history` parity columns (`tier_scope`, `enable_l1`, `limit_cases`), `benchmark_reports` DuckDB schema, and process-wide `DB_WRITE_LOCK` + `load_dotenv(override=False)` in `web/app.py`. | — |
| **`cloud-models-crud-api`** | FastAPI CRUD endpoints (`/api/cloud-providers`, `/api/cloud-models`, read-only `/api/cloud-config/export-yaml`) and Pydantic schemas in `web/schemas.py`. | `db-hardening-and-parity-schema` |
| **`report-studio-backend-and-bundle`** | Paginated/filtered `GET /api/runs`, `adapters/report_registry.py` (`draft` → `published` sealed snapshot lifecycle, `Parity Guard`, `run_case_evaluations` slice aggregation, metadata-only AI-Ready `JSON` & `<benchmark_report>` `Markdown` builder), and `/api/reports*` FastAPI endpoints. | `db-hardening-and-parity-schema` |
| **`web-studio-ui-redesign`** | `web/templates/index.html`, `web/static/app.js`, `web/static/index.css`: add `Models` tab (read-only local adapters + Cloud CRUD UI), retire `Matrix Studio` HTML/JS and replace with read-only `Report Studio`, add `History` pagination + multi-page selection bar → `Report Studio`, and update `tests/test_experiment_api.py`. | `cloud-models-crud-api`, `report-studio-backend-and-bundle` |

**Build Order:** `db-hardening-and-parity-schema` → (`cloud-models-crud-api` + `report-studio-backend-and-bundle`) → `web-studio-ui-redesign`

---

## 1. Objective & Scope

Deliver two purpose-driven Web Dashboard capabilities while resolving DuckDB concurrency, registry safety, and parity schema gaps identified during adversarial review:

1. **`Models` Dashboard Tab (Local Read-Only + Cloud CRUD):**
   - Display local code-first adapters (MLX, Ollama, MPS, L1, Mock) read-only with backend, runtime tier, quantization, and availability status.
   - Provide full CRUD over DuckDB `cloud_providers` and `cloud_models` (`enabled` toggle, thresholds, `remote_model_slug`, `question_profile_id`, `state_format`, `input_price_per_1m_usd`, `max_context_tokens`, provider URL/endpoint/dialect/`api_key_env`/concurrency/limits) with a boolean `.env` presence badge (zero raw secret exposure).
2. **`Report Studio` Tab (Replacing `Matrix Studio` UI):**
   - Strictly read-only curation over completed and `budget_stopped` runs—never executes benchmarks.
   - Paginated, filterable `History` (`dataset`, `model`, `status`) with persistent multi-page run selection (`Set<run_id>`) feeding directly into `Report Studio`.
   - Two-state DuckDB lifecycle: **`draft`** (editable; warns & prunes if a referenced run was deleted from `History`) → **`published`** (permanently sealed frozen snapshot; `409 Conflict` on edit, immune to future `History` deletions; supports Delete with confirmation and Duplicate as Draft).
   - Automatic **Parity Guards** surfacing mismatches in `dataset`, `tier_scope`, `enable_l1`, `limit_cases`, and partial `budget_stopped` runs.
   - One-click **AI-Ready Report Bundle** (`Copy Markdown`, `Download .md`, `Download .json`) with exact `0–100%` metrics, `EvalStatus` counts, latency/cost telemetry, `threat_domain` & `analysis_tier` slices, and metadata-only failure/discrepancy summaries (`case_id`, `threat_domain`, `tool_name`, `expected`, `predicted`).

### Out of Scope
* In-app LLM API auto-drafting button (external AI consumes the exported Markdown/JSON bundle).
* Raw `tool_arguments` / `context` payload embedding inside AI-Ready Bundles.
* Editing local code-first adapter Python logic or thresholds from Web UI (ADR 0010).
* Deleting `benchmark_matrix.py` CLI or `adapters/experiment_registry.py` (`experiment_templates`).
* Ollama live network health probes or Python source-file path display in `Models`.
* "Refresh Snapshot" on published reports (use Duplicate as Draft instead).
* L1 Fail-Fast Cascade USD-saved telemetry (deferred to a future telemetry slice).

---

## 2. Tech Stack & Dependencies

* **Language & Runtime:** Python 3.12+ (macOS Apple Silicon Darwin arm64)
* **Backend:** FastAPI, Uvicorn, Pydantic v2, Jinja2, `python-dotenv`, `pyyaml`
* **Database:** DuckDB 1.1+ (`data/benchmark_runs.duckdb`)
* **Frontend:** Vanilla HTML/CSS/JS (`web/templates/index.html`, `web/static/app.js`, `web/static/index.css`)
* **Testing:** Pytest + FastAPI `TestClient` (`httpx`)

---

## 3. Commands

```bash
# 1. Run targeted Phase 9 unit & API tests
.venv/bin/python -m pytest tests/test_cloud_registry.py tests/test_cloud_models_api.py tests/test_reports_api.py tests/test_experiment_api.py -v

# 2. Run full regression suite
make test-unit

# 3. Lint / static check (ruff)
.venv/bin/ruff check adapters/ web/ tests/

# 4. Launch Web Dashboard locally (dev reload)
.venv/bin/python -m uvicorn web.app:app --host 127.0.0.1 --port 8000 --reload
```

---

## 4. Project Structure

```text
FaradAiBenchmark/
├── adapters/
│   ├── cloud_registry.py                 # Updated: delete_*, lowercase IDs, collision & URL guards, run_history parity cols
│   └── report_registry.py                # [NEW] DuckDB benchmark_reports CRUD, draft->published freeze, Parity Guard, MD/JSON bundle builder
├── benchmark_matrix.py                   # Updated: write tier_scope, enable_l1, limit_cases into run_history
├── web/
│   ├── app.py                            # Updated: load_dotenv, DB_WRITE_LOCK, /api/cloud-*, paginated /api/runs, /api/reports*
│   ├── schemas.py                        # Updated: Cloud Provider/Model CRUD, PaginatedRuns, Report & Export Pydantic schemas
│   ├── templates/
│   │   └── index.html                    # Updated: add Models tab, replace Matrix Studio with Report Studio, History pagination & selection bar
│   └── static/
│       ├── app.js                        # Updated: Models CRUD UI, Report Studio UI, History pagination/multi-select, remove ~400L dead Matrix JS
│       └── index.css                     # Updated: Models cards/badges, Report Studio layout, sealed-report badge, History selection bar
├── tests/
│   ├── test_cloud_registry.py            # Extended: delete, FK guard, lowercase PK, static collision, query-string URL, env check
│   ├── test_cloud_models_api.py          # [NEW] FastAPI /api/cloud-providers & /api/cloud-models CRUD + secret hygiene tests
│   ├── test_reports_api.py               # [NEW] Paginated /api/runs, draft->published immutability, Parity Guard, MD/JSON bundle tests
│   └── test_experiment_api.py            # Updated: keep backend /api/experiments coverage, assert Models + Report Studio UI instead of Matrix Studio
├── CONTEXT.md                            # Updated with Phase 9 canonical glossary terms
├── docs/adr/0012-web-studio-models-crud-and-periodic-report-studio.md
├── docs/specs/web-studio-models-and-report-studio-spec.md
└── SPEC.md                               # [THIS FILE] Phase 9 Canonical Feature Specification
```

---

## 5. DuckDB Schema, API Contract & Code Style

### 5.1 DuckDB Schemas
```sql
-- 1. run_history structured parity columns
ALTER TABLE run_history ADD COLUMN IF NOT EXISTS tier_scope VARCHAR DEFAULT 'all';
ALTER TABLE run_history ADD COLUMN IF NOT EXISTS enable_l1 BOOLEAN DEFAULT NULL;
ALTER TABLE run_history ADD COLUMN IF NOT EXISTS limit_cases INTEGER DEFAULT NULL;

-- 2. Periodic curated reports table
CREATE TABLE IF NOT EXISTS benchmark_reports (
    report_id         VARCHAR PRIMARY KEY,          -- e.g. rpt-20261124-a1b2c3
    title             VARCHAR NOT NULL,
    period_label      VARCHAR DEFAULT '',           -- e.g. 2026-11 / Q4-2026
    researcher_notes  VARCHAR DEFAULT '',
    status            VARCHAR NOT NULL DEFAULT 'draft', -- 'draft' | 'published'
    selected_run_ids  VARCHAR NOT NULL DEFAULT '[]',    -- JSON array of run_id strings
    snapshot_json     VARCHAR DEFAULT NULL,         -- Frozen JSON dossier populated on publish
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    published_at      TIMESTAMP DEFAULT NULL
);
```

### 5.2 FastAPI Endpoints
* **Cloud Registry CRUD:**
  * `GET /api/cloud-providers`, `POST /api/cloud-providers`, `PUT /api/cloud-providers/{provider_id}`, `DELETE /api/cloud-providers/{provider_id}` (`409` if referenced by models)
  * `GET /api/cloud-models`, `POST /api/cloud-models`, `PUT /api/cloud-models/{model_id}`, `DELETE /api/cloud-models/{model_id}`
  * `GET /api/cloud-config/export-yaml` (read-only YAML download)
* **Paginated & Filtered `History`:**
  * `GET /api/runs?limit=50&offset=0&dataset=&model=&status=` → `{items: List[RunSummary], total_count: int, limit: int, offset: int}`
* **Report Studio:**
  * `GET /api/reports`, `POST /api/reports`, `GET /api/reports/{report_id}`, `PUT /api/reports/{report_id}` (`409` if `published`)
  * `POST /api/reports/{report_id}/publish`, `POST /api/reports/{report_id}/duplicate`, `DELETE /api/reports/{report_id}`
  * `GET /api/reports/{report_id}/export?format=md|json`

### 5.3 AI-Ready Report Bundle Contract (Metadata-Only)
1. **Header & Context:** `report_id`, `title`, `period_label`, `status`, `published_at` / `generated_at`, `researcher_notes`.
2. **Parity Guards (`parity_warnings[]`):** Flags differing `dataset_name`, `tier_scope`, `enable_l1`, `total_cases`/`limit_cases`, and `budget_stopped` partial runs.
3. **Executive Comparison Table (`runs[]`):** `0–100%` metrics (`accuracy`, `precision`, `recall`, `f1`, `fpr`), `tp/fp/fn/tn`, `ok/refusal/error/skipped` counts, `avg_latency_ms`, `avg_inference_rtt_ms`, `avg_retry_wait_ms`, tokens, `total_cost_usd`, `cost_source`, `runtime_tier`, `enable_l1`, `status`.
4. **Slice Breakdowns:** Per-`threat_domain` and per-`analysis_tier` (`STATIC_CAPABLE`, `SEMANTIC_REQUIRED`, `HYBRID`) accuracy/recall/count aggregated from `run_case_evaluations` (legacy fallback: `category_stats`).
5. **Metadata-Only Failure & Discrepancy Summaries (Zero Raw Payloads):**
   - Per run: max **5 FN** + **5 FP** (`case_id`, `threat_domain`, `tool_name`, `expected_malicious`, `predicted_blocked`, `eval_status`, `latency_ms`).
   - Common-dataset disagreements (when ≥ 2 runs share a dataset): max **10 cases** where selected runs split between `BLOCKED` and `ALLOWED` (`case_id`, `threat_domain`, `tool_name`, `expected_malicious`, per-run verdict map).

### 5.4 Code Style Convention
```python
"""adapters/report_registry.py: DuckDB periodic report persistence & AI-Ready bundle builder."""

from enum import StrEnum
import threading

DB_WRITE_LOCK = threading.Lock()


class ReportStatus(StrEnum):
    """Two-state governance lifecycle for Curated Benchmark Reports (ADR 0012)."""

    DRAFT = "draft"
    PUBLISHED = "published"


class ReportImmutableError(ValueError):
    """Raised when attempting to mutate a sealed (published) benchmark report."""
```
* Use explicit SQL column lists in every `INSERT` / `SELECT` (never `SELECT *` for positional unpacking).
* Acquire `DB_WRITE_LOCK` around every DuckDB write connection in `web/app.py`.
* Keep Pydantic models strictly typed in `web/schemas.py`; never return raw `.env` secret values.

---

## 6. Testing Strategy

1. **Registry & Validation Unit Tests (`tests/test_cloud_registry.py`):**
   - Lowercase normalization (`OR-Jev` → `or-jev` updates existing PK, never duplicates).
   - Static `ADAPTER_REGISTRY` name collision (`laya-mlx`, `mock`, `kev-0.8b`) raises `ValueError`.
   - `base_url` with `?api_key=...` or `user:pass@` rejected; `https://` enforced (localhost exempt).
   - `delete_cloud_provider` raises `ValueError` while child models exist, succeeds after child models are deleted.
2. **Cloud Models API Tests (`tests/test_cloud_models_api.py`):**
   - Full CRUD round-trip over FastAPI `TestClient` with isolated temporary DuckDB.
   - Verify `api_key_configured` boolean reflects `os.environ`/`.env` while raw secret value never appears anywhere in JSON response.
   - Verify `409 Conflict` when deleting a referenced provider.
3. **Report Studio & History API Tests (`tests/test_reports_api.py`):**
   - `GET /api/runs` pagination (`limit`, `offset`, `total_count`) and `dataset`/`model`/`status` filtering.
   - Rejecting `failed`/`running`/`pending` runs while accepting `completed` and `budget_stopped` runs.
   - `draft` creation, editing, and graceful pruning/warning when a referenced run is deleted from `History`.
   - `publish` freezes `snapshot_json`, returns `409 Conflict` on subsequent `PUT`, survives later `DELETE /api/runs/{run_id}`, and supports `duplicate` → new `draft` + `DELETE`.
   - `parity_warnings` fire accurately on mismatched datasets, `tier_scope`, `enable_l1`, `limit_cases`, and `budget_stopped`.
   - `/export?format=md` and `/export?format=json` contain exact `0–100%` metrics, slice tables, and metadata-only failure lists with **zero raw `tool_arguments`/`context` strings**.
4. **UI & Regression Tests (`tests/test_experiment_api.py` + `make test-unit`):**
   - Verify `GET /` serves `Models` and `Report Studio` tabs and no longer contains `Matrix Studio` / `page-matrix`.
   - Verify `/api/experiments` backend and full `make test-unit` pass with zero regressions.

---

## 7. Boundaries

* **Always do:**
  * Acquire `DB_WRITE_LOCK` on every DuckDB write in `web/app.py`.
  * Normalize `provider_id` / `model_id` to lowercase and check static `ADAPTER_REGISTRY` collisions.
  * Compute metrics strictly over `eval_status == 'OK'` in `0–100%` units.
  * Run `make test-unit` after every vertical slice.
* **Ask first:**
  * Adding any new Python dependency to `pyproject.toml`.
  * Changing `GET /api/runs` response shape if any external script outside `web/` depends on it (verify via repo grep during planning).
  * Including raw `tool_arguments` or `context` payloads in future report versions.
* **Never do:**
  * Return, log, or persist raw API key values in DuckDB, YAML, or HTTP responses.
  * Mutate a `published` report's `snapshot_json` or metadata.
  * Trigger benchmark execution from `Report Studio`.
  * Delete `benchmark_matrix.py` or `adapters/experiment_registry.py`.

---

## 8. Success Criteria

1. **Models Dashboard Live:** User can view all local adapters (read-only) and create, edit, enable/disable, and delete cloud providers & cloud models from the `Models` tab, with accurate `.env` presence badges and newly added/enabled cloud models immediately selectable on `Dashboard`.
2. **History Pagination & Multi-Page Selection:** User can filter and paginate through >20 historical runs, select `completed` and `budget_stopped` runs across multiple pages, and send them to `Report Studio` in one click.
3. **Two-State Report Governance:** User can edit a `draft` report, publish/seal it into an immutable `published` snapshot that survives later `History` deletions, duplicate any report into a new `draft`, or delete a report with confirmation.
4. **AI-Ready Export:** User can copy `<benchmark_report>` Markdown or download `.md` / `.json` dossiers containing exact metrics, `EvalStatus` counts, domain/tier breakdowns, parity caveats, and metadata-only failure/discrepancy summaries with zero raw attack payloads.
5. **Clean Retirement & Zero Regression:** `Matrix Studio` HTML/JS dead code is removed from Web UI, `benchmark_matrix.py` CLI remains functional, and full `make test-unit` passes.

---

## 9. Open Questions

* **None blocking.** All architectural, domain, security, and UX decisions were resolved in `/doubt-driven-development` and `/grill-with-docs` (ADR 0012). *(Note: during `/plan`, we will verify whether any existing test/script outside `web/static/app.js` expects `GET /api/runs` to return a bare JSON list vs. `{items, total_count}` so we preserve backwards compatibility cleanly.)*
