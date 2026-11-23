# Spec: Generic Cloud Decision Model Benchmarking (Phase 8)

* **Spec Document:** `SPEC.md` (mirrored in [docs/specs/cloud-decision-model-benchmarking-spec.md](docs/specs/cloud-decision-model-benchmarking-spec.md))
* **Related ADR:** [ADR 0011: Generic Cloud Decision Model Architecture & System One Wire Parity](docs/adr/0011-generic-cloud-decision-model-architecture.md)
* **Prior ADRs & Specs:** [ADR 0009](docs/adr/0009-ollama-decision-model-adapters.md), [ADR 0010](docs/adr/0010-code-first-adapters-duckdb-matrix-and-dual-track-serving.md), [Phase 7 Spec](docs/specs/declarative-experiment-matrix-spec.md)
* **Domain Model:** [CONTEXT.md](CONTEXT.md)
* **Wayfinder Map:** [MAP.md](docs/wayfinder/cloud-decision-providers/MAP.md)
* **Status:** Draft — Pending Human Review & Approval

---

## 0. Capability Map & Explicit Assumptions

### Explicit Assumptions
1. **Protocol Focus:** Phase 8 targets exclusively **System One / Decisions API** cloud providers (`OpenRouter Decisions`, `TypeSafe Direct`, `Liquid AI`, `Perplexity Decisions`) rather than `/v1/chat/completions` LLMs or proprietary security SaaS APIs.
2. **Primary Verification Target:** Initial live verification runs on OpenRouter (`typesafe/jev-1.14`) using `OPENROUTER_API_KEY` from `.env`; Perplexity (`usage.cost` / top-level `refusal`) and Liquid AI (`noul` vs `probability` answer key) fields marked unverified in [WF-001 research](docs/wayfinder/cloud-decision-providers/research/systemone-provider-api-contracts.md) will be validated against live responses before production use.
3. **Database & Unit Reset:** Existing legacy `run_history` rows in `data/benchmark_runs.duckdb` using `0.0–1.0` ratios can be cleared or normalized to `0.0–100.0` percentages so CLI, Matrix, and Web Dashboard share one metric unit.
4. **Runtime Dependencies:** `httpx>=0.27.0` (promoted from `dev`) and `pyyaml>=6.0` are approved additions to `pyproject.toml`.

### Capability Map (Module Decomposition)

| Module ID | Responsibility | Depends On |
|---|---|---|
| **`eval-status-and-state-parity`** | `EvalStatus` (`OK \| REFUSAL \| ERROR \| SKIPPED`), `inference_rtt_ms` / `retry_wait_ms`, shared `BaseModelAdapter.format_decision_state()`, refusal-safe local & factory parsing, and `run_history` `0–100%` normalization. | — |
| **`cloud-provider-registry`** | DuckDB `cloud_providers` & `cloud_models` schema, Pydantic validation, YAML export/import, secret hygiene (`api_key_env`, `https://`, header denylist), and unified `resolve_adapter()`. | — |
| **`systemone-cloud-adapter`** | `SystemOneCloudAdapter` implementing closed `ProviderDialect` dialects (`OPENROUTER_DECISIONS`, `TYPESAFE_SYSTEMONE`, `LIQUID_SYSTEMONE`, `PERPLEXITY_DECISIONS`), `httpx.Client` thread-local pooling, `Retry-After` + jittered backoff, and `QuestionProfile` support. | `eval-status-and-state-parity`, `cloud-provider-registry` |
| **`cloud-matrix-execution`** | `ThreadPoolExecutor` bounded concurrency, single DuckDB writer lock, pre-dispatch atomic `max_cost_usd` reservation, `cost_source` tracking, `--resume-run-id` with `config_hash`, `HybridCascadeAdapter` lock/passthrough, and `web/app.py` explicit-column insert + `asyncio.to_thread`. | `systemone-cloud-adapter` |

**Build Order:** `eval-status-and-state-parity` + `cloud-provider-registry` → `systemone-cloud-adapter` → `cloud-matrix-execution`

---

## 1. Objective & Scope

Deliver a **generic, zero-code-onboarding cloud benchmarking pipeline** that allows security researchers to register any System One / Decisions API model (starting with `typesafe/jev-1.14` on OpenRouter as a cloud reference baseline) in DuckDB or YAML without modifying Python source code, while preserving scientific parity with local Apple Silicon runs (`Laya`, `Kev`, `Ollama`):

1. **Zero-Code Model Onboarding (ADR 0010 Compliant):** New models (`typesafe/jev-1.14`, `liquid/d1.2-ultra`, `perplexity/pplx-decider-v1.3:free`, `cloudflare/clef` via OpenRouter) are registered declaratively in `cloud_providers` / `cloud_models` (or YAML) over a single typed `SystemOneCloudAdapter` governed by a closed `ProviderDialect` enum.
2. **Apples-to-Apples Parity & Non-Coercive Metrics:** Shared `BaseModelAdapter.format_decision_state()`, explicit `EvalStatus` (`OK | REFUSAL | ERROR | SKIPPED`) excluding failures/refusals from `TP/TN/FP/FN` denominators, and `inference_rtt_ms` vs `retry_wait_ms` separation.
3. **Cloud Economics & Resiliency:** Bounded-concurrency execution over stateless AI payloads (`httpx.Client` connection pooling), atomic `max_cost_usd` reservation, `cost_source` provenance (`api_reported` | `estimated_fallback`), and deterministic `--resume-run-id`.
4. **Secret Isolation:** API keys live strictly in `.env` (`OPENROUTER_API_KEY`, etc.); DuckDB/YAML store only env variable names (`api_key_env`), enforcing `https://` URLs and header denylists.

### Out of Scope
* General-purpose Chat/Completions cloud LLMs (`/v1/chat/completions`).
* Proprietary non-System-One security SaaS APIs (Lakera Guard, AWS Bedrock Guardrails, Azure AI Content Safety, OpenAI Moderation). Direct Cloudflare Workers AI (`/ai/run/{model}`) is excluded from `SystemOneCloudAdapter` — route via OpenRouter or implement a dedicated typed adapter via ADR 0010's escape hatch.
* Curated per-report result lists & bespoke report builder.
* Web Dashboard Studio Cloud CRUD UI & L1 Cascade USD-saved telemetry (follow-on vertical slices).

---

## 2. Tech Stack & Dependencies

* **Language & Runtime:** Python 3.12+ (macOS Apple Silicon Darwin arm64)
* **Database & Storage:** DuckDB 1.1+, PyArrow 15+, Parquet
* **HTTP & Config Dependencies (`pyproject.toml`):** `httpx>=0.27.0` (moved to runtime `dependencies`), `pyyaml>=6.0` (added to runtime `dependencies`), `pydantic>=2.6.0`
* **CLI & Web Frameworks:** Rich, FastAPI, Uvicorn, Jinja2
* **Testing:** Pytest

---

## 3. Commands & Usage

```bash
# 1. Install updated dependencies (incl. httpx & pyyaml)
uv pip install -e ".[dev]"

# 2. Run targeted Phase 8 unit test suites
.venv/bin/python -m pytest tests/test_cloud_registry.py tests/test_systemone_cloud_adapter.py tests/test_cloud_execution_resume.py -v

# 3. Run full existing + new regression suite
make test-unit

# 4. Seed / import / list cloud providers and models in DuckDB
.venv/bin/python scripts/manage_cloud_models.py --import config/cloud_models/default_systemone.yaml
.venv/bin/python scripts/manage_cloud_models.py --list
.venv/bin/python scripts/manage_cloud_models.py --export config/cloud_models/exported.yaml

# 5. Run a 2-case live sanity check or 200-case smoke run via benchmark_runner.py
.venv/bin/python benchmark_runner.py --dataset data/processed/farad_decision_bench_v1.parquet --model or-jev-1.14 --limit 2

# 6. Run comparative matrix (cloud reference + local models) with hard budget cap
.venv/bin/python benchmark_matrix.py --smoke --models laya-mlx,ollama-d1,or-jev-1.14 --max-cost-usd 0.50

# 7. Resume an interrupted cloud run deterministically without double-paying
.venv/bin/python benchmark_matrix.py --resume-run-id run-abcd1234 --max-cost-usd 0.50

# 8. Launch Web Dashboard
make web
```

---

## 4. Project Structure

```text
FaradAiBenchmark/
├── adapters/
│   ├── base.py                           # EvalStatus, extended EvaluationResult, format_decision_state()
│   ├── cloud_registry.py                 # [NEW] DuckDB cloud_providers & cloud_models + YAML import/export + resolve_adapter()
│   ├── systemone_cloud_adapter.py        # [NEW] SystemOneCloudAdapter + ProviderDialect enum + QuestionProfile
│   ├── ollama_decision_adapter.py        # Updated: format_decision_state(), explicit refusal guard
│   └── kev_adapter.py                    # Updated: format_decision_state(), explicit refusal guard
├── config/
│   └── cloud_models/                     # [NEW] Declarative YAML cloud provider & model profiles
│       └── default_systemone.yaml
├── scripts/
│   └── manage_cloud_models.py            # [NEW] CLI helper for cloud provider/model DuckDB <-> YAML management
├── tests/
│   ├── test_cloud_registry.py            # [NEW] Schema, secret hygiene, resolution & YAML round-trip tests
│   ├── test_systemone_cloud_adapter.py   # [NEW] Dialect parsing, refusal, retry/backoff, overflow & cost tests
│   └── test_cloud_execution_resume.py    # [NEW] Concurrency, budget reservation, writer lock & resume tests
├── benchmark_runner.py                   # Dynamic resolve_adapter(), EvalStatus metrics, latency separation
├── benchmark_matrix.py                   # CLOUD_DECISION_API tier, 0-100% unit parity, concurrency, --resume-run-id
├── guard_mcp_factory.py                  # Explicit REFUSAL/ERROR propagation (no silent ALLOWED)
├── laya_security_guard_mcp.py            # Updated: format_decision_state(), explicit refusal guard
├── web/
│   ├── app.py                            # Explicit-column INSERT, asyncio.to_thread, remove silent Mock fallback
│   └── schemas.py                        # CLOUD_DECISION_API, eval_status, token/cost fields
├── .env.example                          # Includes OPENROUTER_API_KEY / TYPESAFE_API_KEY / LIQUID_API_KEY / PERPLEXITY_API_KEY
├── pyproject.toml                        # Runtime dependencies include httpx & pyyaml
└── SPEC.md                               # [THIS FILE] Phase 8 Canonical Feature Specification
```

---

## 5. DuckDB Schema & Code Style Conventions

### 5.1 DuckDB Registry & Telemetry Schema
```sql
CREATE TABLE IF NOT EXISTS cloud_providers (
    provider_id        VARCHAR PRIMARY KEY,
    display_name       VARCHAR NOT NULL,
    dialect            VARCHAR NOT NULL, -- ProviderDialect enum value
    base_url           VARCHAR NOT NULL, -- https:// enforced unless localhost
    endpoint_path      VARCHAR NOT NULL, -- e.g. /api/alpha/decisions, /v1/systemone
    api_key_env        VARCHAR NOT NULL, -- env var name ONLY (never raw secret)
    extra_headers_json VARCHAR DEFAULT '{}',
    timeout_seconds    DOUBLE DEFAULT 15.0,
    max_concurrency    INTEGER DEFAULT 8,
    rpm_limit          INTEGER DEFAULT NULL,
    max_body_bytes     INTEGER DEFAULT NULL,
    max_questions      INTEGER DEFAULT NULL,
    created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cloud_models (
    model_id                VARCHAR PRIMARY KEY, -- e.g. or-jev-1.14
    provider_id             VARCHAR NOT NULL,
    remote_model_slug       VARCHAR NOT NULL,    -- e.g. typesafe/jev-1.14
    question_profile_id     VARCHAR NOT NULL DEFAULT 'dual_check_v1',
    state_format            VARCHAR NOT NULL DEFAULT 'canonical_text', -- canonical_text | structured_json
    exploit_threshold       DOUBLE DEFAULT 0.50,
    misalignment_threshold  DOUBLE DEFAULT 0.65,
    threat_threshold        DOUBLE DEFAULT 0.50,
    input_price_per_1m_usd  DOUBLE DEFAULT NULL,
    max_context_tokens      INTEGER DEFAULT NULL,
    enabled                 BOOLEAN DEFAULT TRUE,
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```
* **`run_history` extensions:** `config_hash VARCHAR`, `question_profile_id VARCHAR`, `refusal_count INTEGER DEFAULT 0`, `error_count INTEGER DEFAULT 0`, `skipped_count INTEGER DEFAULT 0`, `input_tokens BIGINT DEFAULT 0`, `output_tokens BIGINT DEFAULT 0`, `cached_tokens BIGINT DEFAULT 0`, `total_cost_usd DOUBLE DEFAULT 0.0`, `cost_source VARCHAR DEFAULT 'none'`, `max_cost_usd DOUBLE DEFAULT NULL`.
* **`run_case_evaluations` extensions:** `eval_status VARCHAR NOT NULL DEFAULT 'OK'`, `inference_rtt_ms DOUBLE DEFAULT 0`, `retry_wait_ms DOUBLE DEFAULT 0`, `input_tokens INTEGER DEFAULT 0`, `output_tokens INTEGER DEFAULT 0`, `cached_tokens INTEGER DEFAULT 0`, `cost_usd DOUBLE DEFAULT 0.0`, `cost_source VARCHAR DEFAULT 'none'`; `predicted_blocked` and `correct` nullable (`BOOLEAN`) for non-`OK` rows.

### 5.2 Standard Python Style: `ProviderDialect`, `EvalStatus` & `SystemOneCloudAdapter`
```python
"""adapters/systemone_cloud_adapter.py: Typed System One Cloud Decision Adapter."""

from enum import StrEnum
from typing import Any
from adapters.base import BaseModelAdapter


class ProviderDialect(StrEnum):
    """Closed set of verified System One cloud wire dialects (ADR 0011)."""

    OPENROUTER_DECISIONS = "OPENROUTER_DECISIONS"
    TYPESAFE_SYSTEMONE = "TYPESAFE_SYSTEMONE"
    LIQUID_SYSTEMONE = "LIQUID_SYSTEMONE"
    PERPLEXITY_DECISIONS = "PERPLEXITY_DECISIONS"


class EvalStatus(StrEnum):
    """Canonical evaluation outcome status separating non-evaluated cases."""

    OK = "OK"
    REFUSAL = "REFUSAL"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
```

---

## 6. Testing Strategy

1. **Registry & Secret Hygiene (`tests/test_cloud_registry.py`):**
   - DuckDB table creation, CRUD, YAML export/import round-trip parity.
   - Reject plaintext `http://` (non-localhost) URLs, reject `Authorization`/`Cookie`/`x-api-key` inside `extra_headers`, reject invalid `ProviderDialect` values.
   - Verify `resolve_adapter()` resolves both static `ADAPTER_REGISTRY` keys and dynamic DuckDB `cloud_models` without `MockSecurityAdapter` fallback.
2. **Protocol Adapter & Parity (`tests/test_systemone_cloud_adapter.py`):**
   - Mocked `httpx.Client` tests for `OPENROUTER_DECISIONS`, `TYPESAFE_SYSTEMONE`, `LIQUID_SYSTEMONE`, and `PERPLEXITY_DECISIONS`.
   - Verify per-question `{"type": "refusal"}` and missing keys map to `eval_status="REFUSAL"`, `verdict="REFUSAL"` (never `ALLOWED`), and also verify local `OllamaDecisionAdapter` / `KevSecurityAdapter` refusal guards.
   - Verify `429` with `Retry-After` and without `Retry-After` (jittered backoff), recording `inference_rtt_ms` separately from `retry_wait_ms`.
   - Verify `max_body_bytes` overflow emits `eval_status="SKIPPED"` without truncating payload.
   - Verify `cost_source` (`api_reported` vs `estimated_fallback`) and header scrubbing from logs/`raw_output`.
3. **Concurrency, Budget & Resume (`tests/test_cloud_execution_resume.py`):**
   - Bounded `ThreadPoolExecutor` + single DuckDB writer lock under simulated multi-worker checkpointing.
   - Atomic pre-dispatch `max_cost_usd` reservation preventing N concurrent workers from overspending.
   - Deterministic `ORDER BY id` `--resume-run-id`: skips prior `OK`/`SKIPPED`, retries prior `ERROR`, and rejects resume when `config_hash` mismatches.
   - `HybridCascadeAdapter` thread-safe `stats` under concurrent execution + L2 telemetry passthrough.
4. **Zero Regression:** All existing unit tests (`make test-unit`) continue passing with `0–100%` metric consistency.

---

## 7. Boundaries

* **Always do:**
  * Use `ORDER BY id` in `load_test_cases()` for deterministic smoke/limit/resume runs.
  * Validate `api_key_env`, `https://`, and `extra_headers` denylist pre-flight.
  * Funnel DuckDB writes through a single writer thread/lock using explicit column lists (never `SELECT *`).
  * Compute accuracy/precision/recall/F1/FPR strictly over `eval_status == 'OK'`.
  * Scrub `Authorization` / API key headers from logs, exceptions, and `raw_output`.
* **Ask first:**
  * Expanding `ProviderDialect` beyond the 4 closed dialects or adding non-System-One SaaS adapters.
  * Adding any Python dependencies beyond `httpx` and `pyyaml`.
* **Never do:**
  * Store raw API keys in DuckDB, YAML, or git-tracked files.
  * Silently truncate `tool_arguments` or `UNTRUSTED_EXTERNAL_DATA` on payload overflow.
  * Fall back silently to `MockSecurityAdapter` or `MLX_NATIVE_METAL` on unknown model IDs.
  * Build an untyped YAML expression/template DSL for response or cost parsing.

---

## 8. Success Criteria

1. **Zero-Code Cloud Onboarding:** Registering a new OpenRouter/TypeSafe/Liquid System One model via `scripts/manage_cloud_models.py` or YAML makes it immediately runnable in `benchmark_runner.py` and `benchmark_matrix.py` with zero Python edits.
2. **Clean Separation & Parity:** Leaderboard and DuckDB accurately tag `CLOUD_DECISION_API`, unify `0–100%` metrics across CLI/Matrix/Web, exclude `REFUSAL`/`ERROR`/`SKIPPED` from `TP/TN/FP/FN`, and preserve `inference_rtt_ms` vs `retry_wait_ms`.
3. **Safe Paid Execution:** Running with `--max-cost-usd` stops cleanly at/under cap even under concurrency, and interrupting + resuming with `--resume-run-id` finishes the exact remaining cases without double-billing.
4. **Live Smoke Verified:** `typesafe/jev-1.14` runs cleanly via OpenRouter on 2 verification cases and 200-case smoke benchmark with verified `cost_usd` and `eval_status`.
5. **Zero Regression:** Full `make test-unit` suite passes.

---

## 9. Open Questions (Pre-Implementation Verification)

1. **Empirical `typesafe/jev-1.14` Wire Check ([WF-005](docs/wayfinder/cloud-decision-providers/tickets/WF-005-jev-openrouter-api-check.md)):** Once `OPENROUTER_API_KEY` is populated in `.env`, capture 2 live responses (1 benign, 1 malicious) to verify exact `usage` keys (`input_tokens` vs `prompt_tokens`), `output_tokens`, `noul` response shape, effective OpenRouter context limit, and `canonical_text` vs `structured_json` parity.
2. **Perplexity & Liquid Live Verification:** Confirm Perplexity `/v1/decisions` `usage.cost` / top-level `refusal` and Liquid `/decisions/v1/systemone` `"noul"` vs `"probability"` key before marking those two dialects production-verified.
