# ADR 0011: Generic Cloud Decision Model Architecture & System One Wire Parity

* **Date:** 2026-11-23
* **Status:** Accepted
* **Scope:** Farad Ai Benchmark / Cloud System One Decision Models, Dynamic Registry, Execution Economics & Parity
* **Supersedes / Extends:** Extends [ADR 0009](0009-ollama-decision-model-adapters.md) and [ADR 0010](0010-code-first-adapters-duckdb-matrix-and-dual-track-serving.md)

---

## 1. Context and Problem Statement
Farad Ai Benchmark needs to benchmark cloud-only System One / Decisions API models — starting with TypeSafe's **Jev** (`typesafe/jev-1.14` on OpenRouter) as a reference baseline alongside Liquid AI (`d1.2`, `d1.2-ultra`), Perplexity Decider (`pplx-decider`), and local Apple Silicon models (`Laya`, `Kev`, `Ollama d1/pplx-decider/mica`) — **without writing a new Python adapter class for every cloud model**.

While ADR 0010 prohibited an untyped zero-code YAML DSL for heterogeneous local SLMs (which vary wildly in tokenizer templates, special delimiters, and logit extraction), cloud System One models converge on a single stateless JSON wire paradigm (`state` + typed `questions` -> `answers` + `usage`). At the same time, an adversarial review (`/doubt-driven-development`) surfaced critical parity, schema, concurrency, and financial risks in naive integration:
1. Existing harnesses (`benchmark_matrix.py`, `web/app.py`, `guard_mcp_factory.py`) and local System One adapters (`ollama_decision_adapter.py`, `kev_adapter.py`, `laya_security_guard_mcp.py`) coerce `ERROR`/`REFUSAL` into `ALLOWED` (`TN`/`FN`) and overwrite adapter latency with outer wall-clock timers.
2. `benchmark_matrix.py` writes `0.0–1.0` ratios into `run_history` while `web/app.py` writes `0.0–100.0` percentages, and `web/app.py` silently falls back to `MockSecurityAdapter()` on unknown model IDs.
3. Paid cloud runs over 2,000+ cases require bounded concurrency, DuckDB write safety, atomic budget enforcement, and deterministic resume without double-billing.

---

## 2. Decision Log

### Decision 1: Protocol-First Adapter + Closed `ProviderDialect` Enum (Preserving ADR 0010)
* **Decision:** Implement one strongly-typed `SystemOneCloudAdapter(BaseModelAdapter)` backed by declarative DuckDB/YAML provider and model profiles (`cloud_providers`, `cloud_models`). All wire-level variations (endpoint path, auth/header style, answer key extraction, refusal extraction, usage/cost extraction) are restricted to a **closed Python `ProviderDialect` enum**:
  * `OPENROUTER_DECISIONS` (`POST /api/alpha/decisions` or `/api/v1/systemone`)
  * `TYPESAFE_SYSTEMONE` (`POST /v1/systemone`)
  * `LIQUID_SYSTEMONE` (`POST /decisions/v1/systemone`)
  * `PERPLEXITY_DECISIONS` (`POST /v1/decisions`)
* **Rationale & Escape Hatch:** Zero-code model onboarding works cleanly across models sharing these verified dialects without inventing an untyped YAML DSL (`cost_path` / `token_keys` expressions). If a future provider diverges outside these tested dialects (e.g., Cloudflare Workers AI's `/ai/run/{model}` RPC envelope with Neuron billing, or proprietary non-System-One SaaS guards), it is routed either through an already-supported aggregator (OpenRouter) or via ADR 0010's **dedicated Python adapter escape hatch**.

### Decision 2: `EvalStatus` Segregation & Zero Silent Coercion
* **Decision:** Introduce `EvalStatus` (`OK | REFUSAL | ERROR | SKIPPED`) across `EvaluationResult`, `run_case_evaluations`, and all benchmark runners (`benchmark_runner.py`, `benchmark_matrix.py`, `web/app.py`), and fix `.get("noul", 0.0)` refusal coercion across local System One adapters (`ollama_decision_adapter.py`, `kev_adapter.py`, `laya_security_guard_mcp.py`).
* **Rationale:** Non-`OK` cases (`REFUSAL`, `ERROR`, `SKIPPED` due to `max_body_bytes` overflow — never silent truncation) must never be counted as `TN`/`FN` in `TP/TN/FP/FN` metrics. Accuracy, Precision, Recall, F1, and FPR are computed strictly over `eval_status == 'OK'`, while `refusal_rate` and `error_rate` are reported separately.

### Decision 3: Canonical Decision State Parity (`format_decision_state`)
* **Decision:** Extract `BaseModelAdapter.format_decision_state()` (using `parse_context_isolation()`, `serialize_arguments(..., sort_keys=True)`, and `CANONICAL_DECODED_ARGUMENTS`) as the default multiline `state` formatter for both local and cloud System One models.
* **Rationale:** Ensures apples-to-apples comparisons between local models and cloud reference models (`typesafe/jev-1.14`). `structured_json` state remains opt-in per model/experiment profile.

### Decision 4: Stateless AI Evaluation Over Pooled HTTP Transport (`httpx`)
* **Decision:** Execute cloud calls via `ThreadPoolExecutor(max_workers=provider.max_concurrency)` using thread-local `httpx.Client` connection pooling (`httpx` and `pyyaml` added to `pyproject.toml`), while keeping every System One API payload 100% stateless and isolated per case. Wrap synchronous evaluations in `asyncio.to_thread()` inside `web/app.py`.
* **Rationale:** Eliminates 50–150ms per-request TCP/TLS handshake inflation without ever accumulating conversation context or leaking state across test cases.

### Decision 5: `CLOUD_DECISION_API` Runtime Tier, Unit Standardization & Explicit Resolution
* **Decision:** Add `CLOUD_DECISION_API` to `runtime_tier`, unify CLI/Matrix/Web resolution through `resolve_adapter(model_id, db_con)` (removing static `argparse choices=` and silent `MockSecurityAdapter()` fallbacks), and standardize `run_history` percentages (`0.0–100.0`) across `benchmark_matrix.py` and `web/app.py`.
* **Rationale:** Guarantees cloud runs are visibly distinguished from local Metal/Ollama/MPS runs and eliminates silent mock evaluations or unit mismatches.

### Decision 6: Atomic Budget Reservation, Latency Separation & Deterministic Resume
* **Decision:**
  * Separate `inference_rtt_ms` (pure HTTP call excluding retry backoff sleeps) from `retry_wait_ms` in `EvaluationResult` and runners; make `HybridCascadeAdapter` thread-safe (`threading.Lock`) and forward L2 telemetry.
  * Track `input_tokens`, `output_tokens`, `cached_tokens`, `cost_usd`, and `cost_source` (`api_reported` | `estimated_fallback`) with lock-guarded pre-dispatch cost reservation against `max_cost_usd`.
  * Funnel DuckDB writes through a single writer thread/lock, replace `web/app.py`'s `SELECT *` positional insert with explicit columns, enforce `ORDER BY id` in `load_test_cases()`, and support `--resume-run-id` validated by `config_hash` (skipping `OK`/`SKIPPED`, retrying `ERROR`).

### Decision 7: Secret Hygiene Boundary
* **Decision:** Store only `api_key_env` names in DuckDB/YAML, require `https://` for non-localhost endpoints, enforce a sensitive-header denylist on `extra_headers` (`Authorization`, `Cookie`, `x-api-key`, `Proxy-Authorization`), validate env vars pre-flight, and scrub auth headers from logs and `raw_output`.

---

## 3. Consequences
* `docs/specs/cloud-decision-model-benchmarking-spec.md` defines the full implementation contract, DuckDB schemas, CLI flags, and verification plan.
* [CONTEXT.md](../../CONTEXT.md) is updated with the canonical domain glossary terms for cloud decision benchmarking.
* General Chat/Completions cloud LLMs (`/v1/chat/completions`), proprietary non-System-One security SaaS APIs (Lakera, Bedrock, Azure, OpenAI Moderation), and curated per-report result lists remain explicitly out of scope.
