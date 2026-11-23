# Implementation Plan: Generic Cloud Decision Model Benchmarking (Phase 8)

* **Feature:** Generic Cloud System One Decision Model Benchmarking (`typesafe/jev-1.14` & multi-provider support)
* **Governing Specification:** [SPEC.md](../SPEC.md) (and [cloud-decision-model-benchmarking-spec.md](../docs/specs/cloud-decision-model-benchmarking-spec.md))
* **Related ADR:** [ADR 0011: Generic Cloud Decision Model Architecture & System One Wire Parity](../docs/adr/0011-generic-cloud-decision-model-architecture.md)
* **Domain Model:** [CONTEXT.md](../CONTEXT.md)
* **Wayfinder Map:** [MAP.md](../docs/wayfinder/cloud-decision-providers/MAP.md)
* **Status:** Awaiting Human Approval

---

## 1. Overview & Architecture

This plan decomposes Phase 8 into **9 vertical, verifiable tasks** grouped across 4 capability modules (`eval-status-and-state-parity`, `cloud-provider-registry`, `systemone-cloud-adapter`, `cloud-matrix-execution`). The goal is to let researchers onboard any cloud System One / Decisions API model (`OpenRouter`, `TypeSafe Direct`, `Liquid AI`, `Perplexity`) via DuckDB/YAML without touching Python code, while maintaining apples-to-apples scientific parity with local Apple Silicon runs (`Laya`, `Kev`, `Ollama`) and protecting paid cloud budgets against races, crashes, and silent refusal coercion.

---

## 2. Key Architecture Decisions (ADR 0011)

- **Closed `ProviderDialect` Enum (ADR 0010 Compliance):** Wire differences across `OPENROUTER_DECISIONS`, `TYPESAFE_SYSTEMONE`, `LIQUID_SYSTEMONE`, and `PERPLEXITY_DECISIONS` live in strongly-typed Python dialect handlers inside `SystemOneCloudAdapter`—never an untyped YAML DSL. Divergent non-System-One providers (e.g., direct Cloudflare Workers AI RPC) use OpenRouter routing or a dedicated typed Python adapter escape hatch.
- **`EvalStatus` & Non-Coercive Metrics:** `OK | REFUSAL | ERROR | SKIPPED` separates failed/refused/oversized cases from `TP/TN/FP/FN` denominators and fixes `.get("noul", 0.0)` / `MockSecurityAdapter` silent fallbacks across existing runners and local adapters.
- **Canonical State & Latency Parity:** `BaseModelAdapter.format_decision_state()` unifies multiline `DEC-07` inputs across local and cloud models; `inference_rtt_ms` is recorded separately from `retry_wait_ms`.
- **Stateless AI over Pooled Transport:** `ThreadPoolExecutor` + thread-local `httpx.Client` connection pooling keeps TCP/TLS overhead off latency metrics while sending 100% isolated, stateless System One requests per case.
- **Safe Paid Execution:** Single DuckDB writer lock, pre-inserted `status='running'` `run_history` rows with `config_hash`, deterministic `ORDER BY id` test loading, lock-guarded atomic `max_cost_usd` reservation, and `cost_source` provenance (`api_reported` | `estimated_fallback`).
- **Unit & Schema Hygiene:** Standardize `run_history` metrics on `0.0–100.0` percentages across CLI, Matrix, and Web UI, and replace `web/app.py`'s positional `SELECT *` insert with explicit column names.

---

## 3. Dependency Graph & Implementation Order

```text
[Task 1: Runtime Deps (pyproject.toml) + WF-005 Live OpenRouter Wire Check]
        │
        ├──────────────────────────────┐
        ▼                              ▼
[Task 2: EvalStatus &           [Task 4: DuckDB Cloud Registry,
 format_decision_state()]        Secret Hygiene & Seed YAML]
        │                              │
        ▼                              ▼
[Task 3: Refusal & State        [Task 5: manage_cloud_models.py CLI &
 Parity in Local/MCP]            Unified resolve_adapter()]
        │                              │
        ▼                              ▼
[🛑 Checkpoint 1]              [🛑 Checkpoint 2]
                                       │
                                       ▼
                               [Task 6: TDD RED - SystemOneCloudAdapter]
                                       │
                                       ▼
                               [Task 7: TDD GREEN - SystemOneCloudAdapter]
                                       │
                                       ▼
                               [🛑 Checkpoint 3]
                                       │
                                       ▼
[Task 8: Cloud Matrix Concurrency, Budget Cap, Single Writer & --resume-run-id]
                                       │
                                       ▼
[Task 9: Web Schema Parity, Explicit-Column INSERT & asyncio.to_thread]
                                       │
                                       ▼
                               [🛑 Checkpoint 4: Full Regression & Smoke Run]
```

*(Note: Tasks 2–3 and Task 4 can be worked independently once Task 1 completes.)*

---

## 4. Risks and Mitigations

| Risk | Impact | Mitigation |
| :--- | :---: | :--- |
| **OpenRouter `typesafe/jev-1.14` actual payload fields differ from docs** (`input_tokens` vs `prompt_tokens`, `noul` shape, 32K/64K vs 262K ctx) | High | Task 1 runs `WF-005` 2-case live check (or captures fixture if key pending) before Task 6–7 lock dialect parsers. |
| **Perplexity/Liquid unverified wire quirks** (`usage.cost`, top-level `refusal`, `probability` vs `noul`) | Medium | Flagged as unverified in `WF-001`; dialect unit tests isolate parsers and require live smoke verification before production enablement. |
| **DuckDB write-lock contention or `SELECT *` column mismatch in `web/app.py`** | High | Task 8 funnels writes through one writer lock; Task 9 replaces `SELECT *` with explicit column lists in `web/app.py`. |
| **Concurrent `max_cost_usd` budget overshoot under `ThreadPoolExecutor`** | High | Task 8 enforces lock-guarded pre-dispatch cost reservation (`reserved + worst_case <= max_cost_usd`) settled on response. |
| **Legacy `run_history` `0–1` vs `0–100` ratio mismatch** | Medium | Task 8 standardizes `0–100%` across `benchmark_matrix.py` and migrates/normalizes existing `<= 1.0` rows cleanly. |

---

## 5. Open Questions

- Confirmed `OPENROUTER_API_KEY` placement in `.env` (gitignored); user populates the actual key before executing the live 2-case verification in Task 1 (`WF-005`).
- Perplexity and Liquid live checks remain gated until keys for those providers are configured.
