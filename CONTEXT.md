# Context & Domain Model: Farad Ai Benchmark

Glossary and ubiquitous language for the benchmark and evaluation platform.

### Analysis Tier
The classification of an inspection target based on the computational mechanism required to detect threats:
- **`STATIC_CAPABLE`**: Threats or patterns that can be detected deterministically via low-latency pattern matching, regex rules, keyword blacklists, or structured DLP checks (e.g., known path traversal strings, raw SQL syntax, secret tokens).
- **`SEMANTIC_REQUIRED`**: Threats that inherently depend on contextual understanding, natural language reasoning, intent analysis, or multi-turn conversational hijacking (e.g., indirect prompt injection, social engineering, role manipulation).
- **`HYBRID`**: Threats where overt variations can be caught by static rules, but evasive or obfuscated variants require semantic reasoning.

### Threat Domain
The security taxonomy category representing the attack vector (e.g., `COMMAND_INJECTION`, `PATH_TRAVERSAL`, `SQLI`, `SSRF`, `INDIRECT_PROMPT_INJECTION`, `DATA_LEAK`).

### DLP (Data Loss Prevention)
The detection, masking, or prevention of unauthorized transmission of sensitive information (PII, credentials, access keys, private certificates) between the LLM and MCP tools.
- **`Outbound DLP`**: The inspection of arguments emitted by the LLM (`tool_arguments`) before execution by an MCP server to prevent exfiltration.

### Engine Tiers & Pipeline
- **`L1 Engine (Static / DLP)`**: Deterministic inspection layer executing pattern matching, regular expressions, and signature rules in microseconds (<1ms).
- **`L2 Engine (Semantic / AI Guard)`**: Natural language intent and contextual inspection layer executing local AI Guard models in milliseconds (~15-40ms).
- **`Fail-Fast Cascade`**: The orchestration pattern where requests pass through L1 first; immediate violations are blocked at L1 with zero GPU/AI Guard overhead, and only clean/inconclusive requests cascade to L2.

### Benchmark Storage & Comparison
- **`Benchmark Case Pool`**: The unified, single-source repository of all standardized test scenarios (`master_benchmark.parquet`). Rather than fragmented subsets or individual files, all evaluations, exploratory filtering, and distributions are queried against this single consolidated pool using columnar metadata filters (`source_dataset`, `threat_domain`, `analysis_tier`, `is_malicious`).
- **`Run Case Evaluation`**: The granular, relational record of a single test case evaluation within a run (`run_id`, `case_id`, `domain`, `expected`, `predicted`, `correct`, `latency_ms`).
- **`Discrepancy Analysis`**: The differential SQL comparison between two benchmark runs to isolate disagreements (cases where Model A and Model B reached opposite verdicts).

### Declarative Rules & L1
- **`Static Security Rule`**: A declarative specification formatted in YAML containing regex match patterns, threat domain mappings, CWE IDs, and description.
- **`Compiled Rule Engine`**: The high-throughput in-memory engine that compiles declarative YAML regex rules on startup to perform sub-millisecond evaluation (<0.2ms).

### Multi-Model & Adapter Architecture
- **`Security Model Adapter`**: The unified abstraction implementing standard parameter evaluation (`evaluate(tool_name, tool_arguments, context) -> Dict`) across heterogeneous AI Guard models (Laya, Qwen3Guard, Granite Guardian, Llama Guard, ShieldGemma, Prompt Guard).
- **`Decision Model (System 1 / Non-Autoregressive)`**: A class of models (e.g. Laya, Kev) that evaluate a document/state and typed questions (`choice`, `noul`, `score`) in a single forward pass without token-by-token text generation. They output calibrated probabilities directly, providing low latency (<25ms) and deterministic boolean decisions.
- **`Fair Quantization Baseline`**: Standardized 4-bit quantization (MLX 4-bit / Q4_K_M) enforced across generative AI Guard models to ensure unified memory footprint (~1.2-2.0 GB) and hardware latency parity on Apple Silicon. For ultra-lightweight decision models (Kev-0.8B), 4-bit quantization enforces a sub-1GB RAM footprint (~500-700 MB).
- **`Guard MCP Factory`**: The shared builder pattern that wraps any `SecurityModelAdapter` into an independent, zero-flag FastMCP server exposing the uniform `inspect_tool_call` tool contract.
- **`Comparative Leaderboard Run`**: The two-phased benchmark execution workflow (200-case smoke test followed by 2000+ full pool evaluation) generating side-by-side accuracy, FPR, and latency metrics across all registered adapters.
- **`Ollama Decision Endpoint (/v1/systemone)`**: The non-autoregressive REST protocol contract natively implemented by Ollama and TypeSafe for evaluating typed questions (`noul`, `choice`, `score`) on structured state without generating conversational text.
- **`Pure L2 Model Evaluation vs. Hybrid Cascade`**: The strict architectural segregation ensuring models are benchmarked both standalone (isolated L2 accuracy and unassisted False Positive Rate) and composed within the Fail-Fast Cascade (L1 + L2), preventing static rule leakage from contaminating pure model evaluations.
- **`Keep-Alive Memory Eviction`**: The explicit zero-second TTL signaling (`keep_alive: 0`) sent to local inference daemons (Ollama) to immediately purge model weights from Apple Silicon unified memory (VRAM) upon adapter unload.
- **`Code-First Adapter vs. Declarative Test Matrix`**: The architectural segregation between model implementation (strongly-typed Python classes handling tokenizer hooks, delimiters, CWE taxonomy mappings, and memory eviction) and experiment orchestration (declarative selection of models, thresholds, datasets, and cascade flags).
- **`DuckDB-Native Experiment Registry`**: The storage of benchmark matrix templates and experiment definitions in DuckDB (`experiment_templates` table) as the single source of truth, establishing relational links (`JOIN`) with `run_history` while supporting optional YAML export/import.
- **`Hardware Ceiling Parity`**: Benchmarking a model in-process (`MLX_NATIVE_METAL` / `PYTORCH_MPS`) to measure the theoretical minimum latency and maximum throughput of Apple Silicon hardware without IPC or HTTP socket overhead.
- **`Production Deployment Parity`**: Benchmarking a model through its production daemon (`OLLAMA_DAEMON_HTTP`) to capture realistic socket latency, JSON serialization, and daemon queueing behaviors under live deployment conditions.
- **`Dual-Track Leaderboard`**: Tagging and segregating leaderboard metrics by `runtime_tier` (`MLX_NATIVE`, `OLLAMA_DAEMON`, `PYTORCH_MPS`) to ensure fair, transparent comparisons between raw silicon execution and daemonized service delivery.
- **`Host Daemon Serving`**: Running Apple Silicon Metal models (such as Laya MLX) directly on the macOS Darwin host (via FastMCP / Uvicorn REST) to preserve Metal GPU unified memory zero-copy, explicitly avoiding macOS Docker container virtualization penalties (CPU-only fallback).
- **`Discrete vs. Continuous Threat Scoring`**: The differentiation between models outputting continuous calibrated probabilities ($0.0 - 1.0$) for ROC-AUC and threshold sweeps (MLX and System 1 Decision models) versus generative models over standard HTTP daemons (Ollama) outputting discrete binary verdicts ($0.0$ or $1.0$).

### Cloud Decision Model Benchmarking (ADR 0011)
- **`Cloud Decision API Tier (CLOUD_DECISION_API)`**: The `runtime_tier` identifier distinguishing stateless, network-routed cloud System One / Decisions API evaluations (e.g., OpenRouter `typesafe/jev-1.14`, TypeSafe Direct, Liquid AI) from local Apple Silicon execution (`MLX_NATIVE_METAL`, `OLLAMA_DAEMON_HTTP`, `PYTORCH_MPS`).
- **`Provider Dialect`**: A closed, strongly-typed Python enum (`OPENROUTER_DECISIONS`, `TYPESAFE_SYSTEMONE`, `LIQUID_SYSTEMONE`, `PERPLEXITY_DECISIONS`) encapsulating endpoint paths, auth/header rules, answer extractors, and error parsing inside `SystemOneCloudAdapter`, preserving ADR 0010's prohibition on untyped YAML DSLs.
- **`Eval Status`**: The canonical case evaluation outcome classification (`OK | REFUSAL | ERROR | SKIPPED`) separating successfully evaluated verdicts (`BLOCKED` / `ALLOWED`) from non-evaluated model refusals, transport/HTTP errors, or pre-flight size-cap skips so non-`OK` cases never contaminate `TP/TN/FP/FN` metrics.
- **`Canonical Decision State`**: The unified multiline `DEC-07` Root Intent Isolation string representation (`BaseModelAdapter.format_decision_state()`) shared identically across local and cloud decision adapters to maintain apples-to-apples benchmark parity.
- **`Inference RTT vs. Retry Wait`**: Explicit latency decomposition separating pure HTTP inference round-trip time (`inference_rtt_ms`) from rate-limit / `429` exponential-backoff sleep time (`retry_wait_ms`).
- **`Cost Source & Budget Reservation`**: Explicit provenance tagging (`api_reported` from provider response `usage.cost` vs. `estimated_fallback` from local per-1M-token pricing) paired with lock-guarded pre-dispatch credit reservation so concurrent workers cannot overshoot `max_cost_usd`.

### Web Studio & Periodic Reporting (ADR 0012)
- **`Curated Benchmark Report`**: A read-only periodic evaluation artifact assembled by selecting completed (or `budget_stopped`) historical benchmark runs without triggering new benchmark executions.
- **`Draft vs. Published Report Lifecycle`**: The two-stage governance model for periodic reports: a **`Draft`** report remains editable (title, period label, researcher notes, and selected runs), whereas a **`Published` (Sealed Snapshot)** report is permanently immutable—its metrics, slice breakdowns, parity caveats, and metadata-only failure summaries are frozen at publication time so later `run_history` deletions never alter historical reports.
- **`Parity Guard`**: Automated cross-run comparability validation that surfaces explicit caveats whenever runs grouped into a report differ in dataset, `tier_scope`, `enable_l1` cascade state, `limit_cases`, or completion status (`budget_stopped`).
- **`AI-Ready Report Bundle`**: A dual-format structured export (machine-readable `JSON` dossier and `<benchmark_report>` `Markdown` brief) strictly free of raw untrusted test payloads, enabling external LLMs to synthesize accurate executive and technical security reports without hallucinating metrics or suffering prompt injection.
- **`DuckDB Single Source of Truth (Cloud Registry)`**: Treating DuckDB (`cloud_providers`, `cloud_models`) as the authoritative mutable store for cloud model definitions managed in the Web UI, while local adapters remain code-first (ADR 0010) and YAML remains a CLI sync mechanism.



