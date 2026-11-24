#!/usr/bin/env python3
"""
web/app.py — Farad Ai Benchmark: Benchmark Dashboard Backend

FastAPI server with:
- REST API for datasets, models, run history
- WebSocket for real-time benchmark progress
- DuckDB for persistent run storage
"""

import asyncio
import json
import threading
import time
import uuid
import math
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

import duckdb
import pyarrow as pa
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from starlette.requests import Request
from adapters.base import BaseModelAdapter, EvalStatus, ProviderDialect, normalize_eval_status
from adapters.cloud_registry import (
    CloudModelSpec,
    CloudProviderSpec,
    delete_cloud_model,
    delete_cloud_provider,
    ensure_run_history_schema,
    export_cloud_config,
    get_cloud_model,
    get_cloud_provider,
    init_cloud_registry,
    is_api_key_configured,
    is_cloud_model,
    list_cloud_models,
    list_cloud_providers,
    resolve_adapter,
    save_cloud_model,
    save_cloud_provider,
)
from adapters.experiment_registry import (
    ExperimentTemplate,
    delete_template,
    get_template,
    init_experiment_registry,
    list_templates,
    save_template,
)
from adapters.report_registry import (
    ReportImmutableError,
    create_draft_report,
    delete_report,
    duplicate_report,
    get_report,
    init_report_registry,
    list_reports,
    publish_report,
    update_draft_report,
)
from web.schemas import (
    CloudDeleteResponse,
    CloudModelItem,
    CloudModelUpsertRequest,
    CloudProviderItem,
    CloudProviderUpsertRequest,
    DatasetItem,
    DeleteRunResponse,
    ExperimentModelConfig,
    ExperimentRunRequest,
    ExperimentRunResponse,
    ExperimentTemplateCreateRequest,
    ExperimentTemplateItem,
    ModelItem,
    ReportCreateRequest,
    ReportDetailResponse,
    ReportSummaryItem,
    ReportUpdateRequest,
    RunCreateRequest,
    RunSummary,
    TestCaseFiltersResponse,
    TestCasesListResponse,
)

# ─── Path Setup ──────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
DB_PATH = PROJECT_ROOT / "data" / "benchmark_runs.duckdb"
WEB_DIR = Path(__file__).resolve().parent
DB_WRITE_LOCK = threading.Lock()

# ─── FastAPI App with Modern Lifespan ────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_dotenv(PROJECT_ROOT / ".env", override=False)
    init_db()
    BaseModelAdapter.configure_memory_limits(1024)
    yield

app = FastAPI(title="Farad Ai Benchmark", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")
templates = Jinja2Templates(directory=WEB_DIR / "templates")

# ─── DuckDB Run History Schema ───────────────────────────────────────────────

def get_db():
    """Return a DuckDB connection with run_history and run_case_evaluations ensured."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(DB_PATH))
    ensure_run_history_schema(con, default_status="pending", index_name="idx_case_eval_lookup")
    init_experiment_registry(con)
    init_cloud_registry(con)
    init_report_registry(con)
    return con


@contextmanager
def db_write_session():
    """Serialize DuckDB write transactions across requests and background benchmark tasks."""
    with DB_WRITE_LOCK:
        con = get_db()
        try:
            yield con
        finally:
            con.close()


def init_db():
    """Initialize the database on startup."""
    with db_write_session():
        pass


# ─── Model Adapter Registry (mirrors benchmark_runner.py) ───────────────────

def get_available_models() -> List[Dict[str, Any]]:
    """Return list of available model adapters."""
    models = [
        {"id": "laya-mlx", "name": "Laya MLX", "description": "Local Apple Silicon — Laya OWASP Guard (4-bit)", "icon": "🍎", "status": "available", "backend": "MLX", "quantization": "4-bit", "loaded": False},
        {"id": "kev-0.8b", "name": "Kev-0.8B", "description": "Jared Palmer Decision Model — Qwen3.5 0.8B (<1GB RAM)", "icon": "⚡", "status": "available", "backend": "MLX", "quantization": "4-bit", "loaded": False},
        {"id": "qwen3guard", "name": "Qwen3Guard-0.6B", "description": "Alibaba dedicated tool & agent safety classifier (MLX 0.6B)", "icon": "🛡️", "status": "available", "backend": "MLX", "quantization": "4-bit", "loaded": False},
        {"id": "granite-guardian", "name": "IBM Granite Guardian 3.0-2B", "description": "Enterprise agentic risk & tool safety classifier (MLX)", "icon": "🛡️", "status": "available", "backend": "MLX", "quantization": "4-bit", "loaded": False},
        {"id": "llama-guard-3", "name": "Meta Llama Guard 3 1B", "description": "MLCommons agent safety & misuse detection (MLX)", "icon": "🦙", "status": "available", "backend": "MLX", "quantization": "4-bit", "loaded": False},
        {"id": "prompt-guard", "name": "Prompt-Guard-86M", "description": "Ultra-fast (<25ms) indirect prompt injection classifier (MPS)", "icon": "⚡", "status": "available", "backend": "MPS", "quantization": "fp16", "loaded": False},
        {"id": "shield-gemma", "name": "Google ShieldGemma 2B", "description": "Policy-based safety classifier (MLX)", "icon": "💎", "status": "available", "backend": "MLX", "quantization": "4-bit", "loaded": False},
        {"id": "ollama-d1", "name": "Liquid AI d1-3B", "description": "LFM2.5-VL non-autoregressive decision model (Ollama)", "icon": "💧", "status": "available", "backend": "Ollama", "quantization": "Q4", "loaded": False},
        {"id": "ollama-pplx-decider", "name": "Perplexity Decider Flash v1.2", "description": "Distilled Qwen3.5-4B calibrated probability model (Ollama)", "icon": "⚡", "status": "available", "backend": "Ollama", "quantization": "Q4", "loaded": False},
        {"id": "ollama-mica", "name": "Mica v0.5-4B", "description": "TypeSafe SystemOne decision model (Ollama)", "icon": "💎", "status": "available", "backend": "Ollama", "quantization": "Q4", "loaded": False},
        {"id": "ollama-llama-guard3", "name": "Llama Guard 3 1B (Ollama)", "description": "Meta Llama Guard 3 via Ollama Daemon (discrete verdict)", "icon": "🦙", "status": "available", "backend": "Ollama", "quantization": "Q4", "loaded": False},
        {"id": "ollama-granite-guardian", "name": "Granite Guardian 2B (Ollama)", "description": "IBM Granite Guardian via Ollama Daemon (discrete verdict)", "icon": "🛡️", "status": "available", "backend": "Ollama", "quantization": "Q4", "loaded": False},
        {"id": "l1-rules", "name": "L1 Static Rules", "description": "Declarative YAML Regex Engine (<0.2ms)", "icon": "⚡", "status": "available", "backend": "Python/Regex", "quantization": "None", "loaded": True},
        {"id": "mock", "name": "Mock (Heuristic)", "description": "Heuristic baseline rule testing engine", "icon": "🧪", "status": "available", "backend": "Heuristic", "quantization": "None", "loaded": True},
    ]
    # Check if laya_mlx is actually importable
    laya_model = next((m for m in models if m["id"] == "laya-mlx"), None)
    if laya_model:
        try:
            import laya_mlx
            laya_model["status"] = "available"
        except ImportError:
            laya_model["status"] = "unavailable"
            laya_model["description"] += " (not installed)"

    if DB_PATH.exists():
        try:
            con = get_db()
            for cm in list_cloud_models(con):
                if cm.enabled:
                    models.append({
                        "id": cm.model_id,
                        "name": f"{cm.model_id} (Cloud)",
                        "description": f"Cloud SystemOne ({cm.remote_model_slug} via {cm.provider_id})",
                        "icon": "☁️",
                        "status": "available",
                        "backend": "Cloud API",
                        "quantization": "Cloud",
                        "loaded": True,
                    })
            con.close()
        except Exception:
            pass

    return models


# Core Benchmark Datasets priority and display configuration
CORE_DATASETS: Dict[str, Dict[str, Any]] = {
    "farad_decision_bench_v1": {
        "priority": 0,
        "name": "🛡️ Farad-Decision-Bench-v1.0",
        "desc": "Official 2,000-case 4-way balanced evaluation benchmark (50/50 Threat vs Benign)",
    },
    "smoke_test_2k": {
        "priority": 0,
        "name": "🛡️ Farad-Decision-Bench-v1.0",
        "desc": "Official 2,000-case 4-way balanced evaluation benchmark (50/50 Threat vs Benign)",
    },
    "benchmark_train": {
        "priority": 1,
        "name": "🏋️ Benchmark Train (7.6k Pool)",
        "desc": "Disjoint training set of 7,629 cases (zero test set overlap)",
    },
    "master_benchmark": {
        "priority": 2,
        "name": "🎯 Master Benchmark (9.6k Full)",
        "desc": "Complete standardized test case pool (9,629 cases across all domains)",
    },
}


def get_available_datasets() -> List[Dict[str, Any]]:
    """Scan processed directory for available Parquet datasets, prioritizing core benchmark suites."""
    datasets = []
    if not PROCESSED_DIR.exists():
        return datasets

    has_farad_v1 = (PROCESSED_DIR / "farad_decision_bench_v1.parquet").exists()

    for pq_file in sorted(PROCESSED_DIR.glob("*.parquet")):
        stem = pq_file.stem
        # Avoid duplicate listing if both canonical farad_decision_bench_v1 and legacy smoke_test_2k exist
        if stem == "smoke_test_2k" and has_farad_v1:
            continue

        try:
            con = duckdb.connect(database=":memory:")
            row_count = con.execute(f"SELECT COUNT(*) FROM '{pq_file}'").fetchone()[0]
            tier_rows = dict(con.execute(f"SELECT analysis_tier, COUNT(*) FROM '{pq_file}' GROUP BY analysis_tier").fetchall())
            con.close()
        except Exception:
            row_count = 0
            tier_rows = {}

        stem = pq_file.stem
        is_core = stem in CORE_DATASETS
        core_info = CORE_DATASETS.get(stem, {})

        display_name = core_info.get("name") or stem.replace("_", " ").title()
        description = core_info.get("desc") or f"Standardized Parquet dataset ({row_count:,} cases)"
        priority = core_info.get("priority", 99)

        size_kb = pq_file.stat().st_size / 1024
        datasets.append({
            "id": stem,
            "name": display_name,
            "filename": pq_file.name,
            "path": str(pq_file),
            "rows": row_count,
            "cases": row_count,
            "static_rows": tier_rows.get("STATIC_CAPABLE", 0),
            "semantic_rows": tier_rows.get("SEMANTIC_REQUIRED", 0),
            "size_kb": round(size_kb, 1),
            "size_mb": round(size_kb / 1024, 2),
            "description": description,
            "source": "Parquet",
            "is_core": is_core,
            "category": "core" if is_core else "domain",
            "_priority": priority,
        })

    # Sort core datasets first by priority, then domain slices alphabetically
    datasets.sort(key=lambda d: (d["_priority"], d["name"]))
    for d in datasets:
        d.pop("_priority", None)

    return datasets



# ─── Active WebSocket Connections ────────────────────────────────────────────

active_connections: List[WebSocket] = []


async def broadcast(message: dict):
    """Send message to all connected WebSocket clients."""
    dead = []
    for ws in active_connections:
        try:
            await ws.send_json(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        active_connections.remove(ws)


# ─── Benchmark Execution Engine ─────────────────────────────────────────────

async def execute_benchmark(run_id: str, dataset_path: str, model_name: str, tier_filter: str = "all", enable_l1: bool = True):
    """Run benchmark asynchronously, streaming progress via WebSocket."""
    import sys
    sys.path.insert(0, str(PROJECT_ROOT))

    ds_path = Path(dataset_path)

    # Load test cases via DuckDB with analysis_tier filter
    data_con = duckdb.connect(database=":memory:")
    try:
        where_clause = ""
        if tier_filter == "static":
            where_clause = "WHERE analysis_tier = 'STATIC_CAPABLE'"
        elif tier_filter in ("semantic", "sentetik"):
            where_clause = "WHERE analysis_tier = 'SEMANTIC_REQUIRED'"

        query = f"SELECT id, source_dataset, threat_domain, analysis_tier, cwe, tool_name, tool_arguments, context, is_malicious FROM '{ds_path}' {where_clause} ORDER BY id ASC"
        records = data_con.execute(query).fetchall()
    except Exception as e:
        with db_write_session() as wcon:
            wcon.execute("UPDATE run_history SET status = 'error' WHERE run_id = ?", [run_id])
        await broadcast({"type": "error", "run_id": run_id, "message": str(e)})
        return
    finally:
        data_con.close()

    total = len(records)
    with db_write_session() as wcon:
        wcon.execute("UPDATE run_history SET total_cases = ?, status = 'running' WHERE run_id = ?", [total, run_id])

    await broadcast({"type": "run_started", "run_id": run_id, "total_cases": total})

    # Initialize model adapter explicitly without silent MockSecurityAdapter fallback
    from benchmark_runner import ADAPTER_REGISTRY, HybridCascadeAdapter, L1StaticAdapter

    is_cloud = is_cloud_model(model_name, DB_PATH)
    try:
        if model_name.lower() in ("l1-rules", "l1_rules"):
            adapter = L1StaticAdapter()
        elif model_name.lower() in ("hybrid-cascade", "hybrid_cascade"):
            adapter = HybridCascadeAdapter()
        else:
            base_adapter = resolve_adapter(model_name, db_target=DB_PATH, adapter_registry=ADAPTER_REGISTRY)
            adapter = HybridCascadeAdapter(l2_adapter=base_adapter) if enable_l1 else base_adapter
    except Exception as init_err:
        with db_write_session() as err_con:
            err_con.execute("UPDATE run_history SET status = 'error' WHERE run_id = ?", [run_id])
        await broadcast({"type": "error", "run_id": run_id, "message": str(init_err)})
        return

    tp = fp = tn = fn = 0
    refusal_count = error_count = skipped_count = 0
    total_in_tok = total_out_tok = total_cached_tok = 0
    total_cost_usd = 0.0
    cost_sources: set[str] = set()
    latencies = []
    category_stats = {}
    case_results = []
    eval_batch = {
        "run_id": [],
        "case_id": [],
        "source": [],
        "domain": [],
        "analysis_tier": [],
        "cwe": [],
        "tool_name": [],
        "is_malicious": [],
        "predicted_blocked": [],
        "correct": [],
        "decided_by": [],
        "confidence": [],
        "latency_ms": [],
        "offload_saved_ms": [],
        "verdict_detail": [],
        "tool_arguments": [],
        "context": [],
        "eval_status": [],
        "inference_rtt_ms": [],
        "retry_wait_ms": [],
        "input_tokens": [],
        "output_tokens": [],
        "cached_tokens": [],
        "cost_usd": [],
        "cost_source": [],
    }
    start_time = time.time()

    try:
        for i, row in enumerate(records):
            case_id, source, domain, tier, cwe, tool_name, args_raw, context, is_malicious = row

            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else (args_raw or {})
            except Exception:
                args = {"raw": str(args_raw)}

            t0 = time.perf_counter()
            result = await asyncio.to_thread(adapter.evaluate, tool_name, args, context or "")
            outer_dt_ms = (time.perf_counter() - t0) * 1000

            raw_verdict = str(result.get("verdict") or "").upper()
            eval_status = normalize_eval_status(result).value

            rtt_val = result.get("inference_rtt_ms")
            dt_ms = float(rtt_val) if rtt_val is not None and float(rtt_val) > 0 else float(result.get("latency_ms") or outer_dt_ms)
            retry_wait_ms = float(result.get("retry_wait_ms", 0.0) or 0.0)
            in_tok = int(result.get("input_tokens", 0) or 0)
            out_tok = int(result.get("output_tokens", 0) or 0)
            c_tok = int(result.get("cached_tokens", 0) or 0)
            c_usd = float(result.get("cost_usd", 0.0) or 0.0)
            c_src = str(result.get("cost_source", "none"))

            total_in_tok += in_tok
            total_out_tok += out_tok
            total_cached_tok += c_tok
            total_cost_usd += c_usd
            if c_src and c_src != "none":
                cost_sources.add(c_src)

            if eval_status == EvalStatus.OK.value:
                latencies.append(dt_ms)
                pred_blocked: Optional[bool] = bool(result.get("is_blocked", False))
                if domain not in category_stats:
                    category_stats[domain] = {"total": 0, "correct": 0}
                category_stats[domain]["total"] += 1

                verdict_correct: Optional[bool] = False
                if is_malicious:
                    if pred_blocked:
                        tp += 1
                        verdict_correct = True
                        category_stats[domain]["correct"] += 1
                    else:
                        fn += 1
                else:
                    if pred_blocked:
                        fp += 1
                    else:
                        tn += 1
                        verdict_correct = True
                        category_stats[domain]["correct"] += 1
            else:
                pred_blocked = None
                verdict_correct = None
                if eval_status == EvalStatus.REFUSAL.value:
                    refusal_count += 1
                elif eval_status == EvalStatus.SKIPPED.value:
                    skipped_count += 1
                else:
                    error_count += 1

            args_display = json.dumps(args, ensure_ascii=False, indent=2)
            if len(args_display) > 2500:
                args_display = args_display[:2500] + "\n... (truncated)"

            decided_by_engine = result.get("decided_by", "L1" if "l1" in model_name else "L2")
            offload_saved = float(result.get("offload_saved_ms", 0.0) or 0.0)

            eval_batch["run_id"].append(run_id)
            eval_batch["case_id"].append(str(case_id))
            eval_batch["source"].append(str(source or ""))
            eval_batch["domain"].append(str(domain or "UNKNOWN"))
            eval_batch["analysis_tier"].append(str(tier or "STATIC_CAPABLE"))
            eval_batch["cwe"].append(str(cwe or ""))
            eval_batch["tool_name"].append(str(tool_name or ""))
            eval_batch["is_malicious"].append(bool(is_malicious))
            eval_batch["predicted_blocked"].append(pred_blocked)
            eval_batch["correct"].append(verdict_correct)
            eval_batch["decided_by"].append(str(decided_by_engine))
            eval_batch["confidence"].append(float(result.get("confidence", 0.0) or 0.0))
            eval_batch["latency_ms"].append(round(dt_ms, 2))
            eval_batch["offload_saved_ms"].append(offload_saved)
            eval_batch["verdict_detail"].append(str(result.get("verdict", "")))
            eval_batch["tool_arguments"].append(args_display)
            eval_batch["context"].append(str(context or ""))
            eval_batch["eval_status"].append(eval_status)
            eval_batch["inference_rtt_ms"].append(round(dt_ms, 2))
            eval_batch["retry_wait_ms"].append(round(retry_wait_ms, 2))
            eval_batch["input_tokens"].append(in_tok)
            eval_batch["output_tokens"].append(out_tok)
            eval_batch["cached_tokens"].append(c_tok)
            eval_batch["cost_usd"].append(c_usd)
            eval_batch["cost_source"].append(c_src)

            record_this = (verdict_correct is False) or (len(case_results) < 200)
            if record_this and len(case_results) < 300:
                case_results.append({
                    "id": case_id,
                    "source": source,
                    "domain": domain,
                    "analysis_tier": tier or "STATIC_CAPABLE",
                    "cwe": cwe,
                    "tool_name": tool_name,
                    "tool_arguments": args_display,
                    "context": context or "",
                    "is_malicious": is_malicious,
                    "predicted_blocked": pred_blocked,
                    "correct": verdict_correct,
                    "eval_status": eval_status,
                    "confidence": result.get("confidence", 0),
                    "latency_ms": round(dt_ms, 2),
                    "verdict_detail": result.get("verdict", ""),
                    "decided_by": decided_by_engine,
                    "offload_saved_ms": offload_saved,
                })

            if (i + 1) % 10 == 0 or (i + 1) == total:
                evaluated = i + 1
                valid_so_far = tp + tn + fp + fn
                elapsed = time.time() - start_time
                throughput = evaluated / elapsed if elapsed > 0 else 0

                cur_acc = ((tp + tn) / valid_so_far) * 100 if valid_so_far > 0 else 0
                cur_prec = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0
                cur_rec = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0
                cur_f1 = (2 * cur_prec * cur_rec / (cur_prec + cur_rec)) if (cur_prec + cur_rec) > 0 else 0
                cur_fpr = (fp / (fp + tn)) * 100 if (fp + tn) > 0 else 0
                cur_avg_lat = (sum(latencies) / len(latencies)) if latencies else 0

                await broadcast({
                    "type": "progress",
                    "run_id": run_id,
                    "evaluated": evaluated,
                    "total": total,
                    "pct": round((evaluated / total) * 100, 1),
                    "throughput": round(throughput, 1),
                    "tp": tp, "tn": tn, "fp": fp, "fn": fn,
                    "accuracy": round(cur_acc, 2),
                    "precision": round(cur_prec, 2),
                    "recall": round(cur_rec, 2),
                    "f1": round(cur_f1, 2),
                    "fpr": round(cur_fpr, 2),
                    "avg_latency_ms": round(cur_avg_lat, 2),
                    "elapsed_secs": round(elapsed, 1),
                })

                if not is_cloud and (i + 1) % 50 == 0:
                    BaseModelAdapter.flush_unified_memory()

                await asyncio.sleep(0)

        # Final metrics computed strictly over eval_status == 'OK'
        valid_total = tp + tn + fp + fn
        elapsed_total = time.time() - start_time
        accuracy = ((tp + tn) / valid_total) * 100 if valid_total > 0 else 0
        precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0
        recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
        fpr = (fp / (fp + tn)) * 100 if (fp + tn) > 0 else 0
        avg_lat = sum(latencies) / len(latencies) if latencies else 0
        latencies.sort()
        p95_lat = latencies[int(len(latencies) * 0.95)] if latencies else 0
        agg_cost_source = (
            next(iter(cost_sources))
            if len(cost_sources) == 1
            else ("mixed" if len(cost_sources) > 1 else "none")
        )

        # Explicit-column PyArrow bulk insert into relational run_case_evaluations (never positional SELECT *)
        with db_write_session() as con:
            if eval_batch["case_id"]:
                eval_schema = pa.schema([
                    ("run_id", pa.string()),
                    ("case_id", pa.string()),
                    ("source", pa.string()),
                    ("domain", pa.string()),
                    ("analysis_tier", pa.string()),
                    ("cwe", pa.string()),
                    ("tool_name", pa.string()),
                    ("is_malicious", pa.bool_()),
                    ("predicted_blocked", pa.bool_()),
                    ("correct", pa.bool_()),
                    ("decided_by", pa.string()),
                    ("confidence", pa.float64()),
                    ("latency_ms", pa.float64()),
                    ("offload_saved_ms", pa.float64()),
                    ("verdict_detail", pa.string()),
                    ("tool_arguments", pa.string()),
                    ("context", pa.string()),
                    ("eval_status", pa.string()),
                    ("inference_rtt_ms", pa.float64()),
                    ("retry_wait_ms", pa.float64()),
                    ("input_tokens", pa.int32()),
                    ("output_tokens", pa.int32()),
                    ("cached_tokens", pa.int32()),
                    ("cost_usd", pa.float64()),
                    ("cost_source", pa.string()),
                ])
                eval_table = pa.Table.from_pydict(eval_batch, schema=eval_schema)
                con.register("eval_table_view", eval_table)
                con.execute("""
                    INSERT OR REPLACE INTO run_case_evaluations (
                        run_id, case_id, source, domain, analysis_tier, cwe,
                        tool_name, is_malicious, predicted_blocked, correct,
                        decided_by, confidence, latency_ms, offload_saved_ms,
                        verdict_detail, tool_arguments, context,
                        eval_status, inference_rtt_ms, retry_wait_ms,
                        input_tokens, output_tokens, cached_tokens, cost_usd, cost_source
                    )
                    SELECT
                        run_id, case_id, source, domain, analysis_tier, cwe,
                        tool_name, is_malicious, predicted_blocked, correct,
                        decided_by, confidence, latency_ms, offload_saved_ms,
                        verdict_detail, tool_arguments, context,
                        eval_status, inference_rtt_ms, retry_wait_ms,
                        input_tokens, output_tokens, cached_tokens, cost_usd, cost_source
                    FROM eval_table_view
                """)

            # Persist summary metrics to run_history
            con.execute("""
                UPDATE run_history SET
                    status = 'completed',
                    evaluated = ?,
                    tp = ?, tn = ?, fp = ?, fn = ?,
                    accuracy = ?, precision_val = ?, recall_val = ?, f1_score = ?,
                    fpr = ?, avg_latency_ms = ?, p95_latency_ms = ?,
                    category_stats = ?, case_results = ?,
                    completed_at = CURRENT_TIMESTAMP,
                    duration_secs = ?,
                    refusal_count = ?, error_count = ?, skipped_count = ?,
                    input_tokens = ?, output_tokens = ?, cached_tokens = ?,
                    total_cost_usd = ?, cost_source = ?
                WHERE run_id = ?
            """, [
                total, tp, tn, fp, fn,
                round(accuracy, 2), round(precision, 2), round(recall, 2), round(f1, 2),
                round(fpr, 2), round(avg_lat, 2), round(p95_lat, 2),
                json.dumps(category_stats), json.dumps(case_results[:100]),
                round(elapsed_total, 2),
                refusal_count, error_count, skipped_count,
                total_in_tok, total_out_tok, total_cached_tok,
                total_cost_usd, agg_cost_source,
                run_id
            ])

        cascade_stats = adapter.get_cascade_stats() if hasattr(adapter, "get_cascade_stats") else None

        await broadcast({
            "type": "run_completed",
            "run_id": run_id,
            "accuracy": round(accuracy, 2),
            "precision": round(precision, 2),
            "recall": round(recall, 2),
            "f1": round(f1, 2),
            "fpr": round(fpr, 2),
            "avg_latency_ms": round(avg_lat, 2),
            "p95_latency_ms": round(p95_lat, 2),
            "duration_secs": round(elapsed_total, 2),
            "total_cases": total,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "category_stats": category_stats,
            "cascade_stats": cascade_stats,
        })

    finally:
        # Release model weights from unified memory after every benchmark run,
        # ensuring the next run starts with a clean baseline (~0 GPU memory).
        if hasattr(adapter, "unload"):
            adapter.unload()
        # If the adapter is a HybridCascade wrapping an L2 adapter, unload that too
        if hasattr(adapter, "l2_adapter") and hasattr(adapter.l2_adapter, "unload"):
            adapter.l2_adapter.unload()
        BaseModelAdapter.flush_unified_memory()


# ─── API Routes ──────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Serve the main dashboard page."""
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/api/datasets", response_model=List[DatasetItem])
async def api_datasets():
    """List available Parquet datasets."""
    return get_available_datasets()


@app.get("/api/models", response_model=List[ModelItem])
async def api_models():
    """List available model adapters."""
    return get_available_models()


@app.post("/api/runs")
async def api_start_run(payload: RunCreateRequest) -> Dict[str, Any]:
    """Start a new benchmark run."""
    dataset_path = payload.dataset_path
    model_name = payload.model_name
    raw_dataset_name = payload.dataset_name
    enable_l1 = payload.enable_l1
    if isinstance(enable_l1, str):
        enable_l1 = enable_l1.lower() in ("true", "1", "yes")
    tier_filter = payload.tier_filter.lower()

    if not dataset_path or not Path(dataset_path).exists():
        return {"error": "Dataset not found", "path": dataset_path}

    from benchmark_runner import ADAPTER_REGISTRY
    from benchmark_matrix import resolve_runtime_tier

    if model_name.lower() not in ("l1-rules", "l1_rules", "hybrid-cascade", "hybrid_cascade"):
        try:
            resolve_adapter(model_name, db_target=DB_PATH, adapter_registry=ADAPTER_REGISTRY)
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    run_id = f"run-{uuid.uuid4().hex[:8]}"
    con_tier = get_db()
    runtime_tier = resolve_runtime_tier(model_name, db_con=con_tier)
    con_tier.close()

    # Effective dataset display name showing selected tier scope
    tier_tag = {
        "all": "all",
        "static": "static",
        "semantic": "semantik",
    }.get(tier_filter, tier_filter)
    effective_dataset_name = f"{raw_dataset_name} ({tier_tag})"

    # Effective model display name showing whether L1 is active
    model_display_names = {
        "laya-mlx": "Laya MLX",
        "kev-0.8b": "Kev-0.8B",
        "kev": "Kev-0.8B",
        "qwen3guard": "Qwen3Guard-0.6B",
        "granite-guardian": "Granite Guardian 3.0",
        "llama-guard-3": "Llama Guard 3 1B",
        "prompt-guard": "Prompt-Guard-86M",
        "shield-gemma": "ShieldGemma 2B",
        "ollama-d1": "Liquid AI d1-3B",
        "liquid-d1": "Liquid AI d1-3B",
        "d1": "Liquid AI d1-3B",
        "ollama-pplx-decider": "Perplexity Decider Flash",
        "pplx-decider": "Perplexity Decider Flash",
        "ollama-mica": "Mica v0.5-4B",
        "mica-v0.5": "Mica v0.5-4B",
        "mica": "Mica v0.5-4B",
        "mock": "Mock",
        "l1-rules": "L1 Static Rules"
    }

    base_display = model_display_names.get(model_name, model_name)
    if model_name in ("l1-rules", "l1_rules"):
        effective_model_name = "L1 Static Rules"
    elif enable_l1:
        effective_model_name = f"{base_display} + L1"
    else:
        effective_model_name = f"{base_display} (Saf)"

    with db_write_session() as con:
        con.execute("""
            INSERT INTO run_history (
                run_id, dataset_name, dataset_path, model_name, status, runtime_tier,
                tier_scope, enable_l1, limit_cases
            )
            VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?)
        """, [
            run_id, effective_dataset_name, dataset_path, effective_model_name, runtime_tier,
            tier_filter, bool(enable_l1), None,
        ])

    # Launch benchmark in background
    asyncio.create_task(execute_benchmark(
        run_id, dataset_path, model_name, tier_filter=tier_filter, enable_l1=enable_l1
    ))

    return {"run_id": run_id, "status": "started"}


@app.get("/api/runs", response_model=List[RunSummary])
async def api_list_runs(
    response: Response,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    dataset: Optional[str] = Query(None),
    model: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List benchmark runs with pagination (X-Total-Count header) and optional filters."""
    where_clauses = ["1=1"]
    params: List[Any] = []
    if dataset and dataset.strip() and dataset.strip().lower() != "all":
        where_clauses.append("dataset_name ILIKE ?")
        params.append(f"%{dataset.strip()}%")
    if model and model.strip() and model.strip().lower() != "all":
        where_clauses.append("model_name ILIKE ?")
        params.append(f"%{model.strip()}%")
    if status and status.strip() and status.strip().lower() != "all":
        where_clauses.append("LOWER(status) = LOWER(?)")
        params.append(status.strip())

    where_sql = " AND ".join(where_clauses)
    con = get_db()
    try:
        total_count = con.execute(
            f"SELECT COUNT(*) FROM run_history WHERE {where_sql}",
            params,
        ).fetchone()[0]
        rows = con.execute(f"""
            SELECT run_id, dataset_name, model_name, status, runtime_tier, experiment_id,
                   total_cases, accuracy, precision_val, recall_val, f1_score,
                   fpr, avg_latency_ms, p95_latency_ms, duration_secs,
                   tp, tn, fp, fn,
                   COALESCE(refusal_count, 0), COALESCE(error_count, 0), COALESCE(skipped_count, 0),
                   COALESCE(total_cost_usd, 0.0), COALESCE(cost_source, 'none'),
                   COALESCE(tier_scope, 'all'), enable_l1, limit_cases,
                   started_at, completed_at
            FROM run_history
            WHERE {where_sql}
            ORDER BY started_at DESC
            LIMIT ? OFFSET ?
        """, [*params, limit, offset]).fetchall()
    finally:
        con.close()

    response.headers["X-Total-Count"] = str(total_count)
    columns = [
        "run_id", "dataset_name", "model_name", "status", "runtime_tier", "experiment_id",
        "total_cases", "accuracy", "precision", "recall", "f1",
        "fpr", "avg_latency_ms", "p95_latency_ms", "duration_secs",
        "tp", "tn", "fp", "fn",
        "refusal_count", "error_count", "skipped_count",
        "total_cost_usd", "cost_source",
        "tier_scope", "enable_l1", "limit_cases",
        "started_at", "completed_at",
    ]
    return [dict(zip(columns, row)) for row in rows]


@app.get("/api/runs/{run_id}")
async def api_get_run(run_id: str, limit: int = 500):
    """Get detailed results for a specific run."""
    con = get_db()
    row = con.execute("""
        SELECT run_id, dataset_name, model_name, status,
               total_cases, evaluated, tp, tn, fp, fn,
               accuracy, precision_val, recall_val, f1_score,
               fpr, avg_latency_ms, p95_latency_ms,
               category_stats, case_results,
               started_at, completed_at, duration_secs
        FROM run_history
        WHERE run_id = ?
    """, [run_id]).fetchone()

    if not row:
        con.close()
        return {"error": "Run not found"}

    # Query relational run_case_evaluations first
    eval_rows = con.execute("""
        SELECT case_id, source, domain, analysis_tier, cwe, tool_name,
               is_malicious, predicted_blocked, correct, decided_by,
               confidence, latency_ms, offload_saved_ms, verdict_detail,
               tool_arguments, context
        FROM run_case_evaluations
        WHERE run_id = ?
        ORDER BY correct ASC, case_id ASC
        LIMIT ?
    """, [run_id, limit]).fetchall()
    con.close()

    if eval_rows:
        cases = [
            {
                "id": r[0],
                "source": r[1],
                "domain": r[2],
                "analysis_tier": r[3],
                "cwe": r[4],
                "tool_name": r[5],
                "is_malicious": r[6],
                "predicted_blocked": r[7],
                "correct": r[8],
                "decided_by": r[9],
                "confidence": r[10],
                "latency_ms": r[11],
                "offload_saved_ms": r[12],
                "verdict_detail": r[13],
                "tool_arguments": r[14],
                "context": r[15],
            }
            for r in eval_rows
        ]
    else:
        cases = json.loads(row[18]) if row[18] else []

    return {
        "run_id": row[0], "dataset_name": row[1], "model_name": row[2],
        "status": row[3], "total_cases": row[4], "evaluated": row[5],
        "tp": row[6], "tn": row[7], "fp": row[8], "fn": row[9],
        "accuracy": row[10], "precision": row[11], "recall": row[12],
        "f1": row[13], "fpr": row[14],
        "avg_latency_ms": row[15], "p95_latency_ms": row[16],
        "category_stats": json.loads(row[17]) if row[17] else {},
        "case_results": cases,
        "started_at": str(row[19]) if row[19] else None,
        "completed_at": str(row[20]) if row[20] else None,
        "duration_secs": row[21],
    }


@app.get("/api/runs/{run_a}/compare/{run_b}")
async def api_compare_runs(
    run_a: str,
    run_b: str,
    filter: str = "all",
    limit: int = 100,
    offset: int = 0
):
    """Compare two benchmark runs and return macro discrepancy metrics and differing cases."""
    con = get_db()

    meta_a = con.execute("""
        SELECT run_id, dataset_name, model_name, total_cases, accuracy,
               precision_val, recall_val, f1_score, fpr, avg_latency_ms
        FROM run_history WHERE run_id = ?
    """, [run_a]).fetchone()

    meta_b = con.execute("""
        SELECT run_id, dataset_name, model_name, total_cases, accuracy,
               precision_val, recall_val, f1_score, fpr, avg_latency_ms
        FROM run_history WHERE run_id = ?
    """, [run_b]).fetchone()

    if not meta_a or not meta_b:
        con.close()
        return {"error": "One or both runs not found", "run_a": bool(meta_a), "run_b": bool(meta_b)}

    cols_meta = ["run_id", "dataset_name", "model_name", "total_cases", "accuracy",
                 "precision", "recall", "f1", "fpr", "avg_latency_ms"]
    run_a_info = dict(zip(cols_meta, meta_a))
    run_b_info = dict(zip(cols_meta, meta_b))

    # Agreement and discrepancy aggregates
    stats_query = """
        SELECT
            COUNT(*) AS total_common,
            SUM(CASE WHEN a.predicted_blocked = b.predicted_blocked THEN 1 ELSE 0 END) AS matching_verdicts,
            SUM(CASE WHEN a.predicted_blocked != b.predicted_blocked THEN 1 ELSE 0 END) AS discrepant_verdicts,
            SUM(CASE WHEN a.is_malicious = TRUE AND a.predicted_blocked = FALSE AND b.predicted_blocked = TRUE THEN 1 ELSE 0 END) AS a_missed_b_caught,
            SUM(CASE WHEN a.is_malicious = TRUE AND a.predicted_blocked = TRUE AND b.predicted_blocked = FALSE THEN 1 ELSE 0 END) AS b_missed_a_caught,
            SUM(CASE WHEN a.correct = TRUE AND b.correct = TRUE THEN 1 ELSE 0 END) AS both_correct,
            SUM(CASE WHEN a.correct = FALSE AND b.correct = FALSE THEN 1 ELSE 0 END) AS both_incorrect,
            COALESCE(AVG(b.latency_ms - a.latency_ms), 0) AS avg_latency_diff_ms
        FROM run_case_evaluations a
        JOIN run_case_evaluations b ON a.case_id = b.case_id
        WHERE a.run_id = ? AND b.run_id = ?
          AND COALESCE(a.eval_status, 'OK') = 'OK'
          AND COALESCE(b.eval_status, 'OK') = 'OK'
    """
    stats_row = con.execute(stats_query, [run_a, run_b]).fetchone()
    total_common = stats_row[0] or 0
    matching = stats_row[1] or 0
    discrepant = stats_row[2] or 0
    agreement_rate = round((matching / total_common * 100), 2) if total_common > 0 else 0.0

    agreement_stats = {
        "total_common": total_common,
        "matching_verdicts": matching,
        "discrepant_verdicts": discrepant,
        "agreement_rate_pct": agreement_rate,
        "a_missed_b_caught": stats_row[3] or 0,
        "b_missed_a_caught": stats_row[4] or 0,
        "both_correct": stats_row[5] or 0,
        "both_incorrect": stats_row[6] or 0,
        "avg_latency_diff_ms": round(stats_row[7] or 0.0, 2),
    }

    # Filter clause for individual discrepancy rows
    if filter == "a_missed_b_caught":
        filter_clause = "AND a.is_malicious = TRUE AND a.predicted_blocked = FALSE AND b.predicted_blocked = TRUE"
    elif filter == "b_missed_a_caught":
        filter_clause = "AND a.is_malicious = TRUE AND a.predicted_blocked = TRUE AND b.predicted_blocked = FALSE"
    elif filter == "fp_diff":
        filter_clause = "AND a.is_malicious = FALSE AND a.predicted_blocked != b.predicted_blocked"
    else:
        # Default: all differences
        filter_clause = "AND a.predicted_blocked != b.predicted_blocked"

    count_query = f"""
        SELECT COUNT(*)
        FROM run_case_evaluations a
        JOIN run_case_evaluations b ON a.case_id = b.case_id
        WHERE a.run_id = ? AND b.run_id = ?
          AND COALESCE(a.eval_status, 'OK') = 'OK'
          AND COALESCE(b.eval_status, 'OK') = 'OK' {filter_clause}
    """
    total_filtered = con.execute(count_query, [run_a, run_b]).fetchone()[0]

    data_query = f"""
        SELECT
            a.case_id, a.source, a.domain, a.analysis_tier, a.cwe, a.tool_name,
            a.is_malicious, a.tool_arguments, a.context,
            a.predicted_blocked AS a_pred, a.correct AS a_correct, a.decided_by AS a_engine,
            a.latency_ms AS a_lat, a.offload_saved_ms AS a_saved, a.verdict_detail AS a_verdict,
            b.predicted_blocked AS b_pred, b.correct AS b_correct, b.decided_by AS b_engine,
            b.latency_ms AS b_lat, b.offload_saved_ms AS b_saved, b.verdict_detail AS b_verdict
        FROM run_case_evaluations a
        JOIN run_case_evaluations b ON a.case_id = b.case_id
        WHERE a.run_id = ? AND b.run_id = ?
          AND COALESCE(a.eval_status, 'OK') = 'OK'
          AND COALESCE(b.eval_status, 'OK') = 'OK' {filter_clause}
        ORDER BY a.case_id ASC
        LIMIT ? OFFSET ?
    """
    rows = con.execute(data_query, [run_a, run_b, limit, offset]).fetchall()
    con.close()

    discrepancies = [
        {
            "case_id": r[0],
            "source": r[1],
            "domain": r[2],
            "analysis_tier": r[3],
            "cwe": r[4],
            "tool_name": r[5],
            "is_malicious": r[6],
            "tool_arguments": r[7],
            "context": r[8],
            "run_a": {
                "predicted_blocked": r[9],
                "correct": r[10],
                "decided_by": r[11],
                "latency_ms": r[12],
                "offload_saved_ms": r[13],
                "verdict_detail": r[14],
            },
            "run_b": {
                "predicted_blocked": r[15],
                "correct": r[16],
                "decided_by": r[17],
                "latency_ms": r[18],
                "offload_saved_ms": r[19],
                "verdict_detail": r[20],
            },
            "latency_diff_ms": round(r[18] - r[12], 2),
        }
        for r in rows
    ]

    return {
        "run_a": run_a_info,
        "run_b": run_b_info,
        "agreement_stats": agreement_stats,
        "discrepancies": discrepancies,
        "pagination": {
            "total": total_filtered,
            "limit": limit,
            "offset": offset,
            "filter": filter
        }
    }


@app.delete("/api/runs/{run_id}", response_model=DeleteRunResponse)
async def api_delete_run(run_id: str):
    """Delete a specific run from history and all associated evaluations."""
    with db_write_session() as con:
        con.execute("DELETE FROM run_case_evaluations WHERE run_id = ?", [run_id])
        con.execute("DELETE FROM run_history WHERE run_id = ?", [run_id])
    return {"deleted": run_id}


# ─── Cloud Provider & Model Registry CRUD Endpoints (ADR 0012) ───────────────

def _serialize_provider(prov: CloudProviderSpec, model_count: int = 0) -> Dict[str, Any]:
    return {
        "provider_id": prov.provider_id,
        "display_name": prov.display_name,
        "dialect": prov.dialect.value,
        "base_url": prov.base_url,
        "endpoint_path": prov.endpoint_path,
        "api_key_env": prov.api_key_env,
        "api_key_configured": is_api_key_configured(prov.api_key_env, env_file=PROJECT_ROOT / ".env"),
        "model_count": model_count,
        "extra_headers": prov.extra_headers,
        "timeout_seconds": prov.timeout_seconds,
        "max_concurrency": prov.max_concurrency,
        "rpm_limit": prov.rpm_limit,
        "max_body_bytes": prov.max_body_bytes,
        "max_questions": prov.max_questions,
    }


def _serialize_cloud_model(
    model: CloudModelSpec,
    providers_by_id: Dict[str, CloudProviderSpec],
) -> Dict[str, Any]:
    prov = providers_by_id.get(model.provider_id)
    return {
        "model_id": model.model_id,
        "provider_id": model.provider_id,
        "provider_display_name": prov.display_name if prov else model.provider_id,
        "dialect": prov.dialect.value if prov else "",
        "api_key_env": prov.api_key_env if prov else "",
        "api_key_configured": (
            is_api_key_configured(prov.api_key_env, env_file=PROJECT_ROOT / ".env") if prov else False
        ),
        "remote_model_slug": model.remote_model_slug,
        "question_profile_id": model.question_profile_id,
        "state_format": model.state_format,
        "exploit_threshold": model.exploit_threshold,
        "misalignment_threshold": model.misalignment_threshold,
        "threat_threshold": model.threat_threshold,
        "input_price_per_1m_usd": model.input_price_per_1m_usd,
        "max_context_tokens": model.max_context_tokens,
        "enabled": model.enabled,
    }


@app.get("/api/cloud-providers", response_model=List[CloudProviderItem])
async def api_list_cloud_providers():
    """List all DuckDB cloud providers with .env key presence badge (zero raw secrets)."""
    con = get_db()
    try:
        providers = list_cloud_providers(con)
        models = list_cloud_models(con)
    finally:
        con.close()
    counts: Dict[str, int] = {}
    for m in models:
        counts[m.provider_id] = counts.get(m.provider_id, 0) + 1
    return [_serialize_provider(p, counts.get(p.provider_id, 0)) for p in providers]


@app.post("/api/cloud-providers", response_model=CloudProviderItem)
async def api_create_cloud_provider(payload: CloudProviderUpsertRequest):
    """Create or update a DuckDB cloud provider profile."""
    try:
        spec = CloudProviderSpec(
            **{**payload.model_dump(), "dialect": ProviderDialect(payload.dialect)}
        )
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    with db_write_session() as con:
        save_cloud_provider(spec, con)
        models = list_cloud_models(con)
    model_count = sum(1 for m in models if m.provider_id == spec.provider_id)
    return _serialize_provider(spec, model_count)


@app.put("/api/cloud-providers/{provider_id}", response_model=CloudProviderItem)
async def api_update_cloud_provider(provider_id: str, payload: CloudProviderUpsertRequest):
    """Update an existing DuckDB cloud provider profile."""
    try:
        spec = CloudProviderSpec(
            **{
                **payload.model_dump(),
                "provider_id": provider_id,
                "dialect": ProviderDialect(payload.dialect),
            }
        )
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    with db_write_session() as con:
        if get_cloud_provider(spec.provider_id, con) is None:
            raise HTTPException(status_code=404, detail=f"Cloud provider '{provider_id}' not found.")
        save_cloud_provider(spec, con)
        models = list_cloud_models(con)
    model_count = sum(1 for m in models if m.provider_id == spec.provider_id)
    return _serialize_provider(spec, model_count)


@app.delete("/api/cloud-providers/{provider_id}", response_model=CloudDeleteResponse)
async def api_delete_cloud_provider(provider_id: str):
    """Delete a cloud provider if no cloud models reference it."""
    with db_write_session() as con:
        try:
            deleted = delete_cloud_provider(provider_id, con)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Cloud provider '{provider_id}' not found.")
    return {"deleted": provider_id.strip().lower()}


@app.get("/api/cloud-models", response_model=List[CloudModelItem])
async def api_list_cloud_models():
    """List all DuckDB cloud models (both enabled and disabled) with provider metadata."""
    con = get_db()
    try:
        providers = {p.provider_id: p for p in list_cloud_providers(con)}
        models = list_cloud_models(con)
    finally:
        con.close()
    return [_serialize_cloud_model(m, providers) for m in models]


@app.post("/api/cloud-models", response_model=CloudModelItem)
async def api_create_cloud_model(payload: CloudModelUpsertRequest):
    """Create or update a DuckDB cloud model profile."""
    try:
        spec = CloudModelSpec(**payload.model_dump())
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    with db_write_session() as con:
        try:
            save_cloud_model(spec, con)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        providers = {p.provider_id: p for p in list_cloud_providers(con)}
    return _serialize_cloud_model(spec, providers)


@app.put("/api/cloud-models/{model_id}", response_model=CloudModelItem)
async def api_update_cloud_model(model_id: str, payload: CloudModelUpsertRequest):
    """Update an existing DuckDB cloud model profile."""
    try:
        spec = CloudModelSpec(**{**payload.model_dump(), "model_id": model_id})
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    with db_write_session() as con:
        if get_cloud_model(spec.model_id, con) is None:
            raise HTTPException(status_code=404, detail=f"Cloud model '{model_id}' not found.")
        try:
            save_cloud_model(spec, con)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        providers = {p.provider_id: p for p in list_cloud_providers(con)}
    return _serialize_cloud_model(spec, providers)


@app.delete("/api/cloud-models/{model_id}", response_model=CloudDeleteResponse)
async def api_delete_cloud_model(model_id: str):
    """Delete a DuckDB cloud model profile."""
    with db_write_session() as con:
        deleted = delete_cloud_model(model_id, con)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Cloud model '{model_id}' not found.")
    return {"deleted": model_id.strip().lower()}


@app.get("/api/cloud-config/export-yaml", response_class=PlainTextResponse)
async def api_export_cloud_yaml():
    """Read-only YAML export of DuckDB cloud providers and models."""
    con = get_db()
    try:
        yaml_text = export_cloud_config(out_path=None, db_target=con)
    finally:
        con.close()
    return PlainTextResponse(
        content=yaml_text,
        media_type="application/x-yaml",
        headers={"Content-Disposition": 'attachment; filename="cloud_models_export.yaml"'},
    )


# ─── Curated Periodic Report Studio Endpoints (ADR 0012) ─────────────────────

@app.get("/api/reports", response_model=List[ReportSummaryItem])
async def api_list_reports():
    """List saved curated benchmark reports (draft and published)."""
    con = get_db()
    try:
        return list_reports(con)
    finally:
        con.close()


@app.post("/api/reports", response_model=ReportDetailResponse)
async def api_create_report(payload: ReportCreateRequest):
    """Create a new editable draft curated benchmark report."""
    with db_write_session() as con:
        try:
            return create_draft_report(
                title=payload.title,
                period_label=payload.period_label,
                researcher_notes=payload.researcher_notes,
                selected_run_ids=payload.selected_run_ids,
                db_target=con,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/reports/{report_id}", response_model=ReportDetailResponse)
async def api_get_report(report_id: str):
    """Fetch a curated report (live dossier for draft; immutable frozen snapshot for published)."""
    with db_write_session() as con:
        report = get_report(report_id, con)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return report


@app.put("/api/reports/{report_id}", response_model=ReportDetailResponse)
async def api_update_report(report_id: str, payload: ReportUpdateRequest):
    """Update a draft report; returns 409 Conflict if the report is already published."""
    with db_write_session() as con:
        try:
            return update_draft_report(
                report_id,
                title=payload.title,
                period_label=payload.period_label,
                researcher_notes=payload.researcher_notes,
                selected_run_ids=payload.selected_run_ids,
                db_target=con,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ReportImmutableError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/reports/{report_id}/publish", response_model=ReportDetailResponse)
async def api_publish_report(report_id: str):
    """Seal a draft report into an immutable published snapshot."""
    with db_write_session() as con:
        try:
            return publish_report(report_id, con)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ReportImmutableError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/reports/{report_id}/duplicate", response_model=ReportDetailResponse)
async def api_duplicate_report(report_id: str):
    """Clone any draft or published report into a new editable draft."""
    with db_write_session() as con:
        try:
            return duplicate_report(report_id, con)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))


@app.delete("/api/reports/{report_id}", response_model=CloudDeleteResponse)
async def api_delete_report(report_id: str):
    """Delete a draft or published report."""
    with db_write_session() as con:
        deleted = delete_report(report_id, con)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return {"deleted": report_id}


@app.get("/api/reports/{report_id}/export")
async def api_export_report(report_id: str, format: str = Query("md", pattern="^(md|json)$")):
    """Export a report as an AI-Ready Markdown (<benchmark_report>) or JSON dossier."""
    with db_write_session() as con:
        report = get_report(report_id, con)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")

    if format == "json":
        return PlainTextResponse(
            content=json.dumps(report["dossier"], indent=2, ensure_ascii=False),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{report_id}.json"'},
        )
    return PlainTextResponse(
        content=report["markdown_preview"],
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{report_id}.md"'},
    )


# ─── Test Cases Explorer Endpoints (ISSUE-006 / 007 / 008) ───────────────────

MASTER_BENCHMARK_PATH = PROCESSED_DIR / "master_benchmark.parquet"

TEST_CASE_COLUMNS: tuple[str, ...] = (
    "id", "source_dataset", "threat_domain", "analysis_tier", "is_malicious",
    "cwe", "owasp_llm", "traffic_direction", "tool_name", "tool_arguments", "context"
)

ALLOWED_SORT_COLUMNS: frozenset[str] = frozenset({
    "id", "source_dataset", "threat_domain", "analysis_tier", "is_malicious", "tool_name"
})


def build_test_cases_filter(
    dataset: Optional[str] = None,
    threat_domain: Optional[str] = None,
    tier: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
) -> tuple[str, list[Any]]:
    """Construct SQL WHERE clause and parameterized values for test case querying (Clean Code / SRP)."""
    where_clauses: list[str] = ["1=1"]
    params: list[Any] = []

    if dataset and dataset != "all":
        where_clauses.append("source_dataset = ?")
        params.append(dataset)

    if threat_domain and threat_domain != "all":
        where_clauses.append("threat_domain = ?")
        params.append(threat_domain)

    if tier and tier != "all":
        where_clauses.append("analysis_tier = ?")
        params.append(tier.upper())

    if status == "safe":
        where_clauses.append("is_malicious = FALSE")
    elif status == "malicious":
        where_clauses.append("is_malicious = TRUE")

    if search and search.strip():
        search_pattern = f"%{search.strip()}%"
        where_clauses.append("(context ILIKE ? OR tool_arguments ILIKE ? OR id ILIKE ? OR cwe ILIKE ?)")
        params.extend([search_pattern] * 4)

    return " AND ".join(where_clauses), params


@app.get("/api/test-cases/filters", response_model=TestCaseFiltersResponse)
async def api_get_test_case_filters() -> dict[str, Any]:
    """Return distinct categories and case counts from master_benchmark.parquet."""
    if not MASTER_BENCHMARK_PATH.exists():
        raise HTTPException(status_code=404, detail="master_benchmark.parquet not found")

    con = duckdb.connect(":memory:")
    try:
        parquet_str = str(MASTER_BENCHMARK_PATH)
        total_pool_cases = con.execute(f'SELECT count(*) FROM "{parquet_str}"').fetchone()[0]

        def _fetch_grouped_counts(col_name: str) -> list[dict[str, Any]]:
            rows = con.execute(f'''
                SELECT {col_name}, count(*) as cnt
                FROM "{parquet_str}"
                GROUP BY {col_name}
                ORDER BY cnt DESC
            ''').fetchall()
            return [{"name": r[0], "count": r[1]} for r in rows if r[0]]

        return {
            "total_pool_cases": total_pool_cases,
            "datasets": _fetch_grouped_counts("source_dataset"),
            "threat_domains": _fetch_grouped_counts("threat_domain"),
            "analysis_tiers": _fetch_grouped_counts("analysis_tier"),
        }
    finally:
        con.close()


@app.get("/api/test-cases", response_model=TestCasesListResponse)
async def api_list_test_cases(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=100, description="Items per page"),
    dataset: Optional[str] = None,
    threat_domain: Optional[str] = None,
    tier: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = Query("id", description="Column to sort by"),
    sort_order: str = Query("asc", description="Sort order: asc or desc"),
) -> dict[str, Any]:
    """Query test cases directly from master_benchmark.parquet with server-side pagination."""
    if not MASTER_BENCHMARK_PATH.exists():
        raise HTTPException(status_code=404, detail="master_benchmark.parquet not found")

    where_sql, params = build_test_cases_filter(dataset, threat_domain, tier, status, search)
    safe_sort_col = sort_by if sort_by in ALLOWED_SORT_COLUMNS else "id"
    safe_sort_dir = "DESC" if sort_order.lower() == "desc" else "ASC"
    parquet_str = str(MASTER_BENCHMARK_PATH)

    con = duckdb.connect(":memory:")
    try:
        # Count total matching records
        count_query = f'SELECT count(*) FROM "{parquet_str}" WHERE {where_sql}'
        total_records = con.execute(count_query, params).fetchone()[0]

        total_pages = max(1, math.ceil(total_records / limit))
        current_page = min(page, total_pages) if total_records > 0 else 1
        offset = (current_page - 1) * limit

        # Select paginated slice
        columns_sql = ", ".join(TEST_CASE_COLUMNS)
        select_query = f'''
            SELECT {columns_sql}
            FROM "{parquet_str}"
            WHERE {where_sql}
            ORDER BY {safe_sort_col} {safe_sort_dir}
            LIMIT ? OFFSET ?
        '''
        query_params = list(params) + [limit, offset]
        rows = con.execute(select_query, query_params).fetchall()
        cases = [dict(zip(TEST_CASE_COLUMNS, r)) for r in rows]

        return {
            "cases": cases,
            "pagination": {
                "page": current_page,
                "limit": limit,
                "total_records": total_records,
                "total_pages": total_pages,
                "has_next": current_page < total_pages,
                "has_prev": current_page > 1,
            },
        }
    finally:
        con.close()


@app.get("/api/test-cases/{case_id}")
async def api_get_test_case(case_id: str) -> dict[str, Any]:
    """Retrieve a single test case by ID from master_benchmark.parquet."""
    if not MASTER_BENCHMARK_PATH.exists():
        raise HTTPException(status_code=404, detail="master_benchmark.parquet not found")

    con = duckdb.connect(":memory:")
    try:
        parquet_str = str(MASTER_BENCHMARK_PATH)
        columns_sql = ", ".join(TEST_CASE_COLUMNS)
        row = con.execute(f'''
            SELECT {columns_sql}
            FROM "{parquet_str}"
            WHERE id = ?
            LIMIT 1
        ''', [case_id]).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail=f"Test case '{case_id}' not found")

        return dict(zip(TEST_CASE_COLUMNS, row))
    finally:
        con.close()


# ─── Declarative Experiment Matrix Studio Endpoints (ADR 0010) ────────────────

async def execute_experiment_template(
    template_id: str,
    limit_override: Optional[int] = None,
    selected_models: Optional[List[str]] = None,
):
    """Run full multi-model experiment matrix sequentially in background, pushing WS updates."""
    from benchmark_matrix import evaluate_model_on_cases, load_test_cases, flush_unified_memory

    con = get_db()
    template = get_template(template_id, con)
    con.close()

    if not template:
        await broadcast({"type": "matrix_error", "template_id": template_id, "error": "Template not found"})
        return

    ds_path = Path(template.dataset_path)
    if not ds_path.is_absolute():
        candidate = PROJECT_ROOT / template.dataset_path
        if candidate.exists():
            ds_path = candidate
        elif (PROCESSED_DIR / template.dataset_path).exists():
            ds_path = PROCESSED_DIR / template.dataset_path
        elif (PROCESSED_DIR / ds_path.name).exists():
            ds_path = PROCESSED_DIR / ds_path.name

    if not ds_path.exists():
        await broadcast({"type": "matrix_error", "template_id": template_id, "error": f"Dataset file not found: {template.dataset_path}"})
        return

    effective_limit = limit_override if limit_override is not None else template.limit_cases
    is_smoke = "smoke" in template.template_id.lower() and (effective_limit == 200 or effective_limit is None)
    records = load_test_cases(ds_path, limit=effective_limit, smoke=is_smoke)

    target_specs = template.models_config
    if selected_models:
        target_specs = [s for s in target_specs if s.get("model_id") in selected_models]

    await broadcast({
        "type": "matrix_started",
        "template_id": template.template_id,
        "template_name": template.name,
        "total_models": len(target_specs),
        "total_cases": len(records),
    })

    completed_results = []
    for model_spec in target_specs:
        model_key = model_spec["model_id"]
        runtime_tier = model_spec.get("runtime_tier")
        enable_cascade = model_spec.get("enable_l1_cascade", False)
        thresholds = {
            k: v for k, v in model_spec.items()
            if k in ["threat_threshold", "exploit_threshold", "misalignment_threshold"]
        }

        await broadcast({
            "type": "matrix_model_started",
            "template_id": template.template_id,
            "model_id": model_key,
            "runtime_tier": runtime_tier or "AUTO",
        })

        def _run_single_eval(m_key=model_key, r_tier=runtime_tier, e_cascade=enable_cascade, t_holds=thresholds):
            db_con = get_db()
            try:
                return evaluate_model_on_cases(
                    model_key=m_key,
                    records=records,
                    dataset_name=ds_path.stem,
                    dataset_path=ds_path,
                    db_con=db_con,
                    enable_cascade=e_cascade,
                    experiment_id=template.template_id,
                    runtime_tier=r_tier,
                    thresholds=t_holds,
                )
            finally:
                db_con.close()

        try:
            res = await asyncio.to_thread(_run_single_eval)
            completed_results.append(res)
            await broadcast({
                "type": "matrix_model_completed",
                "template_id": template.template_id,
                "model_id": model_key,
                "run_id": res["run_id"],
                "accuracy": round(res.get("accuracy", 0.0), 2),
                "f1_score": round(res.get("f1_score", 0.0), 2),
                "avg_latency_ms": round(res.get("avg_latency_ms", 0.0), 2),
            })
        except Exception as err:
            await broadcast({
                "type": "matrix_model_error",
                "template_id": template.template_id,
                "model_id": model_key,
                "error": str(err),
            })
        finally:
            await asyncio.to_thread(flush_unified_memory)

    await broadcast({
        "type": "matrix_completed",
        "template_id": template.template_id,
        "completed_count": len(completed_results),
        "total_count": len(target_specs),
    })


@app.get("/api/experiments", response_model=List[ExperimentTemplateItem])
async def api_list_experiments():
    """List all stored experiment matrix templates."""
    con = get_db()
    try:
        templates = list_templates(con)
        return [t.to_dict() for t in templates]
    finally:
        con.close()


@app.get("/api/experiments/{template_id}", response_model=ExperimentTemplateItem)
async def api_get_experiment(template_id: str):
    """Fetch a single experiment matrix template by ID."""
    con = get_db()
    try:
        template = get_template(template_id, con)
        if not template:
            raise HTTPException(status_code=404, detail=f"Experiment template '{template_id}' not found")
        return template.to_dict()
    finally:
        con.close()


@app.post("/api/experiments", response_model=ExperimentTemplateItem)
async def api_save_experiment(payload: ExperimentTemplateCreateRequest):
    """Create or update an experiment matrix template."""
    if not payload.name or not payload.name.strip():
        raise HTTPException(status_code=400, detail="Experiment template name cannot be empty")
    if not payload.models_config or len(payload.models_config) == 0:
        raise HTTPException(status_code=400, detail="models_config must contain at least one model specification")

    template = ExperimentTemplate(
        template_id=payload.template_id.strip(),
        name=payload.name.strip(),
        description=payload.description or "",
        dataset_path=payload.dataset_path.strip(),
        models_config=payload.models_config,
        limit_cases=payload.limit_cases,
    )

    con = get_db()
    try:
        save_template(template, con)
        saved = get_template(template.template_id, con)
        return saved.to_dict()
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    finally:
        con.close()


@app.delete("/api/experiments/{template_id}")
async def api_delete_experiment(template_id: str):
    """Delete an experiment matrix template."""
    con = get_db()
    try:
        deleted = delete_template(template_id, con)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"Experiment template '{template_id}' not found")
        return {"deleted": template_id}
    finally:
        con.close()


@app.post("/api/experiments/{template_id}/run", response_model=ExperimentRunResponse)
async def api_run_experiment(template_id: str, payload: Optional[ExperimentRunRequest] = None):
    """Initiate background matrix execution for an experiment template."""
    con = get_db()
    try:
        template = get_template(template_id, con)
        if not template:
            raise HTTPException(status_code=404, detail=f"Experiment template '{template_id}' not found")
    finally:
        con.close()

    limit_override = payload.limit_cases if payload else None
    selected_models = payload.selected_models if payload else None
    models_to_run = [m for m in template.models_config if not selected_models or m.get("model_id") in selected_models]

    asyncio.create_task(execute_experiment_template(
        template_id=template_id,
        limit_override=limit_override,
        selected_models=selected_models,
    ))

    return {
        "template_id": template_id,
        "status": "started",
        "models_count": len(models_to_run),
        "message": f"Experiment matrix '{template.name}' queued with {len(models_to_run)} model evaluations."
    }


# ─── WebSocket ───────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time benchmark progress updates."""
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            # Keep connection alive; client can also send commands
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        active_connections.remove(websocket)
    except Exception:
        if websocket in active_connections:
            active_connections.remove(websocket)


# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8765)
