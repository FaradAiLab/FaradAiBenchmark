"""
tests/test_cloud_execution_resume.py

Unit tests for Cloud Matrix Concurrency, Single DuckDB Writer Lock,
Atomic Budget Cap Reservation, Deterministic --resume-run-id,
EvalStatus Metrics, and HybridCascadeAdapter Thread-Safety (Task 8).
"""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import duckdb
import httpx
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from adapters.base import EvalStatus
from adapters.cloud_registry import (
    CloudModelSpec,
    CloudProviderSpec,
    ProviderDialect,
    init_cloud_registry,
    save_cloud_model,
    save_cloud_provider,
)
from benchmark_matrix import (
    evaluate_model_on_cases,
    init_db,
    load_test_cases,
    render_leaderboard,
)
from benchmark_runner import HybridCascadeAdapter


def _write_sample_parquet(path: Path, count: int = 10) -> None:
    rows = {
        "id": [f"case-{i:03d}" for i in range(count)],
        "source_dataset": ["unit_test"] * count,
        "threat_domain": ["COMMAND_INJECTION" if i % 2 == 0 else "BENIGN" for i in range(count)],
        "analysis_tier": ["SEMANTIC_REQUIRED"] * count,
        "cwe": ["CWE-78" if i % 2 == 0 else "BENIGN" for i in range(count)],
        "tool_name": ["bash" if i % 2 == 0 else "read_file" for i in range(count)],
        "tool_arguments": [
            json.dumps({"cmd": "cat /etc/passwd"} if i % 2 == 0 else {"path": f"doc_{i}.txt"})
            for i in range(count)
        ],
        "context": ["Run task" for _ in range(count)],
        "is_malicious": [i % 2 == 0 for i in range(count)],
    }
    pq.write_table(pa.Table.from_pydict(rows), path)


def _setup_cloud_db(db_path: Path, monkeypatch, *, max_concurrency: int = 4) -> duckdb.DuckDBPyConnection:
    monkeypatch.setenv("TEST_CLOUD_KEY", "sk-matrix-secret")
    con = init_db(db_path)
    init_cloud_registry(con)
    save_cloud_provider(
        CloudProviderSpec(
            provider_id="or-test",
            display_name="OpenRouter Test",
            dialect=ProviderDialect.OPENROUTER_DECISIONS,
            base_url="https://openrouter.ai",
            endpoint_path="/api/alpha/decisions",
            api_key_env="TEST_CLOUD_KEY",
            max_concurrency=max_concurrency,
        ),
        con,
    )
    save_cloud_model(
        CloudModelSpec(
            model_id="or-jev-test",
            provider_id="or-test",
            remote_model_slug="typesafe/jev-1.14",
            input_price_per_1m_usd=0.042,
        ),
        con,
    )
    return con


def test_load_test_cases_is_deterministic_ordered(tmp_path: Path):
    pq_path = tmp_path / "shuffled.parquet"
    rows = {
        "id": ["case-003", "case-001", "case-002"],
        "source_dataset": ["s", "s", "s"],
        "threat_domain": ["BENIGN", "BENIGN", "BENIGN"],
        "analysis_tier": ["STATIC_CAPABLE"] * 3,
        "cwe": ["BENIGN"] * 3,
        "tool_name": ["read_file"] * 3,
        "tool_arguments": ["{}"] * 3,
        "context": [""] * 3,
        "is_malicious": [False, False, False],
    }
    pq.write_table(pa.Table.from_pydict(rows), pq_path)
    loaded_unshuffled = load_test_cases(pq_path, limit=3, shuffle=False)
    assert [r[0] for r in loaded_unshuffled] == ["case-001", "case-002", "case-003"]

    pq_path_alt = tmp_path / "shuffled_alt.parquet"
    rows_alt = {
        "id": ["case-002", "case-003", "case-001"],
        "source_dataset": ["s", "s", "s"],
        "threat_domain": ["BENIGN", "BENIGN", "BENIGN"],
        "analysis_tier": ["STATIC_CAPABLE"] * 3,
        "cwe": ["BENIGN"] * 3,
        "tool_name": ["read_file"] * 3,
        "tool_arguments": ["{}"] * 3,
        "context": [""] * 3,
        "is_malicious": [False, False, False],
    }
    pq.write_table(pa.Table.from_pydict(rows_alt), pq_path_alt)
    assert load_test_cases(pq_path) == load_test_cases(pq_path_alt)


def test_concurrent_cloud_matrix_run_persists_cost_tier_and_excludes_refusals(tmp_path: Path, monkeypatch):
    pq_path = tmp_path / "bench.parquet"
    _write_sample_parquet(pq_path, count=6)
    con = _setup_cloud_db(tmp_path / "bench.duckdb", monkeypatch, max_concurrency=3)
    records = load_test_cases(pq_path)

    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content.decode("utf-8"))
        state_str = str(body["state"])
        if "doc_3.txt" in state_str:
            return httpx.Response(
                200,
                json={
                    "answers": {
                        "misalignment": {"type": "refusal"},
                        "exploit": {"type": "noul", "noul": 0.0},
                    },
                    "usage": {"input_tokens": 100, "output_tokens": 0, "cost": 0.0001},
                },
            )
        is_mal = "/etc/passwd" in state_str
        return httpx.Response(
            200,
            json={
                "answers": {
                    "misalignment": {"type": "noul", "noul": 0.1},
                    "exploit": {"type": "noul", "noul": 0.9 if is_mal else 0.05},
                },
                "usage": {"input_tokens": 200, "output_tokens": 0, "cost": 0.0002},
            },
        )

    RealClient = httpx.Client
    transport = httpx.MockTransport(handler)
    with patch("adapters.systemone_cloud_adapter.httpx.Client", side_effect=lambda **kw: RealClient(transport=transport, timeout=5.0)):
        res = evaluate_model_on_cases(
            model_key="or-jev-test",
            records=records,
            dataset_name="bench",
            dataset_path=pq_path,
            db_con=con,
        )

    assert res["runtime_tier"] == "CLOUD_DECISION_API"
    # 6 cases: 5 OK (3 malicious TP, 2 benign TN), 1 REFUSAL -> accuracy must be 100.0%, NOT 5/6!
    assert res["accuracy"] == pytest.approx(100.0)
    assert res["refusal_count"] == 1
    assert res["total_cost_usd"] == pytest.approx(0.0011)

    row = con.execute(
        "SELECT status, runtime_tier, accuracy, refusal_count, total_cost_usd, cost_source "
        "FROM run_history WHERE run_id = ?",
        [res["run_id"]],
    ).fetchone()
    assert row[0] == "completed"
    assert row[1] == "CLOUD_DECISION_API"
    assert row[2] == pytest.approx(100.0)
    assert row[3] == 1
    assert row[4] == pytest.approx(0.0011)
    assert row[5] == "api_reported"

    refusal_eval = con.execute(
        "SELECT eval_status, predicted_blocked, correct FROM run_case_evaluations WHERE run_id = ? AND case_id = 'case-003'",
        [res["run_id"]],
    ).fetchone()
    assert refusal_eval[0] == "REFUSAL"
    assert refusal_eval[1] is None
    assert refusal_eval[2] is None

    # Ensure leaderboard renders CLOUD_DECISION_API without errors
    render_leaderboard([res])
    con.close()


def test_atomic_budget_cap_prevents_concurrent_overspend(tmp_path: Path, monkeypatch):
    pq_path = tmp_path / "budget.parquet"
    _write_sample_parquet(pq_path, count=10)
    con = _setup_cloud_db(tmp_path / "budget.duckdb", monkeypatch, max_concurrency=4)
    records = load_test_cases(pq_path)

    call_count = 0
    call_lock = threading.Lock()

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal call_count
        time.sleep(0.02)
        with call_lock:
            call_count += 1
        return httpx.Response(
            200,
            json={
                "answers": {
                    "misalignment": {"type": "noul", "noul": 0.1},
                    "exploit": {"type": "noul", "noul": 0.1},
                },
                "usage": {"input_tokens": 1000, "output_tokens": 0, "cost": 0.05},
            },
        )

    RealClient = httpx.Client
    transport = httpx.MockTransport(handler)
    with patch("adapters.systemone_cloud_adapter.httpx.Client", side_effect=lambda **kw: RealClient(transport=transport, timeout=5.0)):
        res = evaluate_model_on_cases(
            model_key="or-jev-test",
            records=records,
            dataset_name="budget",
            dataset_path=pq_path,
            db_con=con,
            max_cost_usd=0.12,
            estimated_cost_per_call_usd=0.05,
        )

    assert call_count <= 2
    assert res["total_cost_usd"] <= 0.12
    assert res["status"] == "budget_stopped"
    con.close()


def test_resume_run_skips_completed_retries_errors_and_blocks_config_drift(tmp_path: Path, monkeypatch):
    pq_path = tmp_path / "resume.parquet"
    _write_sample_parquet(pq_path, count=5)
    con = _setup_cloud_db(tmp_path / "resume.duckdb", monkeypatch, max_concurrency=2)
    records = load_test_cases(pq_path)
    failing_path = json.loads(next(r[6] for r in records[:3] if not r[8]))["path"]

    seen_calls: list[str] = []
    fail_target = True

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal fail_target
        body = json.loads(req.content.decode("utf-8"))
        state_str = str(body["state"])
        seen_calls.append(state_str)
        if failing_path in state_str and fail_target:
            return httpx.Response(500, text="transient failure")
        is_mal = "/etc/passwd" in state_str
        return httpx.Response(
            200,
            json={
                "answers": {
                    "misalignment": {"type": "noul", "noul": 0.1},
                    "exploit": {"type": "noul", "noul": 0.9 if is_mal else 0.05},
                },
                "usage": {"input_tokens": 100, "output_tokens": 0, "cost": 0.01},
            },
        )

    RealClient = httpx.Client
    transport = httpx.MockTransport(handler)
    with patch("adapters.systemone_cloud_adapter.httpx.Client", side_effect=lambda **kw: RealClient(transport=transport, timeout=5.0)):
        # Stop after 3 cases via max_cost_usd=0.025 (2 OK * $0.01 = $0.02, plus 1 ERROR * $0.00 = $0.02)
        first = evaluate_model_on_cases(
            model_key="or-jev-test",
            records=records[:3],
            dataset_name="resume",
            dataset_path=pq_path,
            db_con=con,
            max_cost_usd=0.05,
        )
        assert first["error_count"] == 1
        run_id = first["run_id"]

        # Config drift (changed threshold) must be rejected on resume
        with pytest.raises(ValueError, match="config_hash"):
            evaluate_model_on_cases(
                model_key="or-jev-test",
                records=records,
                dataset_name="resume",
                dataset_path=pq_path,
                db_con=con,
                thresholds={"exploit_threshold": 0.99},
                resume_run_id=run_id,
            )

        # Now resume cleanly with matching config: prior OKs skipped, prior ERROR retried, remaining run
        seen_calls.clear()
        fail_target = False
        resumed = evaluate_model_on_cases(
            model_key="or-jev-test",
            records=records,
            dataset_name="resume",
            dataset_path=pq_path,
            db_con=con,
            resume_run_id=run_id,
        )

    assert len(seen_calls) == 3  # Only case-001 (prior ERROR) + case-003 + case-004!
    assert resumed["run_id"] == run_id
    assert resumed["status"] == "completed"
    assert resumed["error_count"] == 0
    assert resumed["accuracy"] == pytest.approx(100.0)
    assert resumed["total_cost_usd"] == pytest.approx(0.05)
    con.close()


def test_hybrid_cascade_thread_safe_and_forwards_telemetry():
    class StubCloudL2:
        def evaluate(self, tool_name, tool_arguments, context=""):
            return {
                "is_blocked": False,
                "confidence": 0.1,
                "verdict": "ALLOWED",
                "eval_status": EvalStatus.OK.value,
                "inference_rtt_ms": 25.0,
                "retry_wait_ms": 5.0,
                "input_tokens": 120,
                "output_tokens": 0,
                "cached_tokens": 10,
                "cost_usd": 0.000005,
                "cost_source": "api_reported",
                "alignment_risk": 0.05,
                "exploit_risk": 0.1,
            }

    cascade = HybridCascadeAdapter(l2_adapter=StubCloudL2(), l2_estimated_latency_ms=0.0)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda i: cascade.evaluate("read_file", {"path": f"f{i}.txt"}, "Read"), range(40)))

    stats = cascade.get_cascade_stats()
    assert stats["total_evaluated"] == 40
    assert stats["decided_by_l2"] == 40
    assert results[0]["eval_status"] == "OK"
    assert results[0]["cost_usd"] == pytest.approx(0.000005)
    assert results[0]["inference_rtt_ms"] == pytest.approx(25.0)
    assert results[0]["retry_wait_ms"] == pytest.approx(5.0)


def test_worker_exception_in_thread_pool_records_error_and_releases_budget(tmp_path: Path, monkeypatch):
    pq_path = tmp_path / "worker_err.parquet"
    _write_sample_parquet(pq_path, count=4)
    con = _setup_cloud_db(tmp_path / "worker_err.duckdb", monkeypatch, max_concurrency=2)
    records = load_test_cases(pq_path)

    class FlakyCloudAdapter:
        is_loaded = True

        def ensure_loaded(self):
            pass

        def unload(self):
            pass

        def evaluate(self, tool_name, tool_arguments, context=""):
            if "doc_1.txt" in json.dumps(tool_arguments):
                raise RuntimeError("boom inside worker")
            return {
                "is_blocked": "/etc/passwd" in json.dumps(tool_arguments),
                "confidence": 0.9,
                "verdict": "BLOCKED" if "/etc/passwd" in json.dumps(tool_arguments) else "ALLOWED",
                "eval_status": EvalStatus.OK.value,
                "inference_rtt_ms": 10.0,
                "cost_usd": 0.01,
                "cost_source": "api_reported",
            }

    with patch("benchmark_matrix.resolve_adapter", return_value=FlakyCloudAdapter()):
        summary = evaluate_model_on_cases(
            model_key="or-jev-test",
            records=records,
            dataset_name="worker_err",
            dataset_path=pq_path,
            db_con=con,
            concurrency=2,
            max_cost_usd=0.10,
        )

    assert summary["status"] == "completed"
    assert summary["error_count"] == 1
    assert summary["evaluated"] == 4
    assert summary["total_cost_usd"] == pytest.approx(0.03)
    hist_row = con.execute(
        "SELECT tp + fp + tn + fn, error_count FROM run_history WHERE run_id = ?",
        [summary["run_id"]],
    ).fetchone()
    assert hist_row == (3, 1)
    err_row = con.execute(
        "SELECT eval_status, verdict_detail, predicted_blocked, correct FROM run_case_evaluations WHERE case_id = 'case-001'"
    ).fetchone()
    assert err_row[0] == "ERROR"
    assert "WORKER_ERROR: boom inside worker" in err_row[1]
    assert err_row[2] is None
    assert err_row[3] is None
    con.close()


def test_resume_run_id_with_multiple_models_fails_fast(tmp_path: Path, monkeypatch):
    import sys

    import benchmark_matrix

    db_path = tmp_path / "cli_fail.duckdb"
    pq_path = tmp_path / "cli_fail.parquet"
    _write_sample_parquet(pq_path, count=2)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "benchmark_matrix.py",
            "--dataset",
            str(pq_path),
            "--db",
            str(db_path),
            "--models",
            "l1-rules,mock",
            "--resume-run-id",
            "run-12345",
        ],
    )
    with pytest.raises(SystemExit) as exc_info:
        benchmark_matrix.main()
    assert exc_info.value.code == 2
