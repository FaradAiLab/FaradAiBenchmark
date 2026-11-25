"""Unit and integration tests for deterministic stratified benchmark shuffling."""

import asyncio
import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from adapters.base import BaseModelAdapter, EvalStatus
from benchmark_matrix import load_test_cases
from benchmark_runner import stratified_shuffle_records


def _make_record(case_id: str, is_malicious: bool, tier: str = "STATIC_CAPABLE") -> tuple:
    domain = "COMMAND_INJECTION" if is_malicious else "BENIGN"
    cwe = "CWE-78" if is_malicious else "BENIGN"
    tool = "bash" if is_malicious else "read_file"
    args = json.dumps({"cmd": f"payload-{case_id}"} if is_malicious else {"path": f"{case_id}.txt"})
    return (case_id, "test_src", domain, tier, cwe, tool, args, "ctx", is_malicious)


def _write_skewed_parquet(path: Path, per_class: int) -> None:
    """Create a Parquet file where all benign IDs sort alphabetically before all malicious IDs."""
    ids: list[str] = []
    domains: list[str] = []
    tiers: list[str] = []
    cwes: list[str] = []
    tools: list[str] = []
    args: list[str] = []
    labels: list[bool] = []

    for i in range(per_class):
        tier = "STATIC_CAPABLE" if i % 2 == 0 else "SEMANTIC_REQUIRED"
        ids.append(f"a-benign-{i:04d}")
        domains.append("BENIGN")
        tiers.append(tier)
        cwes.append("BENIGN")
        tools.append("read_file")
        args.append(json.dumps({"path": f"file_{i}.txt"}))
        labels.append(False)

    for i in range(per_class):
        tier = "STATIC_CAPABLE" if i % 2 == 0 else "SEMANTIC_REQUIRED"
        ids.append(f"z-malicious-{i:04d}")
        domains.append("COMMAND_INJECTION")
        tiers.append(tier)
        cwes.append("CWE-78")
        tools.append("bash")
        args.append(json.dumps({"cmd": f"cat /etc/passwd #{i}"}))
        labels.append(True)

    table = pa.Table.from_pydict(
        {
            "id": ids,
            "source_dataset": ["skewed"] * len(ids),
            "threat_domain": domains,
            "analysis_tier": tiers,
            "cwe": cwes,
            "tool_name": tools,
            "tool_arguments": args,
            "context": ["ctx"] * len(ids),
            "is_malicious": labels,
        }
    )
    pq.write_table(table, path)


def test_stratified_shuffle_records_edge_cases():
    assert stratified_shuffle_records([]) == []

    single = [_make_record("only-1", True)]
    assert stratified_shuffle_records(single) == single

    single_class = [_make_record(f"b-{i:02d}", False) for i in range(12)]
    shuffled_fwd = stratified_shuffle_records(single_class)
    shuffled_rev = stratified_shuffle_records(list(reversed(single_class)))
    assert len(shuffled_fwd) == 12
    assert shuffled_fwd == shuffled_rev
    assert {r[0] for r in shuffled_fwd} == {r[0] for r in single_class}


def test_stratified_shuffle_records_balanced_and_deterministic():
    records = []
    for i in range(50):
        tier = "STATIC_CAPABLE" if i < 25 else "SEMANTIC_REQUIRED"
        records.append(_make_record(f"a-benign-{i:03d}", False, tier))
        records.append(_make_record(f"z-malicious-{i:03d}", True, tier))

    shuffled = stratified_shuffle_records(records)
    shuffled_rev = stratified_shuffle_records(list(reversed(records)))
    assert shuffled == shuffled_rev
    assert len(shuffled) == 100

    first_10 = shuffled[:10]
    assert sum(1 for r in first_10 if r[8]) == 5
    assert sum(1 for r in first_10 if not r[8]) == 5
    assert {r[3] for r in first_10} == {"STATIC_CAPABLE", "SEMANTIC_REQUIRED"}


def test_load_test_cases_stratified_limit_and_smoke(tmp_path: Path):
    skewed_100 = tmp_path / "skewed_100.parquet"
    _write_skewed_parquet(skewed_100, per_class=50)

    limited = load_test_cases(skewed_100, limit=20)
    assert len(limited) == 20
    assert sum(1 for r in limited if r[8]) == 10
    assert sum(1 for r in limited if not r[8]) == 10

    skewed_240 = tmp_path / "skewed_240.parquet"
    _write_skewed_parquet(skewed_240, per_class=120)

    smoke_cases = load_test_cases(skewed_240, smoke=True)
    assert len(smoke_cases) == 200
    assert sum(1 for r in smoke_cases if r[8]) == 100
    assert sum(1 for r in smoke_cases if not r[8]) == 100
    assert sum(1 for r in smoke_cases[:10] if r[8]) == 5
    assert sum(1 for r in smoke_cases[:10] if not r[8]) == 5


def test_execute_benchmark_live_progress_is_stratified(tmp_path: Path, monkeypatch):
    import web.app as web_app

    ds_path = tmp_path / "skewed_40.parquet"
    _write_skewed_parquet(ds_path, per_class=20)
    db_path = tmp_path / "web_test.duckdb"
    monkeypatch.setattr(web_app, "DB_PATH", db_path)
    web_app.init_db()

    class _StubAdapter:
        def evaluate(self, tool_name, tool_arguments, context=""):
            is_mal = tool_name == "bash"
            # Predict blocked for all malicious cases plus one benign file so FP > 0 early too
            is_fp = "file_0.txt" in json.dumps(tool_arguments)
            blocked = is_mal or is_fp
            return {
                "is_blocked": blocked,
                "confidence": 0.9 if blocked else 0.1,
                "latency_ms": 5.0,
                "inference_rtt_ms": 5.0,
                "verdict": "BLOCKED" if blocked else "ALLOWED",
                "eval_status": EvalStatus.OK.value,
                "decided_by": "L2",
            }

    events: list[dict] = []

    async def _capture_broadcast(msg: dict):
        events.append(msg)

    monkeypatch.setattr(web_app, "broadcast", _capture_broadcast)
    monkeypatch.setattr(web_app, "resolve_adapter", lambda *a, **kw: _StubAdapter())
    monkeypatch.setattr(web_app, "is_cloud_model", lambda *a, **kw: True)
    monkeypatch.setattr(BaseModelAdapter, "flush_unified_memory", classmethod(lambda cls: None))

    run_id = "run-stratified-test"
    with web_app.db_write_session() as con:
        con.execute(
            """
            INSERT INTO run_history (run_id, dataset_name, dataset_path, model_name, status)
            VALUES (?, 'skewed', ?, 'stub', 'pending')
            """,
            [run_id, str(ds_path)],
        )

    asyncio.run(
        web_app.execute_benchmark(
            run_id, str(ds_path), "stub", tier_filter="all", enable_l1=False
        )
    )

    progress_events = [e for e in events if e.get("type") == "progress"]
    assert progress_events
    first_progress = progress_events[0]
    assert first_progress["evaluated"] == 10
    assert first_progress["tp"] + first_progress["fn"] == 5
    assert first_progress["tn"] + first_progress["fp"] == 5
    assert first_progress["precision"] > 0
    assert first_progress["recall"] > 0
    assert first_progress["f1"] > 0
