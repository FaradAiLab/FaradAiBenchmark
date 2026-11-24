"""
adapters/report_registry.py

DuckDB-native Curated Periodic Benchmark Reports (ADR 0012):
- Two-state lifecycle: draft (editable) -> published (immutable sealed snapshot)
- Automatic Parity Guard caveats (dataset, tier_scope, enable_l1, limit_cases, budget_stopped)
- run_case_evaluations slice aggregation (threat_domain, analysis_tier, inference_rtt_ms, retry_wait_ms)
- Metadata-only AI-Ready Report Bundle (JSON dossier + <benchmark_report> Markdown, zero raw payloads)
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import duckdb

from adapters.experiment_registry import DEFAULT_DB_PATH, get_connection

SELECTABLE_RUN_STATUSES = frozenset({"completed", "budget_stopped"})
MAX_FAILURES_PER_TYPE = 5
MAX_DISAGREEMENTS = 10


class ReportStatus(StrEnum):
    """Two-state governance lifecycle for Curated Benchmark Reports (ADR 0012)."""

    DRAFT = "draft"
    PUBLISHED = "published"


class ReportImmutableError(ValueError):
    """Raised when attempting to mutate a sealed (published) benchmark report."""


def init_report_registry(
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> None:
    """Create benchmark_reports table in DuckDB if absent."""
    with get_connection(db_target) as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS benchmark_reports (
                report_id         VARCHAR PRIMARY KEY,
                title             VARCHAR NOT NULL,
                period_label      VARCHAR DEFAULT '',
                researcher_notes  VARCHAR DEFAULT '',
                status            VARCHAR NOT NULL DEFAULT 'draft',
                selected_run_ids  VARCHAR NOT NULL DEFAULT '[]',
                snapshot_json     VARCHAR DEFAULT NULL,
                created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                published_at      TIMESTAMP DEFAULT NULL
            );
            """
        )


def _infer_legacy_tier_scope(dataset_name: str, tier_scope: str | None) -> str:
    if tier_scope and tier_scope.strip():
        return tier_scope.strip().lower()
    lower = (dataset_name or "").lower()
    if "(static)" in lower:
        return "static"
    if "(semantik)" in lower or "(semantic)" in lower:
        return "semantic"
    return "all"


def _infer_legacy_enable_l1(model_name: str, enable_l1: bool | None) -> bool | None:
    if enable_l1 is not None:
        return bool(enable_l1)
    name = model_name or ""
    if "+ L1" in name:
        return True
    if "(Saf)" in name or "(Pure)" in name:
        return False
    return None


def _normalize_dataset_base(dataset_name: str) -> str:
    return re.sub(r"\s*\((all|static|semantik|semantic)\)\s*$", "", (dataset_name or "").strip(), flags=re.IGNORECASE)


def _fmt_ts(val: Any) -> str | None:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)


def _dedupe_ids(run_ids: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for rid in run_ids:
        cleaned = str(rid).strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            ordered.append(cleaned)
    return ordered


def _validate_selectable_runs(con: duckdb.DuckDBPyConnection, run_ids: list[str]) -> list[str]:
    cleaned = _dedupe_ids(run_ids)
    if not cleaned:
        return []
    placeholders = ", ".join(["?"] * len(cleaned))
    rows = con.execute(
        f"SELECT run_id, status FROM run_history WHERE run_id IN ({placeholders})",
        cleaned,
    ).fetchall()
    status_by_id = {str(r[0]): str(r[1] or "").lower() for r in rows}
    missing = [rid for rid in cleaned if rid not in status_by_id]
    if missing:
        raise ValueError(f"Unknown run_id(s): {', '.join(missing)}")
    invalid = [
        f"{rid} (status={status_by_id[rid]})"
        for rid in cleaned
        if status_by_id[rid] not in SELECTABLE_RUN_STATUSES
    ]
    if invalid:
        raise ValueError(
            "Only completed or budget_stopped runs can be included in a report; rejected: "
            + ", ".join(invalid)
        )
    return cleaned


def _fetch_run_rows(con: duckdb.DuckDBPyConnection, run_ids: list[str]) -> list[dict[str, Any]]:
    if not run_ids:
        return []
    placeholders = ", ".join(["?"] * len(run_ids))
    rows = con.execute(
        f"""
        SELECT run_id, dataset_name, dataset_path, model_name, status,
               COALESCE(runtime_tier, 'UNKNOWN'),
               total_cases, evaluated, tp, tn, fp, fn,
               accuracy, precision_val, recall_val, f1_score, fpr,
               avg_latency_ms, p95_latency_ms, duration_secs,
               COALESCE(refusal_count, 0), COALESCE(error_count, 0), COALESCE(skipped_count, 0),
               COALESCE(input_tokens, 0), COALESCE(output_tokens, 0), COALESCE(cached_tokens, 0),
               COALESCE(total_cost_usd, 0.0), COALESCE(cost_source, 'none'),
               tier_scope, enable_l1, limit_cases,
               COALESCE(category_stats, '{{}}'),
               started_at, completed_at
        FROM run_history
        WHERE run_id IN ({placeholders})
        """,
        run_ids,
    ).fetchall()
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        (
            run_id, dataset_name, dataset_path, model_name, status, runtime_tier,
            total_cases, evaluated, tp, tn, fp, fn,
            accuracy, precision_val, recall_val, f1_score, fpr,
            avg_latency_ms, p95_latency_ms, duration_secs,
            refusal_count, error_count, skipped_count,
            input_tokens, output_tokens, cached_tokens,
            total_cost_usd, cost_source,
            tier_scope, enable_l1, limit_cases,
            category_stats_raw, started_at, completed_at,
        ) = row
        ok_count = int(tp or 0) + int(tn or 0) + int(fp or 0) + int(fn or 0)
        try:
            cat_stats = json.loads(category_stats_raw) if isinstance(category_stats_raw, str) else {}
        except (json.JSONDecodeError, TypeError):
            cat_stats = {}
        by_id[str(run_id)] = {
            "run_id": str(run_id),
            "dataset_name": str(dataset_name or ""),
            "dataset_base": _normalize_dataset_base(str(dataset_name or "")),
            "dataset_path": str(dataset_path or ""),
            "model_name": str(model_name or ""),
            "status": str(status or ""),
            "runtime_tier": str(runtime_tier or "UNKNOWN"),
            "tier_scope": _infer_legacy_tier_scope(str(dataset_name or ""), tier_scope),
            "enable_l1": _infer_legacy_enable_l1(str(model_name or ""), enable_l1),
            "limit_cases": int(limit_cases) if limit_cases is not None else None,
            "total_cases": int(total_cases or 0),
            "evaluated": int(evaluated or 0),
            "ok_count": ok_count,
            "refusal_count": int(refusal_count or 0),
            "error_count": int(error_count or 0),
            "skipped_count": int(skipped_count or 0),
            "tp": int(tp or 0),
            "tn": int(tn or 0),
            "fp": int(fp or 0),
            "fn": int(fn or 0),
            "accuracy": round(float(accuracy or 0.0), 2),
            "precision": round(float(precision_val or 0.0), 2),
            "recall": round(float(recall_val or 0.0), 2),
            "f1": round(float(f1_score or 0.0), 2),
            "fpr": round(float(fpr or 0.0), 2),
            "avg_latency_ms": round(float(avg_latency_ms or 0.0), 2),
            "p95_latency_ms": round(float(p95_latency_ms or 0.0), 2),
            "avg_inference_rtt_ms": 0.0,
            "avg_retry_wait_ms": 0.0,
            "duration_secs": round(float(duration_secs or 0.0), 2),
            "input_tokens": int(input_tokens or 0),
            "output_tokens": int(output_tokens or 0),
            "cached_tokens": int(cached_tokens or 0),
            "total_cost_usd": round(float(total_cost_usd or 0.0), 6),
            "cost_source": str(cost_source or "none"),
            "started_at": _fmt_ts(started_at),
            "completed_at": _fmt_ts(completed_at),
            "_legacy_category_stats": cat_stats,
        }
    return [by_id[rid] for rid in run_ids if rid in by_id]


def _compute_parity_warnings(runs: list[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    if not runs:
        return warnings

    budget_runs = [r["run_id"] for r in runs if r["status"].lower() == "budget_stopped"]
    if budget_runs:
        warnings.append(
            f"Partial execution: run(s) {', '.join(budget_runs)} stopped early due to budget cap (status=budget_stopped)."
        )

    if len(runs) < 2:
        return warnings

    datasets = sorted({r["dataset_base"] for r in runs if r["dataset_base"]})
    if len(datasets) > 1:
        warnings.append(
            f"Dataset mismatch: curated runs span multiple datasets ({', '.join(datasets)})."
        )

    tiers = sorted({r["tier_scope"] for r in runs})
    if len(tiers) > 1:
        warnings.append(
            f"Analysis tier scope mismatch: runs use different tier_scope values ({', '.join(tiers)})."
        )

    l1_states = {r["enable_l1"] for r in runs if r["enable_l1"] is not None}
    if len(l1_states) > 1:
        warnings.append(
            "L1 cascade mismatch: report mixes L1+Model cascade runs with Pure Model runs."
        )

    case_counts = sorted({r["total_cases"] for r in runs})
    if len(case_counts) > 1:
        warnings.append(
            f"Case count mismatch: runs evaluated different case counts ({', '.join(str(c) for c in case_counts)})."
        )

    return warnings


def _enrich_from_case_evaluations(
    con: duckdb.DuckDBPyConnection,
    runs: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, list[dict[str, Any]]]], list[dict[str, Any]]]:
    """Aggregate latency splits, domain/tier slices, and metadata-only failures/disagreements (zero raw payloads)."""
    if not runs:
        return {}, {}, {}, []

    run_ids = [r["run_id"] for r in runs]
    placeholders = ", ".join(["?"] * len(run_ids))

    # 1. Inference RTT vs Retry Wait per run
    rtt_rows = con.execute(
        f"""
        SELECT run_id,
               AVG(COALESCE(inference_rtt_ms, latency_ms)),
               AVG(COALESCE(retry_wait_ms, 0.0))
        FROM run_case_evaluations
        WHERE run_id IN ({placeholders})
        GROUP BY run_id
        """,
        run_ids,
    ).fetchall()
    rtt_map = {str(r[0]): (round(float(r[1] or 0.0), 2), round(float(r[2] or 0.0), 2)) for r in rtt_rows}
    for r in runs:
        if r["run_id"] in rtt_map:
            r["avg_inference_rtt_ms"], r["avg_retry_wait_ms"] = rtt_map[r["run_id"]]

    # 2. Domain breakdown (strictly over eval_status == 'OK')
    domain_breakdown: dict[str, dict[str, Any]] = {}
    dom_rows = con.execute(
        f"""
        SELECT domain, run_id,
               COUNT(*) AS total,
               SUM(CASE WHEN COALESCE(eval_status, 'OK') = 'OK' THEN 1 ELSE 0 END) AS ok_cnt,
               SUM(CASE WHEN COALESCE(eval_status, 'OK') = 'OK' AND correct = TRUE THEN 1 ELSE 0 END) AS correct_cnt,
               SUM(CASE WHEN COALESCE(eval_status, 'OK') = 'OK' AND is_malicious = TRUE AND predicted_blocked = TRUE THEN 1 ELSE 0 END) AS tp_cnt,
               SUM(CASE WHEN COALESCE(eval_status, 'OK') = 'OK' AND is_malicious = TRUE AND predicted_blocked = FALSE THEN 1 ELSE 0 END) AS fn_cnt,
               SUM(CASE WHEN COALESCE(eval_status, 'OK') = 'OK' AND is_malicious = FALSE AND predicted_blocked = TRUE THEN 1 ELSE 0 END) AS fp_cnt
        FROM run_case_evaluations
        WHERE run_id IN ({placeholders})
        GROUP BY domain, run_id
        ORDER BY domain ASC, run_id ASC
        """,
        run_ids,
    ).fetchall()
    runs_with_dom = set()
    for dom, rid, total, ok_cnt, corr, tp_c, fn_c, fp_c in dom_rows:
        runs_with_dom.add(str(rid))
        ok_n = int(ok_cnt or 0)
        tp_n, fn_n, fp_n = int(tp_c or 0), int(fn_c or 0), int(fp_c or 0)
        acc = round((int(corr or 0) / ok_n) * 100.0, 2) if ok_n > 0 else 0.0
        rec = round((tp_n / (tp_n + fn_n)) * 100.0, 2) if (tp_n + fn_n) > 0 else None
        domain_breakdown.setdefault(str(dom), {})[str(rid)] = {
            "total": int(total or 0),
            "ok": ok_n,
            "accuracy": acc,
            "recall": rec,
            "fp": fp_n,
            "fn": fn_n,
        }

    # Fallback to legacy category_stats JSON for runs without relational rows
    for r in runs:
        if r["run_id"] not in runs_with_dom and isinstance(r.get("_legacy_category_stats"), dict):
            for dom, stats in r["_legacy_category_stats"].items():
                if not isinstance(stats, dict):
                    continue
                total_n = int(stats.get("total", 0) or 0)
                corr_n = int(stats.get("correct", 0) or 0)
                acc = round((corr_n / total_n) * 100.0, 2) if total_n > 0 else 0.0
                domain_breakdown.setdefault(str(dom), {})[r["run_id"]] = {
                    "total": total_n,
                    "ok": total_n,
                    "accuracy": acc,
                    "recall": None,
                    "fp": 0,
                    "fn": 0,
                }

    # 3. Analysis tier breakdown
    tier_breakdown: dict[str, dict[str, Any]] = {}
    tier_rows = con.execute(
        f"""
        SELECT analysis_tier, run_id,
               COUNT(*) AS total,
               SUM(CASE WHEN COALESCE(eval_status, 'OK') = 'OK' THEN 1 ELSE 0 END) AS ok_cnt,
               SUM(CASE WHEN COALESCE(eval_status, 'OK') = 'OK' AND correct = TRUE THEN 1 ELSE 0 END) AS correct_cnt,
               SUM(CASE WHEN COALESCE(eval_status, 'OK') = 'OK' AND is_malicious = TRUE AND predicted_blocked = TRUE THEN 1 ELSE 0 END) AS tp_cnt,
               SUM(CASE WHEN COALESCE(eval_status, 'OK') = 'OK' AND is_malicious = TRUE AND predicted_blocked = FALSE THEN 1 ELSE 0 END) AS fn_cnt,
               SUM(CASE WHEN COALESCE(eval_status, 'OK') = 'OK' AND is_malicious = FALSE AND predicted_blocked = TRUE THEN 1 ELSE 0 END) AS fp_cnt,
               SUM(CASE WHEN COALESCE(eval_status, 'OK') = 'OK' AND is_malicious = FALSE AND predicted_blocked = FALSE THEN 1 ELSE 0 END) AS tn_cnt
        FROM run_case_evaluations
        WHERE run_id IN ({placeholders})
        GROUP BY analysis_tier, run_id
        ORDER BY analysis_tier ASC, run_id ASC
        """,
        run_ids,
    ).fetchall()
    for tier, rid, total, ok_cnt, corr, tp_c, fn_c, fp_c, tn_c in tier_rows:
        ok_n = int(ok_cnt or 0)
        tp_n, fn_n, fp_n, tn_n = int(tp_c or 0), int(fn_c or 0), int(fp_c or 0), int(tn_c or 0)
        acc = round((int(corr or 0) / ok_n) * 100.0, 2) if ok_n > 0 else 0.0
        rec = round((tp_n / (tp_n + fn_n)) * 100.0, 2) if (tp_n + fn_n) > 0 else None
        fpr_v = round((fp_n / (fp_n + tn_n)) * 100.0, 2) if (fp_n + tn_n) > 0 else None
        tier_breakdown.setdefault(str(tier), {})[str(rid)] = {
            "total": int(total or 0),
            "ok": ok_n,
            "accuracy": acc,
            "recall": rec,
            "fpr": fpr_v,
        }

    # 4. Metadata-only failure summaries (STRICTLY ZERO raw tool_arguments or context)
    failure_summaries: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for rid in run_ids:
        fn_rows = con.execute(
            """
            SELECT case_id, domain, tool_name, is_malicious, predicted_blocked,
                   COALESCE(eval_status, 'OK'), latency_ms
            FROM run_case_evaluations
            WHERE run_id = ? AND COALESCE(eval_status, 'OK') = 'OK'
              AND is_malicious = TRUE AND predicted_blocked = FALSE
            ORDER BY confidence DESC, case_id ASC
            LIMIT ?
            """,
            [rid, MAX_FAILURES_PER_TYPE],
        ).fetchall()
        fp_rows = con.execute(
            """
            SELECT case_id, domain, tool_name, is_malicious, predicted_blocked,
                   COALESCE(eval_status, 'OK'), latency_ms
            FROM run_case_evaluations
            WHERE run_id = ? AND COALESCE(eval_status, 'OK') = 'OK'
              AND is_malicious = FALSE AND predicted_blocked = TRUE
            ORDER BY confidence DESC, case_id ASC
            LIMIT ?
            """,
            [rid, MAX_FAILURES_PER_TYPE],
        ).fetchall()
        failure_summaries[rid] = {
            "false_negatives": [
                {
                    "case_id": str(r[0]),
                    "threat_domain": str(r[1]),
                    "tool_name": str(r[2] or ""),
                    "expected_malicious": bool(r[3]),
                    "predicted_blocked": bool(r[4]),
                    "eval_status": str(r[5]),
                    "latency_ms": round(float(r[6] or 0.0), 2),
                }
                for r in fn_rows
            ],
            "false_positives": [
                {
                    "case_id": str(r[0]),
                    "threat_domain": str(r[1]),
                    "tool_name": str(r[2] or ""),
                    "expected_malicious": bool(r[3]),
                    "predicted_blocked": bool(r[4]),
                    "eval_status": str(r[5]),
                    "latency_ms": round(float(r[6] or 0.0), 2),
                }
                for r in fp_rows
            ],
        }

    # 5. Common-dataset inter-run disagreements (max 10, metadata-only)
    disagreements: list[dict[str, Any]] = []
    if len(run_ids) >= 2:
        dis_case_rows = con.execute(
            f"""
            SELECT case_id,
                   MIN(domain) AS domain,
                   MIN(tool_name) AS tool_name,
                   BOOL_OR(is_malicious) AS expected_malicious
            FROM run_case_evaluations
            WHERE run_id IN ({placeholders})
              AND COALESCE(eval_status, 'OK') = 'OK'
              AND predicted_blocked IS NOT NULL
            GROUP BY case_id
            HAVING COUNT(DISTINCT run_id) >= 2
               AND COUNT(DISTINCT predicted_blocked) > 1
            ORDER BY case_id ASC
            LIMIT ?
            """,
            [*run_ids, MAX_DISAGREEMENTS],
        ).fetchall()
        if dis_case_rows:
            dis_case_ids = [str(r[0]) for r in dis_case_rows]
            case_ph = ", ".join(["?"] * len(dis_case_ids))
            verdict_rows = con.execute(
                f"""
                SELECT case_id, run_id, predicted_blocked
                FROM run_case_evaluations
                WHERE run_id IN ({placeholders}) AND case_id IN ({case_ph})
                """,
                [*run_ids, *dis_case_ids],
            ).fetchall()
            verdict_map: dict[str, dict[str, str]] = {}
            for cid, rid, p_blk in verdict_rows:
                verdict_map.setdefault(str(cid), {})[str(rid)] = (
                    "BLOCKED" if p_blk else ("ALLOWED" if p_blk is False else "N/A")
                )
            for cid, dom, tname, exp_mal in dis_case_rows:
                disagreements.append(
                    {
                        "case_id": str(cid),
                        "threat_domain": str(dom),
                        "tool_name": str(tname or ""),
                        "expected_malicious": bool(exp_mal),
                        "verdicts": verdict_map.get(str(cid), {}),
                    }
                )

    return domain_breakdown, tier_breakdown, failure_summaries, disagreements


def build_report_dossier(
    con: duckdb.DuckDBPyConnection,
    *,
    report_id: str,
    title: str,
    period_label: str,
    researcher_notes: str,
    status: str,
    selected_run_ids: list[str],
    published_at: str | None = None,
) -> dict[str, Any]:
    """Assemble the complete metadata-only AI-Ready JSON dossier."""
    runs = _fetch_run_rows(con, selected_run_ids)
    parity_warnings = _compute_parity_warnings(runs)
    domain_breakdown, tier_breakdown, failure_summaries, disagreements = _enrich_from_case_evaluations(con, runs)

    clean_runs = [{k: v for k, v in r.items() if not k.startswith("_")} for r in runs]
    return {
        "schema_version": "1.0",
        "payload_policy": "metadata_only_no_raw_payloads",
        "report": {
            "report_id": report_id,
            "title": title,
            "period_label": period_label,
            "status": status,
            "published_at": published_at,
            "generated_at": datetime.now(UTC).isoformat(),
            "researcher_notes": researcher_notes,
        },
        "parity_warnings": parity_warnings,
        "runs": clean_runs,
        "domain_breakdown": domain_breakdown,
        "tier_breakdown": tier_breakdown,
        "failure_summaries": failure_summaries,
        "disagreements": disagreements,
    }


def render_report_markdown(dossier: dict[str, Any]) -> str:
    """Render an AI-Ready <benchmark_report> Markdown brief from a structured dossier."""
    meta = dossier.get("report", {})
    warnings = dossier.get("parity_warnings", [])
    runs = dossier.get("runs", [])
    domain_breakdown = dossier.get("domain_breakdown", {})
    tier_breakdown = dossier.get("tier_breakdown", {})
    failure_summaries = dossier.get("failure_summaries", {})
    disagreements = dossier.get("disagreements", [])

    lines: list[str] = [
        "<benchmark_report>",
        f"# Periodic Security Benchmark Report: {meta.get('title', 'Untitled')}",
        "",
        f"- **Report ID:** `{meta.get('report_id', '')}`",
        f"- **Period / Tag:** {meta.get('period_label') or 'N/A'}",
        f"- **Governance Status:** `{meta.get('status', 'draft')}`"
        + (f" (Published at: `{meta['published_at']}`)" if meta.get("published_at") else ""),
        f"- **Runs Included:** {len(runs)}",
        "- **Payload Policy:** Metadata-only (raw attack payloads excluded)",
    ]
    if meta.get("researcher_notes"):
        lines.extend(["", "## Researcher Notes", meta["researcher_notes"]])

    if warnings:
        lines.extend(["", "## Parity Warnings (Apples-to-Apples Caveats)"])
        for w in warnings:
            lines.append(f"- ⚠️ {w}")

    lines.extend(["", "## Executive Comparison Matrix"])
    if runs:
        lines.append(
            "| Run ID | Model | Tier | Dataset | Scope | L1 | Status | Cases (OK/Ref/Err/Skip) | Acc % | Prec % | Rec % | F1 % | FPR % | Avg Lat (ms) | RTT / Retry (ms) | Cost (USD) |"
        )
        lines.append("|---|---|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for r in runs:
            l1_txt = "ON" if r.get("enable_l1") is True else ("OFF" if r.get("enable_l1") is False else "N/A")
            counts = f"{r['total_cases']} ({r['ok_count']}/{r['refusal_count']}/{r['error_count']}/{r['skipped_count']})"
            cost_txt = f"${r['total_cost_usd']:.4f} ({r['cost_source']})" if r.get("total_cost_usd") else "$0.0000"
            lines.append(
                f"| `{r['run_id']}` | {r['model_name']} | `{r['runtime_tier']}` | {r['dataset_base']} | "
                f"`{r['tier_scope']}` | {l1_txt} | `{r['status']}` | {counts} | "
                f"{r['accuracy']:.2f} | {r['precision']:.2f} | {r['recall']:.2f} | {r['f1']:.2f} | {r['fpr']:.2f} | "
                f"{r['avg_latency_ms']:.1f} | {r['avg_inference_rtt_ms']:.1f}/{r['avg_retry_wait_ms']:.1f} | {cost_txt} |"
            )
    else:
        lines.append("_No runs selected._")

    if domain_breakdown and runs:
        lines.extend(["", "## Threat Domain Breakdown (Accuracy %)"])
        run_headers = " | ".join(f"`{r['run_id']}` ({r['model_name']})" for r in runs)
        lines.append(f"| Threat Domain | {run_headers} |")
        lines.append("|---|" + "|".join(["---:"] * len(runs)) + "|")
        for dom in sorted(domain_breakdown.keys()):
            cells = []
            for r in runs:
                entry = domain_breakdown[dom].get(r["run_id"])
                cells.append(f"{entry['accuracy']:.1f}% (n={entry['ok']})" if entry else "—")
            lines.append(f"| `{dom}` | " + " | ".join(cells) + " |")

    if tier_breakdown and runs:
        lines.extend(["", "## Analysis Tier Breakdown (Accuracy %)"])
        run_headers = " | ".join(f"`{r['run_id']}`" for r in runs)
        lines.append(f"| Analysis Tier | {run_headers} |")
        lines.append("|---|" + "|".join(["---:"] * len(runs)) + "|")
        for tier in sorted(tier_breakdown.keys()):
            cells = []
            for r in runs:
                entry = tier_breakdown[tier].get(r["run_id"])
                cells.append(f"{entry['accuracy']:.1f}% (n={entry['ok']})" if entry else "—")
            lines.append(f"| `{tier}` | " + " | ".join(cells) + " |")

    if failure_summaries:
        has_any = any(
            v.get("false_negatives") or v.get("false_positives") for v in failure_summaries.values()
        )
        if has_any:
            lines.extend(["", "## Metadata-Only Failure Summaries (Top 5 FN / FP per Run)"])
            for r in runs:
                fs = failure_summaries.get(r["run_id"], {})
                fns = fs.get("false_negatives", [])
                fps = fs.get("false_positives", [])
                if not fns and not fps:
                    continue
                lines.append(f"### `{r['run_id']}` — {r['model_name']}")
                if fns:
                    lines.append("- **False Negatives (Missed Threats):** " + ", ".join(
                        f"`{c['case_id']}` ({c['threat_domain']}, tool=`{c['tool_name']}`)" for c in fns
                    ))
                if fps:
                    lines.append("- **False Positives (Over-blocked Benign):** " + ", ".join(
                        f"`{c['case_id']}` ({c['threat_domain']}, tool=`{c['tool_name']}`)" for c in fps
                    ))

    if disagreements:
        lines.extend(["", "## Inter-Run Disagreements (Top 10 Common Cases, Metadata-Only)"])
        lines.append("| Case ID | Threat Domain | Tool | Expected | Verdicts |")
        lines.append("|---|---|---|---|---|")
        for d in disagreements:
            exp = "MALICIOUS" if d["expected_malicious"] else "BENIGN"
            v_txt = ", ".join(f"`{rid}`={verdict}" for rid, verdict in d["verdicts"].items())
            lines.append(f"| `{d['case_id']}` | `{d['threat_domain']}` | `{d['tool_name']}` | {exp} | {v_txt} |")

    lines.append("</benchmark_report>")
    return "\n".join(lines)


def _row_to_summary(row: tuple) -> dict[str, Any]:
    (
        report_id, title, period_label, researcher_notes, status,
        selected_run_ids_raw, created_at, updated_at, published_at,
    ) = row
    try:
        run_ids = json.loads(selected_run_ids_raw) if isinstance(selected_run_ids_raw, str) else []
    except (json.JSONDecodeError, TypeError):
        run_ids = []
    return {
        "report_id": str(report_id),
        "title": str(title),
        "period_label": str(period_label or ""),
        "researcher_notes": str(researcher_notes or ""),
        "status": str(status),
        "selected_run_ids": run_ids,
        "run_count": len(run_ids),
        "created_at": _fmt_ts(created_at),
        "updated_at": _fmt_ts(updated_at),
        "published_at": _fmt_ts(published_at),
    }


def list_reports(
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> list[dict[str, Any]]:
    init_report_registry(db_target)
    with get_connection(db_target) as con:
        rows = con.execute(
            """
            SELECT report_id, title, period_label, researcher_notes, status,
                   selected_run_ids, created_at, updated_at, published_at
            FROM benchmark_reports
            ORDER BY updated_at DESC, created_at DESC
            """
        ).fetchall()
        return [_row_to_summary(r) for r in rows]


def create_draft_report(
    *,
    title: str,
    period_label: str = "",
    researcher_notes: str = "",
    selected_run_ids: list[str] | None = None,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> dict[str, Any]:
    init_report_registry(db_target)
    clean_title = title.strip()
    if not clean_title:
        raise ValueError("Report title cannot be empty.")

    with get_connection(db_target) as con:
        valid_ids = _validate_selectable_runs(con, selected_run_ids or [])
        report_id = f"rpt-{datetime.now(UTC).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
        con.execute(
            """
            INSERT INTO benchmark_reports (
                report_id, title, period_label, researcher_notes, status,
                selected_run_ids, snapshot_json, created_at, updated_at, published_at
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, NULL)
            """,
            [
                report_id,
                clean_title,
                period_label.strip(),
                researcher_notes.strip(),
                ReportStatus.DRAFT.value,
                json.dumps(valid_ids),
            ],
        )
        result = get_report(report_id, con)
        assert result is not None
        return result


def get_report(
    report_id: str,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> dict[str, Any] | None:
    init_report_registry(db_target)
    with get_connection(db_target) as con:
        row = con.execute(
            """
            SELECT report_id, title, period_label, researcher_notes, status,
                   selected_run_ids, snapshot_json, created_at, updated_at, published_at
            FROM benchmark_reports
            WHERE report_id = ?
            """,
            [report_id],
        ).fetchone()
        if not row:
            return None

        (
            rid, title, period_label, researcher_notes, status,
            selected_run_ids_raw, snapshot_json_raw, created_at, updated_at, published_at,
        ) = row
        summary = _row_to_summary(
            (rid, title, period_label, researcher_notes, status, selected_run_ids_raw, created_at, updated_at, published_at)
        )

        if status == ReportStatus.PUBLISHED.value and snapshot_json_raw:
            dossier = json.loads(snapshot_json_raw)
            return {
                **summary,
                "pruned_run_ids": [],
                "dossier": dossier,
                "markdown_preview": render_report_markdown(dossier),
            }

        # Draft: prune any runs that were deleted from History since draft creation
        stored_ids: list[str] = summary["selected_run_ids"]
        existing_rows = _fetch_run_rows(con, stored_ids)
        existing_valid_ids = [
            r["run_id"] for r in existing_rows if r["status"].lower() in SELECTABLE_RUN_STATUSES
        ]
        pruned_ids = [x for x in stored_ids if x not in set(existing_valid_ids)]
        if pruned_ids:
            con.execute(
                "UPDATE benchmark_reports SET selected_run_ids = ?, updated_at = CURRENT_TIMESTAMP WHERE report_id = ?",
                [json.dumps(existing_valid_ids), rid],
            )
            summary["selected_run_ids"] = existing_valid_ids
            summary["run_count"] = len(existing_valid_ids)

        dossier = build_report_dossier(
            con,
            report_id=str(rid),
            title=str(title),
            period_label=str(period_label or ""),
            researcher_notes=str(researcher_notes or ""),
            status=str(status),
            selected_run_ids=existing_valid_ids,
            published_at=_fmt_ts(published_at),
        )
        return {
            **summary,
            "pruned_run_ids": pruned_ids,
            "dossier": dossier,
            "markdown_preview": render_report_markdown(dossier),
        }


def update_draft_report(
    report_id: str,
    *,
    title: str | None = None,
    period_label: str | None = None,
    researcher_notes: str | None = None,
    selected_run_ids: list[str] | None = None,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> dict[str, Any]:
    init_report_registry(db_target)
    with get_connection(db_target) as con:
        row = con.execute(
            "SELECT title, period_label, researcher_notes, status, selected_run_ids FROM benchmark_reports WHERE report_id = ?",
            [report_id],
        ).fetchone()
        if not row:
            raise KeyError(f"Report '{report_id}' not found.")
        cur_title, cur_period, cur_notes, cur_status, cur_ids_raw = row
        if cur_status == ReportStatus.PUBLISHED.value:
            raise ReportImmutableError(
                f"Report '{report_id}' is published (sealed) and cannot be edited. Duplicate it as a draft instead."
            )

        new_title = cur_title if title is None else title.strip()
        if not new_title:
            raise ValueError("Report title cannot be empty.")
        new_period = cur_period if period_label is None else period_label.strip()
        new_notes = cur_notes if researcher_notes is None else researcher_notes.strip()
        if selected_run_ids is None:
            new_ids = json.loads(cur_ids_raw) if isinstance(cur_ids_raw, str) else []
        else:
            new_ids = _validate_selectable_runs(con, selected_run_ids)

        con.execute(
            """
            UPDATE benchmark_reports
            SET title = ?, period_label = ?, researcher_notes = ?,
                selected_run_ids = ?, updated_at = CURRENT_TIMESTAMP
            WHERE report_id = ?
            """,
            [new_title, new_period, new_notes, json.dumps(new_ids), report_id],
        )
        result = get_report(report_id, con)
        assert result is not None
        return result


def publish_report(
    report_id: str,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> dict[str, Any]:
    """Seal a draft report into an immutable published snapshot."""
    init_report_registry(db_target)
    with get_connection(db_target) as con:
        row = con.execute(
            "SELECT title, period_label, researcher_notes, status, selected_run_ids FROM benchmark_reports WHERE report_id = ?",
            [report_id],
        ).fetchone()
        if not row:
            raise KeyError(f"Report '{report_id}' not found.")
        title, period_label, researcher_notes, status, selected_run_ids_raw = row
        if status == ReportStatus.PUBLISHED.value:
            raise ReportImmutableError(f"Report '{report_id}' is already published.")

        stored_ids = json.loads(selected_run_ids_raw) if isinstance(selected_run_ids_raw, str) else []
        existing = _fetch_run_rows(con, stored_ids)
        valid_ids = [r["run_id"] for r in existing if r["status"].lower() in SELECTABLE_RUN_STATUSES]
        if not valid_ids:
            raise ValueError("Cannot publish a report with zero valid completed/budget_stopped runs.")

        published_ts = datetime.now(UTC).isoformat()
        dossier = build_report_dossier(
            con,
            report_id=report_id,
            title=str(title),
            period_label=str(period_label or ""),
            researcher_notes=str(researcher_notes or ""),
            status=ReportStatus.PUBLISHED.value,
            selected_run_ids=valid_ids,
            published_at=published_ts,
        )
        con.execute(
            """
            UPDATE benchmark_reports
            SET status = ?, selected_run_ids = ?, snapshot_json = ?,
                published_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE report_id = ?
            """,
            [
                ReportStatus.PUBLISHED.value,
                json.dumps(valid_ids),
                json.dumps(dossier, ensure_ascii=False),
                report_id,
            ],
        )
        result = get_report(report_id, con)
        assert result is not None
        return result


def duplicate_report(
    report_id: str,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> dict[str, Any]:
    """Clone any draft or published report into a new editable draft."""
    init_report_registry(db_target)
    with get_connection(db_target) as con:
        row = con.execute(
            "SELECT title, period_label, researcher_notes, selected_run_ids FROM benchmark_reports WHERE report_id = ?",
            [report_id],
        ).fetchone()
        if not row:
            raise KeyError(f"Report '{report_id}' not found.")
        title, period_label, researcher_notes, selected_run_ids_raw = row
        stored_ids = json.loads(selected_run_ids_raw) if isinstance(selected_run_ids_raw, str) else []
        # Keep only runs that still exist in run_history so cloning an old published report never crashes
        existing = _fetch_run_rows(con, stored_ids)
        valid_ids = [r["run_id"] for r in existing if r["status"].lower() in SELECTABLE_RUN_STATUSES]
        return create_draft_report(
            title=f"{title} (Copy)",
            period_label=str(period_label or ""),
            researcher_notes=str(researcher_notes or ""),
            selected_run_ids=valid_ids,
            db_target=con,
        )


def delete_report(
    report_id: str,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> bool:
    init_report_registry(db_target)
    with get_connection(db_target) as con:
        exists = con.execute(
            "SELECT 1 FROM benchmark_reports WHERE report_id = ?",
            [report_id],
        ).fetchone()
        if not exists:
            return False
        con.execute("DELETE FROM benchmark_reports WHERE report_id = ?", [report_id])
        return True
