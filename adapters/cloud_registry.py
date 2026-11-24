"""
adapters/cloud_registry.py

DuckDB-Native Cloud Provider & Model Registry, Secret Hygiene Validation,
YAML Import/Export, and Unified Adapter Resolution (ADR 0011).
"""

import inspect
import json
import logging
import os
import re
from contextlib import suppress
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import duckdb
import yaml
from dotenv import dotenv_values
from pydantic import BaseModel, Field, field_validator

from adapters.base import BaseModelAdapter, ProviderDialect
from adapters.experiment_registry import DEFAULT_DB_PATH, get_connection

logger = logging.getLogger(__name__)

SENSITIVE_HEADER_DENYLIST = frozenset({
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
    "x-auth-token",
})
ENV_VAR_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
LOCALHOST_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
STATIC_LOCAL_ADAPTER_IDS = frozenset({
    "laya-mlx",
    "kev-0.8b",
    "qwen3guard",
    "granite-guardian",
    "llama-guard-3",
    "prompt-guard",
    "shield-gemma",
    "ollama-d1",
    "ollama-pplx-decider",
    "ollama-mica",
    "ollama-llama-guard3",
    "ollama-granite-guardian",
    "l1-rules",
    "mock",
})


def _get_reserved_static_ids() -> frozenset[str]:
    """Return all lowercase static local adapter keys that cloud models must not shadow."""
    reserved = set(STATIC_LOCAL_ADAPTER_IDS)
    with suppress(Exception):
        from benchmark_runner import ADAPTER_REGISTRY
        reserved.update(k.strip().lower() for k in ADAPTER_REGISTRY)
    return frozenset(reserved)


def is_api_key_configured(env_name: str, env_file: Path | None = None) -> bool:
    """Return True if env_name is non-empty in process env or .env file (never returns the secret)."""
    cleaned = env_name.strip()
    if not cleaned:
        return False
    if os.environ.get(cleaned, "").strip():
        return True
    dotenv_path = env_file or (Path(__file__).resolve().parent.parent / ".env")
    if dotenv_path.exists():
        with suppress(OSError):
            vals = dotenv_values(dotenv_path)
            if (vals.get(cleaned) or "").strip():
                return True
    return False


class CloudProviderSpec(BaseModel):
    """Declarative cloud System One provider profile (zero plaintext secrets)."""

    provider_id: str = Field(..., min_length=1)
    display_name: str = Field(..., min_length=1)
    dialect: ProviderDialect
    base_url: str = Field(..., min_length=1)
    endpoint_path: str = Field(..., min_length=1)
    api_key_env: str = Field(..., min_length=1)
    extra_headers: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = Field(15.0, gt=0.0)
    max_concurrency: int = Field(8, ge=1, le=64)
    rpm_limit: int | None = Field(None, ge=1)
    max_body_bytes: int | None = Field(None, ge=1024)
    max_questions: int | None = Field(None, ge=1)

    @field_validator("provider_id")
    @classmethod
    def normalize_provider_id(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not cleaned:
            raise ValueError("provider_id cannot be empty.")
        return cleaned

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        cleaned = value.strip().rstrip("/")
        parsed = urlparse(cleaned)
        if parsed.query or parsed.fragment:
            raise ValueError(
                f"Provider base_url must not contain query strings or fragments, got: {value!r}"
            )
        if parsed.username or parsed.password:
            raise ValueError(
                f"Provider base_url must not contain embedded credentials, got: {value!r}"
            )
        host = (parsed.hostname or "").lower()
        if parsed.scheme == "https" and host:
            return cleaned
        if parsed.scheme == "http" and host in LOCALHOST_HOSTS:
            return cleaned
        raise ValueError(
            f"Provider base_url must use https:// (except localhost/127.0.0.1), got: {value!r}"
        )

    @field_validator("endpoint_path")
    @classmethod
    def validate_endpoint_path(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned.startswith("/"):
            raise ValueError(f"endpoint_path must start with '/', got: {value!r}")
        return cleaned

    @field_validator("api_key_env")
    @classmethod
    def validate_api_key_env(cls, value: str) -> str:
        cleaned = value.strip()
        if not ENV_VAR_NAME_RE.match(cleaned):
            raise ValueError(
                "api_key_env must be an uppercase environment variable name (e.g. OPENROUTER_API_KEY), "
                "never a raw API key."
            )
        return cleaned

    @field_validator("extra_headers")
    @classmethod
    def validate_extra_headers(cls, value: dict[str, str]) -> dict[str, str]:
        for key in value:
            if key.strip().lower() in SENSITIVE_HEADER_DENYLIST:
                raise ValueError(
                    f"Sensitive header {key!r} is forbidden in extra_headers; use api_key_env instead."
                )
        return {str(k).strip(): str(v) for k, v in value.items()}


class CloudModelSpec(BaseModel):
    """Declarative cloud System One model profile linked to a CloudProviderSpec."""

    model_id: str = Field(..., min_length=1)
    provider_id: str = Field(..., min_length=1)
    remote_model_slug: str = Field(..., min_length=1)
    question_profile_id: str = Field("dual_check_v1", min_length=1)
    state_format: Literal["canonical_text", "structured_json"] = "canonical_text"
    exploit_threshold: float = Field(0.50, ge=0.0, le=1.0)
    misalignment_threshold: float = Field(0.65, ge=0.0, le=1.0)
    threat_threshold: float = Field(0.50, ge=0.0, le=1.0)
    input_price_per_1m_usd: float | None = Field(None, ge=0.0)
    max_context_tokens: int | None = Field(None, ge=1)
    enabled: bool = True

    @field_validator("model_id")
    @classmethod
    def normalize_model_id(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not cleaned:
            raise ValueError("model_id cannot be empty.")
        if cleaned in _get_reserved_static_ids():
            raise ValueError(
                f"model_id {cleaned!r} collides with a reserved local adapter name; choose a distinct ID."
            )
        return cleaned

    @field_validator("provider_id")
    @classmethod
    def normalize_model_provider_id(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not cleaned:
            raise ValueError("provider_id cannot be empty.")
        return cleaned


def init_cloud_registry(
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> None:
    """Create cloud_providers and cloud_models tables in DuckDB if absent."""
    with get_connection(db_target) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS cloud_providers (
                provider_id        VARCHAR PRIMARY KEY,
                display_name       VARCHAR NOT NULL,
                dialect            VARCHAR NOT NULL,
                base_url           VARCHAR NOT NULL,
                endpoint_path      VARCHAR NOT NULL,
                api_key_env        VARCHAR NOT NULL,
                extra_headers_json VARCHAR DEFAULT '{}',
                timeout_seconds    DOUBLE DEFAULT 15.0,
                max_concurrency    INTEGER DEFAULT 8,
                rpm_limit          INTEGER DEFAULT NULL,
                max_body_bytes     INTEGER DEFAULT NULL,
                max_questions      INTEGER DEFAULT NULL,
                created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS cloud_models (
                model_id                VARCHAR PRIMARY KEY,
                provider_id             VARCHAR NOT NULL,
                remote_model_slug       VARCHAR NOT NULL,
                question_profile_id     VARCHAR NOT NULL DEFAULT 'dual_check_v1',
                state_format            VARCHAR NOT NULL DEFAULT 'canonical_text',
                exploit_threshold       DOUBLE DEFAULT 0.50,
                misalignment_threshold  DOUBLE DEFAULT 0.65,
                threat_threshold        DOUBLE DEFAULT 0.50,
                input_price_per_1m_usd  DOUBLE DEFAULT NULL,
                max_context_tokens      INTEGER DEFAULT NULL,
                enabled                 BOOLEAN DEFAULT TRUE,
                created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)


def _row_to_provider(row: tuple) -> CloudProviderSpec:
    (
        provider_id,
        display_name,
        dialect,
        base_url,
        endpoint_path,
        api_key_env,
        extra_headers_raw,
        timeout_seconds,
        max_concurrency,
        rpm_limit,
        max_body_bytes,
        max_questions,
    ) = row
    headers = json.loads(extra_headers_raw) if isinstance(extra_headers_raw, str) else (extra_headers_raw or {})
    return CloudProviderSpec(
        provider_id=provider_id,
        display_name=display_name,
        dialect=ProviderDialect(dialect),
        base_url=base_url,
        endpoint_path=endpoint_path,
        api_key_env=api_key_env,
        extra_headers=headers,
        timeout_seconds=float(timeout_seconds),
        max_concurrency=int(max_concurrency),
        rpm_limit=rpm_limit,
        max_body_bytes=max_body_bytes,
        max_questions=max_questions,
    )


def _row_to_model(row: tuple) -> CloudModelSpec:
    (
        model_id,
        provider_id,
        remote_model_slug,
        question_profile_id,
        state_format,
        exploit_threshold,
        misalignment_threshold,
        threat_threshold,
        input_price_per_1m_usd,
        max_context_tokens,
        enabled,
    ) = row
    return CloudModelSpec(
        model_id=model_id,
        provider_id=provider_id,
        remote_model_slug=remote_model_slug,
        question_profile_id=question_profile_id,
        state_format=state_format,
        exploit_threshold=float(exploit_threshold),
        misalignment_threshold=float(misalignment_threshold),
        threat_threshold=float(threat_threshold),
        input_price_per_1m_usd=input_price_per_1m_usd,
        max_context_tokens=max_context_tokens,
        enabled=bool(enabled),
    )


def save_cloud_provider(
    provider: CloudProviderSpec,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> None:
    """Insert or update a validated CloudProviderSpec in DuckDB."""
    init_cloud_registry(db_target)
    headers_json = json.dumps(provider.extra_headers, ensure_ascii=False, sort_keys=True)
    with get_connection(db_target) as con:
        exists = con.execute(
            "SELECT 1 FROM cloud_providers WHERE provider_id = ?",
            [provider.provider_id],
        ).fetchone()
        if exists:
            con.execute(
                """
                UPDATE cloud_providers
                SET display_name = ?, dialect = ?, base_url = ?, endpoint_path = ?,
                    api_key_env = ?, extra_headers_json = ?, timeout_seconds = ?,
                    max_concurrency = ?, rpm_limit = ?, max_body_bytes = ?,
                    max_questions = ?, updated_at = CURRENT_TIMESTAMP
                WHERE provider_id = ?
                """,
                [
                    provider.display_name,
                    provider.dialect.value,
                    provider.base_url,
                    provider.endpoint_path,
                    provider.api_key_env,
                    headers_json,
                    provider.timeout_seconds,
                    provider.max_concurrency,
                    provider.rpm_limit,
                    provider.max_body_bytes,
                    provider.max_questions,
                    provider.provider_id,
                ],
            )
        else:
            con.execute(
                """
                INSERT INTO cloud_providers (
                    provider_id, display_name, dialect, base_url, endpoint_path,
                    api_key_env, extra_headers_json, timeout_seconds, max_concurrency,
                    rpm_limit, max_body_bytes, max_questions, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                [
                    provider.provider_id,
                    provider.display_name,
                    provider.dialect.value,
                    provider.base_url,
                    provider.endpoint_path,
                    provider.api_key_env,
                    headers_json,
                    provider.timeout_seconds,
                    provider.max_concurrency,
                    provider.rpm_limit,
                    provider.max_body_bytes,
                    provider.max_questions,
                ],
            )


def get_cloud_provider(
    provider_id: str,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> CloudProviderSpec | None:
    """Fetch a CloudProviderSpec by provider_id (case-insensitive)."""
    with get_connection(db_target) as con:
        row = con.execute(
            """
            SELECT provider_id, display_name, dialect, base_url, endpoint_path,
                   api_key_env, extra_headers_json, timeout_seconds, max_concurrency,
                   rpm_limit, max_body_bytes, max_questions
            FROM cloud_providers
            WHERE LOWER(provider_id) = LOWER(?)
            """,
            [provider_id.strip()],
        ).fetchone()
        return _row_to_provider(row) if row else None


def delete_cloud_provider(
    provider_id: str,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> bool:
    """Delete a CloudProviderSpec by provider_id if no cloud_models reference it."""
    key = provider_id.strip().lower()
    with get_connection(db_target) as con:
        existing = con.execute(
            "SELECT provider_id FROM cloud_providers WHERE LOWER(provider_id) = ?",
            [key],
        ).fetchone()
        if not existing:
            return False
        ref_count = con.execute(
            "SELECT COUNT(*) FROM cloud_models WHERE LOWER(provider_id) = ?",
            [key],
        ).fetchone()[0]
        if ref_count > 0:
            raise ValueError(
                f"Cannot delete provider '{key}': {ref_count} cloud model(s) still reference it. "
                "Delete or reassign those models first."
            )
        con.execute("DELETE FROM cloud_providers WHERE LOWER(provider_id) = ?", [key])
        return True


def list_cloud_providers(
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> list[CloudProviderSpec]:
    """List all registered CloudProviderSpec records."""
    with get_connection(db_target) as con:
        rows = con.execute(
            """
            SELECT provider_id, display_name, dialect, base_url, endpoint_path,
                   api_key_env, extra_headers_json, timeout_seconds, max_concurrency,
                   rpm_limit, max_body_bytes, max_questions
            FROM cloud_providers
            ORDER BY provider_id ASC
            """
        ).fetchall()
        return [_row_to_provider(r) for r in rows]


def save_cloud_model(
    model: CloudModelSpec,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> None:
    """Insert or update a validated CloudModelSpec in DuckDB (requires existing provider_id)."""
    init_cloud_registry(db_target)
    with get_connection(db_target) as con:
        prov_exists = con.execute(
            "SELECT 1 FROM cloud_providers WHERE provider_id = ?",
            [model.provider_id],
        ).fetchone()
        if not prov_exists:
            raise ValueError(f"Unknown provider_id {model.provider_id!r}; register provider first.")

        exists = con.execute(
            "SELECT 1 FROM cloud_models WHERE model_id = ?",
            [model.model_id],
        ).fetchone()
        if exists:
            con.execute(
                """
                UPDATE cloud_models
                SET provider_id = ?, remote_model_slug = ?, question_profile_id = ?,
                    state_format = ?, exploit_threshold = ?, misalignment_threshold = ?,
                    threat_threshold = ?, input_price_per_1m_usd = ?,
                    max_context_tokens = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
                WHERE model_id = ?
                """,
                [
                    model.provider_id,
                    model.remote_model_slug,
                    model.question_profile_id,
                    model.state_format,
                    model.exploit_threshold,
                    model.misalignment_threshold,
                    model.threat_threshold,
                    model.input_price_per_1m_usd,
                    model.max_context_tokens,
                    model.enabled,
                    model.model_id,
                ],
            )
        else:
            con.execute(
                """
                INSERT INTO cloud_models (
                    model_id, provider_id, remote_model_slug, question_profile_id,
                    state_format, exploit_threshold, misalignment_threshold, threat_threshold,
                    input_price_per_1m_usd, max_context_tokens, enabled, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                [
                    model.model_id,
                    model.provider_id,
                    model.remote_model_slug,
                    model.question_profile_id,
                    model.state_format,
                    model.exploit_threshold,
                    model.misalignment_threshold,
                    model.threat_threshold,
                    model.input_price_per_1m_usd,
                    model.max_context_tokens,
                    model.enabled,
                ],
            )


def get_cloud_model(
    model_id: str,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> CloudModelSpec | None:
    """Fetch a CloudModelSpec by model_id (case-insensitive match on lowercased key)."""
    with get_connection(db_target) as con:
        row = con.execute(
            """
            SELECT model_id, provider_id, remote_model_slug, question_profile_id,
                   state_format, exploit_threshold, misalignment_threshold, threat_threshold,
                   input_price_per_1m_usd, max_context_tokens, enabled
            FROM cloud_models
            WHERE LOWER(model_id) = LOWER(?)
            """,
            [model_id],
        ).fetchone()
        return _row_to_model(row) if row else None


def list_cloud_models(
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> list[CloudModelSpec]:
    """List all registered CloudModelSpec records."""
    with get_connection(db_target) as con:
        rows = con.execute(
            """
            SELECT model_id, provider_id, remote_model_slug, question_profile_id,
                   state_format, exploit_threshold, misalignment_threshold, threat_threshold,
                   input_price_per_1m_usd, max_context_tokens, enabled
            FROM cloud_models
            ORDER BY model_id ASC
            """
        ).fetchall()
        return [_row_to_model(r) for r in rows]


def delete_cloud_model(
    model_id: str,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> bool:
    """Delete a CloudModelSpec by model_id (case-insensitive)."""
    key = model_id.strip().lower()
    with get_connection(db_target) as con:
        existing = con.execute(
            "SELECT model_id FROM cloud_models WHERE LOWER(model_id) = ?",
            [key],
        ).fetchone()
        if not existing:
            return False
        con.execute("DELETE FROM cloud_models WHERE LOWER(model_id) = ?", [key])
        return True


def export_cloud_config(
    out_path: Path | None = None,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> str:
    """Export cloud_providers and cloud_models from DuckDB to YAML."""
    providers = [p.model_dump(mode="json") for p in list_cloud_providers(db_target)]
    models = [m.model_dump(mode="json") for m in list_cloud_models(db_target)]
    payload = {"providers": providers, "models": models}
    yaml_str = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(yaml_str, encoding="utf-8")
    return yaml_str


def import_cloud_config(
    yaml_path: Path,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> dict[str, int]:
    """Validate and upsert cloud providers and models from YAML into DuckDB."""
    if not yaml_path.exists():
        raise FileNotFoundError(f"Cloud config YAML not found: {yaml_path}")
    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("Invalid cloud config YAML: root must be a mapping.")

    providers_raw = data.get("providers") or []
    models_raw = data.get("models") or []
    if not isinstance(providers_raw, list) or not isinstance(models_raw, list):
        raise TypeError("Invalid cloud config YAML: 'providers' and 'models' must be lists.")

    providers = [CloudProviderSpec(**item) for item in providers_raw]
    models = [CloudModelSpec(**item) for item in models_raw]

    init_cloud_registry(db_target)
    for p in providers:
        save_cloud_provider(p, db_target)
    for m in models:
        save_cloud_model(m, db_target)

    return {"providers": len(providers), "models": len(models)}


def is_cloud_model(
    model_id: str,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
) -> bool:
    """Return True if model_id corresponds to an enabled DuckDB cloud_models record."""
    if not isinstance(db_target, duckdb.DuckDBPyConnection) and not Path(db_target).exists():
        return False
    try:
        with get_connection(db_target) as con:
            tables = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
            if "cloud_models" not in tables:
                return False
            row = con.execute(
                "SELECT enabled FROM cloud_models WHERE LOWER(model_id) = LOWER(?)",
                [model_id],
            ).fetchone()
            return bool(row and row[0])
    except (duckdb.Error, OSError):
        return False


def _instantiate_static_adapter(adapter_cls: type, thresholds: dict[str, float]) -> BaseModelAdapter:
    """Instantiate static adapter passing only supported threshold kwargs."""
    if not thresholds:
        return adapter_cls()
    sig = inspect.signature(adapter_cls.__init__)
    params = sig.parameters
    accepts_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
    if accepts_var_kw:
        return adapter_cls(**thresholds)
    supported = {k: v for k, v in thresholds.items() if k in params}
    return adapter_cls(**supported) if supported else adapter_cls()


def resolve_adapter(
    model_id: str,
    db_target: Path | str | duckdb.DuckDBPyConnection = DEFAULT_DB_PATH,
    adapter_registry: dict[str, type] | None = None,
    thresholds: dict[str, float] | None = None,
) -> BaseModelAdapter:
    """Resolve a model_id across static ADAPTER_REGISTRY or DuckDB cloud_models without silent fallbacks."""
    key = model_id.strip().lower()
    if adapter_registry is None:
        from benchmark_runner import ADAPTER_REGISTRY
        adapter_registry = ADAPTER_REGISTRY

    if key in adapter_registry:
        return _instantiate_static_adapter(adapter_registry[key], thresholds or {})

    db_available = isinstance(db_target, duckdb.DuckDBPyConnection) or Path(db_target).exists()
    if db_available:
        with get_connection(db_target) as con:
            tables = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
            if "cloud_models" in tables and "cloud_providers" in tables:
                model_spec = get_cloud_model(model_id, con)
                if model_spec is not None:
                    if not model_spec.enabled:
                        raise ValueError(f"Cloud model '{model_id}' is disabled in cloud_models.")
                    provider_spec = get_cloud_provider(model_spec.provider_id, con)
                    if provider_spec is None:
                        raise ValueError(
                            f"Cloud model '{model_id}' references missing provider '{model_spec.provider_id}'."
                        )
                    from adapters.systemone_cloud_adapter import SystemOneCloudAdapter

                    th = thresholds or {}
                    return SystemOneCloudAdapter(
                        provider=provider_spec,
                        model_spec=model_spec,
                        exploit_threshold=th.get("exploit_threshold", model_spec.exploit_threshold),
                        misalignment_threshold=th.get(
                            "misalignment_threshold", model_spec.misalignment_threshold
                        ),
                        threat_threshold=th.get("threat_threshold", model_spec.threat_threshold),
                    )

    raise KeyError(
        f"Unknown model adapter '{model_id}'. Register it in ADAPTER_REGISTRY or cloud_models."
    )


def ensure_run_history_schema(
    con: duckdb.DuckDBPyConnection,
    *,
    default_status: str = "completed",
    index_name: str = "idx_case_eval_lookup",
) -> None:
    """Create and migrate run_history and run_case_evaluations tables idempotently."""
    con.execute(
        f"""
        CREATE TABLE IF NOT EXISTS run_history (
            run_id          VARCHAR PRIMARY KEY,
            dataset_name    VARCHAR NOT NULL,
            dataset_path    VARCHAR NOT NULL,
            model_name      VARCHAR NOT NULL,
            status          VARCHAR NOT NULL DEFAULT '{default_status}',
            total_cases     INTEGER DEFAULT 0,
            evaluated       INTEGER DEFAULT 0,
            tp              INTEGER DEFAULT 0,
            tn              INTEGER DEFAULT 0,
            fp              INTEGER DEFAULT 0,
            fn              INTEGER DEFAULT 0,
            accuracy        DOUBLE DEFAULT 0,
            precision_val   DOUBLE DEFAULT 0,
            recall_val      DOUBLE DEFAULT 0,
            f1_score        DOUBLE DEFAULT 0,
            fpr             DOUBLE DEFAULT 0,
            avg_latency_ms  DOUBLE DEFAULT 0,
            p95_latency_ms  DOUBLE DEFAULT 0,
            category_stats  VARCHAR DEFAULT '{{}}',
            case_results    VARCHAR DEFAULT '[]',
            started_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at    TIMESTAMP,
            duration_secs   DOUBLE DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS run_case_evaluations (
            run_id              VARCHAR NOT NULL,
            case_id             VARCHAR NOT NULL,
            source              VARCHAR DEFAULT '',
            domain              VARCHAR NOT NULL,
            analysis_tier       VARCHAR NOT NULL,
            cwe                 VARCHAR DEFAULT '',
            tool_name           VARCHAR DEFAULT '',
            is_malicious        BOOLEAN NOT NULL,
            predicted_blocked   BOOLEAN,
            correct             BOOLEAN,
            decided_by          VARCHAR NOT NULL,
            confidence          DOUBLE DEFAULT 0,
            latency_ms          DOUBLE DEFAULT 0,
            offload_saved_ms    DOUBLE DEFAULT 0,
            verdict_detail      VARCHAR DEFAULT '',
            tool_arguments      VARCHAR DEFAULT '',
            context             VARCHAR DEFAULT '',
            eval_status         VARCHAR NOT NULL DEFAULT 'OK',
            inference_rtt_ms    DOUBLE DEFAULT 0,
            retry_wait_ms       DOUBLE DEFAULT 0,
            input_tokens        INTEGER DEFAULT 0,
            output_tokens       INTEGER DEFAULT 0,
            cached_tokens       INTEGER DEFAULT 0,
            cost_usd            DOUBLE DEFAULT 0.0,
            cost_source         VARCHAR DEFAULT 'none',
            PRIMARY KEY (run_id, case_id)
        );
        CREATE INDEX IF NOT EXISTS {index_name} ON run_case_evaluations (run_id, correct);
        """
    )
    for stmt in [
        "ALTER TABLE run_history ADD COLUMN IF NOT EXISTS config_hash VARCHAR;",
        "ALTER TABLE run_history ADD COLUMN IF NOT EXISTS question_profile_id VARCHAR;",
        "ALTER TABLE run_history ADD COLUMN IF NOT EXISTS refusal_count INTEGER DEFAULT 0;",
        "ALTER TABLE run_history ADD COLUMN IF NOT EXISTS error_count INTEGER DEFAULT 0;",
        "ALTER TABLE run_history ADD COLUMN IF NOT EXISTS skipped_count INTEGER DEFAULT 0;",
        "ALTER TABLE run_history ADD COLUMN IF NOT EXISTS input_tokens BIGINT DEFAULT 0;",
        "ALTER TABLE run_history ADD COLUMN IF NOT EXISTS output_tokens BIGINT DEFAULT 0;",
        "ALTER TABLE run_history ADD COLUMN IF NOT EXISTS cached_tokens BIGINT DEFAULT 0;",
        "ALTER TABLE run_history ADD COLUMN IF NOT EXISTS total_cost_usd DOUBLE DEFAULT 0.0;",
        "ALTER TABLE run_history ADD COLUMN IF NOT EXISTS cost_source VARCHAR DEFAULT 'none';",
        "ALTER TABLE run_history ADD COLUMN IF NOT EXISTS max_cost_usd DOUBLE DEFAULT NULL;",
        "ALTER TABLE run_history ADD COLUMN IF NOT EXISTS tier_scope VARCHAR DEFAULT 'all';",
        "ALTER TABLE run_history ADD COLUMN IF NOT EXISTS enable_l1 BOOLEAN DEFAULT NULL;",
        "ALTER TABLE run_history ADD COLUMN IF NOT EXISTS limit_cases INTEGER DEFAULT NULL;",
        "ALTER TABLE run_case_evaluations ADD COLUMN IF NOT EXISTS eval_status VARCHAR DEFAULT 'OK';",
        "ALTER TABLE run_case_evaluations ADD COLUMN IF NOT EXISTS inference_rtt_ms DOUBLE DEFAULT 0;",
        "ALTER TABLE run_case_evaluations ADD COLUMN IF NOT EXISTS retry_wait_ms DOUBLE DEFAULT 0;",
        "ALTER TABLE run_case_evaluations ADD COLUMN IF NOT EXISTS input_tokens INTEGER DEFAULT 0;",
        "ALTER TABLE run_case_evaluations ADD COLUMN IF NOT EXISTS output_tokens INTEGER DEFAULT 0;",
        "ALTER TABLE run_case_evaluations ADD COLUMN IF NOT EXISTS cached_tokens INTEGER DEFAULT 0;",
        "ALTER TABLE run_case_evaluations ADD COLUMN IF NOT EXISTS cost_usd DOUBLE DEFAULT 0.0;",
        "ALTER TABLE run_case_evaluations ADD COLUMN IF NOT EXISTS cost_source VARCHAR DEFAULT 'none';",
    ]:
        con.execute(stmt)

    for nullable_stmt in [
        "ALTER TABLE run_case_evaluations ALTER COLUMN predicted_blocked DROP NOT NULL;",
        "ALTER TABLE run_case_evaluations ALTER COLUMN correct DROP NOT NULL;",
    ]:
        with suppress(duckdb.Error):
            con.execute(nullable_stmt)
