"""
tests/test_cloud_registry.py

Unit tests for DuckDB Cloud Provider & Model Registry, Secret Hygiene,
YAML Export/Import round-trip, and unified resolve_adapter() (Tasks 4 & 5).
"""

from pathlib import Path

import duckdb
import pytest

from adapters.cloud_registry import (
    CloudModelSpec,
    CloudProviderSpec,
    ProviderDialect,
    export_cloud_config,
    get_cloud_model,
    import_cloud_config,
    init_cloud_registry,
    list_cloud_models,
    list_cloud_providers,
    resolve_adapter,
    save_cloud_model,
    save_cloud_provider,
)


@pytest.fixture
def temp_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "cloud_test.duckdb"
    init_cloud_registry(db_path)
    return db_path


def test_init_cloud_registry_creates_tables(temp_db: Path):
    con = duckdb.connect(str(temp_db))
    try:
        tables = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
        assert "cloud_providers" in tables
        assert "cloud_models" in tables
    finally:
        con.close()


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://openrouter.ai",
        "http://api.typesafe.ai",
        "ftp://openrouter.ai",
    ],
)
def test_provider_rejects_non_https_remote_urls(bad_url: str):
    with pytest.raises(ValueError, match="https://"):
        CloudProviderSpec(
            provider_id="bad-prov",
            display_name="Bad",
            dialect=ProviderDialect.OPENROUTER_DECISIONS,
            base_url=bad_url,
            endpoint_path="/api/alpha/decisions",
            api_key_env="OPENROUTER_API_KEY",
        )


def test_provider_allows_localhost_http():
    p = CloudProviderSpec(
        provider_id="local-sys1",
        display_name="Local SystemOne",
        dialect=ProviderDialect.TYPESAFE_SYSTEMONE,
        base_url="http://127.0.0.1:11434",
        endpoint_path="/v1/systemone",
        api_key_env="LOCAL_DUMMY_KEY",
    )
    assert p.base_url == "http://127.0.0.1:11434"


@pytest.mark.parametrize("bad_header", ["Authorization", "authorization", "Cookie", "x-api-key", "Proxy-Authorization"])
def test_provider_rejects_sensitive_extra_headers(bad_header: str):
    with pytest.raises(ValueError, match="Sensitive header"):
        CloudProviderSpec(
            provider_id="bad-hdr",
            display_name="Bad Header",
            dialect=ProviderDialect.OPENROUTER_DECISIONS,
            base_url="https://openrouter.ai",
            endpoint_path="/api/alpha/decisions",
            api_key_env="OPENROUTER_API_KEY",
            extra_headers={bad_header: "sk-secret"},
        )


def test_provider_rejects_raw_secret_in_api_key_env():
    with pytest.raises(ValueError, match="api_key_env"):
        CloudProviderSpec(
            provider_id="bad-env",
            display_name="Bad Env",
            dialect=ProviderDialect.OPENROUTER_DECISIONS,
            base_url="https://openrouter.ai",
            endpoint_path="/api/alpha/decisions",
            api_key_env="sk-or-v1-1234567890",
        )


def test_yaml_round_trip_preserves_providers_and_models(temp_db: Path, tmp_path: Path):
    prov = CloudProviderSpec(
        provider_id="openrouter",
        display_name="OpenRouter Decisions",
        dialect=ProviderDialect.OPENROUTER_DECISIONS,
        base_url="https://openrouter.ai",
        endpoint_path="/api/alpha/decisions",
        api_key_env="OPENROUTER_API_KEY",
        extra_headers={"X-OpenRouter-Title": "FaradAiBenchmark"},
        timeout_seconds=20.0,
        max_concurrency=4,
        rpm_limit=60,
        max_body_bytes=4_500_000,
        max_questions=64,
    )
    model = CloudModelSpec(
        model_id="or-jev-1.14",
        provider_id="openrouter",
        remote_model_slug="typesafe/jev-1.14",
        question_profile_id="dual_check_v1",
        state_format="canonical_text",
        exploit_threshold=0.50,
        misalignment_threshold=0.65,
        threat_threshold=0.50,
        input_price_per_1m_usd=0.042,
        max_context_tokens=64000,
        enabled=True,
    )
    save_cloud_provider(prov, temp_db)
    save_cloud_model(model, temp_db)

    yaml_out = tmp_path / "exported.yaml"
    export_cloud_config(yaml_out, temp_db)

    fresh_db = tmp_path / "fresh.duckdb"
    init_cloud_registry(fresh_db)
    counts = import_cloud_config(yaml_out, fresh_db)
    assert counts["providers"] == 1
    assert counts["models"] == 1

    loaded_provs = list_cloud_providers(fresh_db)
    loaded_models = list_cloud_models(fresh_db)
    assert len(loaded_provs) == 1
    assert loaded_provs[0].dialect == ProviderDialect.OPENROUTER_DECISIONS
    assert loaded_provs[0].extra_headers == {"X-OpenRouter-Title": "FaradAiBenchmark"}
    assert loaded_models[0].model_id == "or-jev-1.14"
    assert loaded_models[0].input_price_per_1m_usd == 0.042


def test_resolve_adapter_handles_static_and_unknown_explicitly(temp_db: Path):
    static_adapter = resolve_adapter("mock", db_target=temp_db)
    assert static_adapter.__class__.__name__ == "MockSecurityAdapter"

    with pytest.raises(KeyError, match="Unknown model adapter"):
        resolve_adapter("nonexistent-model-xyz", db_target=temp_db)


def test_default_seed_yaml_imports_cleanly(temp_db: Path):
    seed_path = Path("config/cloud_models/default_systemone.yaml")
    assert seed_path.exists()
    counts = import_cloud_config(seed_path, temp_db)
    assert counts["providers"] >= 3
    assert counts["models"] >= 3
    jev = get_cloud_model("or-jev-1.14", temp_db)
    assert jev is not None
    assert jev.remote_model_slug == "typesafe/jev-1.14"
