"""
tests/test_cloud_models_api.py

FastAPI integration tests for Cloud Providers & Cloud Models CRUD endpoints
and secret hygiene (ADR 0012 / Task 3).
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import web.app as web_app


@pytest.fixture
def api_client(tmp_path: Path, monkeypatch):
    test_db = tmp_path / "cloud_api_test.duckdb"
    monkeypatch.setattr(web_app, "DB_PATH", test_db)
    monkeypatch.setattr(web_app, "PROJECT_ROOT", tmp_path)
    (tmp_path / ".env").write_text("OPENROUTER_API_KEY=sk-secret-do-not-leak\n", encoding="utf-8")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("UNCONFIGURED_API_KEY", raising=False)
    web_app.init_db()
    return TestClient(web_app.app)


def test_cloud_provider_and_model_crud_lifecycle(api_client: TestClient):
    # 1. Create provider (mixed case normalizes to lowercase)
    create_prov = api_client.post(
        "/api/cloud-providers",
        json={
            "provider_id": "OpenRouter",
            "display_name": "OpenRouter Decisions",
            "dialect": "OPENROUTER_DECISIONS",
            "base_url": "https://openrouter.ai",
            "endpoint_path": "/api/alpha/decisions",
            "api_key_env": "OPENROUTER_API_KEY",
            "extra_headers": {"X-OpenRouter-Title": "FaradAiBenchmark"},
            "timeout_seconds": 20.0,
            "max_concurrency": 4,
        },
    )
    assert create_prov.status_code == 200
    prov_data = create_prov.json()
    assert prov_data["provider_id"] == "openrouter"
    assert prov_data["api_key_configured"] is True
    assert "sk-secret-do-not-leak" not in create_prov.text

    # 2. Update provider with missing env key
    upd_prov = api_client.put(
        "/api/cloud-providers/openrouter",
        json={
            "provider_id": "openrouter",
            "display_name": "OpenRouter Updated",
            "dialect": "OPENROUTER_DECISIONS",
            "base_url": "https://openrouter.ai",
            "endpoint_path": "/api/alpha/decisions",
            "api_key_env": "UNCONFIGURED_API_KEY",
            "timeout_seconds": 25.0,
            "max_concurrency": 6,
        },
    )
    assert upd_prov.status_code == 200
    assert upd_prov.json()["display_name"] == "OpenRouter Updated"
    assert upd_prov.json()["api_key_configured"] is False

    # 3. Create cloud model
    create_model = api_client.post(
        "/api/cloud-models",
        json={
            "model_id": "OR-Jev-1.14",
            "provider_id": "openrouter",
            "remote_model_slug": "typesafe/jev-1.14",
            "exploit_threshold": 0.50,
            "misalignment_threshold": 0.65,
            "threat_threshold": 0.50,
            "input_price_per_1m_usd": 0.042,
            "max_context_tokens": 64000,
            "enabled": True,
        },
    )
    assert create_model.status_code == 200
    model_data = create_model.json()
    assert model_data["model_id"] == "or-jev-1.14"
    assert model_data["enabled"] is True

    # 4. Appears in /api/models when enabled
    models_resp = api_client.get("/api/models")
    assert any(m["id"] == "or-jev-1.14" for m in models_resp.json())

    # 5. Provider delete blocked (409) while model references it
    del_prov_blocked = api_client.delete("/api/cloud-providers/openrouter")
    assert del_prov_blocked.status_code == 409

    # 6. Disable model via PUT -> disappears from /api/models but stays in /api/cloud-models
    upd_model = api_client.put(
        "/api/cloud-models/or-jev-1.14",
        json={
            "model_id": "or-jev-1.14",
            "provider_id": "openrouter",
            "remote_model_slug": "typesafe/jev-1.14",
            "exploit_threshold": 0.45,
            "misalignment_threshold": 0.60,
            "threat_threshold": 0.50,
            "input_price_per_1m_usd": 0.042,
            "max_context_tokens": 64000,
            "enabled": False,
        },
    )
    assert upd_model.status_code == 200
    assert upd_model.json()["enabled"] is False
    assert not any(m["id"] == "or-jev-1.14" for m in api_client.get("/api/models").json())
    assert len(api_client.get("/api/cloud-models").json()) == 1

    # 7. Export YAML read-only download works and contains zero raw secrets
    yaml_resp = api_client.get("/api/cloud-config/export-yaml")
    assert yaml_resp.status_code == 200
    assert "or-jev-1.14" in yaml_resp.text
    assert "sk-secret-do-not-leak" not in yaml_resp.text

    # 8. Delete model, then delete provider succeeds
    assert api_client.delete("/api/cloud-models/or-jev-1.14").status_code == 200
    assert api_client.delete("/api/cloud-providers/openrouter").status_code == 200
    assert api_client.get("/api/cloud-providers").json() == []
    assert api_client.get("/api/cloud-models").json() == []


def test_cloud_model_rejects_local_adapter_collision_and_bad_headers(api_client: TestClient):
    api_client.post(
        "/api/cloud-providers",
        json={
            "provider_id": "openrouter",
            "display_name": "OpenRouter",
            "dialect": "OPENROUTER_DECISIONS",
            "base_url": "https://openrouter.ai",
            "endpoint_path": "/api/alpha/decisions",
            "api_key_env": "OPENROUTER_API_KEY",
        },
    )
    bad_model = api_client.post(
        "/api/cloud-models",
        json={
            "model_id": "laya-mlx",
            "provider_id": "openrouter",
            "remote_model_slug": "typesafe/jev-1.14",
        },
    )
    assert bad_model.status_code == 422

    bad_prov = api_client.post(
        "/api/cloud-providers",
        json={
            "provider_id": "bad-prov",
            "display_name": "Bad",
            "dialect": "OPENROUTER_DECISIONS",
            "base_url": "https://openrouter.ai?token=secret",
            "endpoint_path": "/api/alpha/decisions",
            "api_key_env": "OPENROUTER_API_KEY",
        },
    )
    assert bad_prov.status_code == 422
