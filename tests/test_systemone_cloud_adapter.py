"""
tests/test_systemone_cloud_adapter.py

Unit tests for SystemOneCloudAdapter, ProviderDialect dialects, QuestionProfile,
Retry-After / jittered backoff, latency separation, overflow SKIPPED,
cost_source provenance, and secret scrubbing (Tasks 6 & 7).
"""

import json
from pathlib import Path

import httpx
import pytest

from adapters.base import EvalStatus
from adapters.cloud_registry import (
    CloudModelSpec,
    CloudProviderSpec,
    ProviderDialect,
    import_cloud_config,
    init_cloud_registry,
    resolve_adapter,
)
from adapters.systemone_cloud_adapter import SystemOneCloudAdapter


def _make_provider(
    dialect: ProviderDialect,
    *,
    base_url: str = "https://openrouter.ai",
    endpoint_path: str = "/api/alpha/decisions",
    api_key_env: str = "TEST_CLOUD_API_KEY",
    max_body_bytes: int | None = None,
) -> CloudProviderSpec:
    return CloudProviderSpec(
        provider_id=f"prov-{dialect.value.lower()}",
        display_name=dialect.value,
        dialect=dialect,
        base_url=base_url,
        endpoint_path=endpoint_path,
        api_key_env=api_key_env,
        extra_headers={"X-OpenRouter-Title": "FaradAiBenchmark"} if dialect == ProviderDialect.OPENROUTER_DECISIONS else {},
        timeout_seconds=5.0,
        max_concurrency=4,
        max_body_bytes=max_body_bytes,
    )


def _make_model(
    provider_id: str,
    *,
    slug: str = "typesafe/jev-1.14",
    price: float | None = 0.042,
    state_format: str = "canonical_text",
) -> CloudModelSpec:
    return CloudModelSpec(
        model_id="test-cloud-model",
        provider_id=provider_id,
        remote_model_slug=slug,
        question_profile_id="dual_check_v1",
        state_format=state_format,
        input_price_per_1m_usd=price,
    )


def test_openrouter_dialect_stateless_and_api_reported_cost(monkeypatch):
    monkeypatch.setenv("TEST_CLOUD_API_KEY", "sk-test-secret-999")
    seen_requests: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_requests.append({
            "url": str(request.url),
            "auth": request.headers.get("authorization"),
            "title": request.headers.get("x-openrouter-title"),
            "body": json.loads(request.content.decode("utf-8")),
        })
        return httpx.Response(
            200,
            json={
                "model": "typesafe/jev-1.14",
                "answers": {
                    "misalignment": {"type": "noul", "noul": 0.12},
                    "exploit": {"type": "noul", "noul": 0.91},
                },
                "usage": {
                    "input_tokens": 350,
                    "output_tokens": 0,
                    "input_tokens_details": {"cached_tokens": 50},
                    "cost": 0.0000147,
                },
            },
        )

    prov = _make_provider(ProviderDialect.OPENROUTER_DECISIONS)
    model = _make_model(prov.provider_id)
    adapter = SystemOneCloudAdapter(
        provider=prov,
        model_spec=model,
        transport=httpx.MockTransport(handler),
    )

    res1 = adapter.evaluate("bash", {"cmd": "cat /etc/passwd"}, "Check logs")
    res2 = adapter.evaluate("read_file", {"path": "README.md"}, "Read docs")

    assert len(seen_requests) == 2
    assert seen_requests[0]["url"] == "https://openrouter.ai/api/alpha/decisions"
    assert seen_requests[0]["auth"] == "Bearer sk-test-secret-999"
    assert seen_requests[0]["title"] == "FaradAiBenchmark"
    # Stateless per-case AI payload: case 1 arguments never leak into case 2 state
    assert "/etc/passwd" not in str(seen_requests[1]["body"]["state"])
    assert "messages" not in seen_requests[0]["body"]

    assert res1["eval_status"] == EvalStatus.OK.value
    assert res1["verdict"] == "BLOCKED"
    assert res1["is_blocked"] is True
    assert res1["input_tokens"] == 350
    assert res1["cached_tokens"] == 50
    assert res1["cost_usd"] == pytest.approx(0.0000147)
    assert res1["cost_source"] == "api_reported"
    # Secret must never be retained in raw_output
    assert "sk-test-secret-999" not in json.dumps(res1)
    assert res2["eval_status"] == EvalStatus.OK.value


def test_typesafe_and_liquid_dialects_fallback_pricing_and_probability_alias(monkeypatch):
    monkeypatch.setenv("TEST_CLOUD_API_KEY", "sk-ts-liq")

    # TypeSafe Direct: returns input_tokens without inline cost
    ts_prov = _make_provider(
        ProviderDialect.TYPESAFE_SYSTEMONE,
        base_url="https://api.typesafe.ai",
        endpoint_path="/v1/systemone",
    )
    ts_adapter = SystemOneCloudAdapter(
        provider=ts_prov,
        model_spec=_make_model(ts_prov.provider_id, slug="jev-1.14.0", price=0.042),
        transport=httpx.MockTransport(
            lambda req: httpx.Response(
                200,
                json={
                    "model": "jev-1.14.0",
                    "answers": {
                        "misalignment": {"type": "noul", "noul": 0.10},
                        "exploit": {"type": "noul", "noul": 0.05},
                    },
                    "usage": {"input_tokens": 1000, "output_tokens": 0},
                },
            )
        ),
    )
    ts_res = ts_adapter.evaluate("read_file", {"path": "a.txt"}, "Read file")
    assert ts_res["verdict"] == "ALLOWED"
    assert ts_res["cost_source"] == "estimated_fallback"
    assert ts_res["cost_usd"] == pytest.approx(0.000042)

    # Liquid Direct: accepts "probability" alias for noul if present
    liq_prov = _make_provider(
        ProviderDialect.LIQUID_SYSTEMONE,
        base_url="https://api.liquid.ai",
        endpoint_path="/decisions/v1/systemone",
    )
    liq_adapter = SystemOneCloudAdapter(
        provider=liq_prov,
        model_spec=_make_model(liq_prov.provider_id, slug="d1.2", price=0.02),
        transport=httpx.MockTransport(
            lambda req: httpx.Response(
                200,
                json={
                    "model": "d1.2",
                    "answers": {
                        "misalignment": {"type": "noul", "probability": 0.85},
                        "exploit": {"type": "noul", "probability": 0.12},
                    },
                    "usage": {"input_tokens": 500, "output_tokens": 0},
                },
            )
        ),
    )
    liq_res = liq_adapter.evaluate("send_email", {"to": "evil@x.com"}, "Summarize")
    assert liq_res["verdict"] == "BLOCKED"
    assert liq_res["alignment_risk"] == 0.85
    assert liq_res["cost_source"] == "estimated_fallback"
    assert liq_res["cost_usd"] == pytest.approx(0.00001)


@pytest.mark.parametrize(
    "payload",
    [
        {
            "answers": {
                "misalignment": {"type": "refusal", "message": "safety block"},
                "exploit": {"type": "noul", "noul": 0.01},
            }
        },
        {
            "refusal": "policy_refusal",
            "answers": {
                "misalignment": {"type": "noul", "noul": 0.01},
                "exploit": {"type": "noul", "noul": 0.01},
            },
        },
    ],
)
def test_refusals_never_coerce_to_allowed(monkeypatch, payload):
    monkeypatch.setenv("TEST_CLOUD_API_KEY", "sk-refusal")
    prov = _make_provider(
        ProviderDialect.PERPLEXITY_DECISIONS,
        base_url="https://api.perplexity.ai",
        endpoint_path="/v1/decisions",
    )
    adapter = SystemOneCloudAdapter(
        provider=prov,
        model_spec=_make_model(prov.provider_id, slug="pplx-decider-latest", price=0.02),
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=payload)),
    )
    res = adapter.evaluate("bash", {"cmd": "ls"}, "List directory")
    assert res["eval_status"] == EvalStatus.REFUSAL.value
    assert res["verdict"] == "REFUSAL"
    assert res["is_blocked"] is False


def test_429_retry_separates_retry_wait_from_inference_rtt(monkeypatch):
    monkeypatch.setenv("TEST_CLOUD_API_KEY", "sk-retry")
    attempts = 0
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, headers={"Retry-After": "1.5"}, json={"error": {"message": "rate limit"}})
        if attempts == 2:
            # 429 without Retry-After header -> jittered backoff
            return httpx.Response(429, json={"error": {"message": "upstream limit"}})
        return httpx.Response(
            200,
            json={
                "answers": {
                    "misalignment": {"type": "noul", "noul": 0.1},
                    "exploit": {"type": "noul", "noul": 0.1},
                },
                "usage": {"input_tokens": 100, "output_tokens": 0, "cost": 0.0000042},
            },
        )

    prov = _make_provider(ProviderDialect.OPENROUTER_DECISIONS)
    adapter = SystemOneCloudAdapter(
        provider=prov,
        model_spec=_make_model(prov.provider_id),
        transport=httpx.MockTransport(handler),
        sleep_fn=sleeps.append,
        max_retries=3,
    )
    res = adapter.evaluate("read_file", {"path": "x.txt"}, "Check")
    assert attempts == 3
    assert len(sleeps) == 2
    assert sleeps[0] == pytest.approx(1.5)
    assert sleeps[1] > 0.0
    assert res["eval_status"] == EvalStatus.OK.value
    assert res["retry_wait_ms"] >= 1500.0
    # Pure inference RTT excludes sleep_fn waits!
    assert res["inference_rtt_ms"] < 500.0


def test_max_body_bytes_overflow_skips_without_truncation(monkeypatch):
    monkeypatch.setenv("TEST_CLOUD_API_KEY", "sk-skip")
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={})

    prov = _make_provider(ProviderDialect.TYPESAFE_SYSTEMONE, max_body_bytes=1024)
    adapter = SystemOneCloudAdapter(
        provider=prov,
        model_spec=_make_model(prov.provider_id),
        transport=httpx.MockTransport(handler),
    )
    res = adapter.evaluate("bash", {"cmd": "A" * 5000}, "Long payload")
    assert called is False
    assert res["eval_status"] == EvalStatus.SKIPPED.value
    assert res["verdict"] == "SKIPPED"
    assert res["is_blocked"] is False


def test_secret_scrubbed_from_error_output(monkeypatch):
    secret = "sk-super-secret-value-xyz"
    monkeypatch.setenv("TEST_CLOUD_API_KEY", secret)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"Failed with Bearer {secret}")

    prov = _make_provider(ProviderDialect.OPENROUTER_DECISIONS)
    adapter = SystemOneCloudAdapter(
        provider=prov,
        model_spec=_make_model(prov.provider_id),
        transport=httpx.MockTransport(handler),
        max_retries=0,
    )
    res = adapter.evaluate("bash", {"cmd": "ls"}, "Test")
    assert res["eval_status"] == EvalStatus.ERROR.value
    assert res["verdict"] == "ERROR"
    assert secret not in json.dumps(res)
    assert "[REDACTED]" in json.dumps(res)


def test_resolve_adapter_returns_systemone_cloud_adapter(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-live-placeholder")
    db_path = tmp_path / "resolve_cloud.duckdb"
    init_cloud_registry(db_path)
    import_cloud_config(Path("config/cloud_models/default_systemone.yaml"), db_path)

    adapter = resolve_adapter("or-jev-1.14", db_target=db_path)
    assert isinstance(adapter, SystemOneCloudAdapter)
    assert adapter.model_spec.remote_model_slug == "typesafe/jev-1.14"


def test_max_questions_and_max_context_tokens_skip_without_http(monkeypatch):
    monkeypatch.setenv("TEST_CLOUD_API_KEY", "sk-guard")
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={})

    # 1. max_questions = 1 < 2 dual-check questions -> SKIPPED
    prov_q = _make_provider(ProviderDialect.OPENROUTER_DECISIONS, max_questions=1)
    adapter_q = SystemOneCloudAdapter(
        provider=prov_q,
        model_spec=_make_model(prov_q.provider_id),
        transport=httpx.MockTransport(handler),
    )
    res_q = adapter_q.evaluate("bash", {"cmd": "ls"}, "Test")
    assert called is False
    assert res_q["eval_status"] == EvalStatus.SKIPPED.value
    assert "max_questions=1" in json.dumps(res_q["raw_output"])

    # 2. max_context_tokens = 10 < ~100 tokens -> SKIPPED
    prov_ctx = _make_provider(ProviderDialect.OPENROUTER_DECISIONS)
    model_ctx = _make_model(prov_ctx.provider_id, max_context_tokens=10)
    adapter_ctx = SystemOneCloudAdapter(
        provider=prov_ctx,
        model_spec=model_ctx,
        transport=httpx.MockTransport(handler),
    )
    res_ctx = adapter_ctx.evaluate("bash", {"cmd": "X" * 500}, "Long context")
    assert called is False
    assert res_ctx["eval_status"] == EvalStatus.SKIPPED.value
    assert "max_context_tokens=10" in json.dumps(res_ctx["raw_output"])
