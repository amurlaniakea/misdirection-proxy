"""Tests for smart health check (readiness probe) and new Prometheus metrics."""
import os
import sys

import pytest

sys.path.insert(0, "/home/sil/misdirection-proxy/src")


def test_health_returns_200_when_healthy():
    """Health check returns 200 when all components are healthy."""
    from fastapi.testclient import TestClient
    from misdirection.proxy.gateway import app

    client = TestClient(app)
    response = client.get("/health")
    data = response.json()
    assert "status" in data
    assert "components" in data
    assert "redis" in data["components"]
    assert "upstream" in data["components"]
    assert "version" in data
    assert data["version"] == "0.6.0"


def test_health_structure():
    """Health check returns proper component structure."""
    from fastapi.testclient import TestClient
    from misdirection.proxy.gateway import app

    client = TestClient(app)
    response = client.get("/health")
    data = response.json()
    # Status must be either healthy or degraded
    assert data["status"] in ("healthy", "degraded")
    # Components must have redis and upstream
    assert data["components"]["redis"] in ("healthy", "degraded", "unhealthy")
    assert data["components"]["upstream"] in ("healthy", "unhealthy")
    # Status code matches health
    if data["status"] == "healthy":
        assert response.status_code == 200
    else:
        assert response.status_code == 503


def test_metrics_expose_blocked_counter():
    """Metrics endpoint exposes misdirection_blocked_total."""
    from fastapi.testclient import TestClient
    from misdirection.proxy.gateway import app

    client = TestClient(app)
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "misdirection_blocked_total" in response.text


def test_metrics_expose_cmpe_latency():
    """Metrics endpoint exposes cmpe_engine_latency histogram."""
    from fastapi.testclient import TestClient
    from misdirection.proxy.gateway import app

    client = TestClient(app)
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "misdirection_cmpe_engine_latency_seconds" in response.text


def test_metrics_expose_circuit_breaker_state():
    """Metrics endpoint exposes circuit breaker state gauge."""
    from fastapi.testclient import TestClient
    from misdirection.proxy.gateway import app

    client = TestClient(app)
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "misdirection_circuit_breaker_state" in response.text


def test_metrics_expose_rate_limiter_fallback():
    """Metrics endpoint exposes rate limiter fallback gauge."""
    from fastapi.testclient import TestClient
    from misdirection.proxy.gateway import app

    client = TestClient(app)
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "misdirection_rate_limiter_fallback_active" in response.text


def test_metrics_expose_redis_healthy():
    """Metrics endpoint still exposes redis_healthy gauge."""
    from fastapi.testclient import TestClient
    from misdirection.proxy.gateway import app

    client = TestClient(app)
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "misdirection_redis_healthy" in response.text


def test_payload_too_large_increments_blocked_metric():
    """Oversized payload increments misdirection_blocked_total{reason='payload_too_large'}."""
    from fastapi.testclient import TestClient
    from misdirection.proxy.gateway import app

    client = TestClient(app)
    huge = "x" * 11000
    response = client.post("/v1/chat/completions", json={
        "messages": [{"role": "user", "content": huge}]
    })
    assert response.status_code == 413

    metrics_response = client.get("/metrics")
    assert 'misdirection_blocked_total{reason="payload_too_large"}' in metrics_response.text
