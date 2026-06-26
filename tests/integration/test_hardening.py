"""Tests for auth on /v1/chat/completions and payload size limit (413)."""
import os
import sys

import pytest

sys.path.insert(0, "/home/sil/misdirection-proxy/src")


@pytest.fixture(autouse=True)
def auth_env():
    """Set GATEWAY_API_KEY for all tests in this module."""
    os.environ["GATEWAY_API_KEY"] = "test-secret-xyz"
    yield
    os.environ.pop("GATEWAY_API_KEY", None)


def test_chat_completions_requires_auth():
    """POST /v1/chat/completions without Bearer token → 401."""
    from fastapi.testclient import TestClient
    from misdirection.proxy.gateway import app

    client = TestClient(app)
    response = client.post("/v1/chat/completions", json={
        "messages": [{"role": "user", "content": "hello"}]
    })
    assert response.status_code == 401


def test_chat_completions_with_valid_auth():
    """POST /v1/chat/completions with valid Bearer token → passes auth (may fail upstream)."""
    from fastapi.testclient import TestClient
    from misdirection.proxy.gateway import app

    client = TestClient(app)
    response = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "hello"}]},
        headers={"Authorization": "Bearer test-secret-xyz"},
    )
    # Should pass auth — may get 502 (no upstream) but NOT 401
    assert response.status_code != 401


def test_chat_completions_wrong_token():
    """POST /v1/chat/completions with wrong token → 401."""
    from fastapi.testclient import TestClient
    from misdirection.proxy.gateway import app

    client = TestClient(app)
    response = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "hello"}]},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert response.status_code == 401


def test_payload_too_large():
    """POST with body exceeding MAX_INPUT_LENGTH → 413."""
    from fastapi.testclient import TestClient
    from misdirection.proxy.gateway import app

    client = TestClient(app)
    huge_content = "x" * 11000  # Default limit is 10000
    response = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": huge_content}]},
        headers={"Authorization": "Bearer test-secret-xyz"},
    )
    assert response.status_code == 413
    assert "Payload too Large" in response.json()["error"]


def test_payload_within_limit():
    """POST with body within limit → passes size check (may fail upstream)."""
    from fastapi.testclient import TestClient
    from misdirection.proxy.gateway import app

    client = TestClient(app)
    response = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "short prompt"}]},
        headers={"Authorization": "Bearer test-secret-xyz"},
    )
    # Should NOT get 413
    assert response.status_code != 413


def test_health_no_auth_required():
    """GET /health remains public (no auth needed)."""
    from fastapi.testclient import TestClient
    from misdirection.proxy.gateway import app

    client = TestClient(app)
    response = client.get("/health")
    # Health is public, but may return 503 if components are degraded
    assert response.status_code in (200, 503)
