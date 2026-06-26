"""FIX #14 — GatewayState must use HybridSessionManager, not raw RedisSessionManager."""
import sys

import pytest

sys.path.insert(0, "/home/sil/misdirection-proxy/src")


@pytest.mark.asyncio
async def test_gateway_state_uses_hybrid_session_manager(monkeypatch):
    """GatewayState with REDIS_URL set must instantiate HybridSessionManager."""
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")

    from misdirection.proxy.gateway import GatewayState
    from misdirection.core.session_manager import HybridSessionManager

    state = GatewayState()
    sm = state.session_manager

    assert isinstance(sm, HybridSessionManager), (
        f"Expected HybridSessionManager, got {type(sm).__name__}"
    )


@pytest.mark.asyncio
async def test_gateway_state_in_memory_without_redis_url(monkeypatch):
    """GatewayState without REDIS_URL must use InMemorySessionManager directly."""
    monkeypatch.delenv("REDIS_URL", raising=False)

    from misdirection.proxy.gateway import GatewayState
    from misdirection.core.session_manager import InMemorySessionManager

    state = GatewayState()
    sm = state.session_manager

    assert isinstance(sm, InMemorySessionManager), (
        f"Expected InMemorySessionManager, got {type(sm).__name__}"
    )


@pytest.mark.asyncio
async def test_gateway_hybrid_fallback_end_to_end(monkeypatch):
    """End-to-end: GatewayState with Redis down accumulates suspicion via fallback."""
    monkeypatch.setenv("REDIS_URL", "redis://localhost:9999")

    from misdirection.proxy.gateway import GatewayState

    state = GatewayState()

    await state.session_manager.record("sess-e2e", suspicion_score=1.0, was_misdirected=True)
    await state.session_manager.record("sess-e2e", suspicion_score=1.0, was_misdirected=True)
    data = await state.session_manager.get("sess-e2e")

    assert data is not None, "Session data must persist in fallback"
    assert data.total_count == 2, f"Expected 2 requests, got {data.total_count}"
    assert data.cumulative_suspicion == 2.0
    assert state.session_manager.is_using_redis is False
