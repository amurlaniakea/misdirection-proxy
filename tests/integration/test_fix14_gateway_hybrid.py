"""FIX #14 — GatewayState must use HybridSessionManager, not raw RedisSessionManager."""
import os
import sys

import pytest

sys.path.insert(0, "/home/sil/misdirection-proxy/src")


@pytest.mark.asyncio
async def test_gateway_state_uses_hybrid_session_manager():
    """GatewayState with REDIS_URL set must instantiate HybridSessionManager."""
    os.environ["REDIS_URL"] = "redis://localhost:6379"

    # Must reimport to pick up the env var at _init_session_manager time
    import importlib
    from misdirection.proxy import gateway
    importlib.reload(gateway)

    state = gateway.GatewayState()
    sm = state.session_manager

    from misdirection.core.session_manager import HybridSessionManager
    assert isinstance(sm, HybridSessionManager), (
        f"Expected HybridSessionManager, got {type(sm).__name__}"
    )
    assert hasattr(sm, "is_using_redis"), "HybridSessionManager must expose is_using_redis"


@pytest.mark.asyncio
async def test_gateway_state_in_memory_without_redis_url():
    """GatewayState without REDIS_URL must use InMemorySessionManager directly."""
    os.environ.pop("REDIS_URL", None)

    from misdirection.proxy.gateway import GatewayState
    from misdirection.core.session_manager import InMemorySessionManager

    state = GatewayState()
    sm = state.session_manager

    assert isinstance(sm, InMemorySessionManager), (
        f"Expected InMemorySessionManager, got {type(sm).__name__}"
    )


@pytest.mark.asyncio
async def test_gateway_hybrid_fallback_end_to_end():
    """End-to-end: GatewayState with Redis down accumulates suspicion via fallback."""
    os.environ["REDIS_URL"] = "redis://localhost:9999"

    from misdirection.proxy.gateway import GatewayState

    state = GatewayState()

    # Record multiple requests (simulating malicious session)
    await state.session_manager.record("sess-e2e", suspicion_score=1.0, was_misdirected=True)
    await state.session_manager.record("sess-e2e", suspicion_score=1.0, was_misdirected=True)
    data = await state.session_manager.get("sess-e2e")

    assert data is not None, "Session data must persist in fallback"
    assert data.total_count == 2, f"Expected 2 requests, got {data.total_count}"
    assert data.cumulative_suspicion == 2.0, (
        f"Expected cumulative_suspicion=2.0, got {data.cumulative_suspicion}"
    )
    assert state.session_manager.is_using_redis is False, (
        "After Redis failure, is_using_redis must be False"
    )
