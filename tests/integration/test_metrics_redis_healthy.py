"""FIX #13 — Integration tests: redis_healthy + HybridSessionManager fallback."""
import os
import sys

import pytest

sys.path.insert(0, "/home/sil/misdirection-proxy/src")


@pytest.mark.asyncio
async def test_metrics_redis_healthy_zero_when_redis_down():
    """GET /metrics with non-available Redis must report redis_healthy=0.

    The /metrics endpoint calls health_check() before reading is_using_redis.
    With HybridSessionManager, health_check() detects the failure and activates
    fallback, so is_using_redis becomes False → redis_val=0.
    """
    os.environ["REDIS_URL"] = "redis://localhost:9999"

    from misdirection.proxy.gateway import GatewayState

    state = GatewayState()

    # Simulate what /metrics does: health_check first, then read is_using_redis
    await state.session_manager.health_check()

    redis_val = 1 if getattr(state.session_manager, "is_using_redis", False) else 0
    assert redis_val == 0, (
        f"redis_healthy must be 0 when Redis is unavailable, got {redis_val}"
    )


@pytest.mark.asyncio
async def test_hybrid_session_get_propagates_failure():
    """HybridSessionManager.get() with Redis down sets _using_fallback=True (FIX #13)."""
    from misdirection.core.session_manager import HybridSessionManager

    mgr = HybridSessionManager(redis_url="redis://localhost:9999")
    assert mgr._using_fallback is False

    result = await mgr.get("test-key")
    assert result is None  # key doesn't exist in fallback
    assert mgr._using_fallback is True
    assert mgr.is_using_redis is False
