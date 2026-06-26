"""FIX #13/FIX#16 — Integration tests: redis_healthy + HybridSessionManager fallback."""
import sys

import pytest

sys.path.insert(0, "/home/sil/misdirection-proxy/src")


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


@pytest.mark.asyncio
async def test_hybrid_session_health_check_fallback_activation():
    """HybridSessionManager.health_check() triggers fallback on Redis failure."""
    from misdirection.core.session_manager import HybridSessionManager

    mgr = HybridSessionManager(redis_url="redis://localhost:9999")

    # health_check should not crash even with Redis down
    result = await mgr.health_check()
    # Returns True (in-memory is always healthy) but fallback is now active
    assert mgr._using_fallback is True


@pytest.mark.asyncio
async def test_gateway_handles_redis_down_gracefully(monkeypatch):
    """GatewayState initializes correctly even with Redis unavailable."""
    monkeypatch.setenv("REDIS_URL", "redis://localhost:9999")

    from misdirection.proxy.gateway import GatewayState
    # Should not crash — HybridSessionManager with bad URL still initializes lazily
    state = GatewayState()
    assert state.session_manager is not None
