"""FIX #13 — RedisSessionManager.get() must propagate exceptions to trigger fallback."""
import asyncio
import sys

import pytest

sys.path.insert(0, "/home/sil/misdirection-proxy/src")

from misdirection.core.session_manager import (
    HybridSessionManager,
    InMemorySessionManager,
    RedisSessionManager,
    SessionData,
)


@pytest.mark.asyncio
async def test_get_with_redis_down_activates_fallback():
    """FIX #13: get() with unavailable Redis must activate fallback mode."""
    mgr = HybridSessionManager(redis_url="redis://localhost:9999")  # No Redis here
    assert mgr._using_fallback is False
    assert mgr.is_using_redis is True

    result = await mgr.get("new-session")

    # None is correct (session doesn't exist), but fallback MUST activate
    assert result is None
    assert mgr._using_fallback is True, "get() with Redis down must activate fallback"
    assert mgr.is_using_redis is False, "is_using_redis must be False when Redis is down"


@pytest.mark.asyncio
async def test_get_new_session_with_healthy_redis_no_false_fallback():
    """Regression: new session (key doesn't exist) with healthy Redis must NOT activate fallback.

    Uses a real RedisSessionManager pointed at fakeredis or in-memory mock
    that simulates a working Redis that simply has no key yet.
    """
    class FakeRedis:
        async def hgetall(self, key):
            return {}  # Key doesn't exist — legitimate None

    class WorkingRedisSessionManager(RedisSessionManager):
        def __init__(self):
            # Skip real Redis init
            self._redis = FakeRedis()
            self._available = True

        async def _get_redis(self):
            return self._redis

    hybrid = HybridSessionManager.__new__(HybridSessionManager)
    hybrid._redis_manager = WorkingRedisSessionManager()
    hybrid._fallback = InMemorySessionManager()
    hybrid._using_fallback = False
    hybrid._last_retry = 0.0

    result = await hybrid.get("brand-new-session")
    assert result is None  # Key doesn't exist — that's fine
    assert hybrid._using_fallback is False, "Healthy Redis with missing key must NOT trigger fallback"
    assert hybrid.is_using_redis is True


@pytest.mark.asyncio
async def test_record_then_get_consistent_fallback():
    """After record() fails and activates fallback, get() must also use fallback."""
    mgr = HybridSessionManager(redis_url="redis://localhost:9999")

    # First: record activates fallback (FIX #8 — already working)
    await mgr.record("sess-1", suspicion_score=1.0, was_misdirected=True)
    assert mgr._using_fallback is True

    # Now get should go to in-memory fallback without retrying Redis
    result = await mgr.get("sess-1")
    assert result is not None  # fallback has it from record()
    assert result.total_count == 1
    assert mgr._using_fallback is True  # Still in fallback
