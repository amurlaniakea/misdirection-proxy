"""End-to-end tests with real Redis 7 instance.

These tests validate atomic operations (HSET, EXPIRE, pipeline) and
the sliding window rate limiter against a real Redis server.

Requires REDIS_URL environment variable pointing to a running Redis instance.
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, "/home/sil/misdirection-proxy/src")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


@pytest.fixture
async def redis_conn():
    """Create a real Redis connection for testing."""
    import redis.asyncio as aioredis
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await r.ping()
    except Exception:
        pytest.skip(f"Redis not available at {REDIS_URL}")
    yield r
    await r.close()


@pytest.fixture(autouse=True)
async def cleanup_redis(redis_conn):
    """Clean up test keys before and after each test."""
    # Clean rate limit keys
    keys = await redis_conn.keys("misdirection:ratelimit:*")
    if keys:
        await redis_conn.delete(*keys)
    # Clean session keys
    keys = await redis_conn.keys("misdirection:session:*")
    if keys:
        await redis_conn.delete(*keys)
    yield
    # Cleanup after test
    keys = await redis_conn.keys("misdirection:ratelimit:*")
    if keys:
        await redis_conn.delete(*keys)
    keys = await redis_conn.keys("misdirection:session:*")
    if keys:
        await redis_conn.delete(*keys)


# ---------------------------------------------------------------------------
# Session Manager E2E
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_session_manager_hset_and_hgetall(redis_conn):
    """Session data is stored as Redis Hash and retrievable."""
    from misdirection.core.session_manager import RedisSessionManager

    manager = RedisSessionManager(redis_url=REDIS_URL)
    await manager.record("test-session", suspicion_score=1.0, was_misdirected=True)

    # Verify data exists in Redis
    raw = await redis_conn.hgetall("misdirection:session:test-session")
    assert "cumulative_suspicion" in raw
    assert float(raw["cumulative_suspicion"]) == 1.0
    assert int(raw["misdirect_count"]) == 1
    assert int(raw["total_count"]) == 1


@pytest.mark.asyncio
async def test_session_manager_expire_set(redis_conn):
    """Session keys have TTL set."""
    from misdirection.core.session_manager import RedisSessionManager

    manager = RedisSessionManager(redis_url=REDIS_URL)
    await manager.record("expire-test", suspicion_score=0.5, was_misdirected=False)

    ttl = await redis_conn.ttl("misdirection:session:expire-test")
    assert ttl > 0  # TTL should be set
    assert ttl <= 86400  # Default 24h


@pytest.mark.asyncio
async def test_session_manager_atomic_pipeline(redis_conn):
    """Multiple records update atomically without race conditions."""
    from misdirection.core.session_manager import RedisSessionManager

    manager = RedisSessionManager(redis_url=REDIS_URL)

    # Simulate concurrent records
    await asyncio.gather(
        manager.record("concurrent-sess", 1.0, True),
        manager.record("concurrent-sess", 0.5, False),
        manager.record("concurrent-sess", 1.0, True),
    )

    data = await manager.get("concurrent-sess")
    assert data is not None
    assert data.total_count == 3
    assert data.misdirect_count == 2
    assert data.cumulative_suspicion == 2.5


@pytest.mark.asyncio
async def test_session_manager_get_nonexistent(redis_conn):
    """Getting non-existent session returns None."""
    from misdirection.core.session_manager import RedisSessionManager

    manager = RedisSessionManager(redis_url=REDIS_URL)
    result = await manager.get("does-not-exist")
    assert result is None


# ---------------------------------------------------------------------------
# Rate Limiter E2E
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redis_rate_limiter_allows_within_limit(redis_conn):
    """Redis rate limiter allows requests within limit."""
    from misdirection.proxy.rate_limiter import RedisSlidingWindowRateLimiter

    limiter = RedisSlidingWindowRateLimiter(redis=redis_conn)
    for _ in range(10):
        assert await limiter.is_allowed("client-1", limit=10, window=60) is True


@pytest.mark.asyncio
async def test_redis_rate_limiter_blocks_over_limit(redis_conn):
    """Redis rate limiter blocks requests exceeding limit."""
    from misdirection.proxy.rate_limiter import RedisSlidingWindowRateLimiter

    limiter = RedisSlidingWindowRateLimiter(redis=redis_conn)
    for _ in range(5):
        await limiter.is_allowed("client-2", limit=5, window=60)
    # 6th request should be blocked
    assert await limiter.is_allowed("client-2", limit=5, window=60) is False


@pytest.mark.asyncio
async def test_redis_rate_limiter_sliding_window(redis_conn):
    """Old requests expire from the sliding window."""
    from misdirection.proxy.rate_limiter import RedisSlidingWindowRateLimiter

    limiter = RedisSlidingWindowRateLimiter(redis=redis_conn)
    # Use a very short window
    for _ in range(3):
        await limiter.is_allowed("client-3", limit=3, window=0.5)
    # Should be blocked
    assert await limiter.is_allowed("client-3", limit=3, window=0.5) is False
    # Wait for window to expire
    await asyncio.sleep(0.6)
    # Should be allowed again
    assert await limiter.is_allowed("client-3", limit=3, window=0.5) is True


@pytest.mark.asyncio
async def test_redis_rate_limiter_separate_keys(redis_conn):
    """Different keys have independent limits."""
    from misdirection.proxy.rate_limiter import RedisSlidingWindowRateLimiter

    limiter = RedisSlidingWindowRateLimiter(redis=redis_conn)
    for _ in range(5):
        await limiter.is_allowed("client-a", limit=5, window=60)
    # client-a is blocked
    assert await limiter.is_allowed("client-a", limit=5, window=60) is False
    # client-b is still allowed
    assert await limiter.is_allowed("client-b", limit=5, window=60) is True


@pytest.mark.asyncio
async def test_redis_rate_limiter_concurrent_burst(redis_conn):
    """Rate limiter handles concurrent burst correctly."""
    from misdirection.proxy.rate_limiter import RedisSlidingWindowRateLimiter

    limiter = RedisSlidingWindowRateLimiter(redis=redis_conn)

    # Send 20 concurrent requests with limit of 10
    results = await asyncio.gather(
        *[limiter.is_allowed("burst-client", limit=10, window=60) for _ in range(20)]
    )

    # Exactly 10 should be allowed, 10 should be blocked
    allowed = sum(1 for r in results if r)
    blocked = sum(1 for r in results if not r)
    assert allowed == 10
    assert blocked == 10


# ---------------------------------------------------------------------------
# Hybrid Session Manager E2E
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hybrid_session_manager_uses_redis(redis_conn):
    """HybridSessionManager uses Redis when available."""
    from misdirection.core.session_manager import HybridSessionManager

    manager = HybridSessionManager(redis_url=REDIS_URL)
    assert manager.is_using_redis is True

    await manager.record("hybrid-test", 1.0, True)
    data = await manager.get("hybrid-test")
    assert data is not None
    assert data.total_count == 1


@pytest.mark.asyncio
async def test_hybrid_session_manager_fallback_on_redis_failure(redis_conn):
    """HybridSessionManager falls back to in-memory when Redis fails."""
    from misdirection.core.session_manager import HybridSessionManager

    # Point to non-existent Redis
    manager = HybridSessionManager(redis_url="redis://localhost:9999")
    assert manager.is_using_redis is True  # Starts optimistic

    # First record should trigger fallback
    await manager.record("fallback-test", 1.0, True)
    assert manager.is_using_redis is False  # Now in fallback

    # Data should still be accessible via in-memory
    data = await manager.get("fallback-test")
    assert data is not None
    assert data.total_count == 1
