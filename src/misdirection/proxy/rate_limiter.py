"""Rate limiter: sliding window counter backed by Redis.

Two implementations:
- RedisSlidingWindowRateLimiter: uses Redis ZSET for distributed rate limiting
- InMemoryRateLimiter: fallback when Redis is unavailable

Both expose the same interface: is_allowed(key) -> bool
"""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class RateLimiter(ABC):
    """Abstract rate limiter interface."""

    @abstractmethod
    async def is_allowed(self, key: str, limit: int, window: float) -> bool:
        """Check if request is within rate limit.

        Args:
            key: Identifier (API key, IP, session)
            limit: Max requests per window
            window: Time window in seconds

        Returns:
            True if request is allowed, False if rate limited
        """
        ...


class InMemoryRateLimiter(RateLimiter):
    """Fallback rate limiter using local memory (non-distributed)."""

    def __init__(self):
        self._windows: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def is_allowed(self, key: str, limit: int, window: float) -> bool:
        now = time.time()
        async with self._lock:
            timestamps = self._windows.get(key, [])
            # Remove expired entries
            cutoff = now - window
            timestamps = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= limit:
                self._windows[key] = timestamps
                return False
            timestamps.append(now)
            self._windows[key] = timestamps
            return True


class RedisSlidingWindowRateLimiter(RateLimiter):
    """Distributed rate limiter using Redis ZSET (sorted set).

    Each key maps to a ZSET where:
    - Member: unique request ID (timestamp + counter)
    - Score: request timestamp (for range queries)

    Atomic operation: ZREMRANGEBYSCORE + ZCARD + ZADD in pipeline
    """

    def __init__(self, redis=None, key_prefix: str = "misdirection:ratelimit:"):
        self._redis = redis
        self._prefix = key_prefix
        self._fallback = InMemoryRateLimiter()

    async def _get_redis(self):
        if self._redis is not None:
            return self._redis
        # Lazy connection via session manager's Redis
        return None

    async def is_allowed(self, key: str, limit: int, window: float) -> bool:
        import uuid
        redis = await self._get_redis()
        if redis is None:
            return await self._fallback.is_allowed(key, limit, window)

        now = time.time()
        window_start = now - window
        redis_key = f"{self._prefix}{key}"

        try:
            # Use Lua script for atomic check-and-add
            lua_script = """
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local window_start = tonumber(ARGV[2])
            local limit = tonumber(ARGV[3])
            local member = ARGV[4]
            local ttl = tonumber(ARGV[5])

            redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
            local count = redis.call('ZCARD', key)

            if count >= limit then
                return 0
            end

            redis.call('ZADD', key, now, member)
            redis.call('EXPIRE', key, ttl)
            return 1
            """

            member = f"{now}:{uuid.uuid4().hex[:8]}"
            ttl = int(window) + 1
            result = await redis.eval(
                lua_script, 1, redis_key, now, window_start, limit, member, ttl
            )

            if result == 0:
                logger.warning(
                    "Rate limit exceeded: key=%s, limit=%d, window=%ds",
                    key, limit, window,
                )
                return False
            return True
        except Exception as e:
            logger.warning("Rate limiter Redis error (%s), using fallback", e)
            return await self._fallback.is_allowed(key, limit, window)
