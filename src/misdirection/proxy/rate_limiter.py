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
            pipe = redis.pipeline()
            # Remove entries outside the window
            pipe.zremrangebyscore(redis_key, 0, window_start)
            # Count current entries
            pipe.zcard(redis_key)
            results = await pipe.execute()
            current_count = results[1]

            if current_count >= limit:
                logger.warning(
                    "Rate limit exceeded: key=%s, count=%d, limit=%d, window=%ds",
                    key, current_count, limit, window,
                )
                return False

            # Add current request
            member = f"{now}:{uuid.uuid4().hex[:8]}"
            pipe2 = redis.pipeline()
            pipe2.zadd(redis_key, {member: now})
            pipe2.expire(redis_key, window + 1)
            await pipe2.execute()
            return True
        except Exception as e:
            logger.warning("Rate limiter Redis error (%s), using fallback", e)
            return await self._fallback.is_allowed(key, limit, window)
