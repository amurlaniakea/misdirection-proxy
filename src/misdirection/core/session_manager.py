"""Session Manager with Redis persistence and in-memory fallback.

Provides distributed session storage for adaptive misdirection scaling.
Supports horizontal scaling across multiple proxy instances behind a load balancer.

Architecture:
    - RedisSessionManager: Primary, uses redis.asyncio with connection pool
    - InMemorySessionManager: Fallback when Redis is unavailable
    - HybridSessionManager: Automatic failover with periodic retry
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)

# Redis key prefix for session data
SESSION_PREFIX = "misdirection:session:"
SESSION_TTL = 86400  # 24 hours in seconds
REDIS_CONNECT_TIMEOUT = 1.0  # aggressive timeout for production failover
RETRY_INTERVAL = 30.0  # seconds between Redis retry attempts when in fallback mode


class SessionData:
    """Represents accumulated session state for adaptive misdirection."""

    def __init__(
        self,
        cumulative_suspicion: float = 0.0,
        misdirect_count: int = 0,
        total_count: int = 0,
        last_request_ts: float = 0.0,
        gamma_a: float = 0.71,
    ):
        self.cumulative_suspicion = cumulative_suspicion
        self.misdirect_count = misdirect_count
        self.total_count = total_count
        self.last_request_ts = last_request_ts or time.time()
        self.gamma_a = gamma_a

    def to_dict(self) -> dict[str, Any]:
        return {
            "cumulative_suspicion": self.cumulative_suspicion,
            "misdirect_count": self.misdirect_count,
            "total_count": self.total_count,
            "last_request_ts": self.last_request_ts,
            "gamma_a": self.gamma_a,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SessionData":
        valid = {"cumulative_suspicion", "misdirect_count", "total_count", "last_request_ts", "gamma_a"}
        filtered = {k: v for k, v in data.items() if k in valid}
        return cls(**filtered)

    def record_request(self, suspicion_score: float, was_misdirected: bool) -> None:
        """Update session state with a new request."""
        self.cumulative_suspicion += suspicion_score
        self.total_count += 1
        if was_misdirected:
            self.misdirect_count += 1
        self.last_request_ts = time.time()


class SessionManager(ABC):
    """Abstract interface for session persistence."""

    @abstractmethod
    async def get(self, session_id: str) -> SessionData | None: ...

    @abstractmethod
    async def save(self, session_id: str, data: SessionData) -> None: ...

    @abstractmethod
    async def record(
        self, session_id: str, suspicion_score: float, was_misdirected: bool
    ) -> SessionData: ...

    @abstractmethod
    async def health_check(self) -> bool: ...


class InMemorySessionManager(SessionManager):
    """Fallback session manager using local memory (non-distributed)."""

    def __init__(self):
        self._sessions: dict[str, SessionData] = {}

    async def get(self, session_id: str) -> SessionData | None:
        return self._sessions.get(session_id)

    async def save(self, session_id: str, data: SessionData) -> None:
        self._sessions[session_id] = data

    async def record(
        self,
        session_id: str,
        suspicion_score: float,
        was_misdirected: bool,
    ) -> SessionData:
        session = self._sessions.get(session_id) or SessionData()
        session.record_request(suspicion_score, was_misdirected)
        self._sessions[session_id] = session
        return session

    async def health_check(self) -> bool:
        return True


class RedisSessionManager(SessionManager):
    """Production session manager using Redis with async I/O.

    Uses Redis Hashes for granular field access and EXPIRE for TTL renewal.
    Connection pool with aggressive timeout for fast failover.
    """

    def __init__(
        self, redis_url: str = "redis://localhost:6379", connect_timeout: float = REDIS_CONNECT_TIMEOUT
    ):
        self._redis_url = redis_url
        self._connect_timeout = connect_timeout
        self._redis = None
        self._available = False

    async def _get_redis(self):
        """Lazy connection with timeout."""
        if self._redis is not None:
            return self._redis

        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(
                self._redis_url,
                socket_connect_timeout=self._connect_timeout,
                socket_timeout=self._connect_timeout,
                decode_responses=True,
            )
            # Test connection
            await self._redis.ping()
            self._available = True
            logger.info("Redis session manager connected to %s", self._redis_url)
        except Exception as e:
            logger.warning("Redis connection failed (%s), will retry on next call", e)
            self._available = False
            raise

        return self._redis

    def _key(self, session_id: str) -> str:
        return f"{SESSION_PREFIX}{session_id}"

    async def get(self, session_id: str) -> SessionData | None:
        try:
            r = await self._get_redis()
            data = await r.hgetall(self._key(session_id))
            if not data:
                return None
            # Convert string values to float/int
            parsed = {}
            for k, v in data.items():
                try:
                    parsed[k] = float(v) if "." in v else int(v)
                except (ValueError, TypeError):
                    parsed[k] = v
            return SessionData.from_dict(parsed)
        except Exception as e:
            logger.warning("Redis get failed for %s: %s", session_id, e)
            raise  # Let HybridSessionManager handle fallback (FIX #13)

    async def save(self, session_id: str, data: SessionData) -> None:
        try:
            r = await self._get_redis()
            key = self._key(session_id)
            # Use pipeline for atomic HSET + EXPIRE
            async with r.pipeline() as pipe:
                await pipe.hset(key, mapping={k: str(v) for k, v in data.to_dict().items()})
                await pipe.expire(key, SESSION_TTL)
                await pipe.execute()
        except Exception as e:
            logger.warning("Redis save failed for %s: %s", session_id, e)
            raise  # Let HybridSessionManager handle fallback

    async def record(
        self,
        session_id: str,
        suspicion_score: float,
        was_misdirected: bool,
    ) -> SessionData:
        """Atomic read-modify-write with Redis."""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                r = await self._get_redis()
                key = self._key(session_id)

                async with r.pipeline() as pipe:
                    await pipe.watch(key)
                    existing = await pipe.hgetall(key)

                    if existing:
                        data = SessionData.from_dict({k: float(v) for k, v in existing.items()})
                    else:
                        data = SessionData()

                    data.record_request(suspicion_score, was_misdirected)

                    pipe.multi()
                    await pipe.hset(key, mapping={k: str(v) for k, v in data.to_dict().items()})
                    await pipe.expire(key, SESSION_TTL)
                    await pipe.execute()
                    return data
            except Exception as e:
                if "WatchError" in type(e).__name__ and attempt < max_retries - 1:
                    logger.debug("Watch conflict on %s, retry %d", session_id, attempt + 1)
                    continue
                logger.warning("Redis record failed for %s: %s", session_id, e)
                raise  # Let HybridSessionManager handle fallback (FIX #8)

    async def health_check(self) -> bool:
        try:
            r = await self._get_redis()
            await r.ping()
            return True
        except Exception:
            return False


class HybridSessionManager(SessionManager):
    """Primary Redis with automatic failover to in-memory.

    Features:
    - Automatic failover when Redis is unavailable
    - Periodic retry to recover Redis connection (FIX #9)
    - Persistent fallback session storage (FIX #8)
    """

    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self._redis_manager = RedisSessionManager(redis_url)
        self._fallback = InMemorySessionManager()  # Persistent fallback (FIX #8)
        self._using_fallback = False
        self._last_retry = 0.0

    async def get(self, session_id: str) -> SessionData | None:
        if not self._using_fallback:
            try:
                result = await self._redis_manager.get(session_id)
                if result is not None:
                    return result
            except Exception:
                self._using_fallback = True
                logger.warning("Redis unavailable, switching to in-memory fallback")
        return await self._fallback.get(session_id)

    async def save(self, session_id: str, data: SessionData) -> None:
        if not self._using_fallback:
            try:
                await self._redis_manager.save(session_id, data)
                return
            except Exception:
                self._using_fallback = True
                logger.warning("Redis unavailable, switching to in-memory fallback")
        await self._fallback.save(session_id, data)

    async def record(
        self,
        session_id: str,
        suspicion_score: float,
        was_misdirected: bool,
    ) -> SessionData:
        if not self._using_fallback:
            try:
                return await self._redis_manager.record(session_id, suspicion_score, was_misdirected)
            except Exception:
                self._using_fallback = True
                logger.warning("Redis unavailable, switching to in-memory fallback")
        # Uses persistent _fallback (FIX #8: accumulates across calls)
        return await self._fallback.record(session_id, suspicion_score, was_misdirected)

    async def health_check(self) -> bool:
        if not self._using_fallback:
            redis_ok = await self._redis_manager.health_check()
            if not redis_ok:
                self._using_fallback = True
                logger.warning("Redis health check failed, switching to in-memory fallback")
                return True  # In-memory fallback is always "healthy"
            return True
        # Periodic retry to recover Redis (FIX #9)
        now = time.time()
        if now - self._last_retry >= RETRY_INTERVAL:
            self._last_retry = now
            redis_ok = await self._redis_manager.health_check()
            if redis_ok:
                self._using_fallback = False
                logger.info("Redis recovered, switching back from fallback")
                return True
        return True  # In-memory is always "healthy"

    @property
    def is_using_redis(self) -> bool:
        return not self._using_fallback
