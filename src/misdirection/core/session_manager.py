"""Session Manager with Redis persistence and in-memory fallback."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)

SESSION_PREFIX = "misdirection:session:"
SESSION_TTL = 86400  # 24 hours
REDIS_CONNECT_TIMEOUT = 1.0  # aggressive timeout for production failover


class SessionData:
    """Accumulated session state for adaptive misdirection."""

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
    async def record(self, session_id: str, suspicion_score: float, was_misdirected: bool) -> SessionData: ...

    @abstractmethod
    async def health_check(self) -> bool: ...


class InMemorySessionManager(SessionManager):
    """Fallback session manager using local memory."""

    def __init__(self):
        self._sessions: dict[str, SessionData] = {}

    async def get(self, session_id: str) -> SessionData | None:
        return self._sessions.get(session_id)

    async def save(self, session_id: str, data: SessionData) -> None:
        self._sessions[session_id] = data

    async def record(self, session_id: str, suspicion_score: float, was_misdirected: bool) -> SessionData:
        session = self._sessions.get(session_id) or SessionData()
        session.record_request(suspicion_score, was_misdirected)
        self._sessions[session_id] = session
        return session

    async def health_check(self) -> bool:
        return True


class RedisSessionManager(SessionManager):
    """Production session manager using Redis with async I/O."""

    def __init__(self, redis_url: str = "redis://localhost:6379", connect_timeout: float = REDIS_CONNECT_TIMEOUT):
        self._redis_url = redis_url
        self._connect_timeout = connect_timeout
        self._redis = None
        self._available = False

    async def _get_redis(self):
        if self._redis is not None:
            return self._redis
        import redis.asyncio as aioredis
        self._redis = aioredis.from_url(
            self._redis_url,
            socket_connect_timeout=self._connect_timeout,
            socket_timeout=self._connect_timeout,
            decode_responses=True,
        )
        await self._redis.ping()
        self._available = True
        return self._redis

    def _key(self, session_id: str) -> str:
        return f"{SESSION_PREFIX}{session_id}"

    async def get(self, session_id: str) -> SessionData | None:
        try:
            r = await self._get_redis()
            data = await r.hgetall(self._key(session_id))
            if not data:
                return None
            parsed = {}
            for k, v in data.items():
                try:
                    parsed[k] = float(v)
                except (ValueError, TypeError):
                    parsed[k] = v
            return SessionData.from_dict(parsed)
        except Exception as e:
            logger.debug("Redis get failed: %s", e)
            return None

    async def save(self, session_id: str, data: SessionData) -> None:
        try:
            r = await self._get_redis()
            key = self._key(session_id)
            async with r.pipeline() as pipe:
                await pipe.hset(key, mapping={k: str(v) for k, v in data.to_dict().items()})
                await pipe.expire(key, SESSION_TTL)
                await pipe.execute()
        except Exception as e:
            logger.warning("Redis save failed: %s", e)

    async def record(self, session_id: str, suspicion_score: float, was_misdirected: bool) -> SessionData:
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
            logger.warning("Redis record failed: %s, using in-memory", e)
            fallback = InMemorySessionManager()
            return await fallback.record(session_id, suspicion_score, was_misdirected)

    async def health_check(self) -> bool:
        try:
            r = await self._get_redis()
            await r.ping()
            return True
        except Exception:
            return False


class HybridSessionManager(SessionManager):
    """Primary Redis with automatic failover to in-memory."""

    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self._redis_manager = RedisSessionManager(redis_url)
        self._fallback = InMemorySessionManager()
        self._using_fallback = False

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

    async def record(self, session_id: str, suspicion_score: float, was_misdirected: bool) -> SessionData:
        if not self._using_fallback:
            try:
                return await self._redis_manager.record(session_id, suspicion_score, was_misdirected)
            except Exception:
                self._using_fallback = True
                logger.warning("Redis unavailable, switching to in-memory fallback")
        return await self._fallback.record(session_id, suspicion_score, was_misdirected)

    async def health_check(self) -> bool:
        if not self._using_fallback:
            return await self._redis_manager.health_check()
        return True

    @property
    def is_using_redis(self) -> bool:
        return not self._using_fallback
