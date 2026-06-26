#!/usr/bin/env python3
"""Tests for FIX #8 (fallback persistence) and FIX #9 (Redis retry)."""

import asyncio
import time
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from misdirection.core.session_manager import (
    HybridSessionManager,
    InMemorySessionManager,
    SessionData,
)


class TestFIX8_FallbackPersistence:
    """FIX #8: Fallback must preserve accumulated suspicion across calls."""

    @pytest.mark.asyncio
    async def test_fallback_accumulates_across_calls(self):
        """Multiple record() calls during Redis failure must accumulate suspicion."""
        # Create a mock Redis that always fails
        mock_redis = AsyncMock()
        mock_redis.ping.side_effect = Exception("Redis down")

        with patch(
            "misdirection.core.session_manager.RedisSessionManager._get_redis",
            side_effect=Exception("Redis down"),
        ):
            hybrid = HybridSessionManager(redis_url="redis://localhost:6379")

            # First call — falls back to memory
            s1 = await hybrid.record("session-A", suspicion_score=0.8, was_misdirected=True)
            assert s1.cumulative_suspicion == pytest.approx(0.8)
            assert s1.total_count == 1

            # Second call — must accumulate (0.8 + 0.8 = 1.6)
            s2 = await hybrid.record("session-A", suspicion_score=0.8, was_misdirected=True)
            assert s2.cumulative_suspicion == pytest.approx(1.6)
            assert s2.total_count == 2

            # Third call
            s3 = await hybrid.record("session-A", suspicion_score=0.5, was_misdirected=False)
            assert s3.cumulative_suspicion == pytest.approx(2.1)
            assert s3.total_count == 3

    @pytest.mark.asyncio
    async def test_sessions_independent_in_fallback(self):
        """Different session IDs must not mix state during fallback."""
        with patch(
            "misdirection.core.session_manager.RedisSessionManager._get_redis",
            side_effect=Exception("Redis down"),
        ):
            hybrid = HybridSessionManager(redis_url="redis://localhost:6379")

            s1 = await hybrid.record("session-X", 1.0, True)
            s2 = await hybrid.record("session-Y", 0.5, False)

            assert s1.cumulative_suspicion == pytest.approx(1.0)
            assert s2.cumulative_suspicion == pytest.approx(0.5)

            # Re-check after more calls
            s1b = await hybrid.record("session-X", 0.3, False)
            assert s1b.cumulative_suspicion == pytest.approx(1.3)


class TestFIX9_RedisRetry:
    """FIX #9: HybridSessionManager must retry Redis after transient failure."""

    @pytest.mark.asyncio
    async def test_recovers_when_redis_comes_back(self):
        """After transient failure, Redis recovery must be detected."""
        redis_available = False

        async def mock_health():
            if not redis_available:
                raise Exception("Redis down")
            return True

        with patch(
            "misdirection.core.session_manager.RedisSessionManager.health_check",
            side_effect=mock_health,
        ), patch(
            "misdirection.core.session_manager.RedisSessionManager.record",
            side_effect=Exception("Redis down"),
        ):
            hybrid = HybridSessionManager(redis_url="redis://localhost:6379")
            hybrid._last_retry = 0  # Force immediate retry

            # Trigger fallback
            await hybrid.record("session-A", 0.8, True)
            assert hybrid._using_fallback is True
            assert hybrid.is_using_redis is False

            # Simulate Redis recovery
            redis_available = True
            hybrid._last_retry = 0  # Force retry check

            # Next health check should detect recovery
            healthy = await hybrid.health_check()
            assert healthy is True
            assert hybrid._using_fallback is False
            assert hybrid.is_using_redis is True

    @pytest.mark.asyncio
    async def test_retry_respects_interval(self):
        """Retry must not attempt Redis more frequently than RETRY_INTERVAL."""
        retry_count = 0

        async def mock_health():
            nonlocal retry_count
            retry_count += 1
            raise Exception("Redis down")

        with patch(
            "misdirection.core.session_manager.RedisSessionManager.record",
            side_effect=Exception("Redis down"),
        ), patch(
            "misdirection.core.session_manager.RedisSessionManager.health_check",
            side_effect=mock_health,
        ):
            hybrid = HybridSessionManager(redis_url="redis://localhost:6379")
            hybrid._last_retry = time.time()  # Just retried

            # Trigger fallback
            await hybrid.record("session-A", 0.8, True)

            # Health check should NOT retry (interval not elapsed)
            await hybrid.health_check()
            assert retry_count == 0  # No retry attempted
