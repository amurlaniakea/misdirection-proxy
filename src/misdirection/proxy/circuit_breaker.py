"""Circuit Breaker for upstream LLM calls.

States:
- CLOSED: Normal operation, requests pass through
- OPEN: Too many failures, requests immediately rejected (fail fast)
- HALF_OPEN: Testing if upstream recovered (allows 1 probe request)

Transitions:
- CLOSED → OPEN: after `failure_threshold` consecutive failures
- OPEN → HALF_OPEN: after `recovery_timeout` seconds
- HALF_OPEN → CLOSED: on success
- HALF_OPEN → OPEN: on failure
"""
from __future__ import annotations

import asyncio
import logging
import time
from enum import Enum

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpen(Exception):
    """Raised when circuit breaker is open (upstream unavailable)."""
    pass


class CircuitBreaker:
    """Protects upstream LLM calls from cascading failures."""

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout: float = 30.0,
        expected_exception: type = Exception,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time = 0.0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        """Current circuit state."""
        if self._state == CircuitState.OPEN:
            # Check if recovery timeout has elapsed
            if time.time() - self._last_failure_time >= self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                logger.info("Circuit breaker transitioning to HALF_OPEN")
        return self._state

    async def call(self, func, *args, **kwargs):
        """Execute function through circuit breaker.

        Raises:
            CircuitBreakerOpen: if circuit is open
            Exception: original exception from func
        """
        async with self._lock:
            current_state = self.state
            if current_state == CircuitState.OPEN:
                raise CircuitBreakerOpen(
                    f"Circuit breaker is OPEN (upstream unavailable). "
                    f"Recovery in {self._recovery_remaining():.1f}s"
                )

        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except self.expected_exception:
            await self._on_failure()
            raise

    async def _on_success(self):
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                logger.info("Circuit breaker CLOSED (upstream recovered)")
            self._state = CircuitState.CLOSED
            self._failure_count = 0

    async def _on_failure(self):
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._failure_count >= self.failure_threshold:
                if self._state != CircuitState.OPEN:
                    logger.warning(
                        "Circuit breaker OPEN after %d consecutive failures",
                        self._failure_count,
                    )
                self._state = CircuitState.OPEN

    def _recovery_remaining(self) -> float:
        """Seconds until circuit transitions to HALF_OPEN."""
        elapsed = time.time() - self._last_failure_time
        return max(0, self.recovery_timeout - elapsed)
