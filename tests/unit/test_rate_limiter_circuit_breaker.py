"""Tests for rate limiter and circuit breaker."""
import asyncio
import sys

import pytest

sys.path.insert(0, "/home/sil/misdirection-proxy/src")

from misdirection.proxy.rate_limiter import InMemoryRateLimiter
from misdirection.proxy.circuit_breaker import CircuitBreaker, CircuitBreakerOpen, CircuitState


# ---------------------------------------------------------------------------
# Rate Limiter Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_in_memory_rate_limiter_allows_within_limit():
    """Requests within limit are allowed."""
    limiter = InMemoryRateLimiter()
    for i in range(10):
        assert await limiter.is_allowed("client-1", limit=10, window=60) is True


@pytest.mark.asyncio
async def test_in_memory_rate_limiter_blocks_over_limit():
    """Requests exceeding limit are blocked."""
    limiter = InMemoryRateLimiter()
    for _ in range(5):
        await limiter.is_allowed("client-1", limit=5, window=60)
    # 6th request should be blocked
    assert await limiter.is_allowed("client-1", limit=5, window=60) is False


@pytest.mark.asyncio
async def test_in_memory_rate_limiter_separate_keys():
    """Different keys have independent limits."""
    limiter = InMemoryRateLimiter()
    for _ in range(5):
        await limiter.is_allowed("client-1", limit=5, window=60)
    # client-1 is blocked
    assert await limiter.is_allowed("client-1", limit=5, window=60) is False
    # client-2 is still allowed
    assert await limiter.is_allowed("client-2", limit=5, window=60) is True


@pytest.mark.asyncio
async def test_in_memory_rate_limiter_window_expires():
    """Old requests expire from the window."""
    limiter = InMemoryRateLimiter()
    # Use a very short window
    for _ in range(3):
        await limiter.is_allowed("client-1", limit=3, window=0.1)
    # Should be blocked
    assert await limiter.is_allowed("client-1", limit=3, window=0.1) is False
    # Wait for window to expire
    await asyncio.sleep(0.15)
    # Should be allowed again
    assert await limiter.is_allowed("client-1", limit=3, window=0.1) is True


# ---------------------------------------------------------------------------
# Circuit Breaker Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_circuit_breaker_starts_closed():
    """Circuit breaker starts in CLOSED state."""
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
    assert cb.state == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_circuit_breaker_opens_after_failures():
    """Circuit opens after threshold consecutive failures."""
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=10.0)

    async def failing_func():
        raise ConnectionError("upstream down")

    for _ in range(3):
        with pytest.raises(ConnectionError):
            await cb.call(failing_func)

    assert cb.state == CircuitState.OPEN


@pytest.mark.asyncio
async def test_circuit_breaker_blocks_when_open():
    """Circuit breaker raises CircuitBreakerOpen when open."""
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=10.0)

    async def failing_func():
        raise ConnectionError("upstream down")

    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(failing_func)

    # Circuit is now open — should raise CircuitBreakerOpen
    with pytest.raises(CircuitBreakerOpen):
        await cb.call(failing_func)


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_after_timeout():
    """Circuit transitions to HALF_OPEN after recovery timeout."""
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)

    async def failing_func():
        raise ConnectionError("upstream down")

    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(failing_func)

    assert cb.state == CircuitState.OPEN

    # Wait for recovery timeout
    await asyncio.sleep(0.15)

    # State should be HALF_OPEN (checked via property)
    assert cb.state == CircuitState.HALF_OPEN


@pytest.mark.asyncio
async def test_circuit_breaker_closes_on_success():
    """Circuit closes after successful call in HALF_OPEN state."""
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)

    async def failing_func():
        raise ConnectionError("upstream down")

    async def success_func():
        return "ok"

    # Open the circuit
    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(failing_func)

    # Wait for recovery timeout
    await asyncio.sleep(0.15)

    # Successful call should close the circuit
    result = await cb.call(success_func)
    assert result == "ok"
    assert cb.state == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_circuit_breaker_reopens_on_half_open_failure():
    """Circuit reopens if HALF_OPEN probe fails."""
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)

    async def failing_func():
        raise ConnectionError("upstream down")

    # Open the circuit
    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(failing_func)

    # Wait for recovery
    await asyncio.sleep(0.15)

    # Failed probe should reopen
    with pytest.raises(ConnectionError):
        await cb.call(failing_func)

    assert cb.state == CircuitState.OPEN


@pytest.mark.asyncio
async def test_circuit_breaker_success_resets_counter():
    """Successful calls reset the failure counter."""
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=10.0)

    async def failing_func():
        raise ConnectionError("upstream down")

    async def success_func():
        return "ok"

    # 2 failures (below threshold)
    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(failing_func)

    # 1 success resets counter
    await cb.call(success_func)

    # Need 3 more failures to open
    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(failing_func)

    # Still closed (counter was reset)
    assert cb.state == CircuitState.CLOSED
