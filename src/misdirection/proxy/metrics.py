"""Prometheus metrics for the Misdirection Gateway.

Exposes production-ready metrics for observability:
- Request counters by classification (benign, suspicious, malicious)
- ML inference latency histogram
- Regex fallback counter
- Redis connection health
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest, CONTENT_TYPE_LATEST

# Request classification counter
requests_total = Counter(
    "misdirection_requests_total",
    "Total requests processed by classification",
    ["classification"],  # benign, suspicious, malicious
)

# ML inference latency histogram
inference_latency = Histogram(
    "misdirection_inference_latency_seconds",
    "ML model inference latency in seconds",
    buckets=[0.0001, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1],
)

# Regex fallback counter (when ML confidence < threshold)
regex_fallbacks_total = Counter(
    "misdirection_regex_fallbacks_total",
    "Total regex fallbacks triggered by low ML confidence",
)

# Active sessions gauge
active_sessions = Gauge(
    "misdirection_active_sessions",
    "Current number of tracked sessions",
)

# Redis connection health
redis_healthy = Gauge(
    "misdirection_redis_healthy",
    "Whether Redis backend is available (1=yes, 0=no)",
)

# Misdirection triggered counter
misdirections_total = Counter(
    "misdirection_triggered_total",
    "Total misdirection responses served",
)

# --- NEW in v0.6.0 ---

# Blocked requests by reason (auth, payload, rate limit)
blocked_requests_total = Counter(
    "misdirection_blocked_total",
    "Total blocked requests by reason",
    ["reason"],  # auth_failure, payload_too_large, rate_limited
)

# CMPE engine processing latency (Capas 0-1-2)
cmpe_engine_latency = Histogram(
    "misdirection_cmpe_engine_latency_seconds",
    "CMPE engine prompt processing latency in seconds",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)

# Rate limiter fallback status (1 = using in-memory fallback, 0 = Redis OK)
rate_limiter_fallback_active = Gauge(
    "misdirection_rate_limiter_fallback_active",
    "Whether rate limiter is in in-memory fallback mode (1=yes, 0=no)",
)

# Circuit breaker state (0=closed, 1=half-open, 2=open)
circuit_breaker_state = Gauge(
    "misdirection_circuit_breaker_state",
    "Circuit breaker state (0=closed, 1=half-open, 2=open)",
)

# Gateway info
gateway_info = Info(
    "misdirection_gateway",
    "Gateway version and configuration",
)


def get_metrics_response() -> tuple[bytes, str]:
    """Generate Prometheus metrics response.

    Returns:
        (body_bytes, content_type) tuple
    """
    return generate_latest(), CONTENT_TYPE_LATEST
