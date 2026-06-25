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
