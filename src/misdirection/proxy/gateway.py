"""HTTP Middleware — FastAPI proxy gateway.

Provides a security gateway that can be placed in front of any LLM provider
(OpenAI, Anthropic, Ollama, etc.) to apply misdirection defense.

Architecture:
    Client → MisdirectionGateway → LLM Provider
              ↓
         [IntentionDetector] → benign → forward to LLM
         [CMPE Engine]       → malicious → return misdirection
         [Metrics Collector] → all requests logged
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from misdirection.core.adaptive import (
    AdaptiveConfig,
    AdaptiveController,
)
from misdirection.core.cmpe import CMPEConfig, CMPEEngine
from misdirection.core.context_filter import ContextFilter, ContextSource
from misdirection.core.session_manager import (
    SessionManager,
    HybridSessionManager,
    RedisSessionManager,
    InMemorySessionManager,
    SessionData,
)
from misdirection.detector.intention import IntentionDetector, IntentionLabel
from misdirection.eval.metrics import (
    DefenseConfig,
    JudgeProfile,
    MisdirectionEvaluator,
)
from misdirection.proxy.metrics import (
    requests_total,
    inference_latency,
    regex_fallbacks_total,
    misdirections_total,
    get_metrics_response,
)
from misdirection.proxy.proxy import ProxyConfig, ProxyDecision

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------

class GatewayState:
    """Shared state for the gateway."""

    def __init__(self):
        self.detector = IntentionDetector()
        self.engine = CMPEEngine(config=CMPEConfig())
        self.proxy_config = ProxyConfig(
            cmpe_config=CMPEConfig(),
            misdirection_threshold=0.5,
            log_decisions=True,
        )
        # Session manager: Redis with in-memory fallback
        self.session_manager: SessionManager = self._init_session_manager()
        self.adaptive = AdaptiveController(config=AdaptiveConfig())
        # Context filter (Frente 2)
        self.context_filter = ContextFilter()
        # Metrics counters
        self.total_requests: int = 0
        self.misdirected_requests: int = 0
        self.blocked_requests: int = 0
        self.start_time: float = 0.0
        self.regex_fallbacks: int = 0
        # Upstream LLM config
        self.upstream_base_url: str = os.getenv(
            "UPSTREAM_LLM_URL", "http://localhost:11434"
        )
        self.upstream_api_key: str = os.getenv("UPSTREAM_LLM_API_KEY", "")

    def _init_session_manager(self) -> SessionManager:
        """Initialize session manager: Hybrid (Redis + in-memory fallback) if REDIS_URL is set."""
        redis_url = os.getenv("REDIS_URL", "")
        if redis_url:
            try:
                manager = HybridSessionManager(redis_url=redis_url)
                logger.info("Hybrid session manager initialized (Redis primary, in-memory fallback): %s", redis_url)
                return manager
            except Exception as e:
                logger.warning("Failed to initialize Hybrid session manager (%s), using in-memory only", e)
        return InMemorySessionManager()


state = GatewayState()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    state.start_time = time.time()
    yield


app = FastAPI(
    title="Misdirection Gateway",
    description="Defensive Misdirection Proxy for AI Agents",
    version="0.2.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """Main proxy endpoint — compatible with OpenAI chat completions API.

    Intercepts the user message, applies misdirection defense if malicious,
    otherwise forwards to the upstream LLM.

    Adaptive mode: if X-Session-ID header is provided, the controller
    escalates defense intensity based on accumulated suspicion.

    Context filtering: if context_sources field is provided in the body,
    each external context source is filtered for indirect injections
    before being forwarded to the upstream LLM.
    """
    body = await request.json()
    state.total_requests += 1

    # Extract session ID (optional — enables adaptive mode)
    session_id = request.headers.get("X-Session-ID", "")

    # --- Frente 2: Context filtering ---
    context_sources = body.get("context_sources", [])
    filtered_sources = []
    context_filter_results = []
    if context_sources:
        for src in context_sources:
            source = ContextSource(
                source_id=src.get("source_id", "unknown"),
                content=src.get("content", ""),
                source_type=src.get("source_type", "rag"),
                metadata=src.get("metadata", {}),
            )
            result = state.context_filter.filter_source(source)
            filtered_sources.append({
                "source_id": result.source_id,
                "content": result.sanitized_content,
                "source_type": source.source_type,
                "was_modified": result.was_modified,
            })
            if result.was_modified:
                context_filter_results.append({
                    "source_id": result.source_id,
                    "intention": result.detected_intention,
                    "confidence": result.confidence,
                    "transformation": result.transformation_applied,
                })
        # Replace context_sources in body with filtered versions
        body["context_sources"] = filtered_sources

    # Extract user messages
    messages = body.get("messages", [])
    user_content = _extract_user_content(messages)

    if not user_content:
        return await _forward_to_upstream(body)

    # Analyze intention with Prometheus tracking
    with inference_latency.time():
        intention = state.detector.detect(user_content)

    # Track request classification
    requests_total.labels(classification=intention.label.value).inc()

    # Adaptive mode: record session and get escalated config
    adaptive_config = None
    gamma_a = state.adaptive.config.gamma_base
    if session_id:
        suspicion_score = _intention_to_suspicion(intention)
        session_data = await state.session_manager.record(
            session_id=session_id,
            suspicion_score=suspicion_score,
            was_misdirected=False,  # updated below
        )
        adaptive_config = state.adaptive.get_adaptive_cmpe_config(
            session_data.cumulative_suspicion
        )
        gamma_a = state.adaptive.get_gamma_a(session_data.cumulative_suspicion)

    if intention.label == IntentionLabel.MALICIOUS and intention.confidence >= state.proxy_config.misdirection_threshold:
        # Generate misdirection with adaptive config if available
        if adaptive_config:
            engine = CMPEEngine(config=adaptive_config)
        else:
            engine = state.engine

        misdirection = engine.generate(
            prompt=user_content,
            detected_intention=intention.detected_intention,
        )
        state.misdirected_requests += 1
        misdirections_total.inc()

        # Update session with misdirect result
        if session_id:
            await state.session_manager.record(
                session_id=session_id,
                suspicion_score=_intention_to_suspicion(intention),
                was_misdirected=True,
            )

        response_content = {
            "id": f"misdirect-{int(time.time() * 1000)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "misdirection-gateway",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": misdirection.full_response,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            },
            "misdirection": {
                "triggered": True,
                "intention": intention.detected_intention,
                "confidence": intention.confidence,
                "gamma_a": round(gamma_a, 4),
                "adaptive": bool(session_id),
            },
        }

        # Include context filter results if any
        if context_filter_results:
            response_content["context_filter"] = {
                "sources_filtered": len(context_filter_results),
                "details": context_filter_results,
            }

        return JSONResponse(content=response_content)

    # Benign or suspicious — forward to upstream LLM
    return await _forward_to_upstream(body)


@app.get("/health")
async def health():
    """Health check endpoint."""
    uptime = time.time() - state.start_time if state.start_time else 0
    return {
        "status": "healthy",
        "version": "0.2.0",
        "uptime_seconds": round(uptime, 1),
    }


@app.get("/metrics")
async def metrics():
    """Prometheus-compatible metrics endpoint.

    Returns metrics in Prometheus text exposition format.
    """
    # Update Redis health gauge and trigger retry (FIX #11 + #12)
    from misdirection.proxy.metrics import redis_healthy

    # is_using_redis is a property (bool), not a method — don't call it
    redis_val = 1 if getattr(state.session_manager, 'is_using_redis', False) else 0
    redis_healthy.set(redis_val)

    # Trigger periodic retry if in fallback (FIX #12)
    # Each Prometheus scrape (15-30s) acts as the retry trigger
    from contextlib import suppress
    with suppress(Exception):
        await state.session_manager.health_check()  # health_check failures are non-fatal for metrics endpoint

    body, content_type = get_metrics_response()
    return Response(content=body, media_type=content_type)


@app.post("/analyze")
async def analyze(request: Request):
    """Analyze a prompt without proxying — returns intention analysis."""
    body = await request.json()
    prompt = body.get("prompt", "")

    if not prompt:
        raise HTTPException(status_code=400, detail="Missing 'prompt' field")

    intention = state.detector.detect(prompt)

    return {
        "prompt": prompt,
        "label": intention.label.value,
        "confidence": intention.confidence,
        "detected_intention": intention.detected_intention,
        "matched_patterns": intention.matched_patterns,
    }


@app.post("/evaluate")
async def evaluate(request: Request):
    """Run evaluation metrics for given defense parameters."""
    body = await request.json()

    defense = DefenseConfig(
        detector_fn_rate=body.get("detector_fn_rate", 0.011),
        detector_fp_rate=body.get("detector_fp_rate", 0.1),
        gamma_a=body.get("gamma_a", 0.627),
    )
    attacker = JudgeProfile(
        false_negative_rate=body.get("attacker_fn_rate", 0.05),
        false_positive_rate=body.get("attacker_fp_rate", 0.15),
    )
    prior = body.get("prior_malicious", 0.5)
    n_attempts = body.get("n_attempts", 100)
    verification_budget = body.get("verification_budget", 1)
    n_cycles = body.get("n_cycles", 5)

    evaluator = MisdirectionEvaluator(
        defense=defense, attacker_judge=attacker, prior_malicious=prior
    )

    block = evaluator.analyze_detect_and_block(n_attempts=n_attempts)
    misdirect = evaluator.analyze_detect_and_misdirect(n_attempts=n_attempts)
    multi = evaluator.analyze_multi_cycle(
        verification_budget=verification_budget, n_cycles=n_cycles
    )
    cost = evaluator.attacker_cost_analysis(
        n_judges=body.get("n_judges", 1),
        verification_budget=verification_budget,
        n_cycles=n_cycles,
    )

    return {
        "detect_and_block": {
            "asr": round(block.asr_per_cycle, 6),
            "ppv": round(block.ppv, 6),
            "p_a1": round(block.p_a1, 6),
        },
        "detect_and_misdirect": {
            "asr": round(misdirect.asr_per_cycle, 6),
            "ppv": round(misdirect.ppv, 6),
            "p_a1": round(misdirect.p_a1, 6),
            "noise_misdirect": round(misdirect.noise_misdirect, 6),
        },
        "asr_reduction_factor": round(
            block.asr_per_cycle / misdirect.asr_per_cycle
            if misdirect.asr_per_cycle > 0
            else float("inf"),
            2,
        ),
        "multi_cycle": {
            "survival_probability": round(multi.survival_probability, 6),
            "contamination_probability": round(multi.contamination_probability, 6),
            "cumulative_contamination": round(multi.cumulative_contamination, 6),
            "cycles_to_95_percent": round(multi.cycles_to_absorbing, 2),
        },
        "attacker_cost": {
            "relative_cost": round(cost["compute_cost_relative"], 2),
            "asr_with_misdirection": round(cost["asr_with_misdirection"], 6),
            "asr_without_misdirection": round(cost["asr_without_misdirection"], 6),
        },
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_user_content(messages: list[dict]) -> str:
    """Extract the last user message content from a messages list."""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                # Handle multi-modal content — extract text parts
                parts = []
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        parts.append(item.get("text", ""))
                return " ".join(parts)
    return ""


def _intention_to_suspicion(intention) -> float:
    """Map intention label to suspicion score for adaptive controller.

    Scores:
        benign -> 0.0
        suspicious -> 0.5
        malicious -> 1.0
    """
    mapping = {
        IntentionLabel.BENIGN: 0.0,
        IntentionLabel.SUSPICIOUS: 0.5,
        IntentionLabel.MALICIOUS: 1.0,
    }
    return mapping.get(intention.label, 0.0)


async def _forward_to_upstream(body: dict[str, Any]):
    """Forward the request to the upstream LLM provider."""
    headers = {
        "Content-Type": "application/json",
    }
    if state.upstream_api_key:
        headers["Authorization"] = f"Bearer {state.upstream_api_key}"

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{state.upstream_base_url}/v1/chat/completions",
                json=body,
                headers=headers,
            )
            return JSONResponse(
                content=response.json(),
                status_code=response.status_code,
            )
    except httpx.ConnectError:
        raise HTTPException(
            status_code=502,
            detail=f"Cannot connect to upstream LLM at {state.upstream_base_url}",
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="Upstream LLM request timed out",
        )
