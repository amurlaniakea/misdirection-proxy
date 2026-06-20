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

import os
import time
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from misdirection.core.cmpe import CMPEConfig, CMPEEngine
from misdirection.detector.intention import IntentionDetector, IntentionLabel
from misdirection.eval.metrics import (
    DefenseConfig,
    JudgeProfile,
    MisdirectionEvaluator,
)
from misdirection.proxy.proxy import ProxyConfig, ProxyDecision


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
        # Metrics
        self.total_requests: int = 0
        self.misdirected_requests: int = 0
        self.blocked_requests: int = 0
        self.start_time: float = 0.0
        # Upstream LLM config
        self.upstream_base_url: str = os.getenv(
            "UPSTREAM_LLM_URL", "http://localhost:11434"
        )
        self.upstream_api_key: str = os.getenv("UPSTREAM_LLM_API_KEY", "")


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
    """
    body = await request.json()
    state.total_requests += 1

    # Extract user messages
    messages = body.get("messages", [])
    user_content = _extract_user_content(messages)

    if not user_content:
        # No user content to analyze — forward as-is
        return await _forward_to_upstream(body)

    # Analyze intention
    intention = state.detector.detect(user_content)

    if intention.label == IntentionLabel.MALICIOUS and intention.confidence >= state.proxy_config.misdirection_threshold:
        # Generate misdirection response
        misdirection = state.engine.generate(
            prompt=user_content,
            detected_intention=intention.detected_intention,
        )
        state.misdirected_requests += 1

        return JSONResponse(
            content={
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
                },
            }
        )

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
    """Gateway metrics."""
    uptime = time.time() - state.start_time if state.start_time else 0
    return {
        "total_requests": state.total_requests,
        "misdirected_requests": state.misdirected_requests,
        "blocked_requests": state.blocked_requests,
        "misdirect_rate": (
            state.misdirected_requests / state.total_requests
            if state.total_requests > 0
            else 0.0
        ),
        "uptime_seconds": round(uptime, 1),
        "upstream_url": state.upstream_base_url,
    }


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
