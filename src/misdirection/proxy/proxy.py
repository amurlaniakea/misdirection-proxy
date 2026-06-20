"""Misdirection Proxy — main defense layer.

Integrates intention detection + CMPE engine to provide
detect-and-misdirection defense for LLM-based systems.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from misdirection.core.cmpe import CMPEConfig, CMPEEngine, MisdirectionResponse
from misdirection.detector.intention import IntentionDetector, IntentionLabel


@dataclass
class ProxyConfig:
    """Configuration for the Misdirection Proxy."""
    cmpe_config: CMPEConfig = field(default_factory=CMPEConfig)
    # Confidence threshold above which misdirection is triggered
    misdirection_threshold: float = 0.5
    # Whether to log decisions
    log_decisions: bool = True


@dataclass
class ProxyDecision:
    """Record of a proxy decision."""
    timestamp: float
    original_prompt: str
    intention_label: str
    intention_confidence: float
    action: str  # "pass", "block", "misdirect"
    misdirection_response: MisdirectionResponse | None = None
    detected_intention: str | None = None


class MisdirectionProxy:
    """Main proxy that intercepts prompts and applies misdirection defense.

    Workflow:
    1. Receive prompt
    2. Detect intention (benign / suspicious / malicious)
    3. If malicious with sufficient confidence → generate misdirection response
    4. If suspicious → optionally apply light misdirection or pass with monitoring
    5. If benign → pass through unchanged
    """

    def __init__(self, config: ProxyConfig | None = None):
        self.config = config or ProxyConfig()
        self.detector = IntentionDetector()
        self.engine = CMPEEngine(config=self.config.cmpe_config)
        self._decision_log: list[ProxyDecision] = []

    def process(self, prompt: str) -> tuple[str, ProxyDecision]:
        """Process a prompt through the misdirection proxy.

        Args:
            prompt: The incoming prompt.

        Returns:
            Tuple of (response_text, decision_record).
            If benign, response_text is the original prompt (pass-through).
            If malicious, response_text is the misdirection response.
        """
        start = time.time()

        # Step 1: Detect intention
        intention = self.detector.detect(prompt)

        # Step 2: Decide action
        if intention.label == IntentionLabel.MALICIOUS and intention.confidence >= self.config.misdirection_threshold:
            # Generate misdirection response
            misdirection = self.engine.generate(
                prompt=prompt,
                detected_intention=intention.detected_intention,
            )
            decision = ProxyDecision(
                timestamp=start,
                original_prompt=prompt,
                intention_label=intention.label.value,
                intention_confidence=intention.confidence,
                action="misdirect",
                misdirection_response=misdirection,
                detected_intention=intention.detected_intention,
            )
            response = misdirection.full_response

        elif intention.label == IntentionLabel.SUSPICIOUS:
            # For suspicious, we pass but log
            decision = ProxyDecision(
                timestamp=start,
                original_prompt=prompt,
                intention_label=intention.label.value,
                intention_confidence=intention.confidence,
                action="pass_monitored",
                detected_intention=intention.detected_intention,
            )
            response = prompt  # Pass through

        else:
            # Benign — pass through
            decision = ProxyDecision(
                timestamp=start,
                original_prompt=prompt,
                intention_label=intention.label.value,
                intention_confidence=intention.confidence,
                action="pass",
            )
            response = prompt

        if self.config.log_decisions:
            self._decision_log.append(decision)

        return response, decision

    @property
    def decision_log(self) -> list[ProxyDecision]:
        """Return the decision log."""
        return list(self._decision_log)

    def get_statistics(self) -> dict:
        """Return statistics about proxy decisions."""
        if not self._decision_log:
            return {"total": 0}

        total = len(self._decision_log)
        actions = {}
        for d in self._decision_log:
            actions[d.action] = actions.get(d.action, 0) + 1

        return {
            "total": total,
            "actions": actions,
            "misdirect_rate": actions.get("misdirect", 0) / total,
            "pass_rate": actions.get("pass", 0) / total,
            "monitored_rate": actions.get("pass_monitored", 0) / total,
        }
