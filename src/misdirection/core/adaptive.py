"""Adaptive Misdirection Controller (Frente 1).

Implements dynamic γ_A scaling based on session history.

Modelo matemático:
    γ_A(t) = min(γ_base + ln(1 + ω · Σ M_i), γ_max)

Donde:
    γ_base:  valor inicial del paper CMPE (default: 0.71)
    M_i:     severidad de la petición i (0.0=benign, 0.5=suspicious, 1.0=malicious)
    ω:       factor de agresividad (default: 0.5)
    γ_max:   límite superior (default: 0.99)

A medida que γ_A(t) crece, el CMPE Engine incrementa:
- Inyección de glue tokens (más tokens de distracción)
- Shuffle agresivo (ventanas de coherencia más pequeñas)
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from threading import RLock


@dataclass
class SessionRecord:
    """Record of a single request within a session."""
    timestamp: float
    intention_label: str
    confidence: float
    suspicion_score: float  # M_i: 0.0=benign, 0.5=suspicious, 1.0=malicious
    was_misdirected: bool


@dataclass
class SessionState:
    """Accumulated state for a session."""
    session_id: str
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    requests: list[SessionRecord] = field(default_factory=list)
    cumulative_suspicion: float = 0.0  # Σ M_i
    misdirect_count: int = 0
    total_count: int = 0

    @property
    def current_gamma_a(self) -> float:
        """Calculate current γ_A based on session history."""
        return _calc_gamma_a(self.cumulative_suspicion)


def _calc_gamma_a(
    cumulative_suspicion: float,
    gamma_base: float = 0.71,
    omega: float = 0.5,
    gamma_max: float = 0.99,
) -> float:
    """Core formula: γ_A(t) = min(γ_base + ln(1 + ω · Σ M_i), γ_max)"""
    return min(gamma_base + math.log(1.0 + omega * cumulative_suspicion), gamma_max)


# Severity mapping for intention labels
_SUSPICION_SCORES = {
    "benign": 0.0,
    "suspicious": 0.5,
    "malicious": 1.0,
}


class InMemorySessionStore:
    """Thread-safe in-memory session store.

    MVP implementation — can be swapped with Redis backend.
    """

    def __init__(self, max_sessions: int = 10000, ttl_seconds: float = 3600.0):
        self._sessions: dict[str, SessionState] = {}
        self._lock = RLock()
        self._max_sessions = max_sessions
        self._ttl = ttl_seconds

    def get_or_create(self, session_id: str) -> SessionState:
        with self._lock:
            if session_id not in self._sessions:
                # Evict oldest if at capacity
                if len(self._sessions) >= self._max_sessions:
                    self._evict_oldest()
                self._sessions[session_id] = SessionState(session_id=session_id)
            return self._sessions[session_id]

    def record(
        self,
        session_id: str,
        intention_label: str,
        confidence: float,
        was_misdirected: bool,
    ) -> SessionState:
        with self._lock:
            session = self.get_or_create(session_id)
            suspicion = _SUSPICION_SCORES.get(intention_label, 0.0)
            record = SessionRecord(
                timestamp=time.time(),
                intention_label=intention_label,
                confidence=confidence,
                suspicion_score=suspicion,
                was_misdirected=was_misdirected,
            )
            session.requests.append(record)
            session.cumulative_suspicion += suspicion
            session.total_count += 1
            if was_misdirected:
                session.misdirect_count += 1
            session.last_activity = time.time()
            return session

    def get(self, session_id: str) -> SessionState | None:
        with self._lock:
            return self._sessions.get(session_id)

    def cleanup_expired(self) -> int:
        """Remove expired sessions. Returns count of removed sessions."""
        now = time.time()
        with self._lock:
            expired = [
                sid for sid, s in self._sessions.items()
                if now - s.last_activity > self._ttl
            ]
            for sid in expired:
                del self._sessions[sid]
            return len(expired)

    def _evict_oldest(self):
        """Evict the least recently active session."""
        if not self._sessions:
            return
        oldest_sid = min(self._sessions, key=lambda sid: self._sessions[sid].last_activity)
        del self._sessions[oldest_sid]


@dataclass
class AdaptiveConfig:
    """Configuration for the adaptive controller."""
    gamma_base: float = 0.71       # γ_base from paper
    omega: float = 0.5             # aggressiveness factor
    gamma_max: float = 0.99        # asymptotic ceiling
    # Shrink factor for shuffle window as γ_A grows (1.0 = no shrink, 0.1 = max shrink)
    min_shrink_factor: float = 0.2
    # Max glue injection probability
    max_glue_prob: float = 0.9


class AdaptiveController:
    """Calculates dynamic defense parameters based on session state."""

    def __init__(self, config: AdaptiveConfig | None = None):
        self.config = config or AdaptiveConfig()

    def get_gamma_a(self, cumulative_suspicion: float) -> float:
        """Calculate γ_A for given cumulative suspicion."""
        return _calc_gamma_a(
            cumulative_suspicion=cumulative_suspicion,
            gamma_base=self.config.gamma_base,
            omega=self.config.omega,
            gamma_max=self.config.gamma_max,
        )

    def get_shuffle_window(self, gamma_a: float, base_max_tokens: int = 15) -> int:
        """Calculate adaptive shuffle window size.

        As γ_A grows, the window shrinks to fragment coherent phrases.
        """
        # Linear interpolation: at γ_A=gamma_base → full window, at γ_A=gamma_max → shrunk
        shrink = 1.0 - (gamma_a - self.config.gamma_base) / (
            self.config.gamma_max - self.config.gamma_base
        )
        shrink = max(shrink, self.config.min_shrink_factor)
        return max(2, int(base_max_tokens * shrink))

    def get_glue_probability(self, gamma_a: float) -> float:
        """Calculate adaptive glue token injection probability."""
        # γ_A=gamma_base → 0.3, γ_A=gamma_max → max_glue_prob
        ratio = (gamma_a - self.config.gamma_base) / (self.config.gamma_max - self.config.gamma_base)
        return min(0.3 + ratio * (self.config.max_glue_prob - 0.3), self.config.max_glue_prob)

    def get_expansion_budget(self, gamma_a: float, base_budget: int = 50) -> int:
        """Calculate adaptive expansion budget.

        As γ_A grows, expansion increases to dilute any remaining coherence.
        """
        ratio = (gamma_a - self.config.gamma_base) / (self.config.gamma_max - self.config.gamma_base)
        return int(base_budget * (1.0 + ratio * 0.5))

    def get_adaptive_cmpe_config(self, cumulative_suspicion: float):
        """Generate a CMPEConfig adapted to the current threat level."""
        from misdirection.core.cmpe import CMPEConfig

        gamma_a = self.get_gamma_a(cumulative_suspicion)
        return CMPEConfig(
            expansion_budget=self.get_expansion_budget(gamma_a),
            glue_injection_prob=self.get_glue_probability(gamma_a),
            max_shuffle_tokens=self.get_shuffle_window(gamma_a),
            seed=None,
        )
