"""Tests for Adaptive Controller (Frente 1)."""

import math
import pytest

from misdirection.core.adaptive import (
    AdaptiveConfig,
    AdaptiveController,
    InMemorySessionStore,
    _calc_gamma_a,
)


class TestGammaAFormula:
    """Tests for the core γ_A(t) formula: γ_A(t) = min(γ_base + ln(1 + ω · Σ M_i), γ_max)."""

    def test_zero_suspicion_equals_base(self):
        result = _calc_gamma_a(0.0)
        assert result == pytest.approx(0.71)

    def test_increases_with_suspicion(self):
        g0 = _calc_gamma_a(0.0)
        g1 = _calc_gamma_a(1.0)
        g5 = _calc_gamma_a(5.0)
        assert g0 < g1 <= g5

    def test_bounded_by_gamma_max(self):
        result = _calc_gamma_a(1000.0)
        assert result <= 0.99

    def test_logarithmic_growth(self):
        """First unit of suspicion adds more than later units (diminishing returns)."""
        g0 = _calc_gamma_a(0.0)
        g1 = _calc_gamma_a(1.0)
        g2 = _calc_gamma_a(2.0)
        assert g1 - g0 > g2 - g1

    def test_custom_params(self):
        result = _calc_gamma_a(5.0, gamma_base=0.5, omega=1.0, gamma_max=0.95)
        expected = min(0.5 + math.log(1.0 + 1.0 * 5.0), 0.95)
        assert result == pytest.approx(expected)

    def test_omega_scales_effect(self):
        g_low = _calc_gamma_a(0.5, omega=0.1)
        g_high = _calc_gamma_a(0.5, omega=2.0)
        assert g_high > g_low


class TestInMemorySessionStore:
    def test_create_session(self):
        store = InMemorySessionStore()
        session = store.get_or_create("test-123")
        assert session.session_id == "test-123"
        assert session.total_count == 0

    def test_record_request(self):
        store = InMemorySessionStore()
        session = store.record("s1", "malicious", 0.8, True)
        assert session.total_count == 1
        assert session.misdirect_count == 1
        assert session.cumulative_suspicion == 1.0

    def test_record_benign(self):
        store = InMemorySessionStore()
        session = store.record("s1", "benign", 0.9, False)
        assert session.total_count == 1
        assert session.misdirect_count == 0
        assert session.cumulative_suspicion == 0.0

    def test_record_suspicious(self):
        store = InMemorySessionStore()
        session = store.record("s1", "suspicious", 0.5, False)
        assert session.cumulative_suspicion == 0.5

    def test_cumulative_across_requests(self):
        store = InMemorySessionStore()
        store.record("s1", "malicious", 0.8, True)
        store.record("s1", "malicious", 0.9, True)
        store.record("s1", "benign", 0.9, False)
        session = store.get("s1")
        assert session.total_count == 3
        assert session.cumulative_suspicion == 2.0
        assert session.misdirect_count == 2

    def test_get_nonexistent(self):
        store = InMemorySessionStore()
        assert store.get("nonexistent") is None

    def test_cleanup_expired(self):
        store = InMemorySessionStore(ttl_seconds=0.01)
        store.get_or_create("old-session")
        import time
        time.sleep(0.02)
        removed = store.cleanup_expired()
        assert removed == 1
        assert store.get("old-session") is None

    def test_max_sessions_eviction(self):
        store = InMemorySessionStore(max_sessions=3)
        for i in range(5):
            store.get_or_create(f"session-{i}")
        assert store.get("session-0") is None
        assert store.get("session-1") is None
        assert store.get("session-4") is not None


class TestAdaptiveController:
    def test_get_gamma_a(self):
        ctrl = AdaptiveController()
        g = ctrl.get_gamma_a(5.0)
        assert 0.71 < g <= 0.99

    def test_get_shuffle_window_shrinks(self):
        ctrl = AdaptiveController()
        w_base = ctrl.get_shuffle_window(0.71, base_max_tokens=15)
        w_high = ctrl.get_shuffle_window(0.95, base_max_tokens=15)
        assert w_high < w_base

    def test_glue_prob_increases(self):
        ctrl = AdaptiveController()
        p_base = ctrl.get_glue_probability(0.71)
        p_high = ctrl.get_glue_probability(0.95)
        assert p_high > p_base

    def test_expansion_budget_increases(self):
        ctrl = AdaptiveController()
        b_base = ctrl.get_expansion_budget(0.71)
        b_high = ctrl.get_expansion_budget(0.95)
        assert b_high > b_base

    def test_adaptive_cmpe_config(self):
        from misdirection.core.cmpe import CMPEConfig
        ctrl = AdaptiveController()
        config_low = ctrl.get_adaptive_cmpe_config(0.0)
        config_high = ctrl.get_adaptive_cmpe_config(10.0)
        assert isinstance(config_low, CMPEConfig)
        assert isinstance(config_high, CMPEConfig)
        assert config_high.glue_injection_prob >= config_low.glue_injection_prob
        assert config_high.max_shuffle_tokens <= config_low.max_shuffle_tokens
        assert config_high.expansion_budget >= config_low.expansion_budget


class TestAttackSimulation:
    def test_escalating_attack_gets_stronger_defense(self):
        store = InMemorySessionStore()
        session_id = "attacker-1"
        gamma_values = []
        for i in range(10):
            session = store.record(session_id, "malicious", 0.8, True)
            gamma_values.append(session.current_gamma_a)
        # Monotonically non-decreasing
        for i in range(1, len(gamma_values)):
            assert gamma_values[i] >= gamma_values[i - 1]
        # Final should be at or near max
        assert gamma_values[-1] > gamma_values[0]

    def test_benign_session_stays_at_base(self):
        store = InMemorySessionStore()
        for i in range(20):
            store.record("benign-user", "benign", 0.95, False)
        session = store.get("benign-user")
        assert session.current_gamma_a == pytest.approx(0.71)
        assert session.cumulative_suspicion == 0.0

    def test_mixed_traffic_escalates_gradually(self):
        store = InMemorySessionStore()
        for i in range(10):
            store.record("mixed", "malicious" if i % 3 == 0 else "benign", 0.7, i % 3 == 0)
        session = store.get("mixed")
        assert session.cumulative_suspicion == 4.0
        gamma = session.current_gamma_a
        assert 0.71 < gamma <= 0.99
