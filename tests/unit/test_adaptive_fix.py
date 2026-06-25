"""Reproduction test for Adaptive Controller omega inconsistency (Fix #4).

Bug: _calc_gamma_a used omega=0.3 by default, while AdaptiveConfig used omega=0.5.
The gamma_a reported in the gateway response (via SessionState.current_gamma_a)
did not match the gamma_a that determined the actual CMPEConfig applied.
"""
import pytest
from misdirection.core.adaptive import (
    AdaptiveConfig,
    AdaptiveController,
    SessionState,
    _calc_gamma_a,
)


class TestAdaptiveOmegaConsistency:
    """Verify that all gamma_a calculation routes use the same omega."""

    def test_calc_gamma_a_default_omega_matches_adaptive_config(self):
        """_calc_gamma_a default omega must equal AdaptiveConfig default omega."""
        # _calc_gamma_a defaults: (cumulative_suspicion, gamma_base=0.71, omega=0.5, gamma_max=0.99)
        defaults = _calc_gamma_a.__defaults__
        assert defaults is not None
        assert defaults[1] == AdaptiveConfig().omega  # omega is 3rd param (index 1 in defaults tuple)

    def test_session_state_gamma_matches_controller_gamma(self):
        """SessionState.current_gamma_a must match AdaptiveController.get_gamma_a."""
        config = AdaptiveConfig(omega=0.5, gamma_base=0.71, gamma_max=0.99)
        controller = AdaptiveController(config=config)

        for suspicion in [0.0, 1.0, 3.0, 5.0, 10.0]:
            session = SessionState(session_id="test")
            session.cumulative_suspicion = suspicion

            # After fix: both should use omega=0.5
            assert session.current_gamma_a == pytest.approx(
                controller.get_gamma_a(suspicion)
            ), f"Mismatch at suspicion={suspicion}"

    def test_custom_omega_propagates_everywhere(self):
        """Custom omega in AdaptiveConfig must be used by the controller."""
        config = AdaptiveConfig(omega=0.8)
        controller = AdaptiveController(config=config)

        gamma = controller.get_gamma_a(5.0)
        expected = min(0.71 + __import__("math").log(1.0 + 0.8 * 5.0), 0.99)
        assert gamma == pytest.approx(expected)

    def test_gamma_a_never_exceeds_gamma_max(self):
        """γ_A must never exceed γ_max regardless of suspicion."""
        controller = AdaptiveController()
        for suspicion in [0, 1, 5, 10, 100]:
            gamma = controller.get_gamma_a(suspicion)
            assert gamma <= 0.99, f"gamma_a={gamma} exceeds gamma_max at suspicion={suspicion}"

    def test_gamma_a_monotonic_increasing(self):
        """γ_A should increase (or stay same) as suspicion grows."""
        controller = AdaptiveController()
        prev = 0.0
        for suspicion in [0.0, 0.5, 1.0, 2.0, 5.0]:
            gamma = controller.get_gamma_a(suspicion)
            assert gamma >= prev, f"gamma_a decreased: {prev} -> {gamma} at suspicion={suspicion}"
            prev = gamma
