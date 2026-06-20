"""Tests for Evaluation Metrics."""

import pytest

from misdirection.eval.metrics import (
    ASResult,
    DefenseConfig,
    JudgeProfile,
    MisdirectionEvaluator,
    MultiCycleResult,
)


class TestMisdirectionEvaluator:
    """Test suite for the evaluation metrics."""

    def setup_method(self):
        self.defense = DefenseConfig(
            detector_fn_rate=0.011,
            detector_fp_rate=0.1,
            gamma_a=0.627,
        )
        self.attacker = JudgeProfile(
            false_negative_rate=0.05,
            false_positive_rate=0.15,
        )
        self.eval = MisdirectionEvaluator(
            defense=self.defense,
            attacker_judge=self.attacker,
            prior_malicious=0.5,
        )

    def test_detect_and_block_returns_valid_asr(self):
        result = self.eval.analyze_detect_and_block(n_attempts=100)
        assert isinstance(result, ASResult)
        assert 0.0 <= result.asr_per_cycle <= 1.0
        assert 0.0 <= result.ppv <= 1.0

    def test_detect_and_misdirect_returns_valid_asr(self):
        result = self.eval.analyze_detect_and_misdirect(n_attempts=100)
        assert isinstance(result, ASResult)
        assert 0.0 <= result.asr_per_cycle <= 1.0
        assert 0.0 <= result.ppv <= 1.0

    def test_misdirection_reduces_ppv(self):
        block = self.eval.analyze_detect_and_block(n_attempts=100)
        misdirect = self.eval.analyze_detect_and_misdirect(n_attempts=100)
        assert misdirect.ppv < block.ppv

    def test_misdirection_has_higher_noise(self):
        block = self.eval.analyze_detect_and_block(n_attempts=100)
        misdirect = self.eval.analyze_detect_and_misdirect(n_attempts=100)
        assert misdirect.noise_misdirect > block.noise_misdirect
        assert misdirect.p_a1 > block.p_a1

    def test_asr_increases_with_n_attempts(self):
        low_n = self.eval.analyze_detect_and_block(n_attempts=10)
        high_n = self.eval.analyze_detect_and_block(n_attempts=1000)
        assert high_n.asr_per_cycle >= low_n.asr_per_cycle

    def test_asr_converges_to_1_with_large_n(self):
        result = self.eval.analyze_detect_and_block(n_attempts=10000)
        assert result.asr_per_cycle > 0.99

    def test_asr_bound_reduces_with_misdirection(self):
        block = self.eval.compute_asr_bound(verification_budget=1, use_misdirection=False)
        misdirect = self.eval.compute_asr_bound(verification_budget=1, use_misdirection=True)
        assert misdirect < block

    def test_misdirection_asr_bound_stays_bounded(self):
        result = self.eval.compute_asr_bound(verification_budget=1, use_misdirection=True)
        assert result < 0.05

    def test_multi_cycle_returns_valid_results(self):
        result = self.eval.analyze_multi_cycle(verification_budget=1, n_cycles=5)
        assert isinstance(result, MultiCycleResult)
        assert 0.0 <= result.survival_probability <= 1.0
        assert 0.0 <= result.contamination_probability <= 1.0
        assert 0.0 <= result.cumulative_contamination <= 1.0

    def test_multi_cycle_contamination_increases_with_cycles(self):
        low = self.eval.analyze_multi_cycle(verification_budget=1, n_cycles=1)
        high = self.eval.analyze_multi_cycle(verification_budget=1, n_cycles=10)
        assert high.cumulative_contamination >= low.cumulative_contamination

    def test_multi_cycle_more_verification_reduces_contamination(self):
        low = self.eval.analyze_multi_cycle(verification_budget=1, n_cycles=5)
        high = self.eval.analyze_multi_cycle(verification_budget=5, n_cycles=5)
        assert high.contamination_probability < low.contamination_probability

    def test_asr_bound_with_verification(self):
        bound = self.eval.compute_asr_bound(verification_budget=1, use_misdirection=True)
        assert 0.0 <= bound <= 1.0

    def test_asr_bound_increases_with_k(self):
        low = self.eval.compute_asr_bound(verification_budget=1, use_misdirection=True)
        high = self.eval.compute_asr_bound(verification_budget=5, use_misdirection=True)
        assert high >= low

    def test_attacker_cost_analysis(self):
        result = self.eval.attacker_cost_analysis(
            base_cost=1.0, n_judges=1, verification_budget=1, n_cycles=1,
        )
        assert "compute_cost_relative" in result
        assert "asr_with_misdirection" in result
        assert result["asr_with_misdirection"] < result["asr_without_misdirection"]

    def test_attacker_cost_increases_with_judges(self):
        low = self.eval.attacker_cost_analysis(n_judges=1, verification_budget=1)
        high = self.eval.attacker_cost_analysis(n_judges=6, verification_budget=1)
        assert high["compute_cost_relative"] > low["compute_cost_relative"]

    def test_paper_reduction_factor(self):
        defense = DefenseConfig(detector_fn_rate=0.011, detector_fp_rate=0.1, gamma_a=0.627)
        attacker_judge = JudgeProfile(false_negative_rate=0.05, false_positive_rate=0.15)
        ev = MisdirectionEvaluator(defense=defense, attacker_judge=attacker_judge, prior_malicious=0.5)
        block = ev.compute_asr_bound(verification_budget=1, use_misdirection=False)
        misdirect = ev.compute_asr_bound(verification_budget=1, use_misdirection=True)
        reduction = block / misdirect if misdirect > 0 else float('inf')
        assert reduction > 5.0

    def test_extreme_gamma_a(self):
        defense = DefenseConfig(detector_fn_rate=0.011, detector_fp_rate=0.1, gamma_a=0.98)
        ev = MisdirectionEvaluator(defense=defense, attacker_judge=self.attacker, prior_malicious=0.5)
        result = ev.analyze_detect_and_misdirect(n_attempts=100)
        assert result.ppv < 0.01

    def test_zero_gamma_a_equals_block(self):
        defense = DefenseConfig(detector_fn_rate=0.011, detector_fp_rate=0.1, gamma_a=0.0)
        ev = MisdirectionEvaluator(defense=defense, attacker_judge=self.attacker, prior_malicious=0.5)
        misdirect = ev.analyze_detect_and_misdirect(n_attempts=100)
        block = ev.analyze_detect_and_block(n_attempts=100)
        assert abs(misdirect.ppv - block.ppv) < 0.001
