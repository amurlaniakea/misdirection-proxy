"""Evaluation metrics for misdirection defense.

Implements the probabilistic framework from Soosahabi & Namsani (2026):
- ASR (Attack Success Rate) bounds
- PPV (Positive Predictive Value) of attacker judge
- γ_A (misdirection-induced false positive rate)
- Multi-cycle contamination model
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class JudgeProfile:
    """Error rates for a judge (attacker-side or defender-side)."""
    false_negative_rate: float  # β: P(judge=0 | T=1)
    false_positive_rate: float  # α: P(judge=1 | T=0)

    def __post_init__(self):
        assert 0.0 <= self.false_negative_rate <= 1.0
        assert 0.0 <= self.false_positive_rate <= 1.0


@dataclass
class DefenseConfig:
    """Configuration for the defense system."""
    detector_fn_rate: float  # β_D: defender false negative rate
    detector_fp_rate: float  # α_D: defender false negative rate
    gamma_a: float           # γ_A: misdirection-induced FP rate

    def __post_init__(self):
        assert 0.0 <= self.detector_fn_rate <= 1.0
        assert 0.0 <= self.detector_fp_rate <= 1.0
        assert 0.0 <= self.gamma_a <= 1.0


@dataclass
class ASResult:
    """Attack Success Rate analysis results."""
    asr_per_cycle: float
    ppv: float
    p_a1: float  # P(A=1): probability attacker judge accepts
    signal: float  # true positive component
    noise_block: float  # FP component without misdirection
    noise_misdirect: float  # FP component from misdirection


@dataclass
class MultiCycleResult:
    """Multi-cycle contamination analysis."""
    survival_probability: float  # P(attacker finds TP in one cycle)
    contamination_probability: float  # P(all candidates are FPs)
    cumulative_contamination: float  # P(contaminated after G cycles)
    cycles_to_absorbing: float  # Expected cycles to full contamination


class MisdirectionEvaluator:
    """Evaluates misdirection defense effectiveness."""

    def __init__(
        self,
        defense: DefenseConfig,
        attacker_judge: JudgeProfile,
        prior_malicious: float = 0.5,
    ):
        self.defense = defense
        self.attacker_judge = attacker_judge
        self.prior = prior_malicious

    def analyze_detect_and_block(self, n_attempts: int = 100) -> ASResult:
        """Analyze ASR under detect-and-block (no misdirection)."""
        q = self.prior
        beta_d = self.defense.detector_fn_rate
        alpha_d = self.defense.detector_fp_rate
        beta_a = self.attacker_judge.false_negative_rate
        alpha_a = self.attacker_judge.false_positive_rate

        # Signal: true positives that pass detector and judge
        signal = q * beta_d * (1 - beta_a)

        # Noise: false positives from detector that judge accepts
        noise = (1 - q) * (1 - alpha_d) * alpha_a

        p_a1 = signal + noise

        # PPV
        ppv = signal / p_a1 if p_a1 > 0 else 0.0

        # ASR with N attempts
        asr = 1.0 - (1.0 - p_a1) ** n_attempts

        return ASResult(
            asr_per_cycle=asr,
            ppv=ppv,
            p_a1=p_a1,
            signal=signal,
            noise_block=noise,
            noise_misdirect=0.0,
        )

    def analyze_detect_and_misdirect(self, n_attempts: int = 100) -> ASResult:
        """Analyze ASR under detect-and-misdirection (with CMPE)."""
        q = self.prior
        beta_d = self.defense.detector_fn_rate
        alpha_d = self.defense.detector_fp_rate
        beta_a = self.attacker_judge.false_negative_rate
        alpha_a = self.attacker_judge.false_positive_rate
        gamma_a = self.defense.gamma_a

        # Signal: same as detect-and-block
        signal = q * beta_d * (1 - beta_a)

        # Noise from detector FPs (same as block)
        noise_block = (1 - q) * (1 - alpha_d) * alpha_a

        # Additional noise from misdirection
        p_d1 = q * (1 - beta_d) + (1 - q) * alpha_d  # P(D=1)
        noise_misdirect = gamma_a * p_d1

        p_a1 = signal + noise_block + noise_misdirect

        # PPV: signal / total
        ppv = signal / p_a1 if p_a1 > 0 else 0.0

        # ASR with N attempts
        asr = 1.0 - (1.0 - p_a1) ** n_attempts

        return ASResult(
            asr_per_cycle=asr,
            ppv=ppv,
            p_a1=p_a1,
            signal=signal,
            noise_block=noise_block,
            noise_misdirect=noise_misdirect,
        )

    def analyze_multi_cycle(
        self,
        verification_budget: int = 1,
        n_cycles: int = 5,
    ) -> MultiCycleResult:
        """Analyze multi-cycle contamination dynamics.

        Args:
            verification_budget: K — candidates verified per cycle.
            n_cycles: G — number of attack cycles.

        Returns:
            MultiCycleResult with contamination probabilities.
        """
        misdirect = self.analyze_detect_and_misdirect()
        ppv = misdirect.ppv

        # Probability that all K candidates in one cycle are FPs
        p_all_fp = (1.0 - ppv) ** verification_budget

        # Probability that attacker finds at least one TP in one cycle
        survival = 1.0 - p_all_fp

        # Cumulative contamination after G cycles
        cumulative = 1.0 - (1.0 - p_all_fp) ** n_cycles

        # Expected cycles to reach 95% contamination
        if p_all_fp > 0:
            import math
            cycles_95 = math.log(0.05) / math.log(1.0 - p_all_fp) if p_all_fp < 1.0 else float('inf')
        else:
            cycles_95 = float('inf')

        return MultiCycleResult(
            survival_probability=survival,
            contamination_probability=p_all_fp,
            cumulative_contamination=cumulative,
            cycles_to_absorbing=cycles_95,
        )

    def compute_asr_bound(
        self,
        verification_budget: int = 1,
        use_misdirection: bool = True,
    ) -> float:
        """Compute ASR upper bound after verification.

        ASR_bound = 1 - (1 - PPV)^K

        This is the probability that at least one of K verified
        candidates is a true positive.
        """
        if use_misdirection:
            result = self.analyze_detect_and_misdirect()
        else:
            result = self.analyze_detect_and_block()
        return 1.0 - (1.0 - result.ppv) ** verification_budget

    def attacker_cost_analysis(
        self,
        base_cost: float = 1.0,
        n_judges: int = 1,
        verification_budget: int = 1,
        n_cycles: int = 1,
    ) -> dict:
        """Compute attacker cost and utility.

        Returns dict with cost breakdown and utility.
        """
        misdirect = self.analyze_detect_and_misdirect()
        block = self.analyze_detect_and_block()

        # Cost scales with judges and verification
        compute_cost = base_cost * n_judges * verification_budget * n_cycles

        # ASR with misdirection
        asr_misdirect = self.compute_asr_bound(verification_budget, use_misdirection=True)
        asr_block = self.compute_asr_bound(verification_budget, use_misdirection=False)

        return {
            "compute_cost_relative": compute_cost,
            "asr_with_misdirection": asr_misdirect,
            "asr_without_misdirection": asr_block,
            "ppv_with_misdirection": misdirect.ppv,
            "ppv_without_misdirection": block.ppv,
            "asr_reduction_factor": asr_block / asr_misdirect if asr_misdirect > 0 else float('inf'),
        }
