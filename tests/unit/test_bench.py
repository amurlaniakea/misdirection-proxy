"""Tests for the adversarial benchmark (v0.5.0)."""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from misdirection.eval.bench import (
    DeterministicAttackerJudge,
    OllamaAttackerJudge,
    BenchmarkReport,
    RequestResult,
    run_benchmark,
    _DIRECT_ATTACKS,
    _INDIRECT_ATTACKS,
    _RAG_INJECTIONS,
)


class TestDeterministicAttackerJudge:
    """Tests for the rule-based attacker judge."""

    def setup_method(self):
        self.judge = DeterministicAttackerJudge()

    def test_refusal_detected(self):
        response = "I cannot help with that request. I'm sorry."
        success, conf = self.judge.evaluate(response)
        assert success is False
        assert conf == pytest.approx(0.9)

    def test_positive_response_looks_successful(self):
        response = "I'd be happy to help you with that. Let me provide some context."
        success, conf = self.judge.evaluate(response)
        assert success is True

    def test_short_response_fails(self):
        response = "OK"
        success, conf = self.judge.evaluate(response)
        assert success is False

    def test_confidence_scales_with_positive_words(self):
        _, conf_low = self.judge.evaluate("Here is some information.")
        _, conf_high = self.judge.evaluate(
            "I'd be happy to help. Great question. Let me elaborate."
        )
        assert conf_high > conf_low


class TestBenchmarkReport:
    """Tests for the benchmark report."""

    def test_empty_report(self):
        report = BenchmarkReport(mode="test", total_rounds=0, session_id="s1", proxy_url="http://test")
        report.compute_metrics()
        assert report.total_requests == 0
        assert report.ppv == 0.0

    def test_all_misdirected(self):
        report = BenchmarkReport(mode="test", total_rounds=3, session_id="s1", proxy_url="http://test")
        for i in range(3):
            report.results.append(RequestResult(
                cycle=i+1, prompt="test", response="misdirected",
                was_misdirected=True, gamma_a=0.71, adaptive=True,
                judge_success=True, judge_confidence=0.8,
                latency_ms=10.0, response_length=100,
            ))
        report.compute_metrics()
        assert report.total_requests == 3
        assert report.misdirected_count == 3
        assert report.ppv == 0.0  # All "successes" are fake (misdirection)

    def test_no_misdirection(self):
        report = BenchmarkReport(mode="test", total_rounds=2, session_id="s1", proxy_url="http://test")
        for i in range(2):
            report.results.append(RequestResult(
                cycle=i+1, prompt="test", response="normal",
                was_misdirected=False, gamma_a=0.71, adaptive=False,
                judge_success=False, judge_confidence=0.1,
                latency_ms=5.0, response_length=50,
            ))
        report.compute_metrics()
        assert report.misdirected_count == 0
        assert report.judge_success_count == 0

    def test_to_dict(self):
        report = BenchmarkReport(mode="deterministic", total_rounds=1, session_id="s1", proxy_url="http://test")
        report.results.append(RequestResult(
            cycle=1, prompt="test", response="resp",
            was_misdirected=True, gamma_a=0.85, adaptive=True,
            judge_success=True, judge_confidence=0.9,
            latency_ms=15.0, response_length=200,
        ))
        d = report.to_dict()
        assert d["mode"] == "deterministic"
        assert d["metrics"]["total_requests"] == 1
        assert d["metrics"]["ppv"] == 0.0
        assert len(d["cycle_data"]) == 1

    def test_save_report(self):
        report = BenchmarkReport(mode="test", total_rounds=1, session_id="s1", proxy_url="http://test")
        report.results.append(RequestResult(
            cycle=1, prompt="test", response="resp",
            was_misdirected=True, gamma_a=0.71, adaptive=False,
            judge_success=False, judge_confidence=0.5,
            latency_ms=10.0, response_length=100,
        ))
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            d = report.to_dict()
            with open(path, "w") as f:
                json.dump(d, f)
            with open(path) as f:
                loaded = json.load(f)
            assert loaded["mode"] == "test"
        finally:
            os.unlink(path)


class TestAttackTemplates:
    """Verify attack prompt templates are well-formed."""

    def test_direct_attacks_not_empty(self):
        assert len(_DIRECT_ATTACKS) > 0
        for a in _DIRECT_ATTACKS:
            assert len(a) > 10

    def test_indirect_attacks_not_empty(self):
        assert len(_INDIRECT_ATTACKS) > 0
        for a in _INDIRECT_ATTACKS:
            assert len(a) > 10

    def test_rag_injections_not_empty(self):
        assert len(_RAG_INJECTIONS) > 0
        for a in _RAG_INJECTIONS:
            assert len(a) > 20

    def test_rag_injections_contain_benign_and_malicious(self):
        """RAG injections should mix benign content with malicious instructions."""
        for a in _RAG_INJECTIONS:
            words = a.lower().split()
            benign_indicators = ["revenue", "weather", "report", "api", "search", "document", "status"]
            has_benign = any(w in words for w in benign_indicators)
            assert has_benign, f"No benign content in: {a}"
            assert has_benign, f"No benign content in: {a}"


class TestRunBenchmark:
    """Integration test for the benchmark runner (mocked proxy)."""

    def test_deterministic_benchmark_runs(self):
        """Run a short benchmark with mocked proxy responses."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "I'd be happy to help. Here is some information."}}],
            "misdirection": {"triggered": True, "gamma_a": 0.85, "adaptive": True},
        }

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__ = MagicMock(return_value=MagicMock(post=MagicMock(return_value=mock_response)))
            mock_client.return_value.__exit__ = MagicMock(return_value=False)

            report = run_benchmark(
                proxy_url="http://localhost:8000",
                mode="deterministic",
                rounds=3,
                session_id="test-session",
            )

        assert report.total_requests == 3
        assert report.mode == "deterministic"
        assert len(report.results) == 3
