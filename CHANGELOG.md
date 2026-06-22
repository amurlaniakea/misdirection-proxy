# Changelog

All notable changes to Misdirection Proxy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-06-22

### Added
- CMPE Engine v0.1.0 — 3-step misdirection algorithm (positive preamble, prompt reshaping, follow-up question)
- Intention Detector v0.1.0 — 5 threat categories with pattern matching
- HTTP Gateway v0.2.0 — FastAPI proxy, OpenAI-compatible `/v1/chat/completions`
- Adaptive Controller v0.3.0 — Dynamic γ_A via `X-Session-ID`, logarithmic escalation
- Context Filter v0.4.0 — Indirect injection detection for RAG/tool-use
- Adversarial Benchmark v0.5.0 — Dual-mode attacker (deterministic + Ollama), PPV/ASR metrics
- Docker Compose stack: proxy + Ollama + model preloader + benchmark profile
- 147 tests (unit + integration)
- CI/CD via GitHub Actions
- Makefile with standard targets
- ruff, mypy, black configuration
- Coverage configuration (minimum 80%)
- SECURITY.md and CHANGELOG.md

### Security
- CMPE reduces ASR from 20% to 0-2% (GPTFuzz) and from 10% to 0% (PAIR)
- PPV reduction of 1-2 orders of magnitude
- Context filtering for indirect prompt injection in RAG/tool-use scenarios
