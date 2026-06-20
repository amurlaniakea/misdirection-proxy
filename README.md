# Misdirection Proxy

Defensive Misdirection Proxy for AI Agents — implementation of CMPE (Contextual Misdirection via Progressive Engagement) against automated jailbreak and prompt injection attacks.

**Author:** Pedro Sordo Martínez (amurlaniakea@gmail.com)
**License:** AGPL-3.0-or-later

## Overview

Based on the research paper "Analyzing Defensive Misdirection Against Model-Guided Automated Attacks on Agentic AI Systems" (Soosahabi & Namsani, 2026), this tool implements a detect-and-misdirection defense layer that:

1. Detects malicious prompts/intentions
2. Replaces predictable refusal responses with controlled misdirection responses
3. Degrades attacker judge PPV (Positive Predictive Value)
4. Bounds ASR (Attack Success Rate) even as attacker query budget grows

## Architecture

```
                    ┌─────────────────────────────┐
                    │     Misdirection Proxy       │
                    │                             │
  Attacker ──────►  │  ┌───────────────────────┐  │
                    │  │  Intention Detector    │  │
                    │  └───────────┬───────────┘  │
                    │              │               │
                    │              ▼               │
                    │  ┌───────────────────────┐  │
                    │  │   CMPE Engine         │  │
                    │  │  1. Positive preamble  │  │
                    │  │  2. Prompt reshaping   │  │
                    │  │  3. Follow-up question │  │
                    │  └───────────┬───────────┘  │
                    │              │               │
                    │              ▼               │
                    │  ┌───────────────────────┐  │
                    │  │  Response Generator    │  │
                    │  └───────────────────────┘  │
                    │                             │
                    └─────────────────────────────┘
```

## Quick Start

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## Status

v0.1.0 — Core implementation with CMPE engine, intention detector, proxy layer, and evaluation metrics.
