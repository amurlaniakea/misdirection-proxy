# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.5.0   | Yes       |

## Reporting a Security Vulnerability

If you discover a security vulnerability in Misdirection Proxy, please report it responsibly.

**Do NOT open a public GitHub Issue for security vulnerabilities.**

Instead, report via email:
- **Email:** amurlaniakea@gmail.com
- **Subject:** `[SECURITY] Misdirection Proxy vulnerability`

Include:
1. Description of the vulnerability
2. Steps to reproduce
3. Affected component
4. Potential impact assessment

You will receive a response within 48 hours.

## Security Considerations

Misdirection Proxy is a defense tool, but has limitations:

- **Intention Detector:** Pattern-based detection can be bypassed by novel attack prompts not matching known patterns.
- **CMPE Engine:** Misdirection responses are heuristic. A sufficiently sophisticated attacker may distinguish them from genuine responses.
- **Adaptive Controller:** The γ_A escalation is logarithmic — very persistent attackers may still succeed given enough queries.
- **Context Filter:** Indirect injection detection relies on pattern matching. Novel injection techniques may evade detection.

**Use Misdirection Proxy as one layer in a defense-in-depth strategy.**

## Dependencies

Runtime: `fastapi`, `uvicorn`, `pydantic`, `httpx`, `python-dotenv`
Dev: `pytest`, `pytest-asyncio`, `pytest-cov`

All dependencies are pinned in `pyproject.toml`.
