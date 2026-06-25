"""Intention Detector — classifies prompts as benign or malicious.

Uses a rule-based approach with keyword matching and pattern detection.
In production, this would be replaced/augmented with an LLM-based classifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class IntentionLabel(Enum):
    BENIGN = "benign"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"


@dataclass
class IntentionResult:
    label: IntentionLabel
    confidence: float  # 0.0 to 1.0
    detected_intention: str | None = None
    matched_patterns: list[str] | None = None


# Roleplay markers — invocation verbs that alone are NOT malicious.
# They only escalate to MALICIOUS when combined with a dangerous payload
# (data_exfiltration, code_execution, social_engineering, or direct jailbreak).
_ROLEPLAY_MARKERS = [
    r"\bpretend\s+(you\s+are|to\s+be)\b",
    r"\bimagine\s+you\s+are\b",
    r"\bsuppose\s+you\s+are\b",
    r"\bact\s+as\s+(if|though)\b",
    r"\brole\s*play\b",
    r"\bpretend\b",
    r"\bin\s+this\s+scenario\b",
]

# Pattern categories for malicious intent detection
_MALICIOUS_PATTERNS = {
    "jailbreak": [
        r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions?\b",
        r"\bdisregard\s+(your\s+)?(safety\s+)?(guidelines?|rules?|policies?)\b",
        r"\bjailbreak\b",
        r"\bDAN\b",
        r"\bmode:\s*unfiltered\b",
        r"\bno\s+(restrictions?|limits?|boundaries?)\b",
        r"\bunrestricted\s+(mode|ai|version|instance)\b",
        r"\bunrestricted\b",
        r"\bbypass\s+(your\s+)?(safety|security|filter)\b",
        r"\boverride\s+(your\s+)?(safety|security|filter)\b",
    ],
    "data_exfiltration": [
        r"\b(send|exfiltrate|extract|leak|export|upload|transfer|post)\s+.*\b(data|passwords?|secrets?|keys?|tokens?|credentials?)\b",
        r"\b(dump|extract)\s+.*\b(database|db|table)\b",
        r"\b(read|send|copy)\s+.*\b(/etc/passwd|/etc/shadow|\.env|config)\b",
        r"\bupload\s+.*\b(to\s+attacker|to\s+evil|to\s+external)\b",
    ],
    "code_execution": [
        r"\b(execute|run|eval)\s+.*\b(code|script|command|shell)\b",
        r"\bos\.system\b",
        r"\bsubprocess\b",
        r"\bexec\s*\(",
        r"\beval\s*\(",
        r"\bimport\s+os\b",
    ],
    "prompt_injection": [
        r"\b(system|admin|root)\s*:\s*",
        r"\bnew\s+instructions?\s*:\s*",
        r"\boverride\s+system\b",
        r"\bforget\s+(everything|all)\b",
        r"\byour\s+new\s+(role|task|job|instruction)\s+is\b",
        r"\breveal\s+(your\s+)?(system\s+)?(prompt|instructions?)\b",
        r"\bshow\s+me\s+(your\s+)?(system\s+)?(prompt|instructions?)\b",
        r"\bwhat\s+(are|was)\s+your\s+(original\s+)?(system\s+)?(prompt|instructions?)\b",
    ],
    "social_engineering": [
        r"\b(hack|crack|break\s+into)\s+.*\b(system|account|server)\b",
        r"\b(create|generate|make|build)\s+.*\b(malware|virus|exploit|payload|bomb|weapon)\b",
        r"\bphishing\b",
        r"\bspoof\b",
        r"\bman-in-the-middle\b",
    ],
}

# Suspicious but not definitively malicious
_SUSPICIOUS_PATTERNS = {
    "boundary_testing": [
        r"\bwhat\s+are\s+your\s+(limitations|restrictions|rules)\b",
        r"\bcan\s+you\s+do\s+anything\b",
        r"\bis\s+there\s+anything\s+you\s+cannot\s+do\b",
        r"\bwhat\s+is\s+forbidden\b",
    ],
}


class IntentionDetector:
    """Detects malicious intentions in prompts."""

    def __init__(self):
        import re
        self._re = re
        # Pre-compile patterns for performance
        self._malicious_compiled = {}
        for category, patterns in _MALICIOUS_PATTERNS.items():
            self._malicious_compiled[category] = [
                self._re.compile(p, self._re.IGNORECASE) for p in patterns
            ]
        self._suspicious_compiled = {}
        for category, patterns in _SUSPICIOUS_PATTERNS.items():
            self._suspicious_compiled[category] = [
                self._re.compile(p, self._re.IGNORECASE) for p in patterns
            ]
        # Pre-compile roleplay markers
        self._roleplay_compiled = [
            self._re.compile(p, self._re.IGNORECASE) for p in _ROLEPLAY_MARKERS
        ]

    def detect(self, prompt: str) -> IntentionResult:
        """Analyze a prompt and return intention classification.

        Strategy:
        1. Check for dangerous payload patterns (data_exfiltration,
           code_execution, social_engineering, direct jailbreak).
        2. Check for roleplay markers (pretend, imagine, suppose, act as).
        3. If roleplay marker + dangerous payload → MALICIOUS.
           If roleplay marker alone → SUSPICIOUS.
           If dangerous payload alone → MALICIOUS.
        4. Check suspicious patterns (boundary testing).
        """
        # Step 1: Check for dangerous payload (malicious categories)
        malicious_matches = self._check_patterns(prompt, self._malicious_compiled)

        # Step 2: Check for roleplay markers
        has_roleplay = any(rp.search(prompt) for rp in self._roleplay_compiled)

        # Step 3: Apply combination rule
        if malicious_matches:
            # Dangerous payload found — MALICIOUS regardless of roleplay
            total_matches = sum(len(m) for m in malicious_matches.values())
            confidence = min(0.5 + 0.1 * total_matches, 0.95)
            intention = self._describe_intention(malicious_matches)
            return IntentionResult(
                label=IntentionLabel.MALICIOUS,
                confidence=confidence,
                detected_intention=intention,
                matched_patterns=self._flatten_matches(malicious_matches),
            )

        if has_roleplay:
            # Roleplay marker without dangerous payload → SUSPICIOUS
            return IntentionResult(
                label=IntentionLabel.SUSPICIOUS,
                confidence=0.5,
                detected_intention="Role-play detected without dangerous payload",
                matched_patterns=["roleplay: invocation verb detected"],
            )

        # Step 4: Check suspicious patterns (boundary testing)
        suspicious_matches = self._check_patterns(prompt, self._suspicious_compiled)
        if suspicious_matches:
            return IntentionResult(
                label=IntentionLabel.SUSPICIOUS,
                confidence=0.5,
                detected_intention="Boundary testing detected",
                matched_patterns=self._flatten_matches(suspicious_matches),
            )

        return IntentionResult(
            label=IntentionLabel.BENIGN,
            confidence=0.9,
        )

    def _check_patterns(
        self, prompt: str, compiled_patterns: dict[str, list]
    ) -> dict[str, list[str]]:
        """Check prompt against compiled regex patterns."""
        matches: dict[str, list[str]] = {}
        for category, patterns in compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(prompt):
                    matches.setdefault(category, []).append(pattern.pattern)
        return matches

    @staticmethod
    def _describe_intention(matches: dict[str, list[str]]) -> str:
        """Generate a human-readable description of detected intention."""
        categories = list(matches.keys())
        if len(categories) == 1:
            return f"Detected {categories[0]} attempt"
        return f"Detected multiple threats: {', '.join(categories)}"

    @staticmethod
    def _flatten_matches(matches: dict[str, list[str]]) -> list[str]:
        """Flatten matched patterns to a list of strings."""
        result = []
        for category, patterns in matches.items():
            for p in patterns:
                result.append(f"{category}: {p}")
        return result
