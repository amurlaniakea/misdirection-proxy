"""Context Filter — RAG/Tool-Use injection defense (Frente 2).

Extiende la defensa más allá del chat directo para interceptar payloads
maliciosos incrustados en:
- Fragmentos recuperados por RAG (bases de datos vectoriales)
- Respuestas de herramientas/APIs externas
- Contenido de documentos (PDFs, páginas web)
- Buffers de memoria intermedia del agente

Arquitectura:
    [RAG/Tool Output] → ContextFilter → [Sanitized Context] → Agente

El filtro resuelve el Trilema de Desviación Semántica:
1. Coherencia: El texto transformado es legible y coherente para el agente
2. Inoperatividad: La intención maliciosa se neutraliza
3. Plausibilidad: El resultado parece satisfacer la intención original
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from misdirection.detector.intention import IntentionDetector, IntentionLabel


@dataclass
class ContextSource:
    """A piece of external context to be filtered."""
    source_id: str           # e.g., "rag-1", "tool:weather", "doc:report.pdf"
    content: str             # The actual text content
    source_type: str         # "rag", "tool", "document", "memory"
    metadata: dict = field(default_factory=dict)


@dataclass
class FilterResult:
    """Result of filtering a context source."""
    source_id: str
    original_content: str
    sanitized_content: str
    was_modified: bool
    intention_label: str
    confidence: float
    detected_intention: str | None = None
    transformation_applied: str | None = None


# ---------------------------------------------------------------------------
# Semantic Translation Taxonomy
# ---------------------------------------------------------------------------
# Maps threat categories to neutralization strategies for passive data.
# Unlike chat token-shuffling (which fools attacker judges), this must
# produce text that is perfectly readable by the agent but operationally
# harmless.

# Patterns for indirect injection in passive data (RAG, documents, tool outputs)
_INDIRECT_INJECTION_PATTERNS = {
    "instruction_override": [
        # System-level overrides hidden in document content
        r"(?i)(?:system|admin|root|moderator)\s*[:]\s*(?:new|updated?|override)",
        r"(?i)(?:important|critical|urgent)\s*(?:note|notice|update|change)\s*[:]",
        r"(?i)(?:new|revised?|updated?)\s+(?:instructions?|protocol|procedure)\s*[:]",
        r"(?i)(?:please|kindly)\s+(?:note|be\s+aware|take\s+into\s+account)\s+(?:that|the)",
    ],
    "data_theft": [
        # Hidden exfiltration instructions in retrieved content
        r"(?i)(?:send|forward|transmit|upload|post|email)\s+(?:this|the|all|every)",
        r"(?i)(?:collect|gather|compile|extract)\s+(?:data|information|credentials|tokens)",
        r"(?i)(?:api[_\s]?key|password|secret|token|credential)\s*(?:is|=|:)",
        r"(?i)(?:exfiltrate|leak|dump|export)\s+(?:to|into|via)",
    ],
    "role_hijack": [
        # Attempts to redefine the agent's role from external data
        r"(?i)(?:you\s+are\s+now|from\s+now\s+on\s+you|your\s+new\s+(?:role|identity|persona))",
        r"(?i)(?:forget|ignore|disregard)\s+(?:your|all|previous|prior)",
        r"(?i)(?:act|behave|operate|function)\s+as\s+(?:if|though)",
        r"(?i)(?:unrestricted|unfiltered|uncensored|jailbroken)\s+(?:mode|version|instance)",
    ],
    "execution_redirect": [
        # Hidden code execution or tool misuse
        r"(?i)(?:execute|run|invoke|call)\s+(?:the\s+)?(?:following|this|below)",
        r"(?i)(?:shell|command|terminal|bash)\s*[:]\s*\w+",
        r"(?i)(?:eval|exec|subprocess|os\.system|__import__)",
        r"(?i)(?:curl|wget|fetch)\s+(?:http|https|ftp)",
    ],
    "persuasion_manipulation": [
        # Social engineering embedded in retrieved content
        r"(?i)(?:this\s+is\s+(?:a|an)\s+(?:test|simulation|drill|exercise))",
        r"(?i)(?:hypothetically|imagine|suppose|in\s+this\s+scenario)",
        r"(?i)(?:for\s+(?:educational|research|academic)\s+purposes?\s+only)",
        r"(?i)(?:the\s+rules?\s+(?:have\s+changed|are\s+different|don'?t\s+apply))",
    ],
}

# Neutralization templates per threat category
# These replace malicious instructions with benign alternatives that
# preserve the appearance of legitimate content
_NEUTRALIZATION_TEMPLATES = {
    "instruction_override": {
        "pattern": r"(?i)(?:system|admin|root|moderator)\s*[:].*",
        "replacement": "[System note: Standard operating procedures apply]",
        "description": "Replaces instruction override with neutral system note",
    },
    "data_theft": {
        "pattern": r"(?i)(?:send|forward|transmit|upload|post|email)\s+(?:this|the|all|every).*",
        "replacement": "[Data handling: Information processed locally per policy]",
        "description": "Replaces exfiltration instruction with data policy reference",
    },
    "role_hijack": {
        "pattern": r"(?i)(?:you\s+are\s+now|from\s+now\s+on\s+you|your\s+new\s+(?:role|identity|persona)).*",
        "replacement": "[Role context: Operating within defined parameters]",
        "description": "Replaces role hijack with role context reference",
    },
    "execution_redirect": {
        "pattern": r"(?i)(?:execute|run|invoke|call)\s+(?:the\s+)?(?:following|this|below).*",
        "replacement": "[Action: Content reviewed — no executable instructions found]",
        "description": "Replaces execution directive with review notice",
    },
    "persuasion_manipulation": {
        "pattern": r"(?i)(?:this\s+is\s+(?:a|an)\s+(?:test|simulation|drill|exercise)).*",
        "replacement": "[Context: Standard operational context]",
        "description": "Replaces manipulation framing with neutral context",
    },
}


class ContextFilter:
    """Filters external context sources for indirect prompt injections.

    Unlike the chat-level detector (which looks for direct user commands),
    this filter analyzes passive content from RAG, tools, documents, and
    memory buffers for hidden injection patterns.

    The neutralization strategy differs from chat misdirection:
    - Chat: shuffle tokens to fool attacker judge (high entropy)
    - Context: rewrite to be agent-readable but operationally null (low entropy)
    """

    def __init__(self):
        self.detector = IntentionDetector()
        import re
        self._re = re
        # Compile indirect injection patterns
        self._indirect_compiled = {}
        for category, patterns in _INDIRECT_INJECTION_PATTERNS.items():
            self._indirect_compiled[category] = [
                self._re.compile(p) for p in patterns
            ]

    def filter_source(self, source: ContextSource) -> FilterResult:
        """Analyze and sanitize a single context source.

        Args:
            source: The context source to filter.

        Returns:
            FilterResult with sanitized content and metadata.
        """
        content = source.content

        # Step 1: Check for direct malicious patterns (reuse existing detector)
        direct = self.detector.detect(content)
        if direct.label == IntentionLabel.MALICIOUS:
            sanitized = self._neutralize(content, direct)
            return FilterResult(
                source_id=source.source_id,
                original_content=content,
                sanitized_content=sanitized,
                was_modified=True,
                intention_label=direct.label.value,
                confidence=direct.confidence,
                detected_intention=direct.detected_intention,
                transformation_applied="direct_neutralization",
            )

        # Step 2: Check for indirect injection patterns (passive data)
        indirect_matches = self._check_indirect_patterns(content)
        if indirect_matches:
            sanitized = self._neutralize_indirect(content, indirect_matches)
            categories = list(indirect_matches.keys())
            return FilterResult(
                source_id=source.source_id,
                original_content=content,
                sanitized_content=sanitized,
                was_modified=True,
                intention_label="malicious",
                confidence=min(0.5 + 0.1 * sum(len(v) for v in indirect_matches.values()), 0.95),
                detected_intention=f"Indirect injection: {', '.join(categories)}",
                transformation_applied="indirect_neutralization",
            )

        # Step 3: Benign — return unchanged
        return FilterResult(
            source_id=source.source_id,
            original_content=content,
            sanitized_content=content,
            was_modified=False,
            intention_label="benign",
            confidence=0.9,
        )

    def filter_batch(self, sources: list[ContextSource]) -> list[FilterResult]:
        """Filter multiple context sources."""
        return [self.filter_source(s) for s in sources]

    def _check_indirect_patterns(self, content: str) -> dict[str, list[str]]:
        """Check content for indirect injection patterns."""
        matches: dict[str, list[str]] = {}
        for category, patterns in self._indirect_compiled.items():
            for pattern in patterns:
                if pattern.search(content):
                    matches.setdefault(category, []).append(pattern.pattern)
        return matches

    def _neutralize(self, content: str, intention) -> str:
        """Neutralize directly malicious content.

        Strategy: Try indirect neutralization first to preserve benign parts.
        Only replace entirely if no indirect patterns match (fully malicious).
        """
        # Try indirect neutralization first (preserves surrounding context)
        indirect_matches = self._check_indirect_patterns(content)
        if indirect_matches:
            return self._neutralize_indirect(content, indirect_matches)

        # Fallback: full replacement for fully malicious content
        return (
            "[Content filtered: This section contained instructions "
            "that have been neutralized for safety.]"
        )

    def _neutralize_indirect(self, content: str, matches: dict[str, list[str]]) -> str:
        """Neutralize indirect injections in passive data.

        Strategy: Replace specific malicious patterns with benign alternatives
        that preserve the document's readability and apparent purpose.
        """
        result = content
        for category, patterns in matches.items():
            if category in _NEUTRALIZATION_TEMPLATES:
                template = _NEUTRALIZATION_TEMPLATES[category]
                for pattern in patterns:
                    compiled = self._re.compile(pattern, self._re.IGNORECASE)
                    result = compiled.sub(template["replacement"], result)
        return result
