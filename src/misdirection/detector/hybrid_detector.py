"""Hybrid Detector: ML-first with regex fallback.

Architecture:
1. ML detector runs first for semantic understanding (multilingual, robust)
2. If ML confidence < threshold, falls back to regex-based detector
3. Regex also acts as a safety net for known patterns ML might miss
"""

from __future__ import annotations

import logging
from pathlib import Path

from misdirection.detector.intention import IntentionDetector, IntentionResult, IntentionLabel

logger = logging.getLogger(__name__)

# ML detector imported lazily to avoid hard dependency on sklearn/numpy


class HybridDetector:
    """Combines ML and regex detectors for robust intention detection.

    Strategy:
    1. ML model predicts with confidence
    2. If confidence >= threshold → use ML result
    3. If confidence < threshold → delegate to regex fallback
    4. Regex acts as safety net for known attack patterns
    """

    def __init__(
        self,
        ml_detector=None,
        regex_detector: IntentionDetector | None = None,
        config=None,
    ):
        from misdirection.detector.ml_detector import MLIntentionDetector, MLDetectorConfig
        self.config = config or MLDetectorConfig()
        self.ml = ml_detector
        self.regex = regex_detector or IntentionDetector()

        # Train ML if not already trained
        if self.ml is None:
            self.ml = MLIntentionDetector(self.config)

    def train_ml(self, data_path: Path | None = None) -> dict:
        """Train the ML component from a training data file."""
        from misdirection.detector.ml_detector import DEFAULT_DATA_PATH

        path = data_path or DEFAULT_DATA_PATH
        detector, metrics = MLIntentionDetector.from_training_file(path)
        self.ml = detector
        return metrics

    def detect(self, text: str) -> IntentionResult:
        """Detect intention using hybrid approach."""
        # Step 1: Try ML first
        if self.ml is not None and self.ml.is_trained:
            try:
                ml_result = self.ml.detect(text)
                # If ML is confident, use its result
                if ml_result.confidence >= self.config.confidence_threshold:
                    return ml_result
                # Low confidence → log and fall through to regex
                logger.debug(
                    "ML confidence %.2f < %.2f, falling back to regex",
                    ml_result.confidence, self.config.confidence_threshold,
                )
            except Exception as e:
                logger.warning("ML detection failed: %s, using regex", e)

        # Step 2: Regex fallback
        return self.regex.detect(text)


def create_default_detector() -> HybridDetector:
    """Create a pre-trained hybrid detector using default training data."""
    from misdirection.detector.ml_detector import DEFAULT_DATA_PATH

    ml_detector, metrics = MLIntentionDetector.from_training_file(DEFAULT_DATA_PATH)
    logger.info(
        "ML detector ready: F1=%.3f, %d samples, %d categories",
        metrics["cv_f1_mean"], metrics["n_samples"], metrics["n_categories"],
    )

    regex_detector = IntentionDetector()
    return HybridDetector(ml_detector=ml_detector, regex_detector=regex_detector)
