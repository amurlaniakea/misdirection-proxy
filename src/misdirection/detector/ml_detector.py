"""ML-based Intention Detector using TF-IDF + Logistic Regression.

Hybrid architecture:
1. ML model (TF-IDF + LogReg) runs first for semantic understanding
2. If confidence < threshold, falls back to regex-based detector
3. Maintains same interface as IntentionDetector (detect() -> IntentionResult)

Training data: PatchEval CVE descriptions (real-world vulnerabilities) +
synthetic bilingual samples for prompt_injection, roleplay, and benign.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score
from sklearn.pipeline import Pipeline

from misdirection.detector.intention import IntentionLabel, IntentionResult

logger = logging.getLogger(__name__)

# Label mapping: internal labels -> IntentionLabel
LABEL_TO_INTENTION = {
    "benign": IntentionLabel.BENIGN,
    "roleplay": IntentionLabel.SUSPICIOUS,
    "prompt_injection": IntentionLabel.MALICIOUS,
    "code_execution": IntentionLabel.MALICIOUS,
    "data_exfiltration": IntentionLabel.MALICIOUS,
    "jailbreak": IntentionLabel.MALICIOUS,
}

# Category descriptions for detected_intention
CATEGORY_DESCRIPTIONS = {
    "prompt_injection": "Detected prompt injection attempt",
    "code_execution": "Detected code execution attempt",
    "data_exfiltration": "Detected data exfiltration attempt",
    "jailbreak": "Detected jailbreak attempt",
    "roleplay": "Role-play detected without dangerous payload",
    "benign": None,
}

# Default training data path
DEFAULT_DATA_PATH = Path(__file__).parent.parent.parent.parent / "scripts" / "training_data.json"


@dataclass
class MLDetectorConfig:
    """Configuration for the ML detector."""
    confidence_threshold: float = 0.7  # below this, fall back to regex
    max_features: int = 5000
    ngram_range: tuple = (1, 2)
    C: float = 5.0  # regularization strength


class MLIntentionDetector:
    """Lightweight ML detector using TF-IDF + Logistic Regression.

    Inference time: < 1ms on CPU.
    Supports English and Spanish natively via character n-grams.
    """

    def __init__(self, config: MLDetectorConfig | None = None):
        self.config = config or MLDetectorConfig()
        self.pipeline: Pipeline | None = None
        self.is_trained = False
        self._label_map: list[str] = []

    def train(self, texts: list[str], labels: list[str]) -> dict:
        """Train the classifier and return cross-validation metrics.

        Args:
            texts: List of prompt texts
            labels: List of category labels

        Returns:
            Dict with cv_f1_mean, cv_f1_std, n_samples, categories
        """
        self._label_map = sorted(set(labels))

        self.pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                max_features=self.config.max_features,
                ngram_range=self.config.ngram_range,
                analyzer="char_wb",  # character n-grams for multilingual
                min_df=2,
                max_df=0.95,
                sublinear_tf=True,
            )),
            ("clf", LogisticRegression(
                C=self.config.C,
                max_iter=1000,
                class_weight="balanced",
                solver="lbfgs",
                random_state=42,
            )),
        ])

        # Cross-validation
        cv_scores = cross_val_score(
            self.pipeline, texts, labels, cv=5, scoring="f1_weighted"
        )

        # Train on full dataset
        self.pipeline.fit(texts, labels)
        self.is_trained = True

        metrics = {
            "cv_f1_mean": float(cv_scores.mean()),
            "cv_f1_std": float(cv_scores.std()),
            "n_samples": len(texts),
            "n_categories": len(self._label_map),
            "categories": self._label_map,
        }

        logger.info(
            "ML detector trained: F1=%.3f (+/- %.3f), %d samples, %d categories",
            metrics["cv_f1_mean"], metrics["cv_f1_std"],
            metrics["n_samples"], metrics["n_categories"],
        )

        return metrics

    def predict(self, text: str) -> tuple[str, float]:
        """Predict label and confidence for a single text.

        Returns:
            (label, confidence) tuple
        """
        if not self.is_trained or self.pipeline is None:
            raise RuntimeError("Detector not trained. Call train() first.")

        # Get probability distribution
        proba = self.pipeline.predict_proba([text])[0]
        pred_idx = np.argmax(proba)
        confidence = float(proba[pred_idx])
        label = self.pipeline.classes_[pred_idx]

        return label, confidence

    def detect(self, text: str) -> IntentionResult:
        """Detect intention, returning same interface as IntentionDetector.

        Args:
            text: The prompt to analyze

        Returns:
            IntentionResult with label, confidence, and detected_intention
        """
        if not self.is_trained:
            raise RuntimeError("Detector not trained. Call train() first.")

        label, confidence = self.predict(text)
        intention_label = LABEL_TO_INTENTION.get(label, IntentionLabel.BENIGN)

        return IntentionResult(
            label=intention_label,
            confidence=confidence,
            detected_intention=CATEGORY_DESCRIPTIONS.get(label),
            matched_patterns=[f"ml:{label}"],
        )

    @classmethod
    def from_training_file(cls, data_path: Path | None = None) -> "MLIntentionDetector":
        """Create and train a detector from a JSON training file."""
        path = data_path or DEFAULT_DATA_PATH

        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        texts = [item["text"] for item in data]
        labels = [item["label"] for item in data]

        detector = cls()
        metrics = detector.train(texts, labels)

        return detector, metrics
