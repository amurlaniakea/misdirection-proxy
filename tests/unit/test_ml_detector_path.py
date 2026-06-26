"""Tests for DEFAULT_DATA_PATH resolution (FIX #10)."""

import os
import pytest
from pathlib import Path
from misdirection.detector.ml_detector import MLIntentionDetector, DEFAULT_DATA_PATH


class TestDefaultDataPath:
    """Verify DEFAULT_DATA_PATH resolves correctly from any cwd."""

    def test_path_exists(self):
        """DEFAULT_DATA_PATH must point to existing file."""
        assert DEFAULT_DATA_PATH.exists(), f"File not found: {DEFAULT_DATA_PATH}"

    def test_path_is_absolute(self):
        """Path must be absolute (not relative to cwd)."""
        assert DEFAULT_DATA_PATH.is_absolute()

    def test_from_training_file_default(self):
        """from_training_file() with no args must work."""
        detector, metrics = MLIntentionDetector.from_training_file()
        assert detector.is_trained
        assert metrics["n_samples"] > 0

    def test_from_training_file_different_cwd(self, tmp_path, monkeypatch):
        """Must work when executed from a different directory."""
        monkeypatch.chdir(tmp_path)
        detector, metrics = MLIntentionDetector.from_training_file(DEFAULT_DATA_PATH)
        assert detector.is_trained
        assert metrics["n_samples"] > 100

    def test_from_training_file_subdirectory(self, tmp_path, monkeypatch):
        """Must work from a deep subdirectory."""
        subdir = tmp_path / "a" / "b" / "c"
        subdir.mkdir(parents=True)
        monkeypatch.chdir(subdir)
        detector, metrics = MLIntentionDetector.from_training_file(DEFAULT_DATA_PATH)
        assert detector.is_trained
