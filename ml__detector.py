"""
NetGuard AI - Threat detector.

Loads the trained model + scaler and exposes a simple predict() API used
by the Flask app / core pipeline to classify a network flow record as
normal or a specific attack type, along with a confidence score.
"""
import os
import joblib
import numpy as np
import pandas as pd

from ml.generate_synthetic_data import FEATURE_COLUMNS
from config import Config


class ThreatDetector:
    def __init__(self, model_path: str = Config.MODEL_PATH, scaler_path: str = Config.SCALER_PATH):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.model = None
        self.scaler = None
        self._load()

    def _load(self):
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
        else:
            self.model = None
            self.scaler = None

    @property
    def is_ready(self) -> bool:
        return self.model is not None and self.scaler is not None

    def predict(self, record: dict) -> dict:
        """
        record: dict with keys matching FEATURE_COLUMNS (missing keys default to 0).
        Returns: {"label": str, "confidence": float, "is_threat": bool, "scores": {label: prob}}
        """
        if not self.is_ready:
            raise RuntimeError(
                "Model not trained yet. Run: python ml/generate_synthetic_data.py "
                "&& python ml/train_model.py"
            )

        row = {col: record.get(col, 0) for col in FEATURE_COLUMNS}
        X = pd.DataFrame([row], columns=FEATURE_COLUMNS)
        X_scaled = self.scaler.transform(X)

        proba = self.model.predict_proba(X_scaled)[0]
        classes = self.model.classes_
        scores = {cls: float(p) for cls, p in zip(classes, proba)}

        best_idx = int(np.argmax(proba))
        label = classes[best_idx]
        confidence = float(proba[best_idx])

        return {
            "label": label,
            "confidence": round(confidence, 4),
            "is_threat": label != "normal",
            "scores": {k: round(v, 4) for k, v in scores.items()},
        }

    def predict_batch(self, records: list) -> list:
        return [self.predict(r) for r in records]


# Singleton instance used across the app
detector = ThreatDetector()
