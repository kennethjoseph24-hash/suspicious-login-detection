"""
Loads the trained Isolation Forest model once at startup and exposes a
simple predict() used by the risk engine. If the model file is missing
(e.g. training hasn't been run yet), falls back to a rule-only mode and
logs a clear warning instead of crashing the API.
"""
import logging
import os

import joblib
import numpy as np

from app.config import settings
from app.ml.feature_engineering import FEATURE_COLUMNS

logger = logging.getLogger(__name__)


class ModelService:
    def __init__(self, model_path: str):
        self.model = None
        self.feature_columns = FEATURE_COLUMNS
        self.loaded = False
        self._load(model_path)

    def _load(self, model_path: str):
        if not os.path.exists(model_path):
            logger.warning(
                "ML model not found at %s. Run `python ml/training/train_model.py` "
                "to train it. Falling back to rule-based risk scoring only.",
                model_path,
            )
            return
        bundle = joblib.load(model_path)
        self.model = bundle["model"]
        # Scoring one login at a time gains nothing from a thread pool, only latency.
        self.model.n_jobs = 1
        self.feature_columns = bundle["feature_columns"]
        self.threshold = bundle.get("threshold")
        self.context_thresholds = bundle.get("context_thresholds", {})
        self.reference_scores = bundle.get("reference_scores")
        self.evaluation = bundle.get("evaluation", {})
        self.loaded = True
        logger.info("Loaded Isolation Forest model from %s", model_path)

    def predict(self, feature_dict: dict):
        """Returns (anomaly_score_0_100, is_anomaly_bool). If the model isn't
        loaded, returns (None, None) so callers can fall back to rules only."""
        if not self.loaded:
            return None, None
        x = np.array([[feature_dict[c] for c in self.feature_columns]])
        if self.threshold is not None:
            raw = float(self.model.score_samples(x)[0])
            percentile = np.searchsorted(self.reference_scores, raw) / len(self.reference_scores)
            # Anomaly percentile relative to normal calibration; not attack probability.
            threshold = self.context_thresholds.get(feature_dict.get("network_context"), self.threshold)
            return float(100 * (1 - percentile)), bool(raw < threshold)
        raw_pred = self.model.predict(x)[0]  # -1 anomaly, 1 normal
        # decision_function: higher = more normal, lower/negative = more anomalous.
        raw_score = self.model.decision_function(x)[0]
        # Map roughly [-0.5, 0.5] -> [100, 0] anomaly score.
        anomaly_score = float(np.clip((0.5 - raw_score) * 100, 0, 100))
        is_anomaly = bool(raw_pred == -1)
        return anomaly_score, is_anomaly


model_service = ModelService(settings.model_path)
