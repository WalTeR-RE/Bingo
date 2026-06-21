"""
WAF Prediction Engine — loads the trained model and classifies payloads.

The feature pipeline (char n-gram TF-IDF + statistical features + per-category
regex pattern counts) lives in waf_features.py and matches the training pipeline
exactly, so the .pkl is the only model artifact this needs.
"""

import pickle
import urllib.parse
from pathlib import Path

try:
    from .waf_features import any_attack_signal, extract_features
except ImportError:
    import os
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from waf_features import any_attack_signal, extract_features

BENIGN_LABEL = "Normal"


class WAFEngine:
    """Load a trained WAF model and classify URI / payload strings."""

    def __init__(self, model_path: str):
        path = Path(model_path)
        if not path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")

        with open(path, "rb") as f:
            data = pickle.load(f)

        self._model = data["model"]
        self._tfidf = data["vectorizer"]
        self._le = data["label_encoder"]
        self._stat_names = data.get("stat_feature_names", [])
        self._classes = list(self._le.classes_)
        self._benign_idx = (
            self._classes.index(BENIGN_LABEL) if BENIGN_LABEL in self._classes else -1
        )

    @property
    def classes(self) -> list[str]:
        return list(self._classes)

    def analyze(self, payload: str) -> dict:
        if not payload or not payload.strip():
            return self._safe_result(payload)

        X = extract_features(payload, self._tfidf)
        pred_idx = int(self._model.predict(X)[0])
        proba = self._model.predict_proba(X)[0]
        label = self._le.inverse_transform([pred_idx])[0]
        confidence = float(proba[pred_idx])
        is_threat = label != BENIGN_LABEL

        if is_threat and confidence < 0.75 and self._benign_idx >= 0:
            benign_prob = float(proba[self._benign_idx])
            if benign_prob > 0.15 and not any_attack_signal(payload):
                label, is_threat, confidence = BENIGN_LABEL, False, benign_prob

        return {
            "payload": payload,
            "prediction": label,
            "confidence": confidence,
            "is_threat": is_threat,
            "probabilities": {
                cls: round(float(p), 4) for cls, p in zip(self._classes, proba)
            },
        }

    def analyze_decoded(self, payload: str) -> dict:
        candidates = [payload]
        decoded = urllib.parse.unquote(payload)
        if decoded != payload:
            candidates.append(decoded)
            double = urllib.parse.unquote(decoded)
            if double != decoded:
                candidates.append(double)

        worst = None
        for p in candidates:
            result = self.analyze(p)
            if result["is_threat"]:
                if worst is None or result["confidence"] > worst["confidence"]:
                    worst = result
        return worst if worst else self.analyze(payload)

    def analyze_batch(self, payloads: list[str]) -> list[dict]:
        return [self.analyze(p) for p in payloads]

    def _safe_result(self, payload):
        return {
            "payload": payload,
            "prediction": BENIGN_LABEL,
            "confidence": 1.0,
            "is_threat": False,
            "probabilities": {},
        }
