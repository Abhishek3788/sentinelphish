import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import joblib
import numpy as np
from app.layers.base import BaseLayer, LayerResult, RedFlag
from app.utils.logger import get_logger

logger = get_logger("layers.ml_ensemble")

ARTIFACTS_DIR = Path(__file__).parent.parent / "models" / "artifacts"


class MLEnsembleLayer(BaseLayer):
    def __init__(self):
        self.rf_model = None
        self.xgb_model = None
        self.lgbm_model = None
        self.scaler = None
        self.feature_names = []
        self._load_models()

    def _load_models(self):
        try:
            if (ARTIFACTS_DIR / "random_forest.joblib").exists():
                self.rf_model = joblib.load(ARTIFACTS_DIR / "random_forest.joblib")
            if (ARTIFACTS_DIR / "xgboost.joblib").exists():
                self.xgb_model = joblib.load(ARTIFACTS_DIR / "xgboost.joblib")
            if (ARTIFACTS_DIR / "lightgbm.joblib").exists():
                self.lgbm_model = joblib.load(ARTIFACTS_DIR / "lightgbm.joblib")
            if (ARTIFACTS_DIR / "scaler.joblib").exists():
                self.scaler = joblib.load(ARTIFACTS_DIR / "scaler.joblib")
            if (ARTIFACTS_DIR / "feature_names.json").exists():
                with open(ARTIFACTS_DIR / "feature_names.json", "r") as f:
                    self.feature_names = json.load(f)
        except Exception as e:
            logger.warning(f"Error loading trained ML models from artifacts: {e}")

    @property
    def name(self) -> str:
        return "ml_ensemble"

    async def analyze(self, url: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        red_flags: List[RedFlag] = []
        details: Dict[str, Any] = {}

        try:
            from app.models.feature_engineering import extract_url_features
            features_dict = extract_url_features(url)
            
            # Align features with training schema
            if self.feature_names:
                vector = [features_dict.get(fn, 0.0) for fn in self.feature_names]
            else:
                vector = list(features_dict.values())

            feature_matrix = np.array([vector])
            if self.scaler:
                feature_matrix = self.scaler.transform(feature_matrix)

            probs = []

            # RF prediction
            if self.rf_model:
                probs.append(self.rf_model.predict_proba(feature_matrix)[0][1])
            # XGB prediction
            if self.xgb_model:
                probs.append(self.xgb_model.predict_proba(feature_matrix)[0][1])
            # LightGBM prediction
            if self.lgbm_model:
                probs.append(self.lgbm_model.predict_proba(feature_matrix)[0][1])

            if probs:
                soft_vote_prob = float(np.mean(probs))
            else:
                # Heuristic estimation if models not yet pre-trained
                soft_vote_prob = self._heuristic_feature_prob(features_dict)

            risk_score = float(soft_vote_prob * 100.0)

            # Extract top contributing features
            top_features = self._get_top_features(features_dict)
            details["top_contributing_features"] = top_features
            details["soft_vote_probability"] = round(soft_vote_prob, 4)

            if risk_score > 70:
                red_flags.append(RedFlag(
                    severity="high",
                    flag=f"ML Ensemble model flagged URL as high-risk phishing ({round(risk_score, 1)}%)"
                ))

            return LayerResult(
                layer_name=self.name,
                risk_score=min(100.0, max(0.0, risk_score)),
                confidence=0.88 if probs else 0.65,
                red_flags=red_flags,
                details=details
            )

        except Exception as e:
            logger.error(f"ML Ensemble layer error for {url}: {e}")
            return LayerResult(
                layer_name=self.name,
                risk_score=0.0,
                confidence=0.0,
                error=str(e)
            )

    def _heuristic_feature_prob(self, features: Dict[str, float]) -> float:
        score = 0.0
        if features.get("url_length", 0) > 75:
            score += 0.2
        if features.get("is_ip_hostname", 0):
            score += 0.4
        if features.get("has_at_symbol", 0):
            score += 0.3
        if features.get("suspicious_keyword_count", 0) > 0:
            score += 0.25
        return min(1.0, score)

    def _get_top_features(self, features: Dict[str, float]) -> List[Dict[str, Any]]:
        sorted_feats = sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)
        return [{"feature": k, "value": v} for k, v in sorted_feats[:5]]
