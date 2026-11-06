"""
STAGE 3 - Risk scoring engine, 0-100.

    score = min(100, rules + ML + isoforest + behaviour + threat_intel)

    ML        = RF predict_proba(attack) * 100 * ml_weight   (cap 30, weight 0.30)
    isoforest = +15 only when the anomaly score crosses the spec95 threshold
                (that threshold gives precision 0.9996 / spec 1.0 on held-out data, so it
                 costs essentially no false positives while adding a second, unsupervised
                 opinion to the supervised RF)
    bands     = >=81 CRITICAL | >=61 HIGH | >=31 MEDIUM | else LOW

Also produces the explainability output used by the dashboard:
  * top-3 contributing features  = feature_importance * standardised deviation
  * counterfactual               = smallest single feature edit that flips the verdict
"""
import json
import math
import os
import pickle
import time

import numpy as np

import features as F

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
MODELS = os.path.join(BASE, "models")
GATEWAY_MODELS = os.path.join(HERE, "models")

HUMAN = {
    "has_sql_keywords": "SQL keywords (UNION/SELECT/OR...)",
    "has_js_keywords": "JavaScript/event-handler markers",
    "has_path_traversal": "path traversal sequences (../, /etc/passwd)",
    "has_cmd_injection": "command injection chains (; cat, | ls, $(...))",
    "has_xxe_patterns": "XXE entity declarations",
    "has_ssi_patterns": "SSI directives (<!--#exec...)",
    "has_injection_patterns": "template/eval injection markers",
    "has_prompt_injection": "prompt-injection phrases",
    "has_suspicious_encoding": "obfuscation markers (%00, double encoding)",
    "url_length": "URL length",
    "url_entropy": "URL entropy (randomness)",
    "num_special_chars": "special character count",
    "num_encoded_chars": "URL-encoded character count",
    "body_length": "request body length",
    "body_entropy": "request body entropy",
    "num_headers": "header count",
    "has_user_agent": "User-Agent presence",
    "requests_per_minute": "requests/minute for this IP",
    "unique_urls_per_session": "distinct URLs in this session",
    "error_rate": "recent error rate for this IP",
}


def _load(path):
    with open(path, "rb") as f:
        return pickle.load(f)


class Scorer:
    def __init__(self, cfg=None):
        self.cfg = cfg or {}
        sc = self.cfg.get("scoring", {})
        self.ml_weight = float(sc.get("ml_weight", 0.30))
        self.ml_cap = float(sc.get("ml_cap", 30))
        self.iforest_cap = float(sc.get("iforest_cap", 15))
        self.max_score = float(sc.get("max", 100))

        with open(os.path.join(MODELS, "model_config.json"), encoding="utf-8") as f:
            self.model_cfg = json.load(f)
        self.features = list(self.model_cfg["features"])
        assert self.features == F.FEATURES, "feature order drift between config and features.py"

        self.rf = _load(os.path.join(MODELS, "aegis_model.pkl"))
        self.scaler = _load(os.path.join(MODELS, "scaler.pkl"))

        # Serving note: both estimators were trained with n_jobs=-1. For one-row online
        # inference the parallel dispatch costs ~40ms per call (measured) while the actual
        # tree walk is sub-millisecond, so we serialise at serving time.
        # Measured: 40.5ms (n_jobs=-1) -> sub-ms (n_jobs=1) for the same prediction.
        self.rf.n_jobs = 1

        self.iforest = self.if_scaler = self.iforest_cfg = None
        p1 = os.path.join(GATEWAY_MODELS, "iforest.pkl")
        p2 = os.path.join(GATEWAY_MODELS, "if_scaler.json" if False else "if_scaler.pkl")
        if os.path.exists(p1) and os.path.exists(p2):
            self.iforest = _load(p1)
            self.if_scaler = _load(p2)
            self.iforest.n_jobs = 1
            with open(os.path.join(GATEWAY_MODELS, "iforest_config.json"), encoding="utf-8") as f:
                self.iforest_cfg = json.load(f)

        self._means = np.asarray(self.scaler.mean_, dtype=float)   # train means, raw units
        self._scales = np.asarray(self.scaler.scale_, dtype=float)
        self._imp = np.asarray(self.rf.feature_importances_, dtype=float)
        self._warm()

    def _warm(self):
        z = self.scaler.transform(np.zeros((1, 20)))
        for _ in range(30):                 # absorb lazy tree/joblib warm-up
            self.rf.predict_proba(z)
        t0 = time.perf_counter()
        for _ in range(100):
            self.rf.predict_proba(z)
        self.rf_ms = (time.perf_counter() - t0) * 1000 / 100
        if self.iforest is not None:
            xi = self.if_scaler.transform(np.zeros((1, 20)))
            for _ in range(30):
                self.iforest.decision_function(xi)
            t0 = time.perf_counter()
            for _ in range(100):
                self.iforest.decision_function(xi)
            self.if_ms = (time.perf_counter() - t0) * 1000 / 100
        else:
            self.if_ms = 0.0

    # ------------------------------------------------------------------
    def predict(self, vec):
        """Return (probability of attack, inference_ms)."""
        x = self.scaler.transform([list(map(float, vec))])
        t0 = time.perf_counter()
        proba = float(self.rf.predict_proba(x)[0][1])
        ms = (time.perf_counter() - t0) * 1000
        return proba, ms

    def anomaly(self, vec):
        """Unsupervised opinion from the retrained IsolationForest."""
        if self.iforest is None:
            return {"available": False, "hard": False, "soft": False,
                    "score": 0.0, "points": 0.0}
        x = self.if_scaler.transform([list(map(float, vec))])
        raw = float(self.iforest.decision_function(x)[0])
        p = self.iforest_cfg["params"]
        hard = raw < float(p["decision_threshold"])            # spec95 point
        soft_thr = p.get("max_f1_threshold")
        soft = bool(soft_thr is not None and raw < float(soft_thr))
        return {
            "available": True, "hard": hard, "soft": soft, "score": round(raw, 5),
            "points": float(self.iforest_cap) if hard else 0.0,
            "threshold": p["decision_threshold"],
        }

    # ------------------------------------------------------------------
    def explain(self, vec):
        """Top-3 driving features: importance * standardised deviation from train mean."""
        v = np.asarray(list(map(float, vec)), dtype=float)
        z = (v - self._means) / np.where(self._scales == 0, 1.0, self._scales)
        contrib = self._imp * np.maximum(z, 0)          # only "above normal" pushes risk up
        order = np.argsort(-contrib)
        top = []
        for i in order[:3]:
            if contrib[i] <= 0.001:
                continue
            name = self.features[i]
            top.append({
                "feature": name,
                "label": HUMAN.get(name, name),
                "value": float(v[i]),
                "train_mean": round(float(self._means[i]), 3),
                "importance": round(float(self._imp[i]), 4),
                "contribution": round(float(contrib[i]), 4),
            })
        return top

    # ------------------------------------------------------------------
    def counterfactual(self, vec, proba, challenge_threshold):
        """Smallest single edit that would move the verdict below the challenge band."""
        base = list(map(float, vec))
        best = None

        for i, name in enumerate(self.features):
            if not name.startswith("has_") and name not in (
                    "url_length", "url_entropy", "num_special_chars",
                    "num_encoded_chars", "body_length"):
                continue
            trial = list(base)
            if name.startswith("has_"):
                if trial[i] <= 0:
                    continue
                trial[i] = 0.0
                new_val = 0.0
            else:
                if abs(trial[i] - self._means[i]) < 1e-9:
                    continue
                new_val = float(self._means[i])
                trial[i] = new_val
            p2, _ = self.predict(trial)
            gain = proba - p2
            if gain > 0 and (best is None or gain > best["gain"]):
                best = {"feature": name, "label": HUMAN.get(name, name),
                        "from": float(base[i]), "to": round(new_val, 3),
                        "proba_after": p2, "gain": gain}

        if best is None or best["proba_after"] >= challenge_threshold:
            return {"available": False}

        return {
            "available": True,
            "feature": best["feature"],
            "label": best["label"],
            "from": best["from"],
            "to": best["to"],
            "proba_after": round(best["proba_after"], 4),
            "text": "Verdict would drop to benign (%.0f%% -> %.0f%%) if %s were normal "
                    "(currently %s). Remove that from the payload and this request passes."
                    % (proba * 100, best["proba_after"] * 100,
                       best["label"], _fmt(best["from"])),
        }

    # ------------------------------------------------------------------
    def score(self, vec, rule_points, behaviour_points, threat_points,
              rule_notes=None, behaviour_notes=None):
        t0 = time.perf_counter()
        proba, ml_ms = self.predict(vec)
        anom = self.anomaly(vec)
        ml_points = min(proba * 100.0 * self.ml_weight, self.ml_cap)

        total = float(rule_points) + ml_points + float(anom["points"]) \
            + float(behaviour_points) + float(threat_points)
        total = min(total, self.max_score)

        if total >= 81:
            severity = "CRITICAL"
        elif total >= 61:
            severity = "HIGH"
        elif total >= 31:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "score": int(round(total)),
            "severity": severity,
            "components": {
                "rules": int(rule_points),
                "ml": round(ml_points, 1),
                "iforest": round(float(anom["points"]), 1),
                "behaviour": int(behaviour_points),
                "threat_intel": int(threat_points),
            },
            "ml": {
                "proba_attack": round(proba, 4),
                "proba_benign": round(1 - proba, 4),
                "flagged": bool(proba >= 0.5),
                "grey_zone": bool(0.45 <= proba <= 0.80),
                "model": "RandomForest(100, depth=12)",
                "trained_rows": self.model_cfg.get("trained_rows"),
                "test_acc": self.model_cfg.get("test_acc"),
                "test_f1": self.model_cfg.get("test_f1"),
                "inference_ms": round(ml_ms, 3),
            },
            "isoforest": anom,
            "notes": {
                "rules": rule_notes or [],
                "behaviour": behaviour_notes or [],
            },
            "explainability": self.explain(vec),
            "total_ms": round((time.perf_counter() - t0) * 1000, 3),
        }

    # ------------------------------------------------------------------
    def model_info(self):
        info = {
            "supervised": {
                "type": "RandomForestClassifier",
                "n_estimators": int(getattr(self.rf, "n_estimators", 0)),
                "max_depth": int(getattr(self.rf, "max_depth", 0) or 0),
                "classes": [int(c) for c in getattr(self.rf, "classes_", [])],
                "n_features": int(self.rf.n_features_in_),
                "features": self.features,
                "trained_rows": self.model_cfg.get("trained_rows"),
                "test_acc": self.model_cfg.get("test_acc"),
                "test_f1": self.model_cfg.get("test_f1"),
                "inference_ms": round(self.rf_ms, 3),
                "scaler": "StandardScaler fitted on train split only",
            },
            "top_importances": [
                {"feature": self.features[i],
                 "label": HUMAN.get(self.features[i], self.features[i]),
                 "importance": round(float(self._imp[i]), 4)}
                for i in np.argsort(-self._imp)[:10]
            ],
        }
        if self.iforest_cfg:
            info["unsupervised"] = {
                "type": "IsolationForest",
                "source": "retrained on 20 features (gateway/models/iforest.pkl)",
                "why_retrained": "original models/isolation_forest.pkl expected 22 features "
                                 "(20 + risk_score + severity) which cannot be produced at "
                                 "request time",
                "params": self.iforest_cfg["params"],
                "test_metrics": self.iforest_cfg["test_metrics"],
                "inference_ms": round(self.if_ms, 3),
            }
        return info


def _fmt(v):
    if isinstance(v, float) and v == int(v):
        return str(int(v))
    return str(v)
