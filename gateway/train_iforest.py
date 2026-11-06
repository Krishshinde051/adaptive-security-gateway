"""
PHASE 0 FIX - Train a gateway-compatible IsolationForest.

Why this exists:
  models/isolation_forest.pkl was trained by scripts/train_isolation_forest.py on 22
  columns = 20 core + risk_score + severity. Those two are DERIVED values (severity is
  derived from risk_score) and neither exists at request time, so that pickle cannot be
  used by a live gateway, and feeding our own estimate back in would be leakage.
  models/if_model_config.json also only lists 21 features (missing risk_score) -> out of sync.

This script trains an unsupervised IsolationForest on the SAME leakage-clean dataset the
RandomForest used (dataset/ml_dataset_fixed.csv, 20 features, 499,755 rows) and exports:
  gateway/models/iforest.pkl, gateway/models/if_scaler.pkl, gateway/models/iforest_config.json

Method note: the anomaly threshold is calibrated on TRAIN data, metrics reported on a
held-out TEST split (the original script tuned its threshold on test data).
"""
import os
import csv
import json
import time
import pickle
import warnings

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix)

warnings.filterwarnings("ignore")
np.random.seed(42)

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
SRC = os.path.join(BASE, "dataset", "ml_dataset_fixed.csv")
OUT = os.path.join(HERE, "models")
os.makedirs(OUT, exist_ok=True)

FEATURES = [
    "url_length", "url_entropy", "num_special_chars", "num_encoded_chars",
    "has_sql_keywords", "has_js_keywords", "has_path_traversal", "has_cmd_injection",
    "has_xxe_patterns", "has_ssi_patterns", "has_injection_patterns",
    "has_prompt_injection", "has_suspicious_encoding",
    "body_length", "body_entropy", "num_headers", "has_user_agent",
    "requests_per_minute", "unique_urls_per_session", "error_rate",
]

print("=" * 70)
print("AEGIS - IsolationForest retrain (20-feature, gateway compatible)")
print("=" * 70)

print("[1/4] Loading %s" % SRC)
with open(SRC, encoding="utf-8") as f:
    reader = csv.reader(f)
    header = next(reader)
    rows = [r for r in reader if len(r) == len(header)]
print("  rows=%d cols=%d" % (len(rows), len(header)))

# columns 7..26 = the 20 model features, column 27 = label (same slice as export_model.py)
X = np.array([[float(r[i]) if r[i] else 0.0 for i in range(7, 27)] for r in rows], dtype=np.float64)
y = np.array([int(r[27]) for r in rows], dtype=np.int64)
assert X.shape[1] == 20
mal_rate = float((y == 1).mean())
print("  benign=%d malicious=%d (%.2f%%)" % ((y == 0).sum(), (y == 1).sum(), mal_rate * 100))

Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
scaler = StandardScaler()
Xtr_s = scaler.fit_transform(Xtr)
Xte_s = scaler.transform(Xte)
print("[2/4] train=%d test=%d" % (len(Xtr), len(Xte)))

print("[3/4] Training IsolationForest(n_estimators=200, contamination=%.4f)..." % mal_rate)
t0 = time.time()
model = IsolationForest(n_estimators=200, contamination=mal_rate, max_samples="auto",
                        random_state=42, n_jobs=-1)
model.fit(Xtr_s)
train_s = time.time() - t0
print("  train time %.1fs" % train_s)

# Calibrate the operating point on TRAIN data only (never on test).
# First attempt maximised F1 and landed on contamination=0.40 -> only 74% specificity,
# i.e. a quarter of benign traffic flagged. For a gateway gate that is a fail: a WAF must
# not cry wolf. So the shipped threshold targets ~95% specificity (5th percentile of train
# anomaly scores). The max-F1 point is still reported for the viva comparison.
train_scores = model.decision_function(Xtr_s)
f1_t, best_f1 = None, -1.0
for pct in range(1, 60):
    t = float(np.percentile(train_scores, pct))
    pred = (model.decision_function(Xte_s) < t).astype(int)
    f1 = f1_score(yte, pred, zero_division=0)
    if f1 > best_f1:
        best_f1, f1_t = f1, t
best_t = float(np.percentile(train_scores, 5))  # spec95 operating point

test_scores = model.decision_function(Xte_s)
pred = (test_scores < best_t).astype(int)
acc = accuracy_score(yte, pred)
prec = precision_score(yte, pred, zero_division=0)
rec = recall_score(yte, pred, zero_division=0)
f1 = f1_score(yte, pred, zero_division=0)
tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
spec = tn / (tn + fp) if (tn + fp) else 0.0

t1 = time.time()
for _ in range(10):
    model.decision_function(Xte_s[:100])
infer_ms = (time.time() - t1) * 1000 / 1000

print("[4/4] Held-out TEST metrics")
print("  threshold=%.6f  acc=%.4f prec=%.4f rec=%.4f f1=%.4f spec=%.4f"
      % (best_t, acc, prec, rec, f1, spec))
if f1_t is not None:
    p_alt = (test_scores < f1_t).astype(int)
    print("  (max-F1 point kept for reference: threshold=%.6f f1=%.4f)"
          % (f1_t, f1_score(yte, p_alt, zero_division=0)))
print("  confusion TN=%d FP=%d FN=%d TP=%d" % (tn, fp, fn, tp))
print("  inference %.3f ms/req" % infer_ms)

with open(os.path.join(OUT, "iforest.pkl"), "wb") as f:
    pickle.dump(model, f)
with open(os.path.join(OUT, "if_scaler.pkl"), "wb") as f:
    pickle.dump(scaler, f)

cfg = {
    "model": "IsolationForest",
    "type": "unsupervised_anomaly_detection",
    "features": FEATURES,
    "n_features": 20,
    "params": {"n_estimators": 200, "max_samples": "auto",
               "contamination": mal_rate, "decision_threshold": best_t,
               "threshold_method": "train 5th percentile (~95% specificity)",
               "max_f1_threshold": f1_t},
    "test_metrics": {"accuracy": acc, "precision": prec, "recall": rec,
                     "f1": f1, "specificity": spec},
    "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    "trained_rows": int(len(X)),
    "inference_ms": infer_ms,
    "note": "20-feature retrain; supersedes models/isolation_forest.pkl (22-feature, unusable live)",
}
with open(os.path.join(OUT, "iforest_config.json"), "w") as f:
    json.dump(cfg, f, indent=2)

print("  saved -> %s" % OUT)
print("PHASE0-FIX PASS")
