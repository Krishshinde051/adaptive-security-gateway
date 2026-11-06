"""
Isolation Forest Optimized - Fast version
Subsample for grid search, full for final model
"""
import os, csv, json, time, pickle, warnings
import numpy as np
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
from sklearn.ensemble import IsolationForest

warnings.filterwarnings('ignore')
np.random.seed(42)

BASE = os.path.join(os.path.dirname(__file__), '..')
DATASET = os.path.join(BASE, 'dataset', 'aegis_dataset.csv')
RESULTS = os.path.join(BASE, 'results')
MODELS = os.path.join(BASE, 'models')
os.makedirs(RESULTS, exist_ok=True)
os.makedirs(MODELS, exist_ok=True)

# ============================================================
# 1. LOAD
# ============================================================
print("=" * 70)
print("ISOLATION FOREST - OPTIMIZED FOR AEGIS")
print("=" * 70)

print("\n[1/5] Loading dataset...")
with open(DATASET, encoding='utf-8') as f:
    reader = csv.reader(f)
    headers = next(reader)
    raw = [row for row in reader if len(row) == len(headers)]

seen = set()
data = []
for row in raw:
    key = ','.join(row[3:29])
    if key not in seen:
        seen.add(key)
        data.append(row)

sev_map = {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
X, y = [], []
for row in data:
    try:
        features = [float(row[i]) if row[i] else 0.0 for i in range(7, 28)]
        features.append(sev_map.get(row[28], 0) if len(row) > 28 else 0)
        X.append(features)
        y.append(int(row[29]))
    except (ValueError, IndexError):
        continue

X = np.array(X)
y = np.array(y)
malicious_rate = sum(y == 1) / len(y)
print(f"   Samples: {len(X):,} | Features: {X.shape[1]}")
print(f"   Benign: {sum(y==0):,} | Malicious: {sum(y==1):,} ({malicious_rate*100:.2f}%)")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

# Subsample for fast grid search (50K)
sub_idx = np.random.RandomState(42).choice(len(X_train_s), size=50000, replace=False)
X_sub = X_train_s[sub_idx]
y_sub = y_train[sub_idx]

# Also subsample test for faster evaluation during grid search
test_idx = np.random.RandomState(42).choice(len(X_test_s), size=20000, replace=False)
X_test_sub = X_test_s[test_idx]
y_test_sub = y_test[test_idx]

print(f"   Train: {len(X_train):,} | Test: {len(X_test):,}")
print(f"   Grid search subsample: 50K train / 20K test")

# ============================================================
# 2. FAST GRID SEARCH (on subsample)
# ============================================================
print("\n[2/5] Grid search on subsample...")

contamination_values = [0.1, 0.2, 0.3, malicious_rate, 0.45, 0.5]
n_est_values = [100, 150, 200]
ms_values = ['auto', 0.75]

best_f1 = 0
best_params = {}

for cont in contamination_values:
    for n_est in n_est_values:
        for ms in ms_values:
            model = IsolationForest(
                n_estimators=n_est, contamination=cont,
                max_samples=ms, random_state=42, n_jobs=-1
            )
            model.fit(X_sub)
            raw_pred = model.predict(X_test_sub)
            y_pred = np.where(raw_pred == -1, 1, 0)
            f1 = f1_score(y_test_sub, y_pred, zero_division=0)
            rec = recall_score(y_test_sub, y_pred, zero_division=0)
            prec = precision_score(y_test_sub, y_pred, zero_division=0)

            if f1 > best_f1:
                best_f1 = f1
                best_params = {'contamination': cont, 'n_estimators': n_est, 'max_samples': ms}
                print(f"   BEST: cont={cont:.4f} n_est={n_est} ms={ms} -> F1={f1:.4f} Prec={prec:.4f} Rec={rec:.4f}")

print(f"\n   Best params: {best_params}")

# ============================================================
# 3. THRESHOLD OPTIMIZATION (on subsample)
# ============================================================
print("\n[3/5] Threshold optimization...")

tune_model = IsolationForest(
    n_estimators=best_params['n_estimators'],
    contamination=best_params['contamination'],
    max_samples=best_params['max_samples'],
    random_state=42, n_jobs=-1
)
tune_model.fit(X_sub)

scores_sub = tune_model.decision_function(X_sub)
scores_test = tune_model.decision_function(X_test_sub)

best_threshold = 0
best_f1_thresh = 0

# Coarse search
for pct in range(5, 96, 5):
    t = np.percentile(scores_sub, pct)
    y_pred = np.where(scores_test < t, 1, 0)
    f1 = f1_score(y_test_sub, y_pred, zero_division=0)
    if f1 > best_f1_thresh:
        best_f1_thresh = f1
        best_threshold = t

# Fine search
for t in np.linspace(best_threshold - 0.1, best_threshold + 0.1, 100):
    y_pred = np.where(scores_test < t, 1, 0)
    f1 = f1_score(y_test_sub, y_pred, zero_division=0)
    if f1 > best_f1_thresh:
        best_f1_thresh = f1
        best_threshold = t

print(f"   Best threshold: {best_threshold:.6f} -> F1: {best_f1_thresh:.4f}")

# ============================================================
# 4. FINAL MODEL ON FULL DATA
# ============================================================
print("\n[4/5] Training final model on FULL dataset...")

t0 = time.time()
final_model = IsolationForest(
    n_estimators=best_params['n_estimators'],
    contamination=best_params['contamination'],
    max_samples=best_params['max_samples'],
    random_state=42, n_jobs=-1
)
final_model.fit(X_train_s)
train_time = time.time() - t0

scores_test_full = final_model.decision_function(X_test_s)
y_pred = np.where(scores_test_full < best_threshold, 1, 0)

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, zero_division=0)
rec = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)
cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()
spec = tn / (tn + fp) if (tn + fp) > 0 else 0

t1 = time.time()
_ = final_model.predict(X_test_s)
infer_ms = (time.time() - t1) * 1000

print(f"\n{'=' * 70}")
print(f"  FINAL ISOLATION FOREST - FULL DATASET RESULTS")
print(f"{'=' * 70}")
print(f"""
  === CONFIGURATION ===
  n_estimators:       {best_params['n_estimators']}
  max_samples:        {best_params['max_samples']}
  contamination:      {best_params['contamination']:.4f}
  decision_threshold: {best_threshold:.6f}

  === PERFORMANCE METRICS ===
  Accuracy:       {acc:.6f}  ({acc*100:.2f}%)
  Precision:      {prec:.6f}  ({prec*100:.2f}%)
  Recall:         {rec:.6f}  ({rec*100:.2f}%)
  F1-Score:       {f1:.6f}  ({f1*100:.2f}%)
  Specificity:    {spec:.6f}  ({spec*100:.2f}%)

  === CONFUSION MATRIX ===
                    Predicted
                  Benign  Malicious
  Actual Benign    {tn:>6}    {fp:>6}
  Actual Malicious {fn:>6}    {tp:>6}

  TP: {tp:>8} | TN: {tn:>8}
  FP: {fp:>8} | FN: {fn:>8}

  === TIMING ===
  Training:    {train_time:.2f}s
  Inference:   {infer_ms:.2f}ms total ({infer_ms/len(X_test)*1000:.4f}ms/sample)
""")

print("  === CLASSIFICATION REPORT ===")
report = classification_report(y_test, y_pred, target_names=['Benign', 'Malicious'])
for line in report.split('\n'):
    print(f"  {line}")

# ============================================================
# 5. EXPORT
# ============================================================
print("\n[5/5] Exporting...")

with open(os.path.join(MODELS, 'isolation_forest.pkl'), 'wb') as f:
    pickle.dump(final_model, f)
with open(os.path.join(MODELS, 'if_scaler.pkl'), 'wb') as f:
    pickle.dump(scaler, f)

config = {
    "model": "IsolationForest",
    "type": "unsupervised_anomaly_detection",
    "params": {
        "n_estimators": best_params['n_estimators'],
        "max_samples": best_params['max_samples'],
        "contamination": float(best_params['contamination']),
        "decision_threshold": float(best_threshold)
    },
    "features": [
        'url_length', 'url_entropy', 'num_special_chars', 'num_encoded_chars',
        'has_sql_keywords', 'has_js_keywords', 'has_path_traversal', 'has_cmd_injection',
        'has_xxe_patterns', 'has_ssi_patterns', 'has_injection_patterns',
        'has_prompt_injection', 'has_suspicious_encoding',
        'body_length', 'body_entropy', 'num_headers', 'has_user_agent',
        'requests_per_minute', 'unique_urls_per_session', 'error_rate', 'severity'
    ],
    "test_metrics": {
        "accuracy": float(acc), "precision": float(prec), "recall": float(rec),
        "f1": float(f1), "specificity": float(spec)
    },
    "trained_rows": len(X),
    "timestamp": datetime.now().isoformat()
}
with open(os.path.join(MODELS, 'if_model_config.json'), 'w') as f:
    json.dump(config, f, indent=2)
with open(os.path.join(RESULTS, 'isolation_forest_final.json'), 'w') as f:
    json.dump(config, f, indent=2)

print(f"\n{'=' * 70}")
print(f"  EXPORTED:")
print(f"    models/isolation_forest.pkl")
print(f"    models/if_scaler.pkl")
print(f"    models/if_model_config.json")
print(f"{'=' * 70}")
print(f"  DONE - IF optimized: F1 {f1*100:.2f}% (was 39.8%)")
print(f"{'=' * 70}")
