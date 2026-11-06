"""
STEP 1 - Freeze model artifacts for gateway.
Trains RandomForest on WHOLE ml_dataset_fixed.csv and saves:
  models/aegis_model.pkl, models/scaler.pkl, models/model_config.json
RF chosen over MLP: 88.5% vs 90.8% but 5x faster inference, explainable.
"""
import os, csv, json, pickle, time
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score

BASE = os.path.join(os.path.dirname(__file__), '..')
SRC = os.path.join(BASE, 'dataset', 'ml_dataset_fixed.csv')
OUT = os.path.join(BASE, 'models')
os.makedirs(OUT, exist_ok=True)

print("Loading fixed dataset...")
with open(SRC, encoding='utf-8') as f:
    r = csv.reader(f); h = next(r)
    rows = [row for row in r if len(row) == len(h)]
print(f"Rows: {len(rows):,}")

FEATURES = [
    'url_length', 'url_entropy', 'num_special_chars', 'num_encoded_chars',
    'has_sql_keywords', 'has_js_keywords', 'has_path_traversal', 'has_cmd_injection',
    'has_xxe_patterns', 'has_ssi_patterns', 'has_injection_patterns',
    'has_prompt_injection', 'has_suspicious_encoding',
    'body_length', 'body_entropy', 'num_headers', 'has_user_agent',
    'requests_per_minute', 'unique_urls_per_session', 'error_rate'
]
X = np.array([[float(row[i]) if row[i] else 0.0 for i in range(7, 27)] for row in rows])
y = np.array([int(row[27]) for row in rows])

Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
scaler = StandardScaler()
Xtr_s = scaler.fit_transform(Xtr)
Xte_s = scaler.transform(Xte)

print("Training RF(100, depth=12)...")
t0 = time.time()
model = RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_leaf=5,
                               n_jobs=-1, random_state=42, class_weight='balanced')
model.fit(Xtr_s, ytr)
print(f"Train time: {time.time()-t0:.1f}s")
yp = model.predict(Xte_s)
print(f"Test acc={accuracy_score(yte, yp):.4f} F1={f1_score(yte, yp):.4f}")

with open(os.path.join(OUT, 'aegis_model.pkl'), 'wb') as f:
    pickle.dump(model, f)
with open(os.path.join(OUT, 'scaler.pkl'), 'wb') as f:
    pickle.dump(scaler, f)
with open(os.path.join(OUT, 'model_config.json'), 'w') as f:
    json.dump({"model": "RandomForest", "features": FEATURES,
               "test_acc": float(accuracy_score(yte, yp)),
               "test_f1": float(f1_score(yte, yp)),
               "trained_rows": len(rows)}, f, indent=2)
print(f"Saved to {OUT}/aegis_model.pkl, scaler.pkl, model_config.json")
