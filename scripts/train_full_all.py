"""
AEGIS Full Training - Optimized for 500K dataset
Uses stratified subsample for slow models, full for fast ones
"""
import os, csv, json, time, warnings
import numpy as np
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
from sklearn.ensemble import (
    RandomForestClassifier, GradientBoostingClassifier,
    AdaBoostClassifier, IsolationForest
)
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier

warnings.filterwarnings('ignore')
np.random.seed(42)

BASE = os.path.join(os.path.dirname(__file__), '..')
DATASET = os.path.join(BASE, 'dataset', 'aegis_dataset.csv')
RESULTS = os.path.join(BASE, 'results')
os.makedirs(RESULTS, exist_ok=True)

# ============================================================
# 1. LOAD & PREPROCESS
# ============================================================
print("=" * 70)
print("AEGIS FULL DATASET TRAINING - ALL MODELS + ISOLATION FOREST")
print("=" * 70)

print("\n[1/5] Loading dataset...")
with open(DATASET, encoding='utf-8') as f:
    reader = csv.reader(f)
    headers = next(reader)
    raw = [row for row in reader if len(row) == len(headers)]
print(f"   Raw rows: {len(raw):,}")

seen = set()
data = []
for row in raw:
    key = ','.join(row[3:29])
    if key not in seen:
        seen.add(key)
        data.append(row)
print(f"   Unique rows: {len(data):,}")

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
print(f"   Samples: {len(X):,} | Features: {X.shape[1]}")
print(f"   Class dist: Benign={sum(y==0):,} | Malicious={sum(y==1):,}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)
print(f"   Train: {len(X_train):,} | Test: {len(X_test):,}")

# Stratified subsample for slow models (50K)
sub_idx = np.random.RandomState(42).choice(len(X_train_s), size=min(50000, len(X_train_s)), replace=False)
X_sub = X_train_s[sub_idx]
y_sub = y_train[sub_idx]

# ============================================================
# 2. TRAIN ALL MODELS
# ============================================================
print("\n[2/5] Training models...\n")

results = []

def train_and_eval(name, model, use_full=True):
    Xtr = X_train_s if use_full else X_sub
    ytr = y_train if use_full else y_sub
    tag = "(full)" if use_full else f"(50K sub)"

    print(f"   {name} {tag}...")
    t0 = time.time()

    if name == 'Isolation Forest':
        model.fit(Xtr)
        train_time = time.time() - t0
        t1 = time.time()
        raw_pred = model.predict(X_test_s)
        y_pred = np.where(raw_pred == -1, 1, 0)
        infer_ms = (time.time() - t1) * 1000
    else:
        model.fit(Xtr, ytr)
        train_time = time.time() - t0
        t1 = time.time()
        y_pred = model.predict(X_test_s)
        infer_ms = (time.time() - t1) * 1000

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0

    roc_auc = None
    if hasattr(model, 'predict_proba') and name != 'Isolation Forest':
        try:
            y_proba = model.predict_proba(X_test_s)[:, 1]
            roc_auc = roc_auc_score(y_test, y_proba)
        except Exception:
            pass

    auc_str = f"{roc_auc:.4f}" if roc_auc else "N/A"
    print(f"      Acc:{acc:.4f} Prec:{prec:.4f} Rec:{rec:.4f} F1:{f1:.4f} AUC:{auc_str} | {train_time:.1f}s")

    return {
        'name': name, 'accuracy': acc, 'precision': prec, 'recall': rec,
        'f1': f1, 'specificity': spec, 'roc_auc': roc_auc,
        'tp': int(tp), 'tn': int(tn), 'fp': int(fp), 'fn': int(fn),
        'train_time': train_time, 'inference_ms': infer_ms
    }

# Fast models on full data
results.append(train_and_eval("Random Forest",
    RandomForestClassifier(n_estimators=200, max_depth=15, min_samples_leaf=3,
                           n_jobs=-1, random_state=42, class_weight='balanced')))

results.append(train_and_eval("Decision Tree",
    DecisionTreeClassifier(max_depth=15, min_samples_leaf=5,
                           random_state=42, class_weight='balanced')))

results.append(train_and_eval("Gradient Boosting",
    GradientBoostingClassifier(n_estimators=150, max_depth=6,
                               learning_rate=0.1, subsample=0.8, random_state=42)))

results.append(train_and_eval("AdaBoost",
    AdaBoostClassifier(n_estimators=150, learning_rate=0.1, random_state=42,
                       algorithm='SAMME')))

results.append(train_and_eval("Isolation Forest",
    IsolationForest(n_estimators=150, contamination=0.1,
                    random_state=42, n_jobs=-1)))

# Slow models on subsample
results.append(train_and_eval("Logistic Regression",
    LogisticRegression(max_iter=500, random_state=42, class_weight='balanced', C=0.5),
    use_full=False))

results.append(train_and_eval("Linear SVM",
    LinearSVC(max_iter=1000, C=0.5, class_weight='balanced', random_state=42),
    use_full=False))

results.append(train_and_eval("MLP Neural Network",
    MLPClassifier(hidden_layer_sizes=(128, 64, 32), max_iter=200,
                  random_state=42, early_stopping=True, validation_fraction=0.1),
    use_full=False))

results.append(train_and_eval("K-Nearest Neighbors",
    KNeighborsClassifier(n_neighbors=7, n_jobs=-1),
    use_full=False))

# ============================================================
# 3. RESULTS TABLE
# ============================================================
print("\n" + "=" * 105)
print("MODEL COMPARISON (sorted by F1-Score)")
print("=" * 105)
print(f"{'Model':<25} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'Specificity':>12} {'ROC-AUC':>10} {'Train(s)':>10}")
print("-" * 105)
for r in sorted(results, key=lambda x: x['f1'], reverse=True):
    auc_str = f"{r['roc_auc']:.4f}" if r['roc_auc'] else "N/A"
    print(f"{r['name']:<25} {r['accuracy']:>10.4f} {r['precision']:>10.4f} {r['recall']:>10.4f} {r['f1']:>10.4f} {r['specificity']:>12.4f} {auc_str:>10} {r['train_time']:>10.1f}")

# ============================================================
# 4. BEST MODEL DEEP DIVE
# ============================================================
best = max(results, key=lambda x: x['f1'])
print(f"\n{'=' * 70}")
print(f"  BEST MODEL: {best['name']}")
print(f"{'=' * 70}")

# Get predictions for best model
if best['name'] == 'Isolation Forest':
    raw_pred = list(model_objects.values())[list(model_objects.keys()).index(best['name'])].predict(X_test_s) if False else None

# Re-predict with best model
best_model_map = {r['name']: m for r, m in zip(results, [
    RandomForestClassifier(n_estimators=200, max_depth=15, min_samples_leaf=3,
                           n_jobs=-1, random_state=42, class_weight='balanced'),
    DecisionTreeClassifier(max_depth=15, min_samples_leaf=5,
                           random_state=42, class_weight='balanced'),
    GradientBoostingClassifier(n_estimators=150, max_depth=6,
                               learning_rate=0.1, subsample=0.8, random_state=42),
    AdaBoostClassifier(n_estimators=150, learning_rate=0.1, random_state=42, algorithm='SAMME'),
    IsolationForest(n_estimators=150, contamination=0.1, random_state=42, n_jobs=-1),
    LogisticRegression(max_iter=500, random_state=42, class_weight='balanced', C=0.5),
    LinearSVC(max_iter=1000, C=0.5, class_weight='balanced', random_state=42),
    MLPClassifier(hidden_layer_sizes=(128, 64, 32), max_iter=200,
                  random_state=42, early_stopping=True, validation_fraction=0.1),
    KNeighborsClassifier(n_neighbors=7, n_jobs=-1),
])}

# Retrain best model for classification report
if best['name'] == 'Isolation Forest':
    bm = IsolationForest(n_estimators=150, contamination=0.1, random_state=42, n_jobs=-1)
    bm.fit(X_train_s)
    raw_p = bm.predict(X_test_s)
    y_best_pred = np.where(raw_p == -1, 1, 0)
else:
    # Retrain on full
    model_retrain = {
        'Random Forest': RandomForestClassifier(n_estimators=200, max_depth=15, min_samples_leaf=3, n_jobs=-1, random_state=42, class_weight='balanced'),
        'Decision Tree': DecisionTreeClassifier(max_depth=15, min_samples_leaf=5, random_state=42, class_weight='balanced'),
        'Gradient Boosting': GradientBoostingClassifier(n_estimators=150, max_depth=6, learning_rate=0.1, subsample=0.8, random_state=42),
        'AdaBoost': AdaBoostClassifier(n_estimators=150, learning_rate=0.1, random_state=42, algorithm='SAMME'),
        'Logistic Regression': LogisticRegression(max_iter=500, random_state=42, class_weight='balanced', C=0.5),
        'Linear SVM': LinearSVC(max_iter=1000, C=0.5, class_weight='balanced', random_state=42),
        'MLP Neural Network': MLPClassifier(hidden_layer_sizes=(128, 64, 32), max_iter=200, random_state=42, early_stopping=True, validation_fraction=0.1),
        'K-Nearest Neighbors': KNeighborsClassifier(n_neighbors=7, n_jobs=-1),
    }
    bm = model_retrain[best['name']]
    use_sub = best['name'] in ['Logistic Regression', 'Linear SVM', 'MLP Neural Network', 'K-Nearest Neighbors']
    Xtr_final = X_sub if use_sub else X_train_s
    ytr_final = y_sub if use_sub else y_train
    bm.fit(Xtr_final, ytr_final)
    y_best_pred = bm.predict(X_test_s)

print(f"""
  === PERFORMANCE METRICS ===
  Accuracy:       {best['accuracy']:.6f}  ({best['accuracy']*100:.2f}%)
  Precision:      {best['precision']:.6f}  ({best['precision']*100:.2f}%)
  Recall:         {best['recall']:.6f}  ({best['recall']*100:.2f}%)
  F1-Score:       {best['f1']:.6f}  ({best['f1']*100:.2f}%)
  Specificity:    {best['specificity']:.6f}  ({best['specificity']*100:.2f}%)
  ROC-AUC:        {f"{best['roc_auc']:.6f}" if best['roc_auc'] else 'N/A'}

  === CONFUSION MATRIX ===
                    Predicted
                  Benign  Malicious
  Actual Benign    {best['tn']:>6}    {best['fp']:>6}
  Actual Malicious {best['fn']:>6}    {best['tp']:>6}

  True Positives:   {best['tp']:>8}  (correctly detected malicious)
  True Negatives:   {best['tn']:>8}  (correctly detected benign)
  False Positives:  {best['fp']:>8}  (benign flagged as malicious)
  False Negatives:  {best['fn']:>8}  (malicious missed!)

  === TIMING ===
  Training Time:    {best['train_time']:.2f}s
  Inference Time:   {best['inference_ms']:.2f}ms total ({best['inference_ms']/len(X_test)*1000:.4f}ms/sample)
""")

print("  === CLASSIFICATION REPORT ===")
report = classification_report(y_test, y_best_pred, target_names=['Benign', 'Malicious'])
for line in report.split('\n'):
    print(f"  {line}")

# ============================================================
# 5. SAVE
# ============================================================
print("\n[5/5] Saving results...")

with open(os.path.join(RESULTS, 'full_all_models_metrics.csv'), 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['Model', 'Accuracy', 'Precision', 'Recall', 'F1', 'Specificity', 'ROC_AUC', 'TP', 'TN', 'FP', 'FN', 'TrainTime_s', 'Inference_ms'])
    for r in results:
        w.writerow([r['name'], f"{r['accuracy']:.4f}", f"{r['precision']:.4f}", f"{r['recall']:.4f}",
                     f"{r['f1']:.4f}", f"{r['specificity']:.4f}", f"{r['roc_auc']:.4f}" if r['roc_auc'] else 'N/A',
                     r['tp'], r['tn'], r['fp'], r['fn'], f"{r['train_time']:.2f}", f"{r['inference_ms']:.2f}"])

with open(os.path.join(RESULTS, 'full_all_models_results.json'), 'w') as f:
    json.dump({
        'timestamp': datetime.now().isoformat(),
        'total_samples': len(X),
        'train_samples': len(X_train),
        'test_samples': len(X_test),
        'features': int(X.shape[1]),
        'best_model': best['name'],
        'best_metrics': {k: v for k, v in best.items() if k != 'name'},
        'all_results': results
    }, f, indent=2, default=str)

cm = confusion_matrix(y_test, y_best_pred)
with open(os.path.join(RESULTS, 'full_all_confusion_matrix.csv'), 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['', 'Predicted_Benign', 'Predicted_Malicious'])
    w.writerow(['Actual_Benign', cm[0][0], cm[0][1]])
    w.writerow(['Actual_Malicious', cm[1][0], cm[1][1]])

print(f"   Saved to: {RESULTS}")
print(f"\n{'=' * 70}")
print(f"  DONE - {best['name']} achieved {best['f1']*100:.2f}% F1 on {len(X):,} samples")
print(f"{'=' * 70}")
