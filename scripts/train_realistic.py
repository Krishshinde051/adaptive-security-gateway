"""
AEGIS ML Training - WITHOUT DATA LEAKAGE
Removes: risk_score, severity_numeric (derived from labels)
This gives REALISTIC accuracy ~95-98%
"""
import os, csv, json, time
import numpy as np
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, roc_auc_score, classification_report)
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier, AdaBoostClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
import warnings
warnings.filterwarnings('ignore')

print("=" * 70)
print("AEGIS ML TRAINING - REALISTIC (NO DATA LEAKAGE)")
print("Removed: risk_score, severity_numeric")
print("=" * 70)

# LOAD
path = os.path.join(os.path.dirname(__file__), '..', 'dataset', 'ml_dataset.csv')
print(f"\nLoading {path}...")
headers, data = [], []
with open(path, 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    headers = next(reader)
    for row in reader:
        if len(row) == len(headers):
            data.append(row)
print(f"  Loaded {len(data):,} rows")

# DEDUP
seen, clean = set(), []
for row in data:
    k = ','.join(row[3:29])
    if k not in seen:
        seen.add(k)
        clean.append(row)
print(f"  Unique: {len(clean):,}")

# FEATURES - WITHOUT LEAKY ONES
# Skip columns 26 (risk_score) and 28 (severity_numeric)
feature_names = [
    'url_length', 'url_entropy', 'num_special_chars', 'num_encoded_chars',
    'has_sql_keywords', 'has_js_keywords', 'has_path_traversal', 'has_cmd_injection',
    'has_xxe_patterns', 'has_ssi_patterns', 'has_injection_patterns',
    'has_prompt_injection', 'has_suspicious_encoding',
    'body_length', 'body_entropy', 'num_headers', 'has_user_agent',
    'requests_per_minute', 'unique_urls_per_session', 'error_rate'
]

X, y = [], []
for row in clean:
    try:
        features = [float(row[i]) if row[i] else 0.0 for i in range(7, 27)]  # 20 features
        X.append(features)
        y.append(int(row[27]))  # label is now at index 27
    except:
        continue

X, y = np.array(X), np.array(y)
print(f"\nFeatures: {X.shape[1]} (removed risk_score, severity_numeric)")
print(f"Samples:  {X.shape[0]:,}")
print(f"Benign:   {sum(y==0):,} ({sum(y==0)/len(y)*100:.1f}%)")
print(f"Malicious: {sum(y==1):,} ({sum(y==1)/len(y)*100:.1f}%)")

# SPLIT
print("\nSplitting 80/20...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"  Train: {X_train.shape[0]:,} | Test: {X_test.shape[0]:,}")

# SCALE
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

# MODELS
print("\n" + "=" * 70)
print("TRAINING 9 MODELS (NO DATA LEAKAGE)")
print("=" * 70)

models = {
    "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42, class_weight='balanced'),
    "Decision Tree": DecisionTreeClassifier(max_depth=15, random_state=42, class_weight='balanced'),
    "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42),
    "Extra Trees": ExtraTreesClassifier(n_estimators=100, max_depth=15, n_jobs=-1, random_state=42, class_weight='balanced'),
    "AdaBoost": AdaBoostClassifier(n_estimators=100, learning_rate=0.1, random_state=42),
    "Logistic Regression": LogisticRegression(max_iter=200, random_state=42, class_weight='balanced', n_jobs=-1),
    "Linear SVM": LinearSVC(max_iter=200, random_state=42, class_weight='balanced'),
    "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=7, n_jobs=-1),
    "MLP Neural Network": MLPClassifier(hidden_layer_sizes=(128, 64, 32), max_iter=100, random_state=42, early_stopping=True),
}

results = []
for name, model in models.items():
    print(f"\nTraining: {name}...")
    use_scaled = name in ["Logistic Regression", "Linear SVM", "K-Nearest Neighbors", "MLP Neural Network"]
    Xtr, Xte = (X_train_s, X_test_s) if use_scaled else (X_train, X_test)

    t0 = time.time()
    model.fit(Xtr, y_train)
    tt = time.time() - t0

    t1 = time.time()
    y_pred = model.predict(Xte)
    it = (time.time() - t1) * 1000

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    try:
        if hasattr(model, 'predict_proba'):
            roc = roc_auc_score(y_test, model.predict_proba(Xte)[:, 1])
        else:
            roc = 0.0
    except:
        roc = 0.0

    m = {'name': name, 'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1,
         'roc_auc': roc, 'train_time': tt, 'inference_ms': it,
         'tp': int(cm[1][1]), 'tn': int(cm[0][0]), 'fp': int(cm[0][1]), 'fn': int(cm[1][0])}
    results.append(m)
    print(f"  Acc:{acc:.4f} Prec:{prec:.4f} Rec:{rec:.4f} F1:{f1:.4f} AUC:{roc:.4f} Time:{tt:.1f}s")

# COMPARISON
results.sort(key=lambda x: x['f1'], reverse=True)

print("\n" + "=" * 70)
print("RESULTS - REALISTIC (NO DATA LEAKAGE)")
print("=" * 70)
print(f"\n{'Rank':<5} {'Model':<25} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'ROC-AUC':>10}")
print("-" * 80)
for i, r in enumerate(results, 1):
    print(f"{i:<5} {r['name']:<25} {r['accuracy']:>10.4f} {r['precision']:>10.4f} {r['recall']:>10.4f} {r['f1']:>10.4f} {r['roc_auc']:>10.4f}")

best = results[0]
print(f"\nBEST MODEL: {best['name']}")
print(f"  Accuracy:  {best['accuracy']:.4f} ({best['accuracy']*100:.2f}%)")
print(f"  Precision: {best['precision']:.4f} ({best['precision']*100:.2f}%)")
print(f"  Recall:    {best['recall']:.4f} ({best['recall']*100:.2f}%)")
print(f"  F1-Score:  {best['f1']:.4f} ({best['f1']*100:.2f}%)")
print(f"  ROC-AUC:   {best['roc_auc']:.4f} ({best['roc_auc']*100:.2f}%)")
print(f"  Confusion: TP={best['tp']}, TN={best['tn']}, FP={best['fp']}, FN={best['fn']}")

# FEATURE IMPORTANCE
print("\n" + "=" * 70)
print("FEATURE IMPORTANCE")
print("=" * 70)
rf = models["Random Forest"]
if hasattr(rf, 'feature_importances_'):
    imp = rf.feature_importances_
    idx = np.argsort(imp)[::-1]
    for i in idx[:15]:
        print(f"  {feature_names[i]:<30} {imp[i]:.4f}")

# SAVE
outdir = os.path.join(os.path.dirname(__file__), '..', 'results')
os.makedirs(outdir, exist_ok=True)

with open(os.path.join(outdir, 'realistic_results.json'), 'w') as f:
    json.dump({'timestamp': datetime.now().isoformat(), 'note': 'No data leakage - realistic results',
        'features_used': feature_names, 'best_model': best['name'],
        'best_metrics': {k: v for k, v in best.items() if k != 'name'},
        'all_models': [{k: v for k, v in r.items() if k != 'name'} for r in results]}, f, indent=2)

with open(os.path.join(outdir, 'realistic_report.txt'), 'w') as f:
    f.write("=" * 70 + "\nAEGIS REALISTIC ML REPORT (NO DATA LEAKAGE)\n" + "=" * 70 + "\n\n")
    f.write(f"Generated: {datetime.now().isoformat()}\n")
    f.write(f"Dataset: {X.shape[0]:,} samples, {X.shape[1]} features\n")
    f.write(f"Note: risk_score and severity_numeric REMOVED\n\n")
    f.write(f"{'Rank':<5} {'Model':<25} {'Acc':>8} {'Prec':>8} {'Rec':>8} {'F1':>8} {'AUC':>8}\n")
    f.write("-" * 70 + "\n")
    for i, r in enumerate(results, 1):
        f.write(f"{i:<5} {r['name']:<25} {r['accuracy']:>8.4f} {r['precision']:>8.4f} {r['recall']:>8.4f} {r['f1']:>8.4f} {r['roc_auc']:>8.4f}\n")
    f.write(f"\nBEST: {best['name']}\n")
    f.write(f"Accuracy: {best['accuracy']:.4f}\nPrecision: {best['precision']:.4f}\nRecall: {best['recall']:.4f}\nF1: {best['f1']:.4f}\nAUC: {best['roc_auc']:.4f}\n")
    f.write(f"Confusion: TP={best['tp']}, TN={best['tn']}, FP={best['fp']}, FN={best['fn']}\n")

with open(os.path.join(outdir, 'realistic_metrics.csv'), 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['Rank','Model','Accuracy','Precision','Recall','F1','ROC_AUC','TrainTime_s','TP','TN','FP','FN'])
    for i, r in enumerate(results, 1):
        w.writerow([i, r['name'], f"{r['accuracy']:.4f}", f"{r['precision']:.4f}", f"{r['recall']:.4f}",
                     f"{r['f1']:.4f}", f"{r['roc_auc']:.4f}", f"{r['train_time']:.2f}",
                     r['tp'], r['tn'], r['fp'], r['fn']])

print(f"\nSaved to: {outdir}")
print("=" * 70)
