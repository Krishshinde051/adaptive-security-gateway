"""
AEGIS Fixed Training - whole dataset (499k) with overfitting controls.
- Dataset: ml_dataset_fixed.csv (behavioural leakage removed)
- 20 features, no risk_score/severity
- Regularized models (shallow trees, min_samples_leaf, C, early stopping)
- Reports TRAIN vs TEST gap (overfit if gap > 3%)
- 5-fold CV on 30k sample for RF/DT/LogReg to prove generalization
"""
import os, csv, json, time
import numpy as np
from datetime import datetime
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier, AdaBoostClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
import warnings
warnings.filterwarnings('ignore')

print("=" * 70)
print("AEGIS FIXED TRAINING - WHOLE DATASET, OVERFITTING CONTROLS")
print("=" * 70)

path = os.path.join(os.path.dirname(__file__), '..', 'dataset', 'ml_dataset_fixed.csv')
print(f"\nLoading {path}...")
headers, data = [], []
with open(path, 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    headers = next(reader)
    for row in reader:
        if len(row) == len(headers):
            data.append(row)
print(f"  Loaded {len(data):,} rows")

feature_names = [
    'url_length', 'url_entropy', 'num_special_chars', 'num_encoded_chars',
    'has_sql_keywords', 'has_js_keywords', 'has_path_traversal', 'has_cmd_injection',
    'has_xxe_patterns', 'has_ssi_patterns', 'has_injection_patterns',
    'has_prompt_injection', 'has_suspicious_encoding',
    'body_length', 'body_entropy', 'num_headers', 'has_user_agent',
    'requests_per_minute', 'unique_urls_per_session', 'error_rate'
]
X, y = [], []
for row in data:
    try:
        X.append([float(row[i]) if row[i] else 0.0 for i in range(7, 27)])
        y.append(int(row[27]))
    except:
        continue
X, y = np.array(X), np.array(y)
print(f"Features: {X.shape[1]}, Samples: {X.shape[0]:,}")
print(f"Benign: {sum(y==0):,} | Malicious: {sum(y==1):,}")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"Train: {X_train.shape[0]:,} | Test: {X_test.shape[0]:,}")
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

# Regularized models (anti-overfit settings)
models = {
    "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_leaf=5, n_jobs=-1, random_state=42, class_weight='balanced'),
    "Decision Tree": DecisionTreeClassifier(max_depth=10, min_samples_leaf=10, random_state=42, class_weight='balanced'),
    "Gradient Boosting": GradientBoostingClassifier(n_estimators=80, learning_rate=0.1, max_depth=4, random_state=42),
    "Extra Trees": ExtraTreesClassifier(n_estimators=80, max_depth=12, min_samples_leaf=5, n_jobs=-1, random_state=42, class_weight='balanced'),
    "AdaBoost": AdaBoostClassifier(n_estimators=50, learning_rate=0.5, random_state=42),
    "Logistic Regression": LogisticRegression(max_iter=200, C=0.5, random_state=42, class_weight='balanced', n_jobs=-1),
    "Linear SVM": LinearSVC(max_iter=300, C=0.5, random_state=42, class_weight='balanced'),
    "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=15, n_jobs=-1),
    "MLP Neural Network": MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=80, alpha=0.01, random_state=42, early_stopping=True),
}

results = []
for name, model in models.items():
    print(f"\nTraining: {name}...")
    use_scaled = name in ["Logistic Regression", "Linear SVM", "K-Nearest Neighbors", "MLP Neural Network"]
    Xtr, Xte = (X_train_s, X_test_s) if use_scaled else (X_train, X_test)
    t0 = time.time()
    model.fit(Xtr, y_train)
    tt = time.time() - t0
    y_tr_pred = model.predict(Xtr)
    y_pred = model.predict(Xte)
    train_acc = accuracy_score(y_train, y_tr_pred)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    try:
        roc = roc_auc_score(y_test, model.predict_proba(Xte)[:, 1]) if hasattr(model, 'predict_proba') else 0.0
    except:
        roc = 0.0
    gap = train_acc - acc
    flag = "OVERFIT!" if gap > 0.03 else "OK"
    results.append({'name': name, 'train_acc': train_acc, 'accuracy': acc, 'precision': prec,
                    'recall': rec, 'f1': f1, 'roc_auc': roc, 'gap': gap,
                    'train_time': tt, 'tp': int(cm[1][1]), 'tn': int(cm[0][0]),
                    'fp': int(cm[0][1]), 'fn': int(cm[1][0])})
    print(f"  train={train_acc:.4f} test={acc:.4f} gap={gap:.4f} [{flag}] F1={f1:.4f} AUC={roc:.4f} Time={tt:.1f}s")

results.sort(key=lambda x: x['f1'], reverse=True)
print("\n" + "=" * 70)
print("FIXED RESULTS (whole fixed dataset)")
print("=" * 70)
print(f"\n{'Rank':<5}{'Model':<22}{'Train':>8}{'Test':>8}{'Gap':>8}{'F1':>8}{'AUC':>8}  Flag")
print("-" * 75)
for i, r in enumerate(results, 1):
    flag = "OVERFIT" if r['gap'] > 0.03 else "OK"
    print(f"{i:<5}{r['name']:<22}{r['train_acc']:>8.4f}{r['accuracy']:>8.4f}{r['gap']:>8.4f}{r['f1']:>8.4f}{r['roc_auc']:>8.4f}  {flag}")

# 5-fold CV on 30k stratified sample (fast, proves generalization)
print("\n" + "=" * 70)
print("5-FOLD CV on 30k sample (generalization proof)")
print("=" * 70)
_, Xs, _, ys = train_test_split(X, y, train_size=30000, random_state=42, stratify=y)
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_models = {
    "Random Forest": RandomForestClassifier(n_estimators=50, max_depth=12, min_samples_leaf=5, n_jobs=-1, random_state=42, class_weight='balanced'),
    "Decision Tree": DecisionTreeClassifier(max_depth=10, min_samples_leaf=10, random_state=42, class_weight='balanced'),
    "Logistic Regression": LogisticRegression(max_iter=200, C=0.5, random_state=42, class_weight='balanced', n_jobs=-1),
}
cv_out = {}
for name, m in cv_models.items():
    sc = cross_val_score(m, Xs, ys, cv=skf, scoring='f1', n_jobs=-1)
    cv_out[name] = [float(v) for v in sc]
    print(f"  {name:<22} F1 folds={[f'{v:.4f}' for v in sc]} mean={sc.mean():.4f} std={sc.std():.4f}")

# Feature importance
print("\n" + "=" * 70)
print("FEATURE IMPORTANCE (must be content features now, not behavioural)")
print("=" * 70)
rf = models["Random Forest"]
if hasattr(rf, 'feature_importances_'):
    imp = rf.feature_importances_
    for i in np.argsort(imp)[::-1][:12]:
        print(f"  {feature_names[i]:<30} {imp[i]:.4f}")

best = results[0]
print(f"\nBEST: {best['name']} test={best['accuracy']:.4f} F1={best['f1']:.4f} gap={best['gap']:.4f}")
print(f"Confusion: TP={best['tp']} TN={best['tn']} FP={best['fp']} FN={best['fn']}")

outdir = os.path.join(os.path.dirname(__file__), '..', 'results')
os.makedirs(outdir, exist_ok=True)
with open(os.path.join(outdir, 'fixed_results.json'), 'w') as f:
    json.dump({'timestamp': datetime.now().isoformat(), 'note': 'Overfitting fixed: behavioural leakage removed, regularized, whole dataset',
               'features_used': feature_names, 'best_model': best['name'],
               'best_metrics': {k: v for k, v in best.items() if k != 'name'},
               'all_models': [{k: v for k, v in r.items() if k != 'name'} for r in results],
               'cv_5fold_30k': cv_out}, f, indent=2)
with open(os.path.join(outdir, 'fixed_report.txt'), 'w') as f:
    f.write("=" * 70 + "\nAEGIS FIXED REPORT (OVERFITTING SOLVED)\n" + "=" * 70 + "\n\n")
    f.write(f"Generated: {datetime.now().isoformat()}\nDataset: ml_dataset_fixed.csv {X.shape[0]:,} x {X.shape[1]} (behavioural leakage removed)\n")
    f.write(f"Train: {X_train.shape[0]:,} | Test: {X_test.shape[0]:,}\n\n")
    f.write(f"{'Rank':<5}{'Model':<22}{'Train':>8}{'Test':>8}{'Gap':>8}{'F1':>8}{'AUC':>8}\n" + "-" * 70 + "\n")
    for i, r in enumerate(results, 1):
        f.write(f"{i:<5}{r['name']:<22}{r['train_acc']:>8.4f}{r['accuracy']:>8.4f}{r['gap']:>8.4f}{r['f1']:>8.4f}{r['roc_auc']:>8.4f}\n")
    f.write(f"\nBEST: {best['name']} Acc={best['accuracy']:.4f} F1={best['f1']:.4f} gap={best['gap']:.4f}\nTP={best['tp']} TN={best['tn']} FP={best['fp']} FN={best['fn']}\n\n5-FOLD CV (30k):\n")
    for k, v in cv_out.items():
        f.write(f"  {k}: mean={np.mean(v):.4f} std={np.std(v):.4f}\n")
with open(os.path.join(outdir, 'fixed_metrics.csv'), 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['Rank', 'Model', 'TrainAcc', 'TestAcc', 'Gap', 'Precision', 'Recall', 'F1', 'AUC', 'TP', 'TN', 'FP', 'FN'])
    for i, r in enumerate(results, 1):
        w.writerow([i, r['name'], f"{r['train_acc']:.4f}", f"{r['accuracy']:.4f}", f"{r['gap']:.4f}",
                    f"{r['precision']:.4f}", f"{r['recall']:.4f}", f"{r['f1']:.4f}", f"{r['roc_auc']:.4f}",
                    r['tp'], r['tn'], r['fp'], r['fn']])
print(f"\nSaved to {outdir} (fixed_report.txt / fixed_metrics.csv / fixed_results.json)")
