"""
AEGIS ML Training - FULL DATASET (500K samples)
Uses scikit-learn for proper ML on complete dataset
"""
import os, csv, json, time
import numpy as np
from datetime import datetime
from collections import Counter

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                             f1_score, confusion_matrix, classification_report,
                             roc_auc_score, precision_recall_curve, auc)
from sklearn.ensemble import (RandomForestClassifier, GradientBoostingClassifier,
                              ExtraTreesClassifier, AdaBoostClassifier)
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
import warnings
warnings.filterwarnings('ignore')

print("=" * 70)
print("AEGIS ML TRAINING - FULL DATASET (500K)")
print("Using scikit-learn for production-grade training")
print("=" * 70)

# ============================================================
# LOAD DATA
# ============================================================
path = os.path.join(os.path.dirname(__file__), '..', 'dataset', 'aegis_dataset.csv')
print(f"\nLoading dataset from {path}...")

headers = []
data = []
with open(path, 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    headers = next(reader)
    for row in reader:
        if len(row) == len(headers):
            data.append(row)

print(f"  Loaded {len(data):,} rows")

# ============================================================
# CLEAN DATA
# ============================================================
print("\nCleaning data...")
# Remove duplicates
seen = set()
clean = []
for row in data:
    key = ','.join(row[3:29])
    if key not in seen:
        seen.add(key)
        clean.append(row)

print(f"  Removed {len(data) - len(clean):,} duplicates")
print(f"  Clean dataset: {len(clean):,} rows")

# ============================================================
# EXTRACT FEATURES
# ============================================================
print("\nExtracting features...")
severity_map = {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

feature_names = [
    'url_length', 'url_entropy', 'num_special_chars', 'num_encoded_chars',
    'has_sql_keywords', 'has_js_keywords', 'has_path_traversal', 'has_cmd_injection',
    'has_xxe_patterns', 'has_ssi_patterns', 'has_injection_patterns',
    'has_prompt_injection', 'has_suspicious_encoding',
    'body_length', 'body_entropy', 'num_headers', 'has_user_agent',
    'requests_per_minute', 'unique_urls_per_session', 'error_rate',
    'risk_score', 'severity_numeric'
]

X = []
y = []
for row in clean:
    try:
        features = [float(row[i]) if row[i] else 0.0 for i in range(7, 28)]
        features.append(severity_map.get(row[28], 0) if len(row) > 28 else 0)
        X.append(features)
        y.append(int(row[29]))
    except:
        continue

X = np.array(X)
y = np.array(y)

print(f"  Features: {X.shape[1]}")
print(f"  Samples:  {X.shape[0]:,}")
print(f"  Benign:   {sum(y == 0):,} ({sum(y == 0)/len(y)*100:.1f}%)")
print(f"  Malicious: {sum(y == 1):,} ({sum(y == 1)/len(y)*100:.1f}%)")

# ============================================================
# TRAIN/TEST SPLIT
# ============================================================
print("\nSplitting data (80/20)...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print(f"  Train: {X_train.shape[0]:,} samples")
print(f"  Test:  {X_test.shape[0]:,} samples")

# ============================================================
# STANDARDIZE
# ============================================================
print("\nStandardizing features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ============================================================
# DEFINE MODELS
# ============================================================
print("\n" + "=" * 70)
print("TRAINING 8 MODELS ON FULL DATASET")
print("=" * 70)

models = {
    "Random Forest": RandomForestClassifier(
        n_estimators=100, max_depth=20, min_samples_split=5,
        n_jobs=-1, random_state=42, class_weight='balanced'
    ),
    "Decision Tree": DecisionTreeClassifier(
        max_depth=15, min_samples_split=10, random_state=42, class_weight='balanced'
    ),
    "Gradient Boosting": GradientBoostingClassifier(
        n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42
    ),
    "Extra Trees": ExtraTreesClassifier(
        n_estimators=100, max_depth=15, n_jobs=-1, random_state=42, class_weight='balanced'
    ),
    "AdaBoost": AdaBoostClassifier(
        n_estimators=100, learning_rate=0.1, random_state=42
    ),
    "Logistic Regression": LogisticRegression(
        max_iter=200, C=1.0, random_state=42, class_weight='balanced', n_jobs=-1
    ),
    "Linear SVM": LinearSVC(
        max_iter=200, C=1.0, random_state=42, class_weight='balanced'
    ),
    "K-Nearest Neighbors": KNeighborsClassifier(
        n_neighbors=7, n_jobs=-1
    ),
    "MLP Neural Network": MLPClassifier(
        hidden_layer_sizes=(128, 64, 32), max_iter=100, random_state=42,
        early_stopping=True, validation_fraction=0.1
    ),
}

# ============================================================
# TRAIN AND EVALUATE
# ============================================================
results = []

for name, model in models.items():
    print(f"\n{'â”€' * 50}")
    print(f"Training: {name}")
    print(f"{'â”€' * 50}")
    
    # Use scaled data for distance-based models
    use_scaled = name in ["Logistic Regression", "Linear SVM", "K-Nearest Neighbors", "MLP Neural Network"]
    Xtr = X_train_scaled if use_scaled else X_train
    Xte = X_test_scaled if use_scaled else X_test
    
    # Train
    t0 = time.time()
    model.fit(Xtr, y_train)
    train_time = time.time() - t0
    print(f"  Training time: {train_time:.2f}s")
    
    # Predict
    t1 = time.time()
    y_pred = model.predict(Xte)
    inference_time = (time.time() - t1) * 1000
    
    # Metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    
    # ROC-AUC (if model supports predict_proba)
    try:
        if hasattr(model, 'predict_proba'):
            y_proba = model.predict_proba(Xte)[:, 1]
            roc_auc = roc_auc_score(y_test, y_proba)
        else:
            roc_auc = 0.0
    except:
        roc_auc = 0.0
    
    metrics = {
        'name': name,
        'accuracy': acc,
        'precision': prec,
        'recall': rec,
        'f1': f1,
        'roc_auc': roc_auc,
        'train_time': train_time,
        'inference_ms': inference_time,
        'confusion_matrix': {
            'tn': int(cm[0][0]),
            'fp': int(cm[0][1]),
            'fn': int(cm[1][0]),
            'tp': int(cm[1][1])
        }
    }
    results.append(metrics)
    
    print(f"  Accuracy:  {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Precision: {prec:.4f} ({prec*100:.2f}%)")
    print(f"  Recall:    {rec:.4f} ({rec*100:.2f}%)")
    print(f"  F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
    print(f"  ROC-AUC:   {roc_auc:.4f}")
    print(f"  Confusion: TP={cm[1][1]}, TN={cm[0][0]}, FP={cm[0][1]}, FN={cm[1][0]}")

# ============================================================
# RESULTS COMPARISON
# ============================================================
print("\n" + "=" * 70)
print("COMPLETE MODEL COMPARISON - FULL 500K DATASET")
print("=" * 70)

results.sort(key=lambda x: x['f1'], reverse=True)

print(f"\n{'Rank':<5} {'Model':<25} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'ROC-AUC':>10}")
print("â”€" * 80)

for i, r in enumerate(results, 1):
    print(f"{i:<5} {r['name']:<25} {r['accuracy']:>10.4f} {r['precision']:>10.4f} {r['recall']:>10.4f} {r['f1']:>10.4f} {r['roc_auc']:>10.4f}")

# ============================================================
# BEST MODEL DETAILS
# ============================================================
best = results[0]

print("\n" + "=" * 70)
print(f"  BEST MODEL: {best['name']}")
print("=" * 70)

print(f"""
+====================================================================+
|                    BEST MODEL METRICS                               |
+====================================================================+
|                                                                     |
|  Accuracy:      {best['accuracy']:.4f}  ({best['accuracy']*100:.2f}%)                    |
|  Precision:     {best['precision']:.4f}  ({best['precision']*100:.2f}%)                    |
|  Recall:        {best['recall']:.4f}  ({best['recall']*100:.2f}%)                    |
|  F1-Score:      {best['f1']:.4f}  ({best['f1']*100:.2f}%)                    |
|  ROC-AUC:       {best['roc_auc']:.4f}  ({best['roc_auc']*100:.2f}%)                    |
|                                                                     |
+---------------------------------------------------------------------+
|                    CONFUSION MATRIX                                  |
+---------------------------------------------------------------------+
|                                                                     |
|                      Predicted                                      |
|                    Benign      Malicious                             |
|  Actual Benign   {best['confusion_matrix']['tn']:>7,}    {best['confusion_matrix']['fp']:>7,}             |
|  Actual Malig.   {best['confusion_matrix']['fn']:>7,}    {best['confusion_matrix']['tp']:>7,}             |
|                                                                     |
+---------------------------------------------------------------------+
|  True Positives (attacks caught):    {best['confusion_matrix']['tp']:>10,}                  |
|  True Negatives (safe allowed):      {best['confusion_matrix']['tn']:>10,}                  |
|  False Positives (safe blocked):     {best['confusion_matrix']['fp']:>10,}                  |
|  False Negatives (attacks missed):   {best['confusion_matrix']['fn']:>10,}                  |
|                                                                     |
+---------------------------------------------------------------------+
|  Training Time:      {best['train_time']:>10.2f}s                               |
|  Inference Time:     {best['inference_ms']:>10.2f}ms                               |
+=====================================================================+
""")

# ============================================================
# FEATURE IMPORTANCE (for tree-based models)
# ============================================================
print("\n" + "=" * 70)
print("FEATURE IMPORTANCE (Top 15)")
print("=" * 70)

# Use Random Forest for feature importance
rf_model = [m for n, m in models.items() if n == "Random Forest"][0]
if hasattr(rf_model, 'feature_importances_'):
    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[::-1][:15]
    
    print(f"\n{'Rank':<5} {'Feature':<30} {'Importance':>12}")
    print("â”€" * 50)
    
    for i, idx in enumerate(indices, 1):
        print(f"{i:<5} {feature_names[idx]:<30} {importances[idx]:>12.4f}")

# ============================================================
# SAVE RESULTS
# ============================================================
outdir = os.path.join(os.path.dirname(__file__), '..', 'results')
os.makedirs(outdir, exist_ok=True)

# JSON
with open(os.path.join(outdir, 'full_dataset_results.json'), 'w') as f:
    json.dump({
        'timestamp': datetime.now().isoformat(),
        'dataset': {
            'total_samples': int(X.shape[0]),
            'train_samples': int(X_train.shape[0]),
            'test_samples': int(X_test.shape[0]),
            'features': int(X.shape[1]),
            'feature_names': feature_names,
            'benign_count': int(sum(y == 0)),
            'malicious_count': int(sum(y == 1))
        },
        'best_model': best['name'],
        'best_metrics': {k: v for k, v in best.items() if k != 'name'},
        'all_models': [{k: v for k, v in r.items() if k != 'name'} for r in results]
    }, f, indent=2)

# TXT Report
with open(os.path.join(outdir, 'full_dataset_report.txt'), 'w') as f:
    f.write("=" * 70 + "\n")
    f.write("AEGIS FULL DATASET ML TRAINING REPORT\n")
    f.write("=" * 70 + "\n\n")
    f.write(f"Generated: {datetime.now().isoformat()}\n")
    f.write(f"Dataset: {X.shape[0]:,} samples, {X.shape[1]} features\n")
    f.write(f"Train: {X_train.shape[0]:,} | Test: {X_test.shape[0]:,}\n\n")
    
    f.write(f"{'Rank':<5} {'Model':<25} {'Acc':>8} {'Prec':>8} {'Rec':>8} {'F1':>8} {'AUC':>8}\n")
    f.write("â”€" * 70 + "\n")
    
    for i, r in enumerate(results, 1):
        f.write(f"{i:<5} {r['name']:<25} {r['accuracy']:>8.4f} {r['precision']:>8.4f} {r['recall']:>8.4f} {r['f1']:>8.4f} {r['roc_auc']:>8.4f}\n")
    
    f.write(f"\n{'=' * 70}\n")
    f.write(f"BEST MODEL: {best['name']}\n")
    f.write(f"{'=' * 70}\n\n")
    f.write(f"Accuracy:  {best['accuracy']:.4f} ({best['accuracy']*100:.2f}%)\n")
    f.write(f"Precision: {best['precision']:.4f} ({best['precision']*100:.2f}%)\n")
    f.write(f"Recall:    {best['recall']:.4f} ({best['recall']*100:.2f}%)\n")
    f.write(f"F1-Score:  {best['f1']:.4f} ({best['f1']*100:.2f}%)\n")
    f.write(f"ROC-AUC:   {best['roc_auc']:.4f} ({best['roc_auc']*100:.2f}%)\n\n")
    f.write(f"Confusion Matrix:\n")
    f.write(f"  True Positives:  {best['confusion_matrix']['tp']}\n")
    f.write(f"  True Negatives:  {best['confusion_matrix']['tn']}\n")
    f.write(f"  False Positives: {best['confusion_matrix']['fp']}\n")
    f.write(f"  False Negatives: {best['confusion_matrix']['fn']}\n")

# CSV
with open(os.path.join(outdir, 'full_dataset_metrics.csv'), 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['Rank', 'Model', 'Accuracy', 'Precision', 'Recall', 'F1', 'ROC_AUC', 'TrainTime_s', 'Inference_ms'])
    for i, r in enumerate(results, 1):
        w.writerow([i, r['name'], f"{r['accuracy']:.4f}", f"{r['precision']:.4f}", 
                     f"{r['recall']:.4f}", f"{r['f1']:.4f}", f"{r['roc_auc']:.4f}",
                     f"{r['train_time']:.2f}", f"{r['inference_ms']:.2f}"])

# Confusion Matrix
with open(os.path.join(outdir, 'full_confusion_matrix.csv'), 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['', 'Predicted_Benign', 'Predicted_Malicious'])
    w.writerow(['Actual_Benign', best['confusion_matrix']['tn'], best['confusion_matrix']['fp']])
    w.writerow(['Actual_Malicious', best['confusion_matrix']['fn'], best['confusion_matrix']['tp']])

print(f"\nResults saved to: {outdir}")
print("=" * 70)
print("TRAINING COMPLETE!")
print("=" * 70)
