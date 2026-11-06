"""
AEGIS ML Training & Evaluation Pipeline
Adaptive Explainable Gateway for Intelligent Security

Pipeline:
1. Load & Clean Dataset
2. Feature Engineering
3. Train 7+ Algorithms
4. Compare All Models
5. Save Best Model + Metrics

Algorithms Compared:
- Random Forest
- XGBoost
- Gradient Boosting
- Extra Trees
- AdaBoost
- Decision Tree
- K-Nearest Neighbors
- Logistic Regression
- Support Vector Machine (Linear)
- MLP Neural Network
"""

import os
import sys
import json
import csv
import time
import pickle
import warnings
import math
from datetime import datetime
from collections import Counter

warnings.filterwarnings('ignore')

# ============================================================
# STEP 1: DATA LOADING & CLEANING
# ============================================================

def load_csv(filepath):
    """Load CSV file manually"""
    print(f"Loading dataset from {filepath}...")
    data = []
    headers = []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        headers = next(reader)
        for row in reader:
            if len(row) == len(headers):
                data.append(row)
    
    print(f"  Loaded {len(data):,} rows with {len(headers)} columns")
    return headers, data

def clean_dataset(headers, data):
    """Clean the dataset"""
    print("\nCleaning dataset...")
    
    # Remove duplicates
    print("  Removing duplicates...")
    seen = set()
    clean_data = []
    for row in data:
        row_key = ','.join(row[3:29])  # Use feature columns as key
        if row_key not in seen:
            seen.add(row_key)
            clean_data.append(row)
    
    removed = len(data) - len(clean_data)
    print(f"  Removed {removed:,} duplicate rows")
    
    # Check for missing values
    print("  Checking for missing values...")
    missing_count = 0
    for row in clean_data:
        for val in row:
            if val == '' or val is None:
                missing_count += 1
    
    print(f"  Found {missing_count:,} missing values")
    
    # Remove rows with missing critical features
    feature_cols = list(range(7, 29))  # Columns 7-28 are features
    clean_data_final = []
    for row in clean_data:
        has_missing = False
        for idx in feature_cols:
            if idx < len(row) and (row[idx] == '' or row[idx] is None):
                has_missing = True
                break
        if not has_missing:
            clean_data_final.append(row)
    
    removed2 = len(clean_data) - len(clean_data_final)
    print(f"  Removed {removed2:,} rows with missing features")
    print(f"  Final clean dataset: {len(clean_data_final):,} rows")
    
    return headers, clean_data_final

# ============================================================
# STEP 2: FEATURE ENGINEERING
# ============================================================

def extract_features(headers, data):
    """Extract numerical features from data"""
    print("\nExtracting features...")
    
    # Feature columns (index 7-28)
    feature_names = [
        'url_length', 'url_entropy', 'num_special_chars', 'num_encoded_chars',
        'has_sql_keywords', 'has_js_keywords', 'has_path_traversal', 'has_cmd_injection',
        'has_xxe_patterns', 'has_ssi_patterns', 'has_injection_patterns',
        'has_prompt_injection', 'has_suspicious_encoding',
        'body_length', 'body_entropy', 'num_headers', 'has_user_agent',
        'requests_per_minute', 'unique_urls_per_session', 'error_rate',
        'risk_score', 'severity_numeric'
    ]
    
    # Severity mapping
    severity_map = {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    
    X = []
    y = []
    
    for row in data:
        try:
            features = []
            # Numerical features (columns 7-27)
            for i in range(7, 28):
                val = row[i]
                if val == '':
                    features.append(0.0)
                else:
                    features.append(float(val))
            
            # Severity (column 28)
            severity = row[28] if len(row) > 28 else 'safe'
            features.append(severity_map.get(severity, 0))
            
            # Label (column 29)
            label = int(row[29])
            
            X.append(features)
            y.append(label)
        except (ValueError, IndexError):
            continue
    
    print(f"  Extracted {len(X)} samples with {len(X[0])} features")
    print(f"  Features: {feature_names}")
    
    return X, y, feature_names

# ============================================================
# STEP 3: SIMPLE ML IMPLEMENTATIONS (No sklearn dependency)
# ============================================================

class SimpleMetrics:
    """Calculate classification metrics"""
    
    @staticmethod
    def confusion_matrix(y_true, y_pred):
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
        tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
        return {'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn}
    
    @staticmethod
    def accuracy(y_true, y_pred):
        correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
        return correct / len(y_true) if y_true else 0
    
    @staticmethod
    def precision(y_true, y_pred):
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
        return tp / (tp + fp) if (tp + fp) > 0 else 0
    
    @staticmethod
    def recall(y_true, y_pred):
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
        return tp / (tp + fn) if (tp + fn) > 0 else 0
    
    @staticmethod
    def f1_score(y_true, y_pred):
        p = SimpleMetrics.precision(y_true, y_pred)
        r = SimpleMetrics.recall(y_true, y_pred)
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0
    
    @staticmethod
    def specificity(y_true, y_pred):
        tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
        return tn / (tn + fp) if (tn + fp) > 0 else 0
    
    @staticmethod
    def auc_roc_simple(y_true, y_scores):
        """Simple AUC estimation based on threshold sweep"""
        # Sort by score descending
        paired = list(zip(y_scores, y_true))
        paired.sort(key=lambda x: x[0], reverse=True)
        
        tp = 0
        fp = 0
        total_pos = sum(y_true)
        total_neg = len(y_true) - total_pos
        
        tpr_list = [0]
        fpr_list = [0]
        
        for score, label in paired:
            if label == 1:
                tp += 1
            else:
                fp += 1
            
            tpr = tp / total_pos if total_pos > 0 else 0
            fpr = fp / total_neg if total_neg > 0 else 0
            tpr_list.append(tpr)
            fpr_list.append(fpr)
        
        # Calculate AUC using trapezoidal rule
        auc = 0
        for i in range(1, len(tpr_list)):
            auc += (fpr_list[i] - fpr_list[i-1]) * (tpr_list[i] + tpr_list[i-1]) / 2
        
        return 1 - auc  # Since we want higher AUC = better


class SimpleDecisionTree:
    """Simple Decision Tree using information gain"""
    
    def __init__(self, max_depth=10, min_samples_split=5):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.tree = None
    
    def _gini(self, labels):
        if not labels:
            return 0
        counts = Counter(labels)
        total = len(labels)
        return 1 - sum((c/total)**2 for c in counts.values())
    
    def _best_split(self, X, y):
        best_gini = float('inf')
        best_feature = None
        best_threshold = None
        
        n_features = len(X[0])
        n_samples = len(X)
        
        # Try random subset of features
        features_to_try = min(int(math.sqrt(n_features)), n_features)
        feature_indices = random.sample(range(n_features), features_to_try)
        
        for feature_idx in feature_indices:
            values = [X[i][feature_idx] for i in range(n_samples)]
            unique_vals = sorted(set(values))
            
            # Try a few thresholds
            n_thresholds = min(10, len(unique_vals) - 1)
            if n_thresholds > 0:
                step = max(1, len(unique_vals) // n_thresholds)
                thresholds = unique_vals[::step][:n_thresholds]
            else:
                thresholds = unique_vals[:-1]
            
            for threshold in thresholds:
                left_idx = [i for i in range(n_samples) if X[i][feature_idx] <= threshold]
                right_idx = [i for i in range(n_samples) if X[i][feature_idx] > threshold]
                
                if len(left_idx) < self.min_samples_split or len(right_idx) < self.min_samples_split:
                    continue
                
                left_gini = self._gini([y[i] for i in left_idx])
                right_gini = self._gini([y[i] for i in right_idx])
                
                weighted_gini = (len(left_idx) * left_gini + len(right_idx) * right_gini) / n_samples
                
                if weighted_gini < best_gini:
                    best_gini = weighted_gini
                    best_feature = feature_idx
                    best_threshold = threshold
        
        return best_feature, best_threshold
    
    def _build_tree(self, X, y, depth=0):
        # Check stopping criteria
        if depth >= self.max_depth or len(X) < self.min_samples_split:
            counts = Counter(y)
            return {'leaf': True, 'prediction': counts.most_common(1)[0][0]}
        
        if len(set(y)) == 1:
            return {'leaf': True, 'prediction': y[0]}
        
        feature, threshold = self._best_split(X, y)
        
        if feature is None:
            counts = Counter(y)
            return {'leaf': True, 'prediction': counts.most_common(1)[0][0]}
        
        left_idx = [i for i in range(len(X)) if X[i][feature] <= threshold]
        right_idx = [i for i in range(len(X)) if X[i][feature] > threshold]
        
        return {
            'leaf': False,
            'feature': feature,
            'threshold': threshold,
            'left': self._build_tree([X[i] for i in left_idx], [y[i] for i in left_idx], depth + 1),
            'right': self._build_tree([X[i] for i in right_idx], [y[i] for i in right_idx], depth + 1)
        }
    
    def fit(self, X, y):
        self.tree = self._build_tree(X, y)
    
    def _predict_one(self, x, node):
        if node['leaf']:
            return node['prediction']
        
        if x[node['feature']] <= node['threshold']:
            return self._predict_one(x, node['left'])
        else:
            return self._predict_one(x, node['right'])
    
    def predict(self, X):
        return [self._predict_one(x, self.tree) for x in X]


class SimpleRandomForest:
    """Simple Random Forest using decision trees"""
    
    def __init__(self, n_trees=10, max_depth=10, min_samples_split=5):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.trees = []
        self.feature_indices = []
    
    def fit(self, X, y):
        n_features = len(X[0])
        self.feature_indices = []
        
        for i in range(self.n_trees):
            # Bootstrap sampling
            n_samples = len(X)
            indices = [random.randint(0, n_samples - 1) for _ in range(n_samples)]
            X_boot = [X[idx] for idx in indices]
            y_boot = [y[idx] for idx in indices]
            
            # Random feature selection
            n_use = max(1, int(math.sqrt(n_features)))
            feat_idx = random.sample(range(n_features), n_use)
            self.feature_indices.append(feat_idx)
            
            X_subset = [[x[f] for f in feat_idx] for x in X_boot]
            
            tree = SimpleDecisionTree(self.max_depth, self.min_samples_split)
            tree.fit(X_subset, y_boot)
            self.trees.append(tree)
    
    def predict(self, X):
        predictions = []
        for tree, feat_idx in zip(self.trees, self.feature_indices):
            X_subset = [[x[f] for f in feat_idx] for x in X]
            predictions.append(tree.predict(X_subset))
        
        # Majority voting
        final_pred = []
        for i in range(len(X)):
            votes = [pred[i] for pred in predictions]
            final_pred.append(Counter(votes).most_common(1)[0][0])
        
        return final_pred
    
    def feature_importance(self, X, y, feature_names):
        """Calculate feature importance via permutation"""
        base_pred = self.predict(X)
        base_accuracy = SimpleMetrics.accuracy(y, base_pred)
        
        importances = {}
        for i, fname in enumerate(feature_names):
            X_perm = [row[:] for row in X]
            for row in X_perm:
                row[i] = random.choice([row[i] for row in X])
            
            perm_pred = self.predict(X_perm)
            perm_accuracy = SimpleMetrics.accuracy(y, perm_pred)
            importances[fname] = base_accuracy - perm_accuracy
        
        return importances


class SimpleKNN:
    """Simple K-Nearest Neighbors"""
    
    def __init__(self, k=5):
        self.k = k
        self.X_train = []
        self.y_train = []
    
    def fit(self, X, y):
        self.X_train = X
        self.y_train = y
    
    def _euclidean(self, x1, x2):
        return math.sqrt(sum((a - b) ** 2 for a, b in zip(x1, x2)))
    
    def predict(self, X):
        predictions = []
        for x in X:
            distances = [(self._euclidean(x, x_train), y) for x_train, y in zip(self.X_train, self.y_train)]
            distances.sort(key=lambda d: d[0])
            k_nearest = [label for _, label in distances[:self.k]]
            predictions.append(Counter(k_nearest).most_common(1)[0][0])
        return predictions


class SimpleLogisticRegression:
    """Simple Logistic Regression with gradient descent"""
    
    def __init__(self, learning_rate=0.01, n_iterations=100):
        self.lr = learning_rate
        self.n_iter = n_iterations
        self.weights = None
        self.bias = 0
    
    def _sigmoid(self, z):
        z = max(-500, min(500, z))
        return 1 / (1 + math.exp(-z))
    
    def fit(self, X, y):
        n_samples, n_features = len(X), len(X[0])
        self.weights = [0.0] * n_features
        self.bias = 0
        
        for _ in range(self.n_iter):
            for i in range(n_samples):
                z = sum(w * x for w, x in zip(self.weights, X[i])) + self.bias
                pred = self._sigmoid(z)
                error = pred - y[i]
                
                for j in range(n_features):
                    self.weights[j] -= self.lr * error * X[i][j]
                self.bias -= self.lr * error
    
    def predict_proba(self, X):
        probas = []
        for x in X:
            z = sum(w * val for w, val in zip(self.weights, x)) + self.bias
            probas.append(self._sigmoid(z))
        return probas
    
    def predict(self, X, threshold=0.5):
        return [1 if p >= threshold else 0 for p in self.predict_proba(X)]


class SimpleSVM:
    """Simple Linear SVM using SGD"""
    
    def __init__(self, learning_rate=0.01, n_iterations=100, lambda_param=0.01):
        self.lr = learning_rate
        self.n_iter = n_iterations
        self.lambda_param = lambda_param
        self.weights = None
        self.bias = 0
    
    def fit(self, X, y):
        n_samples, n_features = len(X), len(X[0])
        self.weights = [0.0] * n_features
        self.bias = 0
        
        # Convert labels to -1, 1
        y_binary = [1 if yi == 1 else -1 for yi in y]
        
        for _ in range(self.n_iter):
            for i in range(n_samples):
                condition = y_binary[i] * (sum(w * x for w, x in zip(self.weights, X[i])) + self.bias)
                
                if condition >= 1:
                    # Correct classification
                    for j in range(n_features):
                        self.weights[j] -= self.lr * self.lambda_param * self.weights[j]
                else:
                    # Misclassification
                    for j in range(n_features):
                        self.weights[j] -= self.lr * (self.lambda_param * self.weights[j] - y_binary[i] * X[i][j])
                    self.bias -= self.lr * (-y_binary[i])
    
    def predict(self, X):
        predictions = []
        for x in X:
            z = sum(w * val for w, val in zip(self.weights, x)) + self.bias
            predictions.append(1 if z >= 0 else 0)
        return predictions


class SimpleMLP:
    """Simple Multi-Layer Perceptron"""
    
    def __init__(self, hidden_size=32, learning_rate=0.01, n_iterations=50):
        self.hidden_size = hidden_size
        self.lr = learning_rate
        self.n_iter = n_iterations
        self.W1 = None
        self.b1 = None
        self.W2 = None
        self.b2 = None
    
    def _sigmoid(self, z):
        z = max(-500, min(500, z))
        return 1 / (1 + math.exp(-z))
    
    def fit(self, X, y):
        n_samples, n_features = len(X), len(X[0])
        
        # Initialize weights
        self.W1 = [[random.gauss(0, 0.1) for _ in range(self.hidden_size)] for _ in range(n_features)]
        self.b1 = [0.0] * self.hidden_size
        self.W2 = [random.gauss(0, 0.1) for _ in range(self.hidden_size)]
        self.b2 = 0.0
        
        for _ in range(self.n_iter):
            for i in range(min(1000, n_samples)):  # Subsample for speed
                # Forward pass
                hidden = [0.0] * self.hidden_size
                for j in range(self.hidden_size):
                    z = sum(X[i][k] * self.W1[k][j] for k in range(n_features)) + self.b1[j]
                    hidden[j] = self._sigmoid(z)
                
                z_out = sum(hidden[j] * self.W2[j] for j in range(self.hidden_size)) + self.b2
                output = self._sigmoid(z_out)
                
                # Backward pass
                error_out = output - y[i]
                
                for j in range(self.hidden_size):
                    error_hidden = error_out * self.W2[j] * hidden[j] * (1 - hidden[j])
                    
                    for k in range(n_features):
                        self.W1[k][j] -= self.lr * error_hidden * X[i][k]
                    self.b1[j] -= self.lr * error_hidden
                    self.W2[j] -= self.lr * error_out * hidden[j]
                
                self.b2 -= self.lr * error_out
    
    def predict(self, X):
        predictions = []
        for x in X:
            hidden = [0.0] * self.hidden_size
            for j in range(self.hidden_size):
                z = sum(x[k] * self.W1[k][j] for k in range(len(x))) + self.b1[j]
                hidden[j] = self._sigmoid(z)
            
            z_out = sum(hidden[j] * self.W2[j] for j in range(self.hidden_size)) + self.b2
            output = self._sigmoid(z_out)
            predictions.append(1 if output >= 0.5 else 0)
        return predictions


class SimpleGradientBoosting:
    """Simple Gradient Boosting"""
    
    def __init__(self, n_estimators=10, learning_rate=0.1, max_depth=5):
        self.n_estimators = n_estimators
        self.lr = learning_rate
        self.max_depth = max_depth
        self.trees = []
        self.initial_pred = 0
    
    def fit(self, X, y):
        self.initial_pred = sum(y) / len(y)
        predictions = [self.initial_pred] * len(y)
        
        for _ in range(self.n_estimators):
            # Calculate residuals
            residuals = [y[i] - predictions[i] for i in range(len(y))]
            
            tree = SimpleDecisionTree(max_depth=self.max_depth, min_samples_split=5)
            tree.fit(X, [1 if r > 0 else 0 for r in residuals])
            self.trees.append(tree)
            
            # Update predictions
            tree_pred = tree.predict(X)
            for i in range(len(predictions)):
                predictions[i] += self.lr * (tree_pred[i] - 0.5)
    
    def predict(self, X):
        predictions = [self.initial_pred] * len(X)
        
        for tree in self.trees:
            tree_pred = tree.predict(X)
            for i in range(len(predictions)):
                predictions[i] += self.lr * (tree_pred[i] - 0.5)
        
        return [1 if p >= 0.5 else 0 for p in predictions]


class SimpleExtraTrees:
    """Simple Extra Trees (like Random Forest but with random thresholds)"""
    
    def __init__(self, n_trees=10, max_depth=10):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.trees = []
    
    def fit(self, X, y):
        for _ in range(self.n_trees):
            # Bootstrap sampling
            n_samples = len(X)
            indices = [random.randint(0, n_samples - 1) for _ in range(n_samples)]
            X_boot = [X[idx] for idx in indices]
            y_boot = [y[idx] for idx in indices]
            
            tree = SimpleDecisionTree(max_depth=self.max_depth, min_samples_split=5)
            tree.fit(X_boot, y_boot)
            self.trees.append(tree)
    
    def predict(self, X):
        all_preds = [tree.predict(X) for tree in self.trees]
        final_pred = []
        for i in range(len(X)):
            votes = [pred[i] for pred in all_preds]
            final_pred.append(Counter(votes).most_common(1)[0][0])
        return final_pred


class SimpleAdaBoost:
    """Simple AdaBoost with Decision Stumps"""
    
    def __init__(self, n_estimators=10):
        self.n_estimators = n_estimators
        self.stumps = []
        self.alphas = []
    
    def fit(self, X, y):
        n_samples = len(X)
        weights = [1.0 / n_samples] * n_samples
        
        for _ in range(self.n_estimators):
            # Find best decision stump
            best_stump = None
            best_error = float('inf')
            
            n_features = len(X[0])
            for feat in range(n_features):
                values = sorted(set(X[i][feat] for i in range(n_samples)))
                for threshold in values[::max(1, len(values)//5)]:
                    pred = [1 if X[i][feat] > threshold else 0 for i in range(n_samples)]
                    error = sum(weights[i] for i in range(n_samples) if pred[i] != y[i])
                    
                    if error < best_error:
                        best_error = error
                        best_stump = (feat, threshold, pred)
            
            if best_stump is None or best_error >= 0.5:
                break
            
            feat, threshold, pred = best_stump
            
            # Calculate alpha
            error = max(best_error, 1e-10)
            alpha = 0.5 * math.log((1 - error) / error)
            
            self.stumps.append((feat, threshold))
            self.alphas.append(alpha)
            
            # Update weights
            for i in range(n_samples):
                if pred[i] != y[i]:
                    weights[i] *= math.exp(alpha)
                else:
                    weights[i] *= math.exp(-alpha)
            
            # Normalize weights
            total = sum(weights)
            weights = [w / total for w in weights]
    
    def predict(self, X):
        predictions = []
        for x in X:
            vote = sum(alpha * (1 if x[feat] > threshold else 0) 
                      for (feat, threshold), alpha in zip(self.stumps, self.alphas))
            predictions.append(1 if vote >= 0.5 else 0)
        return predictions


# ============================================================
# STEP 4: TRAINING & EVALUATION PIPELINE
# ============================================================

import random

def train_test_split(X, y, test_size=0.2, random_state=42):
    """Split data into train/test sets"""
    random.seed(random_state)
    n = len(X)
    indices = list(range(n))
    random.shuffle(indices)
    
    split = int(n * (1 - test_size))
    train_idx = indices[:split]
    test_idx = indices[split:]
    
    X_train = [X[i] for i in train_idx]
    X_test = [X[i] for i in test_idx]
    y_train = [y[i] for i in train_idx]
    y_test = [y[i] for i in test_idx]
    
    return X_train, X_test, y_train, y_test


def standardize(X_train, X_test):
    """Standardize features (z-score normalization)"""
    n_features = len(X_train[0])
    means = [0.0] * n_features
    stds = [1.0] * n_features
    
    # Calculate means
    for i in range(n_features):
        values = [X_train[j][i] for j in range(len(X_train))]
        means[i] = sum(values) / len(values)
    
    # Calculate stds
    for i in range(n_features):
        values = [X_train[j][i] for j in range(len(X_train))]
        variance = sum((v - means[i]) ** 2 for v in values) / len(values)
        stds[i] = max(math.sqrt(variance), 1e-8)
    
    # Apply normalization
    X_train_norm = [[(x - m) / s for x, m, s in zip(row, means, stds)] for row in X_train]
    X_test_norm = [[(x - m) / s for x, m, s in zip(row, means, stds)] for row in X_test]
    
    return X_train_norm, X_test_norm, means, stds


def evaluate_model(name, model, X_test, y_test):
    """Evaluate a model and return metrics"""
    start_time = time.time()
    y_pred = model.predict(X_test)
    inference_time = time.time() - start_time
    
    metrics = {
        'name': name,
        'accuracy': SimpleMetrics.accuracy(y_test, y_pred),
        'precision': SimpleMetrics.precision(y_test, y_pred),
        'recall': SimpleMetrics.recall(y_test, y_pred),
        'f1_score': SimpleMetrics.f1_score(y_test, y_pred),
        'specificity': SimpleMetrics.specificity(y_test, y_pred),
        'inference_time_ms': inference_time * 1000,
    }
    
    cm = SimpleMetrics.confusion_matrix(y_test, y_pred)
    metrics['confusion_matrix'] = cm
    
    return metrics


def run_training_pipeline():
    """Main training pipeline"""
    
    print("=" * 70)
    print("AEGIS ML TRAINING PIPELINE")
    print("Adaptive Explainable Gateway for Intelligent Security")
    print("=" * 70)
    
    # ============================================================
    # STEP 1: LOAD DATA
    # ============================================================
    
    dataset_path = os.path.join(os.path.dirname(__file__), '..', 'dataset', 'aegis_dataset.csv')
    headers, data = load_csv(dataset_path)
    
    # ============================================================
    # STEP 2: CLEAN DATA
    # ============================================================
    
    headers, data = clean_dataset(headers, data)
    
    # ============================================================
    # STEP 3: EXTRACT FEATURES
    # ============================================================
    
    X, y, feature_names = extract_features(headers, data)
    
    # ============================================================
    # STEP 4: SPLIT DATA
    # ============================================================
    
    print("\nSplitting data (80/20 train/test)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(f"  Training set: {len(X_train):,} samples")
    print(f"  Test set: {len(X_test):,} samples")
    
    # Class distribution
    train_dist = Counter(y_train)
    test_dist = Counter(y_test)
    print(f"  Train - Benign: {train_dist[0]:,}, Malicious: {train_dist[1]:,}")
    print(f"  Test  - Benign: {test_dist[0]:,}, Malicious: {test_dist[1]:,}")
    
    # ============================================================
    # STEP 5: STANDARDIZE FEATURES
    # ============================================================
    
    print("\nStandardizing features...")
    X_train_norm, X_test_norm, means, stds = standardize(X_train, X_test)
    print("  Features standardized (z-score normalization)")
    
    # ============================================================
    # STEP 6: TRAIN MULTIPLE MODELS
    # ============================================================
    
    print("\n" + "=" * 70)
    print("TRAINING MODELS")
    print("=" * 70)
    
    # Use a subset for faster training
    train_subset = min(50000, len(X_train))
    test_subset = min(10000, len(X_test))
    
    print(f"\nUsing subset: {train_subset:,} train, {test_subset:,} test (for speed)")
    
    X_train_small = X_train[:train_subset]
    y_train_small = y_train[:train_subset]
    X_test_small = X_test[:test_subset]
    y_test_small = y_test[:test_subset]
    X_train_norm_small = X_train_norm[:train_subset]
    X_test_norm_small = X_test_norm[:test_subset]
    
    models_config = [
        ("Random Forest", SimpleRandomForest(n_trees=20, max_depth=15), X_train, y_train, X_test, False),
        ("Decision Tree", SimpleDecisionTree(max_depth=15), X_train, y_train, X_test, False),
        ("Gradient Boosting", SimpleGradientBoosting(n_estimators=15, max_depth=8), X_train, y_train, X_test, False),
        ("Extra Trees", SimpleExtraTrees(n_trees=15, max_depth=12), X_train, y_train, X_test, False),
        ("AdaBoost", SimpleAdaBoost(n_estimators=15), X_train, y_train, X_test, False),
        ("K-Nearest Neighbors", SimpleKNN(k=7), X_train_norm_small, y_train_small, X_test_norm_small, True),
        ("Logistic Regression", SimpleLogisticRegression(learning_rate=0.01, n_iterations=100), X_train_norm_small, y_train_small, X_test_norm_small, True),
        ("Linear SVM", SimpleSVM(learning_rate=0.001, n_iterations=50), X_train_norm_small, y_train_small, X_test_norm_small, True),
        ("MLP Neural Network", SimpleMLP(hidden_size=32, learning_rate=0.01, n_iterations=30), X_train_norm_small, y_train_small, X_test_norm_small, True),
    ]
    
    all_results = []
    
    for name, model, Xtr, ytr, Xte, is_normalized in models_config:
        print(f"\n{'-' * 50}")
        print(f"Training: {name}")
        print(f"{'â”€' * 50}")
        
        start_time = time.time()
        
        try:
            model.fit(Xtr, ytr)
            train_time = time.time() - start_time
            print(f"  Training time: {train_time:.2f}s")
            
            metrics = evaluate_model(name, model, Xte, yte if 'yte' in dir() else y_test_small if is_normalized else y_test)
            metrics['train_time_s'] = train_time
            all_results.append(metrics)
            
            print(f"  Accuracy:  {metrics['accuracy']:.4f}")
            print(f"  Precision: {metrics['precision']:.4f}")
            print(f"  Recall:    {metrics['recall']:.4f}")
            print(f"  F1 Score:  {metrics['f1_score']:.4f}")
            print(f"  Specificity: {metrics['specificity']:.4f}")
        except Exception as e:
            print(f"  ERROR: {e}")
            import traceback
            traceback.print_exc()
    
    # ============================================================
    # STEP 7: COMPARE ALL MODELS
    # ============================================================
    
    print("\n" + "=" * 70)
    print("MODEL COMPARISON")
    print("=" * 70)
    
    # Sort by F1 score
    all_results.sort(key=lambda x: x.get('f1_score', 0), reverse=True)
    
    print(f"\n{'Model':<25} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'Time(s)':>10}")
    print("â”€" * 85)
    
    for r in all_results:
        print(f"{r['name']:<25} {r['accuracy']:>10.4f} {r['precision']:>10.4f} {r['recall']:>10.4f} {r['f1_score']:>10.4f} {r.get('train_time_s', 0):>10.2f}")
    
    # ============================================================
    # STEP 8: BEST MODEL DETAILED METRICS
    # ============================================================
    
    best = all_results[0]
    
    print("\n" + "=" * 70)
    print(f"BEST MODEL: {best['name']}")
    print("=" * 70)
    
    print(f"""
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                 DETAILED METRICS                             â•‘
â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•£
â•‘                                                              â•‘
â•‘  Accuracy:           {best['accuracy']:.4f}  ({best['accuracy']*100:.2f}%)
â•‘  Precision:          {best['precision']:.4f}  ({best['precision']*100:.2f}%)
â•‘  Recall:             {best['recall']:.4f}  ({best['recall']*100:.2f}%)
â•‘  F1-Score:           {best['f1_score']:.4f}  ({best['f1_score']*100:.2f}%)
â•‘  Specificity:        {best['specificity']:.4f}  ({best['specificity']*100:.2f}%)
â•‘                                                              â•‘
â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•£
â•‘                 CONFUSION MATRIX                             â•‘
â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•£
â•‘                                                              â•‘
â•‘                    Predicted                                  â•‘
â•‘                  Benign    Malicious                          â•‘
â•‘  Actual Benign  [{best['confusion_matrix']['tn']:>7}]  [{best['confusion_matrix']['fp']:>7}]     â•‘
â•‘  Actual Malig.  [{best['confusion_matrix']['fn']:>7}]  [{best['confusion_matrix']['tp']:>7}]     â•‘
â•‘                                                              â•‘
â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•£
â•‘  True Positives:   {best['confusion_matrix']['tp']:>10}                       â•‘
â•‘  True Negatives:   {best['confusion_matrix']['tn']:>10}                       â•‘
â•‘  False Positives:  {best['confusion_matrix']['fp']:>10}                       â•‘
â•‘  False Negatives:  {best['confusion_matrix']['fn']:>10}                       â•‘
â•‘                                                              â•‘
â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•£
â•‘  Training Time:    {best.get('train_time_s', 0):>10.2f}s                       â•‘
â•‘  Inference Time:   {best.get('inference_time_ms', 0):>10.2f}ms                      â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
""")
    
    # ============================================================
    # STEP 9: SAVE RESULTS TO FILES
    # ============================================================
    
    print("Saving results to files...")
    
    output_dir = os.path.join(os.path.dirname(__file__), '..', 'results')
    os.makedirs(output_dir, exist_ok=True)
    
    # Save comparison results
    comparison_path = os.path.join(output_dir, 'model_comparison.json')
    with open(comparison_path, 'w') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'dataset_size': len(X),
            'features_count': len(feature_names),
            'feature_names': feature_names,
            'train_size': len(X_train),
            'test_size': len(X_test),
            'models': [{k: v for k, v in r.items() if k != 'confusion_matrix'} for r in all_results],
            'best_model': {k: v for k, v in best.items() if k != 'confusion_matrix'},
            'confusion_matrix': best['confusion_matrix']
        }, f, indent=2)
    print(f"  Saved: {comparison_path}")
    
    # Save as readable text
    txt_path = os.path.join(output_dir, 'model_comparison.txt')
    with open(txt_path, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("AEGIS MODEL COMPARISON REPORT\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write("=" * 70 + "\n\n")
        
        f.write(f"Dataset: {len(X):,} samples, {len(feature_names)} features\n")
        f.write(f"Train: {len(X_train):,} | Test: {len(X_test):,}\n\n")
        
        f.write(f"{'Model':<25} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'Time(s)':>10}\n")
        f.write("â”€" * 85 + "\n")
        
        for r in all_results:
            f.write(f"{r['name']:<25} {r['accuracy']:>10.4f} {r['precision']:>10.4f} {r['recall']:>10.4f} {r['f1_score']:>10.4f} {r.get('train_time_s', 0):>10.2f}\n")
        
        f.write("\n" + "=" * 70 + "\n")
        f.write(f"BEST MODEL: {best['name']}\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Accuracy:  {best['accuracy']:.4f} ({best['accuracy']*100:.2f}%)\n")
        f.write(f"Precision: {best['precision']:.4f} ({best['precision']*100:.2f}%)\n")
        f.write(f"Recall:    {best['recall']:.4f} ({best['recall']*100:.2f}%)\n")
        f.write(f"F1-Score:  {best['f1_score']:.4f} ({best['f1_score']*100:.2f}%)\n")
        f.write(f"Specificity: {best['specificity']:.4f} ({best['specificity']*100:.2f}%)\n\n")
        
        f.write("Confusion Matrix:\n")
        f.write(f"  True Negatives:  {best['confusion_matrix']['tn']}\n")
        f.write(f"  False Positives: {best['confusion_matrix']['fp']}\n")
        f.write(f"  False Negatives: {best['confusion_matrix']['fn']}\n")
        f.write(f"  True Positives:  {best['confusion_matrix']['tp']}\n")
    
    print(f"  Saved: {txt_path}")
    
    # Save confusion matrix as CSV
    cm_path = os.path.join(output_dir, 'confusion_matrix.csv')
    with open(cm_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['', 'Predicted_Benign', 'Predicted_Malicious'])
        writer.writerow(['Actual_Benign', best['confusion_matrix']['tn'], best['confusion_matrix']['fp']])
        writer.writerow(['Actual_Malicious', best['confusion_matrix']['fn'], best['confusion_matrix']['tp']])
    print(f"  Saved: {cm_path}")
    
    # Save metrics summary CSV
    metrics_csv_path = os.path.join(output_dir, 'all_models_metrics.csv')
    with open(metrics_csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Model', 'Accuracy', 'Precision', 'Recall', 'F1-Score', 'Specificity', 'Train_Time_s', 'Inference_Time_ms'])
        for r in all_results:
            writer.writerow([
                r['name'],
                f"{r['accuracy']:.4f}",
                f"{r['precision']:.4f}",
                f"{r['recall']:.4f}",
                f"{r['f1_score']:.4f}",
                f"{r['specificity']:.4f}",
                f"{r.get('train_time_s', 0):.2f}",
                f"{r.get('inference_time_ms', 0):.2f}"
            ])
    print(f"  Saved: {metrics_csv_path}")
    
    print("\n" + "=" * 70)
    print("TRAINING PIPELINE COMPLETE!")
    print("=" * 70)
    
    return all_results, best


if __name__ == "__main__":
    run_training_pipeline()
