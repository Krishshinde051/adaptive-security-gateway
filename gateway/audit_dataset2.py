"""DATASET AUDIT part 2 - empty cells by column + train/test duplicate leakage."""
import csv
import os
from collections import Counter

import numpy as np
from sklearn.model_selection import train_test_split

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DS = os.path.join(BASE, "dataset")

path = os.path.join(DS, "ml_dataset_fixed.csv")
with open(path, encoding="utf-8", newline="") as f:
    r = csv.reader(f)
    header = next(r)
    rows = [row for row in r if len(row) == len(header)]

print("=" * 78)
print("EMPTY CELLS BY COLUMN  (ml_dataset_fixed.csv)")
print("=" * 78)
empt = Counter()
for row in rows:
    for i, v in enumerate(row):
        if v == "":
            empt[header[i]] += 1
if not empt:
    print("  none")
for col, n in empt.most_common():
    in_model = "MODEL FEATURE" if col in header[7:27] else "non-feature (metadata)"
    print("  %-24s %8d empties  (%.1f%%)  <- %s"
          % (col, n, 100.0 * n / len(rows), in_model))

FEAT = header[7:27]
bad = [c for c in FEAT if empt.get(c)]
print("  [ %s ] model-feature columns have no empty cells"
      % ("ok" if not bad else "FAIL: %s" % bad))

print()
print("=" * 78)
print("TRAIN/TEST DUPLICATE LEAKAGE  (replicating export_model.py split)")
print("=" * 78)
X = np.array([[float(row[i]) if row[i] else 0.0 for i in range(7, 27)] for row in rows])
y = np.array([int(row[27]) for row in rows])
raw_idx = np.arange(len(rows))
tr, te = train_test_split(raw_idx, test_size=0.2, random_state=42, stratify=y)

# identity key = the 20 features + label (what the model actually sees)
keys = [",".join(row[7:28]) for row in rows]
train_keys = Counter(keys[i] for i in tr)
leaked = sum(1 for i in te if train_keys.get(keys[i], 0) > 0)
uniq = len(set(keys))
print("  rows                       : %d" % len(rows))
print("  unique feature-vectors     : %d (%.1f%% of rows are duplicates)"
      % (uniq, 100.0 * (len(rows) - uniq) / len(rows)))
print("  test rows whose EXACT twin : %d / %d  (%.1f%%)"
      % (leaked, len(te), 100.0 * leaked / len(te)))
print("  -> that %.0f%% of the test set is memorisable by the model"
      % (100.0 * leaked / len(te)))
print("  reported test_acc=0.8847 therefore OVERSTATES generalisation.")

# honest re-measure: score only test rows with no twin in train
train_key_set = set(train_keys)
clean_te = [i for i in te if keys[i] not in train_key_set]
print()
print("  re-evaluating aegis_model.pkl on the %d CLEAN (non-duplicated) test rows..."
      % len(clean_te))
import pickle
with open(os.path.join(BASE, "models", "aegis_model.pkl"), "rb") as f:
    model = pickle.load(f)
with open(os.path.join(BASE, "models", "scaler.pkl"), "rb") as f:
    scaler = pickle.load(f)
model.n_jobs = 1
Xs = scaler.transform(X)
pred = np.zeros(len(rows), dtype=int)
pred[:] = model.predict(Xs)
acc_clean = float((pred[clean_te] == y[clean_te]).mean())
acc_all = float((pred[te] == y[te]).mean())
print("  accuracy on original test split : %.4f  (matches reported 0.8847 if similar)"
      % acc_all)
print("  accuracy on de-duplicated test  : %.4f  <- the honest number" % acc_clean)
print("  drop                            : %.4f" % (acc_all - acc_clean))

# class-wise on clean set
for lab, name in ((0, "benign"), (1, "malicious")):
    sel = [i for i in clean_te if y[i] == lab]
    a = float((pred[sel] == y[sel]).mean())
    print("    %-9s clean accuracy: %.4f  (n=%d)" % (name, a, len(sel)))
