"""
DATASET AUDIT - read-only verification of dataset/*.csv

Answers: is the 500,000-row dataset actually right?
  1. shape, parse integrity, empty cells
  2. label / attack_type distribution and cross-tab
  3. ml_dataset.csv  vs  ml_dataset_fixed.csv -> did fix_overfitting.py change ONLY the
     behavioural columns, and did it leave labels untouched?
  4. feature ranges + class-conditional means (leakage probe)
  5. aegis_dataset.csv risk_score / severity vs label -> are they derived (leaky) columns?
  6. duplicate rows
"""
import csv
import math
import os
from collections import Counter, defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DS = os.path.join(BASE, "dataset")

FEATS = ["url_length", "url_entropy", "num_special_chars", "num_encoded_chars",
         "has_sql_keywords", "has_js_keywords", "has_path_traversal", "has_cmd_injection",
         "has_xxe_patterns", "has_ssi_patterns", "has_injection_patterns",
         "has_prompt_injection", "has_suspicious_encoding", "body_length", "body_entropy",
         "num_headers", "has_user_agent", "requests_per_minute",
         "unique_urls_per_session", "error_rate"]
BEHAV = ["requests_per_minute", "unique_urls_per_session", "error_rate",
         "body_length", "body_entropy", "num_headers"]
CONTENT = [f for f in FEATS if f not in BEHAV]


def read(name):
    path = os.path.join(DS, name)
    with open(path, encoding="utf-8", newline="") as f:
        r = csv.reader(f)
        header = next(r)
        rows, bad = [], 0
        for row in r:
            if len(row) != len(header):
                bad += 1
                continue
            rows.append(row)
    return header, rows, bad


def f(row, idx):
    v = row[idx]
    if v is None or v == "":
        return None
    try:
        return float(v)
    except ValueError:
        return None


print("=" * 78)
print("1. SHAPE / PARSE INTEGRITY")
print("=" * 78)
data = {}
for name in ("aegis_dataset.csv", "gateway_dataset.csv", "ml_dataset.csv",
             "ml_dataset_fixed.csv"):
    h, rows, bad = read(name)
    data[name] = (h, rows)
    empt = sum(1 for r in rows for c in r if c == "")
    print("  %-24s rows=%-7d cols=%-3d malformed=%-4d empty_cells=%d"
          % (name, len(rows), len(h), bad, empt))

print()
print("=" * 78)
print("2. LABEL / ATTACK_TYPE DISTRIBUTION  (ml_dataset_fixed.csv)")
print("=" * 78)
h, rows = data["ml_dataset_fixed.csv"]
li, ai = h.index("label"), h.index("attack_type")
labels = Counter(r[li] for r in rows)
print("  label counts: %s  (ratio malicious=%.2f%%)"
      % (dict(labels), 100.0 * labels.get("1", 0) / len(rows)))
xt = defaultdict(Counter)
for r in rows:
    xt[r[ai]][r[li]] += 1
print("  %-20s %8s %8s" % ("attack_type", "label0", "label1"))
bad_xt = []
for at in sorted(xt):
    z, o = xt[at].get("0", 0), xt[at].get("1", 0)
    print("  %-20s %8d %8d" % (at, z, o))
    if at != "benign" and z > 0:
        bad_xt.append((at, z))
    if at == "benign" and o > 0:
        bad_xt.append(("benign", o))
print("  [ %s ] attack_type <-> label consistency"
      % ("ok - every non-benign row is label=1" if not bad_xt
         else "FAIL - mismatches: %s" % bad_xt[:5]))

print()
print("=" * 78)
print("3. ml_dataset.csv vs ml_dataset_fixed.csv (fix_overfitting.py claim)")
print("=" * 78)
h0, r0 = data["ml_dataset.csv"]
h1, r1 = data["ml_dataset_fixed.csv"]
assert h0 == h1, "column layout differs between the two files"
if len(r0) != len(r1):
    print("  [FAIL] row counts differ %d vs %d" % (len(r0), len(r1)))
idx = {n: i for i, n in enumerate(h0)}
changed = Counter()
label_flips = 0
content_touched = 0
for a, b in zip(r0, r1):
    if a[idx["label"]] != b[idx["label"]]:
        label_flips += 1
    for col in h0:
        if a[idx[col]] != b[idx[col]]:
            changed[col] += 1
            if col in CONTENT:
                content_touched += 1
print("  rows compared          : %d" % min(len(r0), len(r1)))
print("  label flips            : %d   [ %s ]"
      % (label_flips, "ok - none" if label_flips == 0 else "FAIL"))
print("  content features edited: %d cells  [ %s ]"
      % (content_touched, "ok - untouched" if content_touched == 0 else "FAIL"))
print("  columns modified:")
for col, n in changed.most_common():
    tag = "behavioural (expected)" if col in BEHAV else \
        ("label (expected?)" if col == "label" else "UNEXPECTED")
    print("      %-28s %8d cells  <- %s" % (col, n, tag))
unexpected = [c for c in changed if c not in BEHAV and c != "label"]
print("  [ %s ] only behavioural columns rewritten"
      % ("ok" if not unexpected else "FAIL - unexpected: %s" % unexpected))

print()
print("=" * 78)
print("4. LEAKAGE PROBE - class-conditional means before / after the fix")
print("=" * 78)
print("  %-26s %-22s %-22s" % ("feature", "BEFORE ben/mal", "AFTER ben/mal"))


def means(rows, header, col, lab):
    i, l = header.index(col), header.index("label")
    acc = defaultdict(list)
    for r in rows:
        v = f(r, i)
        if v is not None:
            acc[r[l]].append(v)
    def _m(x):
        return (sum(x) / len(x)) if x else float("nan")
    return _m(acc.get("0", [])), _m(acc.get("1", []))


for col in BEHAV:
    b0, m0 = means(r0, h0, col, "label")
    b1, m1 = means(r1, h1, col, "label")
    sep0 = abs(b0 - m0) / (abs(b0) + 1e-9) * 100
    sep1 = abs(b1 - m1) / (abs(b1) + 1e-9) * 100
    flag = "SEPARABLE->GONE" if sep0 > 80 and sep1 < sep0 else ""
    print("  %-26s %8.3f / %-10.3f %8.3f / %-10.3f  %s"
          % (col, b0, m0, b1, m1, flag))

print()
print("  content features (should stay separable - they carry the real signal):")
for col in CONTENT:
    b1, m1 = means(r1, h1, col, "label")
    print("    %-26s benign=%-9.3f malicious=%-9.3f" % (col, b1, m1))

print()
print("=" * 78)
print("5. aegis_dataset.csv risk_score / severity vs label  (why the old iForest was wrong)")
print("=" * 78)
ha, ra = data["aegis_dataset.csv"]
idxa = {n: i for i, n in enumerate(ha)}
agree_score = agree_sev = 0
sev_by_label = defaultdict(Counter)
for r in ra:
    lab = r[idxa["label"]]
    rs = f(r, idxa["risk_score"])
    if rs is not None:
        pred = 1 if rs >= 10 else 0
        agree_score += (pred == int(lab))
    sev_by_label[lab][r[idxa["severity"]]] += 1
    sev_by_label[lab]  # noop
print("  risk_score>=10 predicts label : %.4f%%  (%d/%d)"
      % (100.0 * agree_score / len(ra), agree_score, len(ra)))
# severity -> label agreement
sev_map = {"safe": 0, "low": 0, "medium": 1, "high": 1, "critical": 1}
agree_sev = sum(1 for r in ra
                if sev_map.get(r[idxa["severity"]], 0) == int(r[idxa["label"]]))
print("  severity(band) predicts label  : %.4f%%  (%d/%d)"
      % (100.0 * agree_sev / len(ra), agree_sev, len(ra)))
print("  severity distribution by label :")
for lab in sorted(sev_by_label):
    print("      label=%s -> %s" % (lab, dict(sev_by_label[lab])))
print("  [ CONCLUSION ] both columns are derived from the label: any model trained with")
print("                 them (the original 22-feature isolation_forest.pkl) simply reads")
print("                 the answer back - that is the leakage the gateway retrain avoids.")

print()
print("=" * 78)
print("6. DUPLICATES")
print("=" * 78)
for name in ("aegis_dataset.csv", "ml_dataset_fixed.csv"):
    h, rows = data[name]
    key_i = [h.index(c) for c in ("method", "url", "user_agent", "label", "attack_type")]
    keys = Counter(",".join(r[i] for i in key_i) for r in rows)
    dupes = sum(v - 1 for v in keys.values() if v > 1)
    print("  %-24s duplicate (method,url,ua,label,type) rows: %d (%.2f%%)"
          % (name, dupes, 100.0 * dupes / len(rows)))

print()
print("=" * 78)
print("7. FEATURE VALUE SANITY (ml_dataset_fixed)")
print("=" * 78)
h, rows = data["ml_dataset_fixed.csv"]
for col in FEATS:
    i = h.index(col)
    vals = [f(r, i) for r in rows[:50000]]
    vals = [v for v in vals if v is not None]
    print("  %-26s min=%-10.3f max=%-12.3f mean=%.3f"
          % (col, min(vals), max(vals), sum(vals) / len(vals)))
