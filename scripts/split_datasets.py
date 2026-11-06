"""
AEGIS Dataset Splitter
Creates 2 separate datasets:
1. ml_dataset.csv      - For ML training (NO leakage)
2. gateway_dataset.csv - For gateway decision engine (ALL features)
"""
import os, csv
from datetime import datetime

print("=" * 60)
print("AEGIS DATASET SPLITTER")
print("=" * 60)

path = os.path.join(os.path.dirname(__file__), '..', 'dataset', 'aegis_dataset.csv')
print(f"\nLoading: {path}")

headers = []
data = []
with open(path, 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    headers = next(reader)
    for row in reader:
        if len(row) == len(headers):
            data.append(row)

print(f"  Loaded: {len(data):,} rows")
print(f"  Columns: {len(headers)}")

# Deduplicate
seen, clean = set(), []
for row in data:
    k = ','.join(row[3:29])
    if k not in seen:
        seen.add(k)
        clean.append(row)
print(f"  Unique: {len(clean):,}")

# Column indices
# 0: id, 1: timestamp, 2: source_ip, 3: method, 4: url, 5: user_agent, 6: content_type
# 7-26: features (7=url_length ... 26=error_rate)
# 27: risk_score (LEAKY)
# 28: severity (LEAKY - text)
# 29: label
# 30: attack_type

# ML Dataset headers (remove leaky features 27, 28)
ml_headers = headers[:27] + headers[29:]  # skip 27 (risk_score) and 28 (severity)
# ML: id, timestamp, source_ip, method, url, user_agent, content_type, url_length..error_rate, label, attack_type

# Gateway Dataset headers (keep all)
gateway_headers = headers

outdir = os.path.join(os.path.dirname(__file__), '..', 'dataset')

# Write ML dataset
print("\nCreating ml_dataset.csv (NO risk_score, NO severity)...")
ml_path = os.path.join(outdir, 'ml_dataset.csv')
with open(ml_path, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(ml_headers)
    for row in clean:
        ml_row = row[:27] + row[29:]  # skip index 27 and 28
        writer.writerow(ml_row)
print(f"  Saved: {ml_path}")
print(f"  Columns: {len(ml_headers)}")

# Write Gateway dataset
print("\nCreating gateway_dataset.csv (ALL features)...")
gw_path = os.path.join(outdir, 'gateway_dataset.csv')
with open(gw_path, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(gateway_headers)
    for row in clean:
        writer.writerow(row)
print(f"  Saved: {gw_path}")
print(f"  Columns: {len(gateway_headers)}")

# Stats
print("\n" + "=" * 60)
print("DATASET SUMMARY")
print("=" * 60)

attack_counts = {}
for row in clean:
    at = row[30]
    attack_counts[at] = attack_counts.get(at, 0) + 1

print(f"\n{'ML Dataset (for training)':}")
print(f"  File: ml_dataset.csv")
print(f"  Rows: {len(clean):,}")
print(f"  Features: {len(ml_headers) - 4} (removed risk_score, severity)")
print(f"  Columns: {', '.join(ml_headers)}")

print(f"\n{'Gateway Dataset (for decision engine)':}")
print(f"  File: gateway_dataset.csv")
print(f"  Rows: {len(clean):,}")
print(f"  Features: {len(gateway_headers) - 4} (all features)")
print(f"  Columns: {', '.join(gateway_headers)}")

print(f"\nAttack Distribution:")
for at, cnt in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"  {at:<25} {cnt:>8,} ({cnt/len(clean)*100:.1f}%)")

print(f"\nDone! Created 2 separate datasets.")
print("=" * 60)
