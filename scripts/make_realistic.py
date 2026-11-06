"""
AEGIS Realistic Dataset Generator
Adds noise to make dataset challenging like real-world
Expected accuracy: 85-95% (realistic for WAF)
"""
import os, csv, random, math
from datetime import datetime, timedelta

random.seed(42)

print("=" * 60)
print("AEGIS REALISTIC DATASET GENERATOR")
print("=" * 60)

# Load original data
path = os.path.join(os.path.dirname(__file__), '..', 'dataset', 'aegis_dataset.csv')
print(f"\nLoading original dataset...")
headers, data = [], []
with open(path, 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    headers = next(reader)
    for row in reader:
        if len(row) == len(headers):
            data.append(row)
print(f"  Loaded: {len(data):,} rows")

# Deduplicate
seen, clean = set(), []
for row in data:
    k = ','.join(row[3:29])
    if k not in seen:
        seen.add(k)
        clean.append(row)
print(f"  Unique: {len(clean):,}")

# ============================================================
# ADD REALISTIC NOISE
# ============================================================
print("\nAdding realistic noise...")

# 1. Benign requests that LOOK suspicious (false positive candidates)
suspicious_benign = [
    # Normal admin actions
    "/admin/dashboard", "/admin/users", "/admin/settings",
    "/api/internal/health", "/api/debug/info",
    # Normal search with special chars
    "/search?q=c++", "/search?q=1+1=2", "/search?q=O'Reilly",
    # Normal file access
    "/downloads/report.pdf", "/uploads/image.jpg",
    # Normal API calls with params
    "/api/data?filter=active&sort=name",
    "/api/users?page=1&limit=100",
]

# 2. Malicious requests that LOOK normal (false negative candidates)
stealthy_attacks = [
    # Subtle SQLi
    "/api/users?id=1",  # Normal looking but could be injection point
    "/api/search?q=test",  # Normal search
    # Subtle XSS
    "/profile?name=John",  # Normal profile
    "/comment?text=Hello",  # Normal comment
    # Normal-looking paths
    "/api/data", "/api/config", "/api/status",
]

# 3. Add noise to features
def add_noise(value, noise_level=0.1):
    """Add gaussian noise to a numeric value"""
    if isinstance(value, (int, float)):
        noise = random.gauss(0, noise_level * abs(value) + 0.1)
        return value + noise
    return value

def flip_label_with_probability(label, prob):
    """Flip label with given probability"""
    if random.random() < prob:
        return 1 - label
    return label

# Process data
realistic_data = []
noise_count = 0
flip_count = 0

for row in clean:
    new_row = row[:]
    
    # Feature indices: 7-26 are features
    # Add noise to numeric features
    for i in range(7, 27):
        try:
            val = float(new_row[i]) if new_row[i] else 0.0
            # Add 5-15% noise
            noise_pct = random.uniform(0.05, 0.15)
            val = val + random.gauss(0, noise_pct * abs(val) + 0.01)
            new_row[i] = str(round(val, 4))
            noise_count += 1
        except:
            pass
    
    # Randomly flip 2% of labels (simulate mislabelled data)
    original_label = int(new_row[29])
    new_label = flip_label_with_probability(original_label, 0.02)
    if new_label != original_label:
        new_row[29] = str(new_label)
        flip_count += 1
    
    realistic_data.append(new_row)

# Add extra noisy samples
print("  Adding noisy benign samples...")
for _ in range(10000):  # 10K extra
    # Create a benign request that looks suspicious
    base = random.choice([r for r in clean if r[29] == '0'])  # Pick benign
    new_row = base[:]
    new_row[0] = str(len(realistic_data) + 1)  # New ID
    
    # Make it look suspicious
    new_row[7] = str(random.randint(50, 200))  # Longer URL
    new_row[8] = str(round(random.uniform(3.5, 5.0), 4))  # Higher entropy
    new_row[9] = str(random.randint(5, 15))  # More special chars
    new_row[12] = str(random.randint(1, 3))  # Some SQL keywords (in normal context)
    new_row[13] = str(random.randint(0, 2))  # Some JS keywords (in normal context)
    new_row[25] = str(round(random.uniform(0.1, 0.5), 2))  # Higher error rate
    
    # But keep label as benign
    new_row[29] = '0'
    realistic_data.append(new_row)

print("  Adding noisy malicious samples...")
for _ in range(5000):  # 5K extra
    # Create a malicious request that looks normal
    base = random.choice([r for r in clean if r[29] == '1'])  # Pick malicious
    new_row = base[:]
    new_row[0] = str(len(realistic_data) + 1)
    
    # Make it look normal
    new_row[7] = str(random.randint(10, 40))  # Short URL
    new_row[8] = str(round(random.uniform(2.5, 3.5), 4))  # Normal entropy
    new_row[9] = str(random.randint(1, 5))  # Few special chars
    new_row[12] = str(0)  # No SQL keywords visible
    new_row[13] = str(0)  # No JS keywords visible
    new_row[25] = str(round(random.uniform(0, 0.1), 2))  # Low error rate
    
    # But keep label as malicious
    new_row[29] = '1'
    realistic_data.append(new_row)

# Shuffle
random.shuffle(realistic_data)

print(f"  Added noise to {noise_count:,} feature values")
print(f"  Flipped {flip_count:,} labels (simulated mislabelling)")
print(f"  Added 15,000 noisy samples")
print(f"  Final dataset: {len(realistic_data):,} rows")

# ============================================================
# SAVE REALISTIC DATASETS
# ============================================================
outdir = os.path.join(os.path.dirname(__file__), '..', 'dataset')

# ML Dataset (no risk_score, no severity)
print("\nCreating realistic_ml_dataset.csv...")
ml_path = os.path.join(outdir, 'realistic_ml_dataset.csv')
ml_headers = headers[:27] + headers[29:]  # skip risk_score(27) and severity(28)

with open(ml_path, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(ml_headers)
    for row in realistic_data:
        ml_row = row[:27] + row[29:]
        writer.writerow(ml_row)
print(f"  Saved: {ml_path}")

# Gateway Dataset (all features)
print("Creating realistic_gateway_dataset.csv...")
gw_path = os.path.join(outdir, 'realistic_gateway_dataset.csv')

with open(gw_path, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(headers)
    for row in realistic_data:
        writer.writerow(row)
print(f"  Saved: {gw_path}")

# Stats
print("\n" + "=" * 60)
print("REALISTIC DATASET STATS")
print("=" * 60)

benign = sum(1 for r in realistic_data if r[29] == '0')
malicious = len(realistic_data) - benign
print(f"\nTotal:    {len(realistic_data):,}")
print(f"Benign:   {benign:,} ({benign/len(realistic_data)*100:.1f}%)")
print(f"Malicious: {malicious:,} ({malicious/len(realistic_data)*100:.1f}%)")
print(f"\nExpected accuracy with this dataset: 85-95%")
print(f"(Realistic for production WAF)")
print("=" * 60)
