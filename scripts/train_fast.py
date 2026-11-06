"""
AEGIS Fast ML Training Pipeline
Optimized for speed - trains on 15K samples
"""
import os, sys, csv, json, time, random, math
from datetime import datetime
from collections import Counter

# ============================================================
# DATA LOADING
# ============================================================
def load_data(path):
    print(f"Loading {path}...")
    headers, data = [], []
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        headers = next(reader)
        for row in reader:
            if len(row) == len(headers):
                data.append(row)
    print(f"  Loaded {len(data):,} rows")
    return headers, data

def extract_features(data):
    severity_map = {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    X, y = [], []
    for row in data:
        try:
            feats = [float(row[i]) if row[i] else 0.0 for i in range(7, 28)]
            feats.append(severity_map.get(row[28], 0) if len(row) > 28 else 0)
            X.append(feats)
            y.append(int(row[29]))
        except:
            continue
    return X, y

def split_data(X, y, test_size=0.2, seed=42):
    random.seed(seed)
    n = len(X)
    idx = list(range(n))
    random.shuffle(idx)
    split = int(n * (1 - test_size))
    return ([X[i] for i in idx[:split]], [X[i] for i in idx[split:]],
            [y[i] for i in idx[:split]], [y[i] for i in idx[split:]])

def standardize(Xtr, Xte):
    nf = len(Xtr[0])
    means = [sum(r[i] for r in Xtr)/len(Xtr) for i in range(nf)]
    stds = [max(math.sqrt(sum((r[i]-means[i])**2 for r in Xtr)/len(Xtr)), 1e-8) for i in range(nf)]
    Xt = [[(x-m)/s for x,m,s in zip(r,means,stds)] for r in Xtr]
    Xv = [[(x-m)/s for x,m,s in zip(r,means,stds)] for r in Xte]
    return Xt, Xv

# ============================================================
# METRICS
# ============================================================
def metrics(yt, yp):
    tp = sum(1 for t,p in zip(yt,yp) if t==1 and p==1)
    tn = sum(1 for t,p in zip(yt,yp) if t==0 and p==0)
    fp = sum(1 for t,p in zip(yt,yp) if t==0 and p==1)
    fn = sum(1 for t,p in zip(yt,yp) if t==1 and p==0)
    acc = (tp+tn)/(tp+tn+fp+fn) if (tp+tn+fp+fn) else 0
    prec = tp/(tp+fp) if (tp+fp) else 0
    rec = tp/(tp+fn) if (tp+fn) else 0
    f1 = 2*prec*rec/(prec+rec) if (prec+rec) else 0
    spec = tn/(tn+fp) if (tn+fp) else 0
    return {'accuracy':acc,'precision':prec,'recall':rec,'f1':f1,'specificity':spec,'tp':tp,'tn':tn,'fp':fp,'fn':fn}

# ============================================================
# SIMPLE DECISION TREE (fast version)
# ============================================================
class FastTree:
    def __init__(self, depth=8):
        self.depth = depth
        self.tree = None

    def _gini(self, labels):
        if not labels: return 0
        c = Counter(labels)
        t = len(labels)
        return 1 - sum((v/t)**2 for v in c.values())

    def _build(self, X, y, d):
        if d >= self.depth or len(X) < 10 or len(set(y)) == 1:
            return {'leaf': True, 'pred': Counter(y).most_common(1)[0][0]}
        
        best_f, best_t, best_g = None, None, float('inf')
        nf = len(X[0])
        features = random.sample(range(nf), min(6, nf))
        
        for f in features:
            vals = sorted(set(r[f] for r in X))
            for t in vals[::max(1, len(vals)//8)]:
                li = [i for i,r in enumerate(X) if r[f] <= t]
                ri = [i for i,r in enumerate(X) if r[f] > t]
                if len(li) < 5 or len(ri) < 5: continue
                g = (len(li)*self._gini([y[i] for i in li]) + len(ri)*self._gini([y[i] for i in ri]))/len(X)
                if g < best_g:
                    best_g, best_f, best_t = g, f, t
        
        if best_f is None:
            return {'leaf': True, 'pred': Counter(y).most_common(1)[0][0]}
        
        li = [i for i,r in enumerate(X) if r[best_f] <= best_t]
        ri = [i for i,r in enumerate(X) if r[best_f] > best_t]
        return {'f': best_f, 't': best_t,
                'l': self._build([X[i] for i in li], [y[i] for i in li], d+1),
                'r': self._build([X[i] for i in ri], [y[i] for i in ri], d+1)}

    def fit(self, X, y): self.tree = self._build(X, y, 0)
    
    def _pred(self, x, n):
        if 'leaf' in n: return n['pred']
        return self._pred(x, n['l'] if x[n['f']] <= n['t'] else n['r'])
    
    def predict(self, X): return [self._pred(x, self.tree) for x in X]

# ============================================================
# RANDOM FOREST
# ============================================================
class FastRF:
    def __init__(self, n=15, depth=10):
        self.n, self.depth = n, depth
        self.trees, self.fidx = [], []

    def fit(self, X, y):
        nf = len(X[0])
        for _ in range(self.n):
            idx = [random.randint(0, len(X)-1) for _ in range(len(X))]
            fi = random.sample(range(nf), max(1, int(math.sqrt(nf))))
            self.fidx.append(fi)
            t = FastTree(self.depth)
            t.fit([[X[i][f] for f in fi] for i in idx], [y[i] for i in idx])
            self.trees.append(t)

    def predict(self, X):
        preds = []
        for t, fi in zip(self.trees, self.fidx):
            preds.append(t.predict([[x[f] for f in fi] for x in X]))
        return [Counter(p).most_common(1)[0][0] for p in zip(*preds)]

# ============================================================
# GRADIENT BOOSTING
# ============================================================
class FastGB:
    def __init__(self, n=20, lr=0.1, depth=5):
        self.n, self.lr, self.depth = n, lr, depth
        self.trees = []
        self.init = 0

    def fit(self, X, y):
        self.init = sum(y)/len(y)
        pred = [self.init]*len(y)
        for _ in range(self.n):
            res = [y[i]-pred[i] for i in range(len(y))]
            t = FastTree(self.depth)
            t.fit(X, [1 if r>0 else 0 for r in res])
            self.trees.append(t)
            tp = t.predict(X)
            pred = [pred[i]+self.lr*(tp[i]-0.5) for i in range(len(pred))]

    def predict(self, X):
        pred = [self.init]*len(X)
        for t in self.trees:
            tp = t.predict(X)
            pred = [pred[i]+self.lr*(tp[i]-0.5) for i in range(len(pred))]
        return [1 if p>=0.5 else 0 for p in pred]

# ============================================================
# LOGISTIC REGRESSION
# ============================================================
class FastLR:
    def __init__(self, lr=0.01, iters=50):
        self.lr, self.iters = lr, iters
        self.w, self.b = [], 0

    def _sig(self, z): return 1/(1+math.exp(max(-500,min(500,z))))

    def fit(self, X, y):
        n, nf = len(X), len(X[0])
        self.w = [0.0]*nf
        for _ in range(self.iters):
            for i in range(min(2000, n)):
                z = sum(w*x for w,x in zip(self.w, X[i])) + self.b
                e = self._sig(z) - y[i]
                self.w = [w - self.lr*e*x for w,x in zip(self.w, X[i])]
                self.b -= self.lr*e

    def predict(self, X):
        return [1 if self._sig(sum(w*x for w,x in zip(self.w,x))+self.b)>=0.5 else 0 for x in X]

# ============================================================
# SVM
# ============================================================
class FastSVM:
    def __init__(self, lr=0.001, iters=30):
        self.lr, self.iters = lr, iters
        self.w, self.b = [], 0

    def fit(self, X, y):
        n, nf = len(X), len(X[0])
        self.w = [0.0]*nf
        yb = [1 if yi==1 else -1 for yi in y]
        for _ in range(self.iters):
            for i in range(min(2000, n)):
                c = yb[i]*(sum(w*x for w,x in zip(self.w, X[i]))+self.b)
                if c < 1:
                    self.w = [w + self.lr*(yb[i]*x - 0.01*w) for w,x in zip(self.w, X[i])]
                    self.b += self.lr*yb[i]

    def predict(self, X):
        return [1 if sum(w*x for w,x in zip(self.w,x))+self.b>=0 else 0 for x in X]

# ============================================================
# KNN
# ============================================================
class FastKNN:
    def __init__(self, k=5):
        self.k = k
        self.Xt, self.yt = [], []

    def fit(self, X, y):
        self.Xt, self.yt = X[:3000], y[:3000]

    def predict(self, X):
        preds = []
        for x in X[:2000]:
            dists = [(sum((a-b)**2 for a,b in zip(x,xt)), yt) for xt,yt in zip(self.Xt, self.yt)]
            dists.sort(key=lambda d: d[0])
            kn = [lb for _,lb in dists[:self.k]]
            preds.append(Counter(kn).most_common(1)[0][0])
        return preds

# ============================================================
# MLP
# ============================================================
class FastMLP:
    def __init__(self, h=24, lr=0.01, iters=20):
        self.h, self.lr, self.iters = h, lr, iters

    def _sig(self, z): return 1/(1+math.exp(max(-500,min(500,z))))

    def fit(self, X, y):
        n, nf = len(X), len(X[0])
        self.W1 = [[random.gauss(0,0.1) for _ in range(self.h)] for _ in range(nf)]
        self.b1 = [0.0]*self.h
        self.W2 = [random.gauss(0,0.1) for _ in range(self.h)]
        self.b2 = 0
        for _ in range(self.iters):
            for i in range(min(1000, n)):
                hid = [self._sig(sum(X[i][k]*self.W1[k][j] for k in range(nf))+self.b1[j]) for j in range(self.h)]
                out = self._sig(sum(hid[j]*self.W2[j] for j in range(self.h))+self.b2)
                eo = out - y[i]
                for j in range(self.h):
                    eh = eo*self.W2[j]*hid[j]*(1-hid[j])
                    self.W1[j] = [w - self.lr*eh*X[i][k] for k,w in enumerate(self.W1[j])]
                    self.b1[j] -= self.lr*eh
                    self.W2[j] -= self.lr*eo*hid[j]
                self.b2 -= self.lr*eo

    def predict(self, X):
        preds = []
        for x in X:
            hid = [self._sig(sum(x[k]*self.W1[k][j] for k in range(len(x)))+self.b1[j]) for j in range(self.h)]
            out = self._sig(sum(hid[j]*self.W2[j] for j in range(self.h))+self.b2)
            preds.append(1 if out>=0.5 else 0)
        return preds

# ============================================================
# MAIN
# ============================================================
def main():
    print("=" * 60)
    print("AEGIS ML TRAINING PIPELINE (FAST)")
    print("=" * 60)

    # Load
    path = os.path.join(os.path.dirname(__file__), '..', 'dataset', 'aegis_dataset.csv')
    headers, data = load_data(path)
    
    # Deduplicate
    print("Deduplicating...")
    seen = set()
    clean = []
    for row in data:
        key = ','.join(row[3:29])
        if key not in seen:
            seen.add(key)
            clean.append(row)
    print(f"  {len(clean):,} unique rows")

    # Features
    X, y = extract_features(clean)
    print(f"  {len(X)} samples, {len(X[0])} features")

    # Split
    Xtr, Xte, ytr, yte = split_data(X, y)
    print(f"  Train: {len(Xtr)}, Test: {len(Xte)}")

    # Standardize
    Xtr_s, Xte_s = standardize(Xtr, Xte)

    # Models
    models = [
        ("Random Forest", FastRF(n=15, depth=10), Xtr, ytr, Xte, False),
        ("Decision Tree", FastTree(depth=12), Xtr, ytr, Xte, False),
        ("Gradient Boosting", FastGB(n=20, lr=0.1, depth=6), Xtr, ytr, Xte, False),
        ("Logistic Regression", FastLR(lr=0.01, iters=50), Xtr_s, ytr, Xte_s, True),
        ("Linear SVM", FastSVM(lr=0.001, iters=30), Xtr_s, ytr, Xte_s, True),
        ("MLP Neural Network", FastMLP(h=24, lr=0.01, iters=20), Xtr_s, ytr, Xte_s, True),
    ]

    results = []
    for name, model, Xtrn, ytrn, Xten, norm in models:
        print(f"\nTraining: {name}...")
        t0 = time.time()
        model.fit(Xtrn, ytrn)
        tt = time.time() - t0
        
        t1 = time.time()
        yp = model.predict(Xten)
        it = (time.time() - t1) * 1000
        
        m = metrics(yte, yp)
        m['name'] = name
        m['train_time'] = tt
        m['inference_ms'] = it
        results.append(m)
        print(f"  Acc: {m['accuracy']:.4f} | Prec: {m['precision']:.4f} | Rec: {m['recall']:.4f} | F1: {m['f1']:.4f} | Train: {tt:.1f}s | Inference: {it:.1f}ms")

    # Sort
    results.sort(key=lambda x: x['f1'], reverse=True)
    best = results[0]

    # Print comparison
    print("\n" + "=" * 60)
    print("MODEL COMPARISON")
    print("=" * 60)
    print(f"{'Model':<25} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10}")
    print("-" * 65)
    for r in results:
        print(f"{r['name']:<25} {r['accuracy']:>10.4f} {r['precision']:>10.4f} {r['recall']:>10.4f} {r['f1']:>10.4f}")

    print(f"\nBEST MODEL: {best['name']}")
    print(f"  Accuracy:  {best['accuracy']:.4f} ({best['accuracy']*100:.2f}%)")
    print(f"  Precision: {best['precision']:.4f} ({best['precision']*100:.2f}%)")
    print(f"  Recall:    {best['recall']:.4f} ({best['recall']*100:.2f}%)")
    print(f"  F1-Score:  {best['f1']:.4f} ({best['f1']*100:.2f}%)")
    print(f"  Confusion: TP={best['tp']}, TN={best['tn']}, FP={best['fp']}, FN={best['fn']}")

    # Save results
    outdir = os.path.join(os.path.dirname(__file__), '..', 'results')
    os.makedirs(outdir, exist_ok=True)

    with open(os.path.join(outdir, 'model_comparison.json'), 'w') as f:
        json.dump({'timestamp': datetime.now().isoformat(), 'best': best['name'],
                    'metrics': {k:v for k,v in best.items() if k!='name'},
                    'all_models': [{k:v for k,v in r.items() if k!='name'} for r in results]}, f, indent=2)

    with open(os.path.join(outdir, 'model_comparison.txt'), 'w') as f:
        f.write("AEGIS MODEL COMPARISON\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n\n")
        f.write(f"{'Model':<25} {'Acc':>8} {'Prec':>8} {'Rec':>8} {'F1':>8}\n")
        f.write("-" * 57 + "\n")
        for r in results:
            f.write(f"{r['name']:<25} {r['accuracy']:>8.4f} {r['precision']:>8.4f} {r['recall']:>8.4f} {r['f1']:>8.4f}\n")
        f.write(f"\nBest: {best['name']}\n")
        f.write(f"Accuracy: {best['accuracy']:.4f}\nPrecision: {best['precision']:.4f}\nRecall: {best['recall']:.4f}\nF1: {best['f1']:.4f}\n")

    with open(os.path.join(outdir, 'all_models_metrics.csv'), 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['Model','Accuracy','Precision','Recall','F1','Specificity','TrainTime_s','Inference_ms'])
        for r in results:
            w.writerow([r['name'],f"{r['accuracy']:.4f}",f"{r['precision']:.4f}",f"{r['recall']:.4f}",f"{r['f1']:.4f}",f"{r['specificity']:.4f}",f"{r['train_time']:.2f}",f"{r['inference_ms']:.2f}"])

    print(f"\nResults saved to {outdir}")
    print("=" * 60)

if __name__ == "__main__":
    main()
