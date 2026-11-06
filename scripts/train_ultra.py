"""
AEGIS Ultra-Fast ML Training (5K samples - ~60 seconds)
"""
import os, csv, json, time, random, math
from datetime import datetime
from collections import Counter

def load_data(path):
    h, d = [], []
    with open(path, 'r', encoding='utf-8') as f:
        r = csv.reader(f)
        h = next(r)
        for row in r:
            if len(row)==len(h): d.append(row)
    return h, d

def extract(data):
    sm = {'safe':0,'low':1,'medium':2,'high':3,'critical':4}
    X, y = [], []
    for row in data:
        try:
            f = [float(row[i]) if row[i] else 0.0 for i in range(7,28)]
            f.append(sm.get(row[28],0) if len(row)>28 else 0)
            X.append(f)
            y.append(int(row[29]))
        except: continue
    return X, y

def split(X, y, ts=0.2):
    random.seed(42)
    n = len(X)
    idx = list(range(n))
    random.shuffle(idx)
    s = int(n*(1-ts))
    return [X[i] for i in idx[:s]], [X[i] for i in idx[s:]], [y[i] for i in idx[:s]], [y[i] for i in idx[s:]]

def std(Xt, Xv):
    nf = len(Xt[0])
    m = [sum(r[i] for r in Xt)/len(Xt) for i in range(nf)]
    sd = [max(math.sqrt(sum((r[i]-m[i])**2 for r in Xt)/len(Xt)),1e-8) for i in range(nf)]
    return [[(x-m[i])/sd[i] for i,(x,mx,sx) in enumerate(zip(r,m,sd))] for r in Xt], [[(x-m[i])/sd[i] for i,(x,mx,sx) in enumerate(zip(r,m,sd))] for r in Xv]

def met(yt, yp):
    tp = sum(1 for t,p in zip(yt,yp) if t==1 and p==1)
    tn = sum(1 for t,p in zip(yt,yp) if t==0 and p==0)
    fp = sum(1 for t,p in zip(yt,yp) if t==0 and p==1)
    fn = sum(1 for t,p in zip(yt,yp) if t==1 and p==0)
    a = (tp+tn)/(tp+tn+fp+fn) if (tp+tn+fp+fn) else 0
    pr = tp/(tp+fp) if (tp+fp) else 0
    rc = tp/(tp+fn) if (tp+fn) else 0
    f1 = 2*pr*rc/(pr+rc) if (pr+rc) else 0
    sp = tn/(tn+fp) if (tn+fp) else 0
    return {'accuracy':a,'precision':pr,'recall':rc,'f1':f1,'specificity':sp,'tp':tp,'tn':tn,'fp':fp,'fn':fn}

# Decision Stump
class Stump:
    def __init__(self): self.f=self.t=0; self.lr=1; self.dir=1
    def fit(self, X, y, w):
        best_e, best_f, best_t, best_d = 1, 0, 0, 1
        nf = len(X[0])
        for f in range(nf):
            vals = sorted(set(r[f] for r in X))
            for t in vals[::max(1,len(vals)//10)]:
                for d in [1,-1]:
                    pred = [d if r[f]>t else -d for r in X]
                    e = sum(w[i] for i in range(len(y)) if (pred[i]==1)!=(y[i]==1))
                    if e < best_e:
                        best_e, best_f, best_t, best_d = e, f, t, d
        self.f, self.t, self.dir = best_f, best_t, best_d
        return best_e

class AdaBoost:
    def __init__(self, n=25): self.n=n; self.stumps=[]
    def fit(self, X, y):
        n=len(X); w=[1.0/n]*n
        for _ in range(self.n):
            s=Stump(); e=s.fit(X,y,w)
            e=max(e,1e-10); a=0.5*math.log((1-e)/e)
            s.lr=a; self.stumps.append(s)
            pred=[s.dir if r[s.f]>s.t else -s.dir for r in X]
            w=[w[i]*math.exp(a*(-1 if pred[i]==y[i] else 1)) for i in range(n)]
            t=sum(w); w=[wi/t for wi in w]
    def predict(self, X):
        return [1 if sum(s.lr*(s.dir if x[s.f]>s.t else -s.dir) for s in self.stumps)>=0 else 0 for x in X]

class Tree:
    def __init__(self, d=8): self.d=d; self.tree=None
    def _gini(self, l):
        if not l: return 0
        c=Counter(l); t=len(l)
        return 1-sum((v/t)**2 for v in c.values())
    def _build(self, X, y, depth):
        if depth>=self.d or len(X)<10 or len(set(y))==1:
            return {'leaf':1,'p':Counter(y).most_common(1)[0][0]}
        bf,bt,bg=None,None,float('inf')
        nf=len(X[0])
        for f in random.sample(range(nf),min(5,nf)):
            vs=sorted(set(r[f] for r in X))
            for t in vs[::max(1,len(vs)//6)]:
                li=[i for i,r in enumerate(X) if r[f]<=t]
                ri=[i for i,r in enumerate(X) if r[f]>t]
                if len(li)<5 or len(ri)<5: continue
                g=(len(li)*self._gini([y[i] for i in li])+len(ri)*self._gini([y[i] for i in ri]))/len(X)
                if g<bg: bg,bf,bt=g,f,t
        if bf is None: return {'leaf':1,'p':Counter(y).most_common(1)[0][0]}
        li=[i for i,r in enumerate(X) if r[bf]<=bt]
        ri=[i for i,r in enumerate(X) if r[bf]>bt]
        return {'f':bf,'t':bt,'l':self._build([X[i] for i in li],[y[i] for i in li],depth+1),'r':self._build([X[i] for i in ri],[y[i] for i in ri],depth+1)}
    def fit(self, X, y): self.tree=self._build(X,y,0)
    def _p(self, x, n):
        if 'leaf' in n: return n['p']
        return self._p(x, n['l'] if x[n['f']]<=n['t'] else n['r'])
    def predict(self, X): return [self._p(x,self.tree) for x in X]

class RF:
    def __init__(self, n=20, d=10): self.n=n; self.d=d; self.trees=[]; self.fi=[]
    def fit(self, X, y):
        nf=len(X[0])
        for _ in range(self.n):
            idx=[random.randint(0,len(X)-1) for _ in range(len(X))]
            fi=random.sample(range(nf),max(1,int(math.sqrt(nf))))
            self.fi.append(fi)
            t=Tree(self.d)
            t.fit([[X[i][f] for f in fi] for i in idx],[y[i] for i in idx])
            self.trees.append(t)
    def predict(self, X):
        ps=[t.predict([[x[f] for f in fi] for x in X]) for t,fi in zip(self.trees,self.fi)]
        return [Counter(p).most_common(1)[0][0] for p in zip(*ps)]

class GB:
    def __init__(self, n=25, lr=0.1, d=5): self.n=n; self.lr=lr; self.d=d; self.trees=[]; self.init=0
    def fit(self, X, y):
        self.init=sum(y)/len(y); p=[self.init]*len(y)
        for _ in range(self.n):
            r=[y[i]-p[i] for i in range(len(y))]
            t=Tree(self.d); t.fit(X,[1 if v>0 else 0 for v in r]); self.trees.append(t)
            tp=t.predict(X); p=[p[i]+self.lr*(tp[i]-0.5) for i in range(len(p))]
    def predict(self, X):
        p=[self.init]*len(X)
        for t in self.trees:
            tp=t.predict(X); p=[p[i]+self.lr*(tp[i]-0.5) for i in range(len(p))]
        return [1 if v>=0.5 else 0 for v in p]

class LR:
    def __init__(self, lr=0.01, it=100): self.lr=lr; self.it=it; self.w=[]; self.b=0
    def _s(self, z): return 1/(1+math.exp(max(-500,min(500,z))))
    def fit(self, X, y):
        n,nf=len(X),len(X[0]); self.w=[0.0]*nf
        for _ in range(self.it):
            for i in range(n):
                z=sum(w*x for w,x in zip(self.w,X[i]))+self.b
                e=self._s(z)-y[i]; self.w=[w-self.lr*e*x for w,x in zip(self.w,X[i])]; self.b-=self.lr*e
    def predict(self, X): return [1 if self._s(sum(w*x for w,x in zip(self.w,x))+self.b)>=0.5 else 0 for x in X]

class SVM:
    def __init__(self, lr=0.001, it=50): self.lr=lr; self.it=it; self.w=[]; self.b=0
    def fit(self, X, y):
        n,nf=len(X),len(X[0]); self.w=[0.0]*nf; yb=[1 if v==1 else -1 for v in y]
        for _ in range(self.it):
            for i in range(n):
                c=yb[i]*(sum(w*x for w,x in zip(self.w,X[i]))+self.b)
                if c<1: self.w=[w+self.lr*(yb[i]*x-0.01*w) for w,x in zip(self.w,X[i])]; self.b+=self.lr*yb[i]
    def predict(self, X): return [1 if sum(w*x for w,x in zip(self.w,x))+self.b>=0 else 0 for x in X]

class MLP:
    def __init__(self, h=20, lr=0.01, it=20): self.h=h; self.lr=lr; self.it=it
    def _s(self, z): return 1/(1+math.exp(max(-500,min(500,z))))
    def fit(self, X, y):
        n,nf=len(X),len(X[0])
        self.W1=[[random.gauss(0,0.1) for _ in range(self.h)] for _ in range(nf)]
        self.b1=[0.0]*self.h; self.W2=[random.gauss(0,0.1) for _ in range(self.h)]; self.b2=0
        for _ in range(self.it):
            for i in range(n):
                h=[self._s(sum(X[i][k]*self.W1[k][j] for k in range(nf))+self.b1[j]) for j in range(self.h)]
                o=self._s(sum(h[j]*self.W2[j] for j in range(self.h))+self.b2)
                eo=o-y[i]
                for j in range(self.h):
                    eh=eo*self.W2[j]*h[j]*(1-h[j])
                    self.W1[j]=[w-self.lr*eh*X[i][k] for k,w in enumerate(self.W1[j])]
                    self.b1[j]-=self.lr*eh; self.W2[j]-=self.lr*eo*h[j]
                self.b2-=self.lr*eo
    def predict(self, X):
        return [1 if self._s(sum(self._s(sum(x[k]*self.W1[k][j] for k in range(len(x)))+self.b1[j])*self.W2[j] for j in range(self.h))+self.b2)>=0.5 else 0 for x in X]

class KNN:
    def __init__(self, k=5): self.k=k; self.Xt=[]; self.yt=[]
    def fit(self, X, y): self.Xt=X[:2000]; self.yt=y[:2000]
    def predict(self, X):
        preds=[]
        for x in X[:2000]:
            d=[(sum((a-b)**2 for a,b in zip(x,xt)),yt) for xt,yt in zip(self.Xt,self.yt)]
            d.sort(key=lambda x:x[0]); kn=[lb for _,lb in d[:self.k]]
            preds.append(Counter(kn).most_common(1)[0][0])
        return preds

def main():
    print("="*60)
    print("AEGIS ULTRA-FAST ML TRAINING")
    print("="*60)

    path = os.path.join(os.path.dirname(__file__), '..', 'dataset', 'aegis_dataset.csv')
    h, data = load_data(path)
    print(f"Loaded {len(data):,} rows")

    # Dedup
    seen=set(); clean=[]
    for row in data:
        k=','.join(row[3:29])
        if k not in seen: seen.add(k); clean.append(row)
    print(f"Unique: {len(clean):,}")

    X, y = extract(clean)
    print(f"Features: {len(X[0])}, Samples: {len(X)}")

    Xtr, Xte, ytr, yte = split(X, y)
    Xtr_s, Xte_s = std(Xtr, Xte)
    print(f"Train: {len(Xtr)}, Test: {len(Xte)}")

    models = [
        ("Random Forest", RF(20, 10), Xtr, ytr, Xte, False),
        ("Decision Tree", Tree(12), Xtr, ytr, Xte, False),
        ("Gradient Boosting", GB(25, 0.1, 6), Xtr, ytr, Xte, False),
        ("AdaBoost", AdaBoost(25), Xtr, ytr, Xte, False),
        ("Logistic Regression", LR(0.01, 100), Xtr_s, ytr, Xte_s, True),
        ("Linear SVM", SVM(0.001, 50), Xtr_s, ytr, Xte_s, True),
        ("MLP Neural Network", MLP(20, 0.01, 20), Xtr_s, ytr, Xte_s, True),
        ("K-Nearest Neighbors", KNN(5), Xtr_s, ytr, Xte_s, True),
    ]

    results = []
    for name, model, Xtn, ytn, Xten, norm in models:
        print(f"\nTraining: {name}...")
        t0=time.time()
        model.fit(Xtn, ytn)
        tt=time.time()-t0
        t1=time.time()
        yp=model.predict(Xten)
        it=(time.time()-t1)*1000
        m=met(yte[:len(yp)], yp)
        m['name']=name; m['train_time']=tt; m['inference_ms']=it
        results.append(m)
        print(f"  Acc:{m['accuracy']:.4f} Prec:{m['precision']:.4f} Rec:{m['recall']:.4f} F1:{m['f1']:.4f} Train:{tt:.1f}s")

    results.sort(key=lambda x: x['f1'], reverse=True)
    best=results[0]

    print("\n"+"="*60)
    print("MODEL COMPARISON")
    print("="*60)
    print(f"{'Model':<25} {'Acc':>8} {'Prec':>8} {'Rec':>8} {'F1':>8} {'Spec':>8}")
    print("-"*65)
    for r in results:
        print(f"{r['name']:<25} {r['accuracy']:>8.4f} {r['precision']:>8.4f} {r['recall']:>8.4f} {r['f1']:>8.4f} {r['specificity']:>8.4f}")

    print(f"\nBEST: {best['name']}")
    print(f"  Accuracy:  {best['accuracy']:.4f} ({best['accuracy']*100:.2f}%)")
    print(f"  Precision: {best['precision']:.4f} ({best['precision']*100:.2f}%)")
    print(f"  Recall:    {best['recall']:.4f} ({best['recall']*100:.2f}%)")
    print(f"  F1-Score:  {best['f1']:.4f} ({best['f1']*100:.2f}%)")
    print(f"  Specificity: {best['specificity']:.4f}")
    print(f"  Confusion: TP={best['tp']}, TN={best['tn']}, FP={best['fp']}, FN={best['fn']}")

    # Save
    outdir=os.path.join(os.path.dirname(__file__), '..', 'results')
    os.makedirs(outdir, exist_ok=True)

    with open(os.path.join(outdir, 'model_comparison.json'), 'w') as f:
        json.dump({'timestamp':datetime.now().isoformat(),'best_model':best['name'],
            'best_metrics':{k:v for k,v in best.items() if k!='name'},
            'all_models':[{k:v for k,v in r.items() if k!='name'} for r in results]}, f, indent=2)

    with open(os.path.join(outdir, 'model_comparison.txt'), 'w') as f:
        f.write("="*60+"\nAEGIS MODEL COMPARISON REPORT\n"+"="*60+"\n\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"Dataset: {len(X):,} samples, {len(X[0])} features\n")
        f.write(f"Train: {len(Xtr):,} | Test: {len(Xte):,}\n\n")
        f.write(f"{'Model':<25} {'Acc':>8} {'Prec':>8} {'Rec':>8} {'F1':>8}\n")
        f.write("-"*57+"\n")
        for r in results:
            f.write(f"{r['name']:<25} {r['accuracy']:>8.4f} {r['precision']:>8.4f} {r['recall']:>8.4f} {r['f1']:>8.4f}\n")
        f.write(f"\n{'='*60}\nBEST MODEL: {best['name']}\n{'='*60}\n")
        f.write(f"Accuracy:  {best['accuracy']:.4f} ({best['accuracy']*100:.2f}%)\n")
        f.write(f"Precision: {best['precision']:.4f} ({best['precision']*100:.2f}%)\n")
        f.write(f"Recall:    {best['recall']:.4f} ({best['recall']*100:.2f}%)\n")
        f.write(f"F1-Score:  {best['f1']:.4f} ({best['f1']*100:.2f}%)\n")
        f.write(f"Specificity: {best['specificity']:.4f}\n")
        f.write(f"Confusion: TP={best['tp']}, TN={best['tn']}, FP={best['fp']}, FN={best['fn']}\n")

    with open(os.path.join(outdir, 'all_models_metrics.csv'), 'w', newline='') as f:
        w=csv.writer(f)
        w.writerow(['Model','Accuracy','Precision','Recall','F1','Specificity','TrainTime_s','Inference_ms'])
        for r in results:
            w.writerow([r['name'],f"{r['accuracy']:.4f}",f"{r['precision']:.4f}",f"{r['recall']:.4f}",f"{r['f1']:.4f}",f"{r['specificity']:.4f}",f"{r['train_time']:.2f}",f"{r['inference_ms']:.2f}"])

    with open(os.path.join(outdir, 'confusion_matrix.csv'), 'w', newline='') as f:
        w=csv.writer(f)
        w.writerow(['','Predicted_Benign','Predicted_Malicious'])
        w.writerow(['Actual_Benign',best['tn'],best['fp']])
        w.writerow(['Actual_Malicious',best['fn'],best['tp']])

    print(f"\nResults saved to: {outdir}")
    print("DONE!")

if __name__=="__main__":
    main()
