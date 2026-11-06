"""
AEGIS ML Training - FINAL FAST VERSION
Uses 5000 samples for instant results
"""
import os, csv, json, time, random, math
from datetime import datetime
from collections import Counter

random.seed(42)

def load(path):
    h,d=[],[]
    with open(path,'r',encoding='utf-8') as f:
        r=csv.reader(f); h=next(r)
        for row in r:
            if len(row)==len(h): d.append(row)
    return h,d

def extract(data):
    sm={'safe':0,'low':1,'medium':2,'high':3,'critical':4}
    X,y=[],[]
    for row in data:
        try:
            f=[float(row[i]) if row[i] else 0.0 for i in range(7,28)]
            f.append(sm.get(row[28],0) if len(row)>28 else 0)
            X.append(f); y.append(int(row[29]))
        except: continue
    return X,y

def split(X,y,ts=0.2):
    idx=list(range(len(X))); random.shuffle(idx)
    s=int(len(X)*(1-ts))
    return [X[i] for i in idx[:s]],[X[i] for i in idx[s:]],[y[i] for i in idx[:s]],[y[i] for i in idx[s:]]

def std(Xt,Xv):
    nf=len(Xt[0])
    m=[sum(r[i] for r in Xt)/len(Xt) for i in range(nf)]
    sd=[max(math.sqrt(sum((r[i]-m[i])**2 for r in Xt)/len(Xt)),1e-8) for i in range(nf)]
    return [[(r[i]-m[i])/sd[i] for i in range(nf)] for r in Xt],[[(r[i]-m[i])/sd[i] for i in range(nf)] for r in Xv]

def met(yt,yp):
    tp=sum(1 for t,p in zip(yt,yp) if t==1 and p==1)
    tn=sum(1 for t,p in zip(yt,yp) if t==0 and p==0)
    fp=sum(1 for t,p in zip(yt,yp) if t==0 and p==1)
    fn=sum(1 for t,p in zip(yt,yp) if t==1 and p==0)
    a=(tp+tn)/(tp+tn+fp+fn)
    pr=tp/(tp+fp) if (tp+fp) else 0
    rc=tp/(tp+fn) if (tp+fn) else 0
    f1=2*pr*rc/(pr+rc) if (pr+rc) else 0
    sp=tn/(tn+fp) if (tn+fp) else 0
    return {'accuracy':a,'precision':pr,'recall':rc,'f1':f1,'specificity':sp,'tp':tp,'tn':tn,'fp':fp,'fn':fn}

class Tree:
    def __init__(s,d=8):s.d=d;s.t=None
    def _g(s,l):
        if not l:return 0
        c=Counter(l);t=len(l)
        return 1-sum((v/t)**2 for v in c.values())
    def _b(s,X,y,d):
        if d>=s.d or len(X)<5 or len(set(y))==1:return{'leaf':1,'p':Counter(y).most_common(1)[0][0]}
        bf,bt,bg=None,None,float('inf')
        for f in random.sample(range(len(X[0])),min(5,len(X[0]))):
            vs=sorted(set(r[f] for r in X))
            for t in vs[::max(1,len(vs)//6)]:
                li=[i for i,r in enumerate(X) if r[f]<=t]
                ri=[i for i,r in enumerate(X) if r[f]>t]
                if len(li)<3 or len(ri)<3:continue
                g=(len(li)*s._g([y[i] for i in li])+len(ri)*s._g([y[i] for i in ri]))/len(X)
                if g<bg:bg,bf,bt=g,f,t
        if bf is None:return{'l':1,'p':Counter(y).most_common(1)[0][0]}
        li=[i for i,r in enumerate(X) if r[bf]<=bt]
        ri=[i for i,r in enumerate(X) if r[bf]>bt]
        return{'f':bf,'t':bt,'l':s._b([X[i] for i in li],[y[i] for i in li],d+1),'r':s._b([X[i] for i in ri],[y[i] for i in ri],d+1)}
    def fit(s,X,y):s.t=s._b(X,y,0)
    def _p(s,x,n):
        if 'leaf' in n or 'p' in n:return n.get('p',0)
        if 'f' not in n:return 0
        try:
            return s._p(x,n['l'] if x[n['f']]<=n['t'] else n['r'])
        except:
            return 0
    def predict(s,X):return[s._p(x,s.t) for x in X]

class RF:
    def __init__(s,n=15,d=10):s.n=n;s.d=d;s.trees=[];s.fi=[]
    def fit(s,X,y):
        nf=len(X[0])
        for _ in range(s.n):
            idx=[random.randint(0,len(X)-1) for _ in range(len(X))]
            fi=random.sample(range(nf),max(1,int(math.sqrt(nf))));s.fi.append(fi)
            t=Tree(s.d);t.fit([[X[i][f] for f in fi] for i in idx],[y[i] for i in idx]);s.trees.append(t)
    def predict(s,X):
        ps=[t.predict([[x[f] for f in fi] for x in X]) for t,fi in zip(s.trees,s.fi)]
        return[Counter(p).most_common(1)[0][0] for p in zip(*ps)]

class GB:
    def __init__(s,n=20,lr=0.1,d=5):s.n=n;s.lr=lr;s.d=d;s.trees=[];s.init=0
    def fit(s,X,y):
        s.init=sum(y)/len(y);p=[s.init]*len(y)
        for _ in range(s.n):
            r=[y[i]-p[i] for i in range(len(y))]
            t=Tree(s.d);t.fit(X,[1 if v>0 else 0 for v in r]);s.trees.append(t)
            tp=t.predict(X);p=[p[i]+s.lr*(tp[i]-0.5) for i in range(len(p))]
    def predict(s,X):
        p=[s.init]*len(X)
        for t in s.trees:tp=t.predict(X);p=[p[i]+s.lr*(tp[i]-0.5) for i in range(len(p))]
        return[1 if v>=0.5 else 0 for v in p]

class Stump:
    def __init__(s):s.f=s.t=0;s.a=1;s.d=1
    def fit(s,X,y,w):
        be,bf,bt,bd=1,0,0,1
        for f in range(len(X[0])):
            vs=sorted(set(r[f] for r in X))
            for t in vs[::max(1,len(vs)//8)]:
                for d in [1,-1]:
                    pr=[d if r[f]>t else -d for r in X]
                    e=sum(w[i] for i in range(len(y)) if (pr[i]==1)!=(y[i]==1))
                    if e<be:be,bf,bt,bd=e,f,t,d
        s.f,s.t,s.d=bf,bt,bd;return be

class Ada:
    def __init__(s,n=20):s.n=n;s.ss=[]
    def fit(s,X,y):
        n=len(X);w=[1.0/n]*n
        for _ in range(s.n):
            st=Stump();e=st.fit(X,y,w);e=max(e,1e-10);a=0.5*math.log((1-e)/e);st.a=a;s.ss.append(st)
            pr=[st.d if r[st.f]>st.t else -st.d for r in X]
            w=[w[i]*math.exp(a*(-1 if pr[i]==y[i] else 1)) for i in range(n)];t=sum(w);w=[wi/t for wi in w]
    def predict(s,X):return[1 if sum(st.a*(st.d if x[st.f]>st.t else -st.d) for st in s.ss)>=0 else 0 for x in X]

class LR:
    def __init__(s,lr=0.1,it=200):s.lr=lr;s.it=it;s.w=[];s.b=0
    def _s(s,z):return 1/(1+math.exp(max(-500,min(500,z))))
    def fit(s,X,y):
        n,nf=len(X),len(X[0]);s.w=[0.0]*nf
        for _ in range(s.it):
            for i in range(n):
                z=sum(w*x for w,x in zip(s.w,X[i]))+s.b;e=s._s(z)-y[i]
                s.w=[w-s.lr*e*x for w,x in zip(s.w,X[i])];s.b-=s.lr*e
    def predict(s,X):return[1 if s._s(sum(w*x for w,x in zip(s.w,x))+s.b)>=0.5 else 0 for x in X]

class SVM:
    def __init__(s,lr=0.01,it=100):s.lr=lr;s.it=it;s.w=[];s.b=0
    def fit(s,X,y):
        n,nf=len(X),len(X[0]);s.w=[0.0]*nf;yb=[1 if v==1 else -1 for v in y]
        for _ in range(s.it):
            for i in range(n):
                c=yb[i]*(sum(w*x for w,x in zip(s.w,X[i]))+s.b)
                if c<1:s.w=[w+s.lr*(yb[i]*x-0.01*w) for w,x in zip(s.w,X[i])];s.b+=s.lr*yb[i]
    def predict(s,X):return[1 if sum(w*x for w,x in zip(s.w,x))+s.b>=0 else 0 for x in X]

class MLP:
    def __init__(s,h=16,lr=0.1,it=30):s.h=h;s.lr=lr;s.it=it
    def _s(s,z):return 1/(1+math.exp(max(-500,min(500,z))))
    def fit(s,X,y):
        n,nf=len(X),len(X[0])
        s.W1=[[random.gauss(0,0.1) for _ in range(s.h)] for _ in range(nf)]
        s.b1=[0.0]*s.h;s.W2=[random.gauss(0,0.1) for _ in range(s.h)];s.b2=0
        for _ in range(s.it):
            for i in range(n):
                h=[s._s(sum(X[i][k]*s.W1[k][j] for k in range(nf))+s.b1[j]) for j in range(s.h)]
                o=s._s(sum(h[j]*s.W2[j] for j in range(s.h))+s.b2);eo=o-y[i]
                for j in range(s.h):
                    eh=eo*s.W2[j]*h[j]*(1-h[j])
                    s.W1[j]=[w-s.lr*eh*X[i][k] for k,w in enumerate(s.W1[j])];s.b1[j]-=s.lr*eh;s.W2[j]-=s.lr*eo*h[j]
                s.b2-=s.lr*eo
    def predict(s,X):
        return[1 if s._s(sum(s._s(sum(x[k]*s.W1[k][j] for k in range(len(x)))+s.b1[j])*s.W2[j] for j in range(s.h))+s.b2)>=0.5 else 0 for x in X]

class KNN:
    def __init__(s,k=5):s.k=k;s.Xt=[];s.yt=[]
    def fit(s,X,y):s.Xt=X[:1000];s.yt=y[:1000]
    def predict(s,X):
        return[Counter([yt for _,yt in sorted([(sum((a-b)**2 for a,b in zip(x,xt)),yt) for xt,yt in zip(s.Xt,s.yt)])[:s.k]]).most_common(1)[0][0] for x in X[:1000]]

print("="*60)
print("AEGIS ML TRAINING - FINAL")
print("="*60)

path=os.path.join(os.path.dirname(__file__),'..','dataset','aegis_dataset.csv')
h,data=load(path)
print(f"Loaded: {len(data):,} rows")

seen=set();clean=[]
for row in data:
    k=','.join(row[3:29])
    if k not in seen:seen.add(k);clean.append(row)
print(f"Unique: {len(clean):,}")

X,y=extract(clean)
print(f"Features: {len(X[0])}, Samples: {len(X)}")

# Use only 5000 samples for speed
X=X[:5000];y=y[:5000]
print(f"Using: {len(X)} samples (for speed)")

Xtr,Xte,ytr,yte=split(X,y)
Xtr_s,Xte_s=std(Xtr,Xte)
print(f"Train: {len(Xtr)}, Test: {len(Xte)}")

models=[
    ("Random Forest",RF(15,10),Xtr,ytr,Xte),
    ("Decision Tree",Tree(12),Xtr,ytr,Xte),
    ("Gradient Boosting",GB(20,0.1,6),Xtr,ytr,Xte),
    ("AdaBoost",Ada(20),Xtr,ytr,Xte),
    ("Logistic Regression",LR(0.1,200),Xtr_s,ytr,Xte_s),
    ("Linear SVM",SVM(0.01,100),Xtr_s,ytr,Xte_s),
    ("MLP Neural Network",MLP(16,0.1,30),Xtr_s,ytr,Xte_s),
    ("K-Nearest Neighbors",KNN(5),Xtr_s,ytr,Xte_s),
]

results=[]
for name,model,Xtn,ytn,Xten in models:
    print(f"\nTraining: {name}...")
    t0=time.time()
    model.fit(Xtn,ytn)
    tt=time.time()-t0
    t1=time.time()
    yp=model.predict(Xten)
    it=(time.time()-t1)*1000
    m=met(yte[:len(yp)],yp)
    m['name']=name;m['train_time']=tt;m['inference_ms']=it
    results.append(m)
    print(f"  Acc:{m['accuracy']:.4f} Prec:{m['precision']:.4f} Rec:{m['recall']:.4f} F1:{m['f1']:.4f} Time:{tt:.1f}s")

results.sort(key=lambda x:x['f1'],reverse=True)
best=results[0]

print("\n"+"="*60)
print("MODEL COMPARISON RESULTS")
print("="*60)
print(f"{'Model':<25} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'Specificity':>12}")
print("-"*77)
for r in results:
    print(f"{r['name']:<25} {r['accuracy']:>10.4f} {r['precision']:>10.4f} {r['recall']:>10.4f} {r['f1']:>10.4f} {r['specificity']:>12.4f}")

print("\n"+"="*60)
print(f"BEST MODEL: {best['name']}")
print("="*60)
print(f"""
  Accuracy:     {best['accuracy']:.4f}  ({best['accuracy']*100:.2f}%)
  Precision:    {best['precision']:.4f}  ({best['precision']*100:.2f}%)
  Recall:       {best['recall']:.4f}  ({best['recall']*100:.2f}%)
  F1-Score:     {best['f1']:.4f}  ({best['f1']*100:.2f}%)
  Specificity:  {best['specificity']:.4f}  ({best['specificity']*100:.2f}%)

  Confusion Matrix:
    True Positives:  {best['tp']}
    True Negatives:  {best['tn']}
    False Positives: {best['fp']}
    False Negatives: {best['fn']}

  Training Time:    {best['train_time']:.2f}s
  Inference Time:   {best['inference_ms']:.2f}ms
""")

outdir=os.path.join(os.path.dirname(__file__),'..','results')
os.makedirs(outdir,exist_ok=True)

with open(os.path.join(outdir,'model_comparison.json'),'w') as f:
    json.dump({'timestamp':datetime.now().isoformat(),'dataset_samples':5000,'features':22,
        'best_model':best['name'],
        'best_metrics':{k:v for k,v in best.items() if k!='name'},
        'all_models':[{k:v for k,v in r.items() if k!='name'} for r in results]},f,indent=2)

with open(os.path.join(outdir,'model_comparison.txt'),'w') as f:
    f.write("="*60+"\nAEGIS MODEL COMPARISON REPORT\n"+"="*60+"\n\n")
    f.write(f"Generated: {datetime.now().isoformat()}\nDataset: 5,000 samples, 22 features\n\n")
    f.write(f"{'Model':<25} {'Acc':>8} {'Prec':>8} {'Rec':>8} {'F1':>8}\n"+"-"*57+"\n")
    for r in results:
        f.write(f"{r['name']:<25} {r['accuracy']:>8.4f} {r['precision']:>8.4f} {r['recall']:>8.4f} {r['f1']:>8.4f}\n")
    f.write(f"\nBEST: {best['name']}\nAccuracy: {best['accuracy']:.4f}\nPrecision: {best['precision']:.4f}\nRecall: {best['recall']:.4f}\nF1: {best['f1']:.4f}\n")

with open(os.path.join(outdir,'all_models_metrics.csv'),'w',newline='') as f:
    w=csv.writer(f)
    w.writerow(['Model','Accuracy','Precision','Recall','F1','Specificity','TrainTime_s','Inference_ms'])
    for r in results:
        w.writerow([r['name'],f"{r['accuracy']:.4f}",f"{r['precision']:.4f}",f"{r['recall']:.4f}",f"{r['f1']:.4f}",f"{r['specificity']:.4f}",f"{r['train_time']:.2f}",f"{r['inference_ms']:.2f}"])

with open(os.path.join(outdir,'confusion_matrix.csv'),'w',newline='') as f:
    w=csv.writer(f)
    w.writerow(['','Predicted_Benign','Predicted_Malicious'])
    w.writerow(['Actual_Benign',best['tn'],best['fp']])
    w.writerow(['Actual_Malicious',best['fn'],best['tp']])

print(f"Results saved to: {outdir}")
print("="*60)
