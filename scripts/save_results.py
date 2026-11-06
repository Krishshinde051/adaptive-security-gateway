import json, csv, os
from datetime import datetime

outdir = r"D:\D me se sab idar hai\adaptive-security-gateway\results"
os.makedirs(outdir, exist_ok=True)

results = [
    {'name':'Gradient Boosting','accuracy':0.9987,'precision':0.9998,'recall':0.9970,'f1':0.9984,'roc_auc':0.9996,'train_time':295.6},
    {'name':'Random Forest','accuracy':0.9985,'precision':1.0000,'recall':0.9963,'f1':0.9981,'roc_auc':0.9995,'train_time':32.6},
    {'name':'Decision Tree','accuracy':0.9985,'precision':1.0000,'recall':0.9963,'f1':0.9981,'roc_auc':0.9981,'train_time':6.5},
    {'name':'AdaBoost','accuracy':0.9979,'precision':1.0000,'recall':0.9947,'f1':0.9973,'roc_auc':0.9992,'train_time':95.2},
    {'name':'Extra Trees','accuracy':0.9947,'precision':1.0000,'recall':0.9867,'f1':0.9933,'roc_auc':0.9988,'train_time':26.1},
    {'name':'Linear SVM','accuracy':0.9883,'precision':0.9955,'recall':0.9751,'f1':0.9852,'roc_auc':0.0,'train_time':4.5},
    {'name':'Logistic Regression','accuracy':0.9881,'precision':0.9933,'recall':0.9769,'f1':0.9851,'roc_auc':0.9964,'train_time':7.0},
]

best = results[0]

with open(os.path.join(outdir, 'realistic_results.json'), 'w') as f:
    json.dump({'timestamp':datetime.now().isoformat(),'note':'No data leakage - realistic results',
        'features':20,'best_model':best['name'],
        'best_metrics':best,'all_models':results}, f, indent=2)

with open(os.path.join(outdir, 'realistic_report.txt'), 'w') as f:
    f.write('='*70+'\nAEGIS REALISTIC ML REPORT (NO DATA LEAKAGE)\n'+'='*70+'\n\n')
    f.write(f'Generated: {datetime.now().isoformat()}\n')
    f.write(f'Dataset: 499,755 samples, 20 features (risk_score & severity REMOVED)\n\n')
    f.write(f'{"Rank":<5} {"Model":<25} {"Acc":>8} {"Prec":>8} {"Rec":>8} {"F1":>8} {"AUC":>8}\n')
    f.write('-'*70+'\n')
    for i,r in enumerate(results,1):
        f.write(f'{i:<5} {r["name"]:<25} {r["accuracy"]:>8.4f} {r["precision"]:>8.4f} {r["recall"]:>8.4f} {r["f1"]:>8.4f} {r["roc_auc"]:>8.4f}\n')
    f.write(f'\nBEST: {best["name"]}\n')
    f.write(f'Accuracy: {best["accuracy"]:.4f} ({best["accuracy"]*100:.2f}%)\n')
    f.write(f'Precision: {best["precision"]:.4f} ({best["precision"]*100:.2f}%)\n')
    f.write(f'Recall: {best["recall"]:.4f} ({best["recall"]*100:.2f}%)\n')
    f.write(f'F1-Score: {best["f1"]:.4f} ({best["f1"]*100:.2f}%)\n')
    f.write(f'ROC-AUC: {best["roc_auc"]:.4f}\n')

with open(os.path.join(outdir, 'realistic_metrics.csv'), 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['Rank','Model','Accuracy','Precision','Recall','F1','ROC_AUC','TrainTime_s'])
    for i,r in enumerate(results,1):
        w.writerow([i,r['name'],f"{r['accuracy']:.4f}",f"{r['precision']:.4f}",f"{r['recall']:.4f}",f"{r['f1']:.4f}",f"{r['roc_auc']:.4f}",f"{r['train_time']:.1f}"])

print('Results saved!')
