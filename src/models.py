# src/models.py
# Phase 3 — Train 7 ML Models
# Goal: Train, evaluate, and save all 7 threat detection models
# Author: Harshal

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.multiclass import OneVsRestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix,
    f1_score, precision_score, recall_score, accuracy_score
)
from xgboost import XGBClassifier
import joblib
import os
import time
import warnings
warnings.filterwarnings('ignore')

# ── Config ───────────────────────────────────────────────────────────────────
PROCESSED_PATH = 'data/processed/'
MODELS_PATH    = 'models/'
PLOTS_PATH     = 'data/processed/'

os.makedirs(MODELS_PATH, exist_ok=True)

# Category → numeric label mapping (from label_encoder.joblib)
# 0=Benign, 1=C2_Botnet, 2=DDoS, 3=Exfiltration,
# 4=LateralMovement, 5=Reconnaissance, 6=WebAttack
CLASS_NAMES = ['Benign', 'C2_Botnet', 'DDoS', 'Exfiltration',
               'LateralMovement', 'Reconnaissance', 'WebAttack']

# ── Load train/test data ──────────────────────────────────────────────────────
print("=" * 60)
print("  Phase 3 — Training 7 ML Models")
print("=" * 60)

print("\n[LOAD] Reading train/test data...")
X_train = pd.read_csv(PROCESSED_PATH + 'X_train.csv')
X_test  = pd.read_csv(PROCESSED_PATH + 'X_test.csv')
y_train = pd.read_csv(PROCESSED_PATH + 'y_train.csv').squeeze()
y_test  = pd.read_csv(PROCESSED_PATH + 'y_test.csv').squeeze()

print(f"       X_train : {X_train.shape[0]:,} rows × {X_train.shape[1]} features")
print(f"       X_test  : {X_test.shape[0]:,} rows × {X_test.shape[1]} features")
print(f"       Classes : {sorted(y_train.unique())}")

# ── Helper functions ──────────────────────────────────────────────────────────

def evaluate_model(model, X_test, y_test, model_name, class_names):
    """Evaluate model and return metrics dict."""
    y_pred = model.predict(X_test)

    report = classification_report(
        y_test, y_pred,
        target_names=class_names,
        output_dict=True,
        zero_division=0
    )

    acc = accuracy_score(y_test, y_pred)
    f1  = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    cm  = confusion_matrix(y_test, y_pred)

    print(f"\n       📊 {model_name} Results:")
    print(f"          Overall Accuracy : {acc:.4f} ({acc*100:.2f}%)")
    print(f"          Weighted F1      : {f1:.4f}")
    print(f"\n       Per-class breakdown:")
    print(f"          {'Class':<20} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    print(f"          {'-'*60}")
    for cls in class_names:
        if cls in report:
            p  = report[cls]['precision']
            r  = report[cls]['recall']
            f  = report[cls]['f1-score']
            s  = int(report[cls]['support'])
            flag = " ⚠️" if f < 0.70 else " ✅"
            print(f"          {cls:<20} {p:>10.4f} {r:>10.4f} {f:>10.4f} {s:>10,}{flag}")

    return {
        'name':     model_name,
        'accuracy': acc,
        'f1':       f1,
        'report':   report,
        'cm':       cm,
        'y_pred':   y_pred,
    }


def save_model(model, filename, model_name):
    """Save model to disk."""
    path = MODELS_PATH + filename
    joblib.dump(model, path)
    size_mb = os.path.getsize(path) / 1024**2
    print(f"       💾 Saved: {path} ({size_mb:.1f} MB)")


def plot_confusion_matrix(cm, class_names, title, ax):
    """Plot a single confusion matrix on given axis."""
    cm_pct = cm.astype(float) / (cm.sum(axis=1, keepdims=True) + 1e-9)
    sns.heatmap(
        cm_pct, annot=True, fmt='.2f', cmap='Blues',
        xticklabels=class_names, yticklabels=class_names,
        ax=ax, linewidths=0.3, vmin=0, vmax=1,
        annot_kws={'size': 7}
    )
    ax.set_title(title, color='white', fontsize=9, fontweight='bold')
    ax.set_xlabel('Predicted', fontsize=7, color='#aaa')
    ax.set_ylabel('Actual', fontsize=7, color='#aaa')
    ax.tick_params(colors='white', labelsize=6)
    ax.set_facecolor('#111')


# ── Storage for all results ───────────────────────────────────────────────────
all_results = []

# ════════════════════════════════════════════════════════
# MODEL 1 — DDoS / DoS Detection (Random Forest)
# Why Random Forest: High volume, clear patterns, fast
# ════════════════════════════════════════════════════════
print("\n" + "─" * 60)
print("  MODEL 1 — DDoS/DoS Detection (Random Forest)")
print("─" * 60)
print("  Target classes: DDoS vs everything else")
print("  Why: DDoS has clear high-rate, high-volume patterns")

# Binary: DDoS=1, everything else=0
y_train_ddos = (y_train == CLASS_NAMES.index('DDoS')).astype(int)
y_test_ddos  = (y_test  == CLASS_NAMES.index('DDoS')).astype(int)

t0 = time.time()
model_ddos = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    class_weight='balanced',   # second layer of imbalance protection
    n_jobs=-1,                 # use all CPU cores
    random_state=42
)
model_ddos.fit(X_train, y_train_ddos)
print(f"\n       ⏱️  Training time: {time.time()-t0:.1f}s")

y_pred_ddos = model_ddos.predict(X_test)
acc_ddos = accuracy_score(y_test_ddos, y_pred_ddos)
f1_ddos  = f1_score(y_test_ddos, y_pred_ddos, zero_division=0)
print(f"       ✅ Accuracy: {acc_ddos:.4f} | F1: {f1_ddos:.4f}")
print(f"       {classification_report(y_test_ddos, y_pred_ddos, target_names=['Not-DDoS','DDoS'], zero_division=0)}")

save_model(model_ddos, 'model_ddos.joblib', 'DDoS Detector')

# Feature importance for DDoS
ddos_importances = pd.Series(
    model_ddos.feature_importances_,
    index=X_train.columns
).sort_values(ascending=False).head(10)
print("       Top 10 features for DDoS detection:")
for feat, imp in ddos_importances.items():
    bar = '█' * int(imp * 100)
    print(f"         {feat:<25} {imp:.4f}  {bar}")

# ════════════════════════════════════════════════════════
# MODEL 2 — Reconnaissance Detection (Random Forest)
# Why: Sequential scan patterns are supervised-learnable
# ════════════════════════════════════════════════════════
print("\n" + "─" * 60)
print("  MODEL 2 — Reconnaissance Detection (Random Forest)")
print("─" * 60)

y_train_recon = (y_train == CLASS_NAMES.index('Reconnaissance')).astype(int)
y_test_recon  = (y_test  == CLASS_NAMES.index('Reconnaissance')).astype(int)

t0 = time.time()
model_recon = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    class_weight='balanced',
    n_jobs=-1,
    random_state=42
)
model_recon.fit(X_train, y_train_recon)
print(f"\n       ⏱️  Training time: {time.time()-t0:.1f}s")

y_pred_recon = model_recon.predict(X_test)
acc_recon = accuracy_score(y_test_recon, y_pred_recon)
f1_recon  = f1_score(y_test_recon, y_pred_recon, zero_division=0)
print(f"       ✅ Accuracy: {acc_recon:.4f} | F1: {f1_recon:.4f}")
print(f"       {classification_report(y_test_recon, y_pred_recon, target_names=['Not-Recon','Recon'], zero_division=0)}")

save_model(model_recon, 'model_recon.joblib', 'Recon Detector')

# ════════════════════════════════════════════════════════
# MODEL 3 — C2 / Botnet Detection (Isolation Forest)
# Why: Botnet beaconing is subtle anomaly — unsupervised works well
# ════════════════════════════════════════════════════════
print("\n" + "─" * 60)
print("  MODEL 3 — C2/Botnet Detection (Isolation Forest)")
print("─" * 60)
print("  Strategy: Train on Benign only, anomaly = C2")
print("  Why: Beaconing patterns are hard to label but easy to spot as anomaly")

# Isolation Forest: train on benign only
X_train_benign = X_train[y_train == CLASS_NAMES.index('Benign')]
print(f"\n       Training on {len(X_train_benign):,} benign rows...")

t0 = time.time()
model_c2 = IsolationForest(
    n_estimators=100,
    contamination=0.05,   # expect ~5% anomalies
    n_jobs=-1,
    random_state=42
)
model_c2.fit(X_train_benign)
print(f"       ⏱️  Training time: {time.time()-t0:.1f}s")

# Predict: -1=anomaly(C2), 1=normal
y_pred_c2_raw = model_c2.predict(X_test)
# Convert: -1 → 1 (C2 detected), 1 → 0 (benign)
y_pred_c2 = (y_pred_c2_raw == -1).astype(int)
y_test_c2 = (y_test == CLASS_NAMES.index('C2_Botnet')).astype(int)

acc_c2 = accuracy_score(y_test_c2, y_pred_c2)
f1_c2  = f1_score(y_test_c2, y_pred_c2, zero_division=0)
print(f"       ✅ Accuracy: {acc_c2:.4f} | F1: {f1_c2:.4f}")
print(f"       {classification_report(y_test_c2, y_pred_c2, target_names=['Normal','C2_Botnet'], zero_division=0)}")

save_model(model_c2, 'model_c2.joblib', 'C2/Botnet Detector')

# ════════════════════════════════════════════════════════
# MODEL 4 — Lateral Movement Detection (Random Forest)
# Why: ARP spoofing + browser hijacking have distinct flag patterns
# ════════════════════════════════════════════════════════
print("\n" + "─" * 60)
print("  MODEL 4 — Lateral Movement Detection (Random Forest)")
print("─" * 60)

y_train_lat = (y_train == CLASS_NAMES.index('LateralMovement')).astype(int)
y_test_lat  = (y_test  == CLASS_NAMES.index('LateralMovement')).astype(int)

t0 = time.time()
model_lateral = RandomForestClassifier(
    n_estimators=150,      # more trees for subtle patterns
    max_depth=20,
    class_weight='balanced',
    n_jobs=-1,
    random_state=42
)
model_lateral.fit(X_train, y_train_lat)
print(f"\n       ⏱️  Training time: {time.time()-t0:.1f}s")

y_pred_lat = model_lateral.predict(X_test)
acc_lat = accuracy_score(y_test_lat, y_pred_lat)
f1_lat  = f1_score(y_test_lat, y_pred_lat, zero_division=0)
print(f"       ✅ Accuracy: {acc_lat:.4f} | F1: {f1_lat:.4f}")
print(f"       {classification_report(y_test_lat, y_pred_lat, target_names=['Not-Lateral','LateralMovement'], zero_division=0)}")

save_model(model_lateral, 'model_lateral.joblib', 'Lateral Movement Detector')

# ════════════════════════════════════════════════════════
# MODEL 5 — Exfiltration Detection (XGBoost)
# Why: Rare events need gradient boosting precision
# ════════════════════════════════════════════════════════
print("\n" + "─" * 60)
print("  MODEL 5 — Exfiltration Detection (XGBoost)")
print("─" * 60)

y_train_exfil = (y_train == CLASS_NAMES.index('Exfiltration')).astype(int)
y_test_exfil  = (y_test  == CLASS_NAMES.index('Exfiltration')).astype(int)

# Calculate scale_pos_weight for XGBoost imbalance handling
neg = (y_train_exfil == 0).sum()
pos = (y_train_exfil == 1).sum()
scale_pw = neg / pos if pos > 0 else 1
print(f"\n       scale_pos_weight: {scale_pw:.2f} (handles remaining imbalance)")

t0 = time.time()
model_exfil = XGBClassifier(
    n_estimators=200,
    max_depth=8,
    learning_rate=0.1,
    scale_pos_weight=scale_pw,
    use_label_encoder=False,
    eval_metric='logloss',
    n_jobs=-1,
    random_state=42,
    verbosity=0
)
model_exfil.fit(X_train, y_train_exfil)
print(f"       ⏱️  Training time: {time.time()-t0:.1f}s")

y_pred_exfil = model_exfil.predict(X_test)
acc_exfil = accuracy_score(y_test_exfil, y_pred_exfil)
f1_exfil  = f1_score(y_test_exfil, y_pred_exfil, zero_division=0)
print(f"       ✅ Accuracy: {acc_exfil:.4f} | F1: {f1_exfil:.4f}")
print(f"       {classification_report(y_test_exfil, y_pred_exfil, target_names=['Not-Exfil','Exfiltration'], zero_division=0)}")

save_model(model_exfil, 'model_exfil.joblib', 'Exfiltration Detector')

# ════════════════════════════════════════════════════════
# MODEL 6 — Web Attack Detection (XGBoost)
# Why: SQLi/XSS/CMDi have subtle feature patterns — needs boosting
# ════════════════════════════════════════════════════════
print("\n" + "─" * 60)
print("  MODEL 6 — Web Attack Detection (XGBoost)")
print("─" * 60)

y_train_web = (y_train == CLASS_NAMES.index('WebAttack')).astype(int)
y_test_web  = (y_test  == CLASS_NAMES.index('WebAttack')).astype(int)

neg_w = (y_train_web == 0).sum()
pos_w = (y_train_web == 1).sum()
scale_pw_web = neg_w / pos_w if pos_w > 0 else 1
print(f"\n       scale_pos_weight: {scale_pw_web:.2f}")

t0 = time.time()
model_web = XGBClassifier(
    n_estimators=200,
    max_depth=8,
    learning_rate=0.1,
    scale_pos_weight=scale_pw_web,
    use_label_encoder=False,
    eval_metric='logloss',
    n_jobs=-1,
    random_state=42,
    verbosity=0
)
model_web.fit(X_train, y_train_web)
print(f"       ⏱️  Training time: {time.time()-t0:.1f}s")

y_pred_web = model_web.predict(X_test)
acc_web = accuracy_score(y_test_web, y_pred_web)
f1_web  = f1_score(y_test_web, y_pred_web, zero_division=0)
print(f"       ✅ Accuracy: {acc_web:.4f} | F1: {f1_web:.4f}")
print(f"       {classification_report(y_test_web, y_pred_web, target_names=['Not-Web','WebAttack'], zero_division=0)}")

save_model(model_web, 'model_web.joblib', 'Web Attack Detector')

# ════════════════════════════════════════════════════════
# MODEL 7 — Malware / Intrusion Detection (Isolation Forest)
# Why: Backdoor persistence is rare anomaly — unsupervised fits
# ════════════════════════════════════════════════════════
print("\n" + "─" * 60)
print("  MODEL 7 — Malware/Intrusion Detection (Isolation Forest)")
print("─" * 60)
print("  Strategy: Train on Benign only, flag anomalies as malware")

t0 = time.time()
model_malware = IsolationForest(
    n_estimators=150,
    contamination=0.02,   # backdoors are rarer than C2
    n_jobs=-1,
    random_state=42
)
model_malware.fit(X_train_benign)
print(f"\n       ⏱️  Training time: {time.time()-t0:.1f}s")

y_pred_mal_raw = model_malware.predict(X_test)
y_pred_mal = (y_pred_mal_raw == -1).astype(int)
# For evaluation: treat C2_Botnet as the proxy for malware
y_test_mal = (y_test == CLASS_NAMES.index('C2_Botnet')).astype(int)

acc_mal = accuracy_score(y_test_mal, y_pred_mal)
f1_mal  = f1_score(y_test_mal, y_pred_mal, zero_division=0)
print(f"       ✅ Accuracy: {acc_mal:.4f} | F1: {f1_mal:.4f}")
print(f"       {classification_report(y_test_mal, y_pred_mal, target_names=['Normal','Malware'], zero_division=0)}")

save_model(model_malware, 'model_malware.joblib', 'Malware Detector')

# ════════════════════════════════════════════════════════
# MASTER MODEL — Multi-class classifier (all 7 categories)
# This is used by the dashboard for full classification
# ════════════════════════════════════════════════════════
print("\n" + "─" * 60)
print("  MASTER MODEL — Full 7-class Classifier (Random Forest)")
print("─" * 60)
print("  This model classifies into all 7 categories at once")
print("  Used by dashboard for quick full-scan")

t0 = time.time()
model_master = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    class_weight='balanced',
    n_jobs=-1,
    random_state=42
)
model_master.fit(X_train, y_train)
print(f"\n       ⏱️  Training time: {time.time()-t0:.1f}s")

results_master = evaluate_model(
    model_master, X_test, y_test,
    'Master 7-class Classifier', CLASS_NAMES
)
all_results.append(results_master)
save_model(model_master, 'model_master.joblib', 'Master Classifier')

# ── Summary Table ─────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("  ALL MODELS SUMMARY")
print("=" * 60)
print(f"\n  {'Model':<30} {'Accuracy':>10} {'F1 Score':>10} {'Status':>10}")
print(f"  {'-'*60}")

models_summary = [
    ('Model 1 — DDoS Detector',      acc_ddos,   f1_ddos),
    ('Model 2 — Recon Detector',      acc_recon,  f1_recon),
    ('Model 3 — C2/Botnet Detector',  acc_c2,     f1_c2),
    ('Model 4 — Lateral Movement',    acc_lat,    f1_lat),
    ('Model 5 — Exfiltration',        acc_exfil,  f1_exfil),
    ('Model 6 — Web Attack',          acc_web,    f1_web),
    ('Model 7 — Malware',             acc_mal,    f1_mal),
    ('Master — 7-class',              results_master['accuracy'],
                                      results_master['f1']),
]

for name, acc, f1 in models_summary:
    status = '✅ Good' if f1 >= 0.75 else ('⚠️  OK' if f1 >= 0.60 else '❌ Needs work')
    print(f"  {name:<30} {acc:>10.4f} {f1:>10.4f} {status:>10}")

# ── Visualizations ────────────────────────────────────────────────────────────
print("\n[PLOTS] Generating model evaluation plots...")
plt.style.use('dark_background')

# ── Plot 1: Model comparison bar chart
fig, axes = plt.subplots(1, 2, figsize=(14, 5))
fig.patch.set_facecolor('#0a0a0a')
fig.suptitle('Phase 3 — Model Performance Summary',
             fontsize=13, color='white', fontweight='bold')

model_names_short = ['DDoS', 'Recon', 'C2', 'Lateral', 'Exfil', 'Web', 'Malware', 'Master']
accs = [m[1] for m in models_summary]
f1s  = [m[2] for m in models_summary]
colors = ['#ff4444','#ff8800','#ff44ff','#ffff00','#4488ff','#44ffff','#ff88ff','#00ff88']

ax1 = axes[0]
ax1.set_facecolor('#111')
bars = ax1.bar(model_names_short, accs, color=colors, edgecolor='#333')
ax1.axhline(y=0.75, color='white', linestyle='--', linewidth=1, alpha=0.5, label='0.75 threshold')
ax1.set_title('Accuracy per Model', color='white')
ax1.set_ylabel('Accuracy', color='white')
ax1.set_ylim(0, 1.1)
ax1.tick_params(colors='white', labelsize=8)
ax1.legend(fontsize=7)
for bar, val in zip(bars, accs):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
             f'{val:.3f}', ha='center', fontsize=7, color='white')

ax2 = axes[1]
ax2.set_facecolor('#111')
bars2 = ax2.bar(model_names_short, f1s, color=colors, edgecolor='#333')
ax2.axhline(y=0.75, color='white', linestyle='--', linewidth=1, alpha=0.5, label='0.75 threshold')
ax2.set_title('F1 Score per Model', color='white')
ax2.set_ylabel('F1 Score', color='white')
ax2.set_ylim(0, 1.1)
ax2.tick_params(colors='white', labelsize=8)
ax2.legend(fontsize=7)
for bar, val in zip(bars2, f1s):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
             f'{val:.3f}', ha='center', fontsize=7, color='white')

plt.tight_layout()
plt.savefig(PLOTS_PATH + 'plot_05_model_performance.png',
            dpi=150, bbox_inches='tight', facecolor='#0a0a0a')
plt.show()
print("       Saved: plot_05_model_performance.png")

# ── Plot 2: Master model confusion matrix
fig, ax = plt.subplots(figsize=(10, 8))
fig.patch.set_facecolor('#0a0a0a')
ax.set_facecolor('#111')
cm = results_master['cm']
cm_pct = cm.astype(float) / (cm.sum(axis=1, keepdims=True) + 1e-9)
sns.heatmap(
    cm_pct, annot=True, fmt='.2f', cmap='Blues',
    xticklabels=CLASS_NAMES, yticklabels=CLASS_NAMES,
    ax=ax, linewidths=0.5, vmin=0, vmax=1,
    annot_kws={'size': 9}
)
ax.set_title('Master Model — Confusion Matrix (row-normalized)',
             color='white', fontsize=12, fontweight='bold', pad=15)
ax.set_xlabel('Predicted Label', color='white', fontsize=10)
ax.set_ylabel('True Label', color='white', fontsize=10)
ax.tick_params(colors='white', labelsize=9)
plt.xticks(rotation=30, ha='right')
plt.tight_layout()
plt.savefig(PLOTS_PATH + 'plot_06_confusion_matrix.png',
            dpi=150, bbox_inches='tight', facecolor='#0a0a0a')
plt.show()
print("       Saved: plot_06_confusion_matrix.png")

# ── Plot 3: Feature importance from master model
fig, ax = plt.subplots(figsize=(10, 7))
fig.patch.set_facecolor('#0a0a0a')
ax.set_facecolor('#111')
importances = pd.Series(
    model_master.feature_importances_,
    index=X_train.columns
).sort_values(ascending=True).tail(20)
colors_imp = ['#4488ff'] * len(importances)
colors_imp[-1] = '#00ff88'   # top feature highlighted
ax.barh(importances.index, importances.values, color=colors_imp)
ax.set_title('Top 20 Feature Importances (Master Model)',
             color='white', fontsize=12, fontweight='bold')
ax.set_xlabel('Importance Score', color='white')
ax.tick_params(colors='white', labelsize=9)
for spine in ax.spines.values():
    spine.set_edgecolor('#333')
plt.tight_layout()
plt.savefig(PLOTS_PATH + 'plot_07_feature_importance.png',
            dpi=150, bbox_inches='tight', facecolor='#0a0a0a')
plt.show()
print("       Saved: plot_07_feature_importance.png")

# ── List saved models ──────────────────────────────────────────────────────────
print("\n[FILES] All saved models:")
for f in sorted(os.listdir(MODELS_PATH)):
    size = os.path.getsize(MODELS_PATH + f) / 1024**2
    print(f"        {f:<35} {size:.1f} MB")

# ── Final summary ──────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("  PHASE 3 COMPLETE — ALL 7 MODELS TRAINED & SAVED")
print("=" * 60)
print()
print("  Models saved to: models/")
print("  ├── model_ddos.joblib       Model 1 — DDoS/DoS")
print("  ├── model_recon.joblib      Model 2 — Reconnaissance")
print("  ├── model_c2.joblib         Model 3 — C2/Botnet")
print("  ├── model_lateral.joblib    Model 4 — Lateral Movement")
print("  ├── model_exfil.joblib      Model 5 — Exfiltration")
print("  ├── model_web.joblib        Model 6 — Web Attacks")
print("  ├── model_malware.joblib    Model 7 — Malware")
print("  └── model_master.joblib     Master — Full 7-class")
print()
print("  Next step: Phase 4 — Attack Timeline Engine")
print("  File to run next: src/timeline.py")
print("=" * 60)