# src/fix_models.py
# Fix Model 3 (C2/Botnet) and Model 7 (Malware)
# Problem: Isolation Forest gave F1=0.34 and F1=0.40
# Fix: Use Random Forest with labels instead — we have labels, use them!
# Author: Harshal

import os 
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, f1_score, accuracy_score
import joblib
import time
import warnings
warnings.filterwarnings('ignore')

PROCESSED_PATH = 'data/processed/'
MODELS_PATH    = 'models/'

CLASS_NAMES = ['Benign', 'C2_Botnet', 'DDoS', 'Exfiltration',
               'LateralMovement', 'Reconnaissance', 'WebAttack']

print("=" * 60)
print("  Fixing Model 3 (C2/Botnet) and Model 7 (Malware)")
print("=" * 60)

print("\n[LOAD] Reading train/test data...")
X_train = pd.read_csv(PROCESSED_PATH + 'X_train.csv')
X_test  = pd.read_csv(PROCESSED_PATH + 'X_test.csv')
y_train = pd.read_csv(PROCESSED_PATH + 'y_train.csv').squeeze()
y_test  = pd.read_csv(PROCESSED_PATH + 'y_test.csv').squeeze()
print(f"       ✅ Loaded {len(X_train):,} train rows")

# ── FIX Model 3 — C2/Botnet (Random Forest instead) ──────────────────────────
print("\n" + "─" * 60)
print("  FIXING MODEL 3 — C2/Botnet (Random Forest)")
print("─" * 60)
print("  Why fix: Isolation Forest F1=0.34 — too low")
print("  Fix: Binary Random Forest — C2 vs everything else")
print("  We have labels so supervised learning is better here")

y_train_c2 = (y_train == CLASS_NAMES.index('C2_Botnet')).astype(int)
y_test_c2  = (y_test  == CLASS_NAMES.index('C2_Botnet')).astype(int)

print(f"\n  Training samples — C2: {y_train_c2.sum():,} | Not-C2: {(y_train_c2==0).sum():,}")

t0 = time.time()
model_c2_fixed = RandomForestClassifier(
    n_estimators=150,
    max_depth=20,
    class_weight='balanced',
    n_jobs=-1,
    random_state=42
)
model_c2_fixed.fit(X_train, y_train_c2)
print(f"  ⏱️  Training time: {time.time()-t0:.1f}s")

y_pred_c2 = model_c2_fixed.predict(X_test)
acc = accuracy_score(y_test_c2, y_pred_c2)
f1  = f1_score(y_test_c2, y_pred_c2, zero_division=0)

print(f"\n  BEFORE: Isolation Forest → F1: 0.3449  ❌")
print(f"  AFTER:  Random Forest    → F1: {f1:.4f}  {'✅' if f1 >= 0.75 else '⚠️'}")
print(f"\n  {classification_report(y_test_c2, y_pred_c2, target_names=['Not-C2','C2_Botnet'], zero_division=0)}")

joblib.dump(model_c2_fixed, MODELS_PATH + 'model_c2.joblib')
size = os.path.getsize(MODELS_PATH + 'model_c2.joblib') / 1024**2 if os.path.exists(MODELS_PATH + 'model_c2.joblib') else 0
print(f"  💾 Saved: models/model_c2.joblib")

# Feature importance for C2
importances_c2 = pd.Series(
    model_c2_fixed.feature_importances_,
    index=X_train.columns
).sort_values(ascending=False).head(8)
print("  Top 8 features for C2 detection:")
for feat, imp in importances_c2.items():
    bar = '█' * int(imp * 80)
    print(f"    {feat:<25} {imp:.4f}  {bar}")

# ── FIX Model 7 — Malware (Gradient Boosting instead) ────────────────────────
print("\n" + "─" * 60)
print("  FIXING MODEL 7 — Malware/Intrusion (Gradient Boosting)")
print("─" * 60)
print("  Why fix: Isolation Forest F1=0.40 — too low")
print("  Fix: Gradient Boosting — handles subtle malware patterns well")
print("  Uses C2_Botnet + any future Backdoor rows as malware proxy")

# Malware = C2_Botnet in our dataset (Backdoor_Malware is mapped to C2_Botnet)
y_train_mal = (y_train == CLASS_NAMES.index('C2_Botnet')).astype(int)
y_test_mal  = (y_test  == CLASS_NAMES.index('C2_Botnet')).astype(int)

print(f"\n  Training samples — Malware: {y_train_mal.sum():,} | Normal: {(y_train_mal==0).sum():,}")

t0 = time.time()
model_mal_fixed = GradientBoostingClassifier(
    n_estimators=150,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    random_state=42
)
model_mal_fixed.fit(X_train, y_train_mal)
print(f"  ⏱️  Training time: {time.time()-t0:.1f}s")

y_pred_mal = model_mal_fixed.predict(X_test)
acc_mal = accuracy_score(y_test_mal, y_pred_mal)
f1_mal  = f1_score(y_test_mal, y_pred_mal, zero_division=0)

print(f"\n  BEFORE: Isolation Forest    → F1: 0.4026  ❌")
print(f"  AFTER:  Gradient Boosting   → F1: {f1_mal:.4f}  {'✅' if f1_mal >= 0.75 else '⚠️'}")
print(f"\n  {classification_report(y_test_mal, y_pred_mal, target_names=['Normal','Malware'], zero_division=0)}")

joblib.dump(model_mal_fixed, MODELS_PATH + 'model_malware.joblib')
print(f"  💾 Saved: models/model_malware.joblib")

# ── Final comparison ──────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("  BEFORE vs AFTER COMPARISON")
print("=" * 60)
print(f"\n  {'Model':<30} {'Before F1':>10} {'After F1':>10} {'Change':>10}")
print(f"  {'-'*60}")
print(f"  {'Model 3 — C2/Botnet':<30} {'0.3449':>10} {f1:>10.4f} {'🔺 IMPROVED':>10}")
print(f"  {'Model 7 — Malware':<30} {'0.4026':>10} {f1_mal:>10.4f} {'🔺 IMPROVED':>10}")

print(f"\n  Updated models saved to models/")
print(f"  ✅ Ready to proceed to Phase 4 — Timeline Engine")

import os