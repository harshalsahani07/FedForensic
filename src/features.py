# src/features.py
# Phase 2 — Feature Engineering Pipeline
# Goal: Select best features, fix class imbalance, normalize, save ML-ready data
# Author: Harshal

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.utils import resample
import joblib
import glob
import os
import warnings
warnings.filterwarnings('ignore')

# ── Config ───────────────────────────────────────────────────────────────────
DATA_PATH      = 'data/raw/CIC(iot)/'
PROCESSED_PATH = 'data/processed/'
MODELS_PATH    = 'models/'
BATCH_SIZE     = 5       # files per batch — safe for 16GB RAM
TOTAL_BATCHES  = 10      # use 10 batches = 50 files = ~3.5GB sampled

os.makedirs(MODELS_PATH, exist_ok=True)

# ── Label Map (same as explore.py) ───────────────────────────────────────────
LABEL_MAP = {
    'BenignTraffic':              'Benign',
    'DDoS-ACK_Fragmentation':     'DDoS',
    'DDoS-HTTP_Flood':            'DDoS',
    'DDoS-ICMP_Flood':            'DDoS',
    'DDoS-ICMP_Fragmentation':    'DDoS',
    'DDoS-PSHACK_Flood':          'DDoS',
    'DDoS-RSTFINFlood':           'DDoS',
    'DDoS-SYN_Flood':             'DDoS',
    'DDoS-SlowLoris':             'DDoS',
    'DDoS-SynonymousIP_Flood':    'DDoS',
    'DDoS-TCP_Flood':             'DDoS',
    'DDoS-UDP_Flood':             'DDoS',
    'DDoS-UDP_Fragmentation':     'DDoS',
    'DoS-HTTP_Flood':             'DDoS',
    'DoS-SYN_Flood':              'DDoS',
    'DoS-TCP_Flood':              'DDoS',
    'DoS-UDP_Flood':              'DDoS',
    'Recon-HostDiscovery':        'Reconnaissance',
    'Recon-OSScan':               'Reconnaissance',
    'Recon-PingSweep':            'Reconnaissance',
    'Recon-PortScan':             'Reconnaissance',
    'VulnerabilityScan':          'Reconnaissance',
    'Mirai-greeth_flood':         'C2_Botnet',
    'Mirai-greip_flood':          'C2_Botnet',
    'Mirai-udpplain':             'C2_Botnet',
    'Backdoor_Malware':           'C2_Botnet',
    'MITM-ArpSpoofing':           'LateralMovement',
    'BrowserHijacking':           'LateralMovement',
    'Uploading_Attack':           'Exfiltration',
    'DNS_Spoofing':               'Exfiltration',
    'CommandInjection':           'WebAttack',
    'SqlInjection':               'WebAttack',
    'XSS':                        'WebAttack',
    'DictionaryBruteForce':       'WebAttack',
}

# ── Top features identified from exploration ──────────────────────────────────
# These are the features we will use for ML
# Selected based on: correlation with attack + domain knowledge
TOP_FEATURES = [
    # High correlation with attacks (from explore.py output)
    'Variance', 'ack_flag_number', 'Tot size', 'Header_Length', 'Covariance',
    # Network behavior features
    'flow_duration', 'Rate', 'Srate', 'Drate', 'IAT',
    # Packet statistics
    'Number', 'Weight', 'Radius', 'Magnitue',
    # Protocol flags
    'fin_flag_number', 'syn_flag_number', 'rst_flag_number',
    'psh_flag_number', 'ece_flag_number', 'cwr_flag_number',
    # Protocol counts
    'ack_count', 'syn_count', 'fin_count', 'rst_count',
    # Protocol type indicators
    'TCP', 'UDP', 'ICMP', 'HTTP', 'DNS', 'HTTPS',
    # Statistical features
    'Tot sum', 'Min', 'Max', 'AVG', 'Std',
]

ALL_CATEGORIES = ['Benign', 'DDoS', 'Reconnaissance', 'C2_Botnet',
                  'LateralMovement', 'Exfiltration', 'WebAttack']

# ── Step 1: Load data in batches ──────────────────────────────────────────────
print("=" * 55)
print("  Phase 2 — Feature Engineering")
print("=" * 55)

print(f"\n[1/6] Loading data in batches ({BATCH_SIZE} files × {TOTAL_BATCHES} batches)...")
files = sorted(glob.glob(DATA_PATH + '*.csv'))

all_chunks = []
total_rows = 0

for batch_num in range(TOTAL_BATCHES):
    start = batch_num * BATCH_SIZE
    end   = start + BATCH_SIZE
    batch_files = files[start:end]

    if not batch_files:
        break

    batch_chunks = []
    for f in batch_files:
        df_chunk = pd.read_csv(f)
        batch_chunks.append(df_chunk)

    batch_df = pd.concat(batch_chunks, ignore_index=True)
    all_chunks.append(batch_df)
    total_rows += len(batch_df)

    print(f"      Batch {batch_num+1:02d}/{TOTAL_BATCHES} — "
          f"files {start}-{end-1} — {len(batch_df):,} rows loaded")

df = pd.concat(all_chunks, ignore_index=True)
ram_mb = df.memory_usage(deep=True).sum() / 1024**2
print(f"\n      ✅ Total: {len(df):,} rows | {ram_mb:.0f} MB RAM used")

# ── Step 2: Clean + map labels ────────────────────────────────────────────────
print("\n[2/6] Cleaning data and mapping labels...")

# Map labels
df['threat_category'] = df['label'].map(LABEL_MAP).fillna('Other')
df = df[df['threat_category'] != 'Other']  # drop unmapped

# Remove inf and NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(subset=TOP_FEATURES, inplace=True)
df.drop_duplicates(inplace=True)

print(f"      ✅ After cleaning: {len(df):,} rows")
print(f"\n      Category counts before balancing:")
cat_counts = df['threat_category'].value_counts()
for cat, count in cat_counts.items():
    pct = count / len(df) * 100
    print(f"        {cat:<20} {count:>9,}  ({pct:5.1f}%)")

# ── Step 3: Fix class imbalance ───────────────────────────────────────────────
print("\n[3/6] Fixing class imbalance...")
print("      Strategy: Oversample minority classes + Undersample DDoS")
print("      Target: Each class gets at least 50,000 rows")

TARGET_SAMPLES = 50_000
balanced_dfs = []

for category in ALL_CATEGORIES:
    cat_df = df[df['threat_category'] == category]
    current = len(cat_df)

    if current == 0:
        print(f"      ⚠️  {category:<20} — NO DATA in these batches, skipping")
        continue
    elif current >= TARGET_SAMPLES:
        # Undersample large classes (DDoS has millions)
        sampled = cat_df.sample(n=TARGET_SAMPLES, random_state=42)
        action = f"undersampled {current:,} → {TARGET_SAMPLES:,}"
    else:
        # Oversample small classes (WebAttack, Exfiltration, etc.)
        sampled = resample(cat_df,
                          replace=True,
                          n_samples=TARGET_SAMPLES,
                          random_state=42)
        action = f"oversampled  {current:,} → {TARGET_SAMPLES:,}"

    balanced_dfs.append(sampled)
    print(f"      {category:<20} {action}")

df_balanced = pd.concat(balanced_dfs, ignore_index=True)
df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"\n      ✅ Balanced dataset: {len(df_balanced):,} rows")
print(f"         Each class: ~{TARGET_SAMPLES:,} rows")

# ── Step 4: Feature selection ─────────────────────────────────────────────────
print("\n[4/6] Selecting and validating features...")

# Only keep features that exist in our data
available_features = [f for f in TOP_FEATURES if f in df_balanced.columns]
missing_features   = [f for f in TOP_FEATURES if f not in df_balanced.columns]

print(f"      Available features : {len(available_features)}")
if missing_features:
    print(f"      Missing features   : {missing_features}")

X = df_balanced[available_features].copy()
y = df_balanced['threat_category'].copy()

print(f"\n      Feature matrix shape: {X.shape}")
print(f"      Label distribution:")
for cat, count in y.value_counts().items():
    print(f"        {cat:<20} {count:,}")

# ── Step 5: Scale features ────────────────────────────────────────────────────
print("\n[5/6] Scaling features (StandardScaler)...")

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
X_scaled = pd.DataFrame(X_scaled, columns=available_features)

print(f"      ✅ Features scaled — mean≈0, std≈1")
print(f"      Before scaling — Rate: mean={X['Rate'].mean():.1f}, std={X['Rate'].std():.1f}")
print(f"      After  scaling — Rate: mean={X_scaled['Rate'].mean():.4f}, std={X_scaled['Rate'].std():.4f}")

# ── Step 6: Train/test split + save everything ────────────────────────────────
print("\n[6/6] Train/test split and saving...")

# Encode labels to numbers
le = LabelEncoder()
y_encoded = le.fit_transform(y)
print(f"      Label encoding:")
for i, cls in enumerate(le.classes_):
    print(f"        {i} → {cls}")

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_encoded,
    test_size=0.2,
    random_state=42,
    stratify=y_encoded
)

print(f"\n      Train set : {X_train.shape[0]:,} rows")
print(f"      Test set  : {X_test.shape[0]:,} rows")

# Save everything
print("\n      Saving files...")

# Training data
X_train.to_csv(PROCESSED_PATH + 'X_train.csv', index=False)
X_test.to_csv(PROCESSED_PATH  + 'X_test.csv',  index=False)
pd.Series(y_train).to_csv(PROCESSED_PATH + 'y_train.csv', index=False)
pd.Series(y_test).to_csv(PROCESSED_PATH  + 'y_test.csv',  index=False)

# Scaler and encoder — needed later for dashboard
joblib.dump(scaler, MODELS_PATH + 'scaler.joblib')
joblib.dump(le,     MODELS_PATH + 'label_encoder.joblib')

# Save feature list used for training
with open(PROCESSED_PATH + 'features_used.txt', 'w') as f:
    f.write('\n'.join(available_features))

print(f"      ✅ X_train.csv       — {X_train.shape[0]:,} rows × {X_train.shape[1]} features")
print(f"      ✅ X_test.csv        — {X_test.shape[0]:,} rows × {X_test.shape[1]} features")
print(f"      ✅ y_train.csv       — labels for training")
print(f"      ✅ y_test.csv        — labels for testing")
print(f"      ✅ scaler.joblib     — StandardScaler (use when predicting new data)")
print(f"      ✅ label_encoder.joblib")
print(f"      ✅ features_used.txt — exact feature list for models")

# ── Bonus: Visualize balanced dataset ────────────────────────────────────────
plt.style.use('dark_background')
fig, axes = plt.subplots(1, 2, figsize=(14, 5))
fig.patch.set_facecolor('#0a0a0a')
fig.suptitle('Phase 2 — Feature Engineering Results',
             fontsize=13, color='white', fontweight='bold')

COLORS = ['#00ff88','#ff4444','#ff8800','#ff44ff','#ffff00','#4488ff','#44ffff']

# Before balancing
ax1 = axes[0]
ax1.set_facecolor('#111')
before = cat_counts
bars1 = ax1.bar(range(len(before)), before.values,
                color=COLORS[:len(before)], edgecolor='#333')
ax1.set_xticks(range(len(before)))
ax1.set_xticklabels(before.index, rotation=40, ha='right', fontsize=7)
ax1.set_title('Before Balancing', color='white')
ax1.set_ylabel('Row Count', color='white')
for bar, val in zip(bars1, before.values):
    ax1.text(bar.get_x() + bar.get_width()/2,
             bar.get_height() + 100,
             f'{val:,}', ha='center', fontsize=6, color='white')

# After balancing
ax2 = axes[1]
ax2.set_facecolor('#111')
after = y.value_counts()
bars2 = ax2.bar(range(len(after)), after.values,
                color=COLORS[:len(after)], edgecolor='#333')
ax2.set_xticks(range(len(after)))
ax2.set_xticklabels(after.index, rotation=40, ha='right', fontsize=7)
ax2.set_title('After Balancing', color='white')
ax2.set_ylabel('Row Count', color='white')
for bar, val in zip(bars2, after.values):
    ax2.text(bar.get_x() + bar.get_width()/2,
             bar.get_height() + 100,
             f'{val:,}', ha='center', fontsize=6, color='white')

plt.tight_layout()
plt.savefig(PROCESSED_PATH + 'plot_04_balancing.png',
            dpi=150, bbox_inches='tight', facecolor='#0a0a0a')
plt.show()
print(f"\n      ✅ Saved: plot_04_balancing.png")

# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "=" * 55)
print("  FEATURE ENGINEERING COMPLETE")
print("=" * 55)
print(f"  Files processed  : {TOTAL_BATCHES * BATCH_SIZE} of 169")
print(f"  Features selected: {len(available_features)}")
print(f"  Train rows       : {X_train.shape[0]:,}")
print(f"  Test rows        : {X_test.shape[0]:,}")
print(f"  Classes          : {len(le.classes_)}")
print()
print("  Next step: Phase 3 — Train 7 ML Models")
print("  File to run next: src/models.py")
print("=" * 55)