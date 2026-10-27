# src/explore.py
# Goal: Understand the full dataset, check quality, prepare for ML
# Dataset: CIC-IoT 2023 (Kaggle version 2, updated 2024)
# Author: Harshal
# Last updated: Phase 1 — Exploration

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
import glob
import os
import warnings
warnings.filterwarnings('ignore')

# ── Config ───────────────────────────────────────────────────────────────────
DATA_PATH    = 'data/raw/CIC(iot)/'
OUTPUT_PATH  = 'data/processed/'
SAMPLE_FILES = 5   # safe for 16GB RAM — loads ~350MB

os.makedirs(OUTPUT_PATH, exist_ok=True)

# ── Complete Label Map — all 34 attack types → 7 threat categories ───────────
LABEL_MAP = {
    # ── Benign ────────────────────────────────────────────────────────────
    'BenignTraffic':              'Benign',

    # ── Model 1: DDoS / DoS ───────────────────────────────────────────────
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

    # ── Model 2: Reconnaissance ───────────────────────────────────────────
    'Recon-HostDiscovery':        'Reconnaissance',
    'Recon-OSScan':               'Reconnaissance',
    'Recon-PingSweep':            'Reconnaissance',
    'Recon-PortScan':             'Reconnaissance',
    'VulnerabilityScan':          'Reconnaissance',

    # ── Model 3: C2 / Botnet ──────────────────────────────────────────────
    'Mirai-greeth_flood':         'C2_Botnet',
    'Mirai-greip_flood':          'C2_Botnet',
    'Mirai-udpplain':             'C2_Botnet',
    'Backdoor_Malware':           'C2_Botnet',

    # ── Model 4: Lateral Movement ─────────────────────────────────────────
    'MITM-ArpSpoofing':           'LateralMovement',
    'BrowserHijacking':           'LateralMovement',

    # ── Model 5: Exfiltration ─────────────────────────────────────────────
    'Uploading_Attack':           'Exfiltration',
    'DNS_Spoofing':               'Exfiltration',

    # ── Model 6: Web Attacks ──────────────────────────────────────────────
    'CommandInjection':           'WebAttack',
    'SqlInjection':               'WebAttack',
    'XSS':                        'WebAttack',
    'DictionaryBruteForce':       'WebAttack',

    # ── Model 7: Malware / Intrusion ──────────────────────────────────────
    # Backdoor_Malware also fits here but is kept in C2 to avoid duplication
}

# Color palette for 8 categories (Benign + 7 threat types)
CATEGORY_COLORS = {
    'Benign':          '#00ff88',
    'DDoS':            '#ff4444',
    'Reconnaissance':  '#ff8800',
    'C2_Botnet':       '#ff44ff',
    'LateralMovement': '#ffff00',
    'Exfiltration':    '#4488ff',
    'WebAttack':       '#44ffff',
    'Other':           '#888888',
}

# Kill chain order (used later in timeline)
KILL_CHAIN_ORDER = [
    'Reconnaissance',
    'WebAttack',
    'C2_Botnet',
    'LateralMovement',
    'Exfiltration',
    'DDoS',
]

# ── Step 1: Load sample files ─────────────────────────────────────────────────
print("=" * 55)
print("  CIC-IoT 2023 — Dataset Exploration")
print("=" * 55)

print(f"\n[1/7] Loading {SAMPLE_FILES} sample files...")
files = sorted(glob.glob(DATA_PATH + '*.csv'))
print(f"      Total files available: {len(files)}")

sample_files = files[:SAMPLE_FILES]
chunks = []
for i, f in enumerate(sample_files):
    df_chunk = pd.read_csv(f)
    chunks.append(df_chunk)
    size_mb = os.path.getsize(f) / 1024**2
    print(f"      [{i+1}/{SAMPLE_FILES}] {os.path.basename(f)} — "
          f"{len(df_chunk):,} rows — {size_mb:.1f} MB")

df = pd.concat(chunks, ignore_index=True)
ram_mb = df.memory_usage(deep=True).sum() / 1024**2
print(f"\n      ✅ Loaded {len(df):,} rows | {len(df.columns)} columns | {ram_mb:.0f} MB RAM used")

# ── Step 2: Map all labels to 7 threat categories ─────────────────────────────
print("\n[2/7] Mapping 34 labels → 7 threat categories...")
df['threat_category'] = df['label'].map(LABEL_MAP).fillna('Other')

print("\n      Raw label distribution:")
label_counts = df['label'].value_counts()
for label, count in label_counts.items():
    category = LABEL_MAP.get(label, 'Other')
    pct = count / len(df) * 100
    print(f"        {label:<35} {count:>8,}  ({pct:5.1f}%)  → {category}")

print("\n      Threat category summary:")
cat_counts = df['threat_category'].value_counts()
for cat, count in cat_counts.items():
    pct = count / len(df) * 100
    bar = '█' * int(pct / 2)
    print(f"        {cat:<20} {count:>8,}  ({pct:5.1f}%)  {bar}")

# ── Step 3: Data quality check ────────────────────────────────────────────────
print("\n[3/7] Data quality check...")

# Missing values
missing = df.isnull().sum()
missing_cols = missing[missing > 0]
if len(missing_cols) == 0:
    print("      ✅ No missing values")
else:
    print(f"      ⚠️  {len(missing_cols)} columns have missing values:")
    for col, cnt in missing_cols.items():
        print(f"        {col}: {cnt:,} ({cnt/len(df)*100:.1f}%)")

# Infinite values
num_df = df.select_dtypes(include=np.number)
inf_count = np.isinf(num_df).sum().sum()
print(f"      {'✅' if inf_count == 0 else '⚠️ '} Infinite values: {inf_count:,}")

# Duplicate rows
dup_count = df.duplicated().sum()
print(f"      {'✅' if dup_count == 0 else '⚠️ '} Duplicate rows: {dup_count:,}")

# Class imbalance check
print("\n      Class imbalance check:")
benign_pct = (df['threat_category'] == 'Benign').sum() / len(df) * 100
attack_pct = 100 - benign_pct
print(f"        Benign traffic : {benign_pct:.1f}%")
print(f"        Attack traffic : {attack_pct:.1f}%")
if benign_pct > 80 or attack_pct > 80:
    print("        ⚠️  High class imbalance — will need SMOTE or class weights in ML")
else:
    print("        ✅ Reasonable class balance")

# ── Step 4: Feature analysis ──────────────────────────────────────────────────
print("\n[4/7] Feature analysis...")
numeric_cols = df.select_dtypes(include=np.number).columns.tolist()
print(f"      Total numeric features: {len(numeric_cols)}")

# Most important features for our 7 models
KEY_FEATURES = [
    'flow_duration', 'Rate', 'Srate', 'Drate',
    'IAT', 'Tot size', 'Number', 'Variance',
    'Covariance', 'Weight', 'Header_Length',
    'fin_flag_number', 'syn_flag_number', 'rst_flag_number',
    'ack_flag_number', 'psh_flag_number',
    'TCP', 'UDP', 'ICMP', 'HTTP', 'DNS'
]

print(f"\n      Key feature statistics:")
print(df[KEY_FEATURES].describe().round(3).to_string())

# ── Step 5: Feature importance preview ───────────────────────────────────────
print("\n[5/7] Quick feature importance check (correlation with attack)...")
df['is_attack'] = (df['threat_category'] != 'Benign').astype(int)
correlations = df[KEY_FEATURES + ['is_attack']].corr()['is_attack'].drop('is_attack')
correlations = correlations.abs().sort_values(ascending=False)
print("\n      Top 10 features most correlated with attacks:")
for feat, corr in correlations.head(10).items():
    bar = '█' * int(corr * 20)
    print(f"        {feat:<25} {corr:.4f}  {bar}")

# ── Step 6: Visualizations ────────────────────────────────────────────────────
print("\n[6/7] Generating visualizations...")
plt.style.use('dark_background')
plt.rcParams.update({'font.family': 'monospace'})

# ── Plot 1: Dataset Overview Dashboard ──
fig = plt.figure(figsize=(16, 10))
fig.patch.set_facecolor('#0a0a0a')
gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.4, wspace=0.35)
fig.suptitle('CIC-IoT 2023 — Dataset Overview', fontsize=16,
             fontweight='bold', color='white', y=0.98)

# Subplot 1 — Threat category bar chart
ax1 = fig.add_subplot(gs[0, 0])
cats = df['threat_category'].value_counts()
colors = [CATEGORY_COLORS.get(c, '#888') for c in cats.index]
bars = ax1.bar(range(len(cats)), cats.values, color=colors, edgecolor='#333')
ax1.set_xticks(range(len(cats)))
ax1.set_xticklabels(cats.index, rotation=45, ha='right', fontsize=7)
ax1.set_title('Threat Categories', color='white', fontsize=10)
ax1.set_facecolor('#111')
for bar, val in zip(bars, cats.values):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 50,
             f'{val:,}', ha='center', va='bottom', fontsize=6, color='white')

# Subplot 2 — Pie chart of categories
ax2 = fig.add_subplot(gs[0, 1])
wedge_colors = [CATEGORY_COLORS.get(c, '#888') for c in cats.index]
ax2.pie(cats.values, labels=cats.index, colors=wedge_colors,
        autopct='%1.1f%%', startangle=90,
        textprops={'fontsize': 7, 'color': 'white'})
ax2.set_title('Distribution %', color='white', fontsize=10)
ax2.set_facecolor('#111')

# Subplot 3 — Top 15 raw attack labels
ax3 = fig.add_subplot(gs[0, 2])
top15 = label_counts.head(15)
ax3.barh(range(len(top15)), top15.values, color='#4488ff')
ax3.set_yticks(range(len(top15)))
ax3.set_yticklabels(top15.index, fontsize=6)
ax3.set_title('Top 15 Attack Labels', color='white', fontsize=10)
ax3.set_facecolor('#111')

# Subplot 4 — Kill chain stage coverage
ax4 = fig.add_subplot(gs[1, 0])
kc_counts = [df[df['threat_category'] == stage].shape[0]
             for stage in KILL_CHAIN_ORDER]
kc_colors = [CATEGORY_COLORS.get(s, '#888') for s in KILL_CHAIN_ORDER]
ax4.barh(KILL_CHAIN_ORDER, kc_counts, color=kc_colors)
ax4.set_title('Kill Chain Stage Coverage', color='white', fontsize=10)
ax4.set_facecolor('#111')
ax4.tick_params(axis='y', labelsize=7)

# Subplot 5 — Top 10 feature correlations with attack
ax5 = fig.add_subplot(gs[1, 1])
top_corr = correlations.head(10)
ax5.barh(top_corr.index, top_corr.values, color='#ff8800')
ax5.set_title('Top Feature-Attack Correlations', color='white', fontsize=10)
ax5.set_facecolor('#111')
ax5.tick_params(axis='y', labelsize=7)

# Subplot 6 — Class balance
ax6 = fig.add_subplot(gs[1, 2])
balance = df['threat_category'].value_counts()
ax6.pie([benign_pct, attack_pct],
        labels=['Benign', 'Attack'],
        colors=['#00ff88', '#ff4444'],
        autopct='%1.1f%%', startangle=90,
        textprops={'fontsize': 9, 'color': 'white'})
ax6.set_title('Benign vs Attack', color='white', fontsize=10)
ax6.set_facecolor('#111')

plt.savefig(OUTPUT_PATH + 'plot_01_overview.png', dpi=150,
            bbox_inches='tight', facecolor='#0a0a0a')
plt.show()
print("      Saved: plot_01_overview.png")

# ── Plot 2: Feature Distributions by Threat Category ──
fig, axes = plt.subplots(2, 4, figsize=(18, 8))
fig.patch.set_facecolor('#0a0a0a')
fig.suptitle('Feature Distributions by Threat Category',
             fontsize=14, fontweight='bold', color='white')

plot_features = ['flow_duration', 'Rate', 'IAT', 'Tot size',
                 'syn_flag_number', 'Header_Length', 'Variance', 'Number']

for ax, feat in zip(axes.flatten(), plot_features):
    ax.set_facecolor('#111')
    for category, color in CATEGORY_COLORS.items():
        subset = df[df['threat_category'] == category][feat].dropna()
        subset = subset.replace([np.inf, -np.inf], np.nan).dropna()
        if len(subset) == 0:
            continue
        p95 = subset.quantile(0.95)
        subset = subset[subset <= p95]
        ax.hist(subset, bins=40, alpha=0.4, label=category,
                color=color, density=True)
    ax.set_title(feat, color='white', fontsize=9)
    ax.set_xlabel('Value', fontsize=7, color='#aaa')
    ax.tick_params(colors='#aaa', labelsize=6)
    for spine in ax.spines.values():
        spine.set_edgecolor('#333')

axes[0][0].legend(fontsize=6, facecolor='#222', labelcolor='white')
plt.tight_layout()
plt.savefig(OUTPUT_PATH + 'plot_02_features.png', dpi=150,
            bbox_inches='tight', facecolor='#0a0a0a')
plt.show()
print("      Saved: plot_02_features.png")

# ── Plot 3: Correlation Heatmap ──
fig, ax = plt.subplots(figsize=(14, 11))
fig.patch.set_facecolor('#0a0a0a')
ax.set_facecolor('#111')
corr_matrix = df[KEY_FEATURES].corr()
mask = np.zeros_like(corr_matrix, dtype=bool)
mask[np.triu_indices_from(mask)] = True
sns.heatmap(corr_matrix, mask=mask, annot=True, fmt='.2f',
            cmap='RdYlGn', ax=ax, linewidths=0.3,
            annot_kws={'size': 7}, vmin=-1, vmax=1,
            cbar_kws={'shrink': 0.8})
ax.set_title('Feature Correlation Matrix', color='white',
             fontsize=13, fontweight='bold', pad=15)
ax.tick_params(colors='white', labelsize=8)
plt.tight_layout()
plt.savefig(OUTPUT_PATH + 'plot_03_correlation.png', dpi=150,
            bbox_inches='tight', facecolor='#0a0a0a')
plt.show()
print("      Saved: plot_03_correlation.png")

# ── Step 7: Save clean sample for ML ─────────────────────────────────────────
print("\n[7/7] Saving clean sample for ML...")

# Clean: remove inf, NaN, duplicates
df_clean = df.copy()
df_clean.replace([np.inf, -np.inf], np.nan, inplace=True)
df_clean.dropna(inplace=True)
df_clean.drop_duplicates(inplace=True)

# Save full clean sample
output_file = OUTPUT_PATH + 'sample_clean.csv'
df_clean.to_csv(output_file, index=False)
size_mb = os.path.getsize(output_file) / 1024**2
print(f"      ✅ Saved: {output_file}")
print(f"         Rows: {len(df_clean):,} | Columns: {len(df_clean.columns)} | Size: {size_mb:.1f} MB")

# Save one small file per threat category (useful for per-model training)
print("\n      Saving per-category samples...")
for category in df_clean['threat_category'].unique():
    cat_df = df_clean[df_clean['threat_category'] == category]
    cat_file = OUTPUT_PATH + f'sample_{category.lower()}.csv'
    cat_df.to_csv(cat_file, index=False)
    print(f"        {category:<20} {len(cat_df):>7,} rows → {cat_file}")

# Save feature list for ML phase
feature_cols = [c for c in df_clean.columns
                if c not in ['label', 'threat_category', 'is_attack']]
with open(OUTPUT_PATH + 'feature_list.txt', 'w') as f:
    f.write('\n'.join(feature_cols))
print(f"\n      ✅ Saved feature list: {OUTPUT_PATH}feature_list.txt")

# ── Final Summary ─────────────────────────────────────────────────────────────
print("\n" + "=" * 55)
print("  EXPLORATION COMPLETE")
print("=" * 55)
print(f"  Files loaded     : {SAMPLE_FILES} of {len(files)}")
print(f"  Total rows       : {len(df_clean):,}")
print(f"  Features         : {len(feature_cols)}")
print(f"  Attack categories: {df_clean['threat_category'].nunique()}")
print(f"  Plots saved      : 3 (in {OUTPUT_PATH})")
print(f"  Clean CSV saved  : {output_file}")
print()
print("  Next step: Phase 2 — Feature Engineering")
print("  File to run next: src/features.py")
print("=" * 55)