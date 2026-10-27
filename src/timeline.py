# src/timeline.py
# Phase 4 — Attack Timeline Reconstruction Engine
# Goal: Take ML model predictions → reconstruct full attack story
# Uses Lockheed Martin Cyber Kill Chain model (7 stages)
# Author: Harshal

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
from matplotlib.patches import FancyArrowPatch
import joblib
import os
import sys
import json
from datetime import datetime, timedelta
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

# Force UTF-8 output so emoji in print() work on Windows cp1252 terminals
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


# ── Config ───────────────────────────────────────────────────────────────────
PROCESSED_PATH = 'data/processed/'
MODELS_PATH    = 'models/'
OUTPUT_PATH    = 'data/processed/'

os.makedirs(OUTPUT_PATH, exist_ok=True)

# ── Kill Chain Definition ─────────────────────────────────────────────────────
# Each threat category maps to a kill chain stage number
# Lower number = earlier in attack lifecycle
KILL_CHAIN = {
    'Reconnaissance':  {'stage': 1, 'color': '#ff8800', 'icon': '🔍', 'desc': 'Attacker maps the network'},
    'WebAttack':       {'stage': 2, 'color': '#ff4488', 'icon': '🌐', 'desc': 'Attacker exploits web vulnerabilities'},
    'C2_Botnet':       {'stage': 3, 'color': '#ff44ff', 'icon': '📡', 'desc': 'Attacker establishes command channel'},
    'LateralMovement': {'stage': 4, 'color': '#ffff00', 'icon': '↔️',  'desc': 'Attacker moves through network'},
    'Exfiltration':    {'stage': 5, 'color': '#4488ff', 'icon': '📤', 'desc': 'Attacker steals data'},
    'DDoS':            {'stage': 6, 'color': '#ff4444', 'icon': '💥', 'desc': 'Attacker floods as smokescreen'},
    'Benign':          {'stage': 0, 'color': '#00ff88', 'icon': '✅', 'desc': 'Normal traffic'},
}

# Severity scores per threat type (1-10)
SEVERITY = {
    'Reconnaissance':  3,
    'WebAttack':       6,
    'C2_Botnet':       8,
    'LateralMovement': 7,
    'Exfiltration':    9,
    'DDoS':            5,
    'Benign':          0,
}

CLASS_NAMES = ['Benign', 'C2_Botnet', 'DDoS', 'Exfiltration',
               'LateralMovement', 'Reconnaissance', 'WebAttack']

# ── Helper: Generate synthetic timestamps ─────────────────────────────────────
# Real PCAPs have timestamps. For CSV data we simulate a realistic attack timeline.
def generate_timestamps(n_events, base_time=None, spread_minutes=60):
    """Generate realistic attack timestamps spread over spread_minutes."""
    if base_time is None:
        base_time = datetime(2024, 1, 15, 14, 0, 0)  # 2pm attack scenario
    timestamps = []
    for i in range(n_events):
        offset = timedelta(seconds=np.random.uniform(0, spread_minutes * 60))
        timestamps.append(base_time + offset)
    return sorted(timestamps)


# ── Step 1: Run all models on sample data ────────────────────────────────────
print("=" * 65)
print("  Phase 4 — Attack Timeline Reconstruction Engine")
print("=" * 65)

print("\n[1/6] Loading models and sample data...")

# Load scaler and encoder
scaler = joblib.load(MODELS_PATH + 'scaler.joblib')
le     = joblib.load(MODELS_PATH + 'label_encoder.joblib')

# Load master model for classification
model_master = joblib.load(MODELS_PATH + 'model_master.joblib')
print("       ✅ Master model loaded")

# Load individual models
models = {
    'DDoS':           joblib.load(MODELS_PATH + 'model_ddos.joblib'),
    'Reconnaissance': joblib.load(MODELS_PATH + 'model_recon.joblib'),
    'C2_Botnet':      joblib.load(MODELS_PATH + 'model_c2.joblib'),
    'LateralMovement':joblib.load(MODELS_PATH + 'model_lateral.joblib'),
    'Exfiltration':   joblib.load(MODELS_PATH + 'model_exfil.joblib'),
    'WebAttack':      joblib.load(MODELS_PATH + 'model_web.joblib'),
}
print(f"       ✅ {len(models)} specialist models loaded")

# Load feature list
with open(PROCESSED_PATH + 'features_used.txt') as f:
    feature_cols = [line.strip() for line in f.readlines()]

# Load test data as our "live traffic sample"
print("\n       Loading sample traffic for timeline analysis...")
X_test  = pd.read_csv(PROCESSED_PATH + 'X_test.csv')
y_test  = pd.read_csv(PROCESSED_PATH + 'y_test.csv').squeeze()

# Take a representative sample — 2000 rows across all attack types
sample_per_class = 200
sample_indices = []
for class_idx in range(len(CLASS_NAMES)):
    idx = y_test[y_test == class_idx].index[:sample_per_class].tolist()
    sample_indices.extend(idx)

# Reindex properly
X_sample = X_test.loc[sample_indices].reset_index(drop=True)
y_sample = y_test.loc[sample_indices].reset_index(drop=True)
print(f"       ✅ Sample: {len(X_sample):,} flows loaded for analysis")


# ── Step 2: Run master model → get predictions + confidence ──────────────────
print("\n[2/6] Running Master Model — classifying all flows...")

# Get predictions
y_pred = model_master.predict(X_sample)

# Get confidence scores (probability of predicted class)
y_proba = model_master.predict_proba(X_sample)
confidence = y_proba.max(axis=1)

# Map numeric predictions back to category names
pred_categories = [CLASS_NAMES[p] for p in y_pred]
true_categories = [CLASS_NAMES[t] for t in y_sample]

print(f"       ✅ Classified {len(X_sample):,} flows")
print(f"\n       Detection breakdown:")
from collections import Counter
counts = Counter(pred_categories)
for cat, count in sorted(counts.items(), key=lambda x: -x[1]):
    stage = KILL_CHAIN.get(cat, {}).get('stage', 0)
    icon  = KILL_CHAIN.get(cat, {}).get('icon', '?')
    print(f"         {icon} {cat:<20} {count:>5} flows  (stage {stage})")


# ── Step 3: Build Event Log ───────────────────────────────────────────────────
print("\n[3/6] Building event log...")

# Generate synthetic timestamps (real PCAP would have real ones)
base_attack_time = datetime(2024, 1, 15, 14, 0, 0)
timestamps = generate_timestamps(len(X_sample), base_attack_time, spread_minutes=90)

# Build event dataframe
events = pd.DataFrame({
    'timestamp':      timestamps,
    'flow_index':     range(len(X_sample)),
    'predicted':      pred_categories,
    'true_label':     true_categories,
    'confidence':     confidence.round(4),
    'severity':       [SEVERITY.get(cat, 0) for cat in pred_categories],
    'kill_chain_stage': [KILL_CHAIN.get(cat, {}).get('stage', 0) for cat in pred_categories],
    'rate':           X_sample['Rate'].values.round(2),
    'tot_size':       X_sample['Tot size'].values.round(2),
    'iat':            X_sample['IAT'].values.round(2),
})

# Filter out benign for attack timeline (keep benign count for context)
benign_count  = (events['predicted'] == 'Benign').sum()
attack_events = events[events['predicted'] != 'Benign'].copy()
attack_events = attack_events.sort_values('timestamp').reset_index(drop=True)

print(f"       ✅ Total events    : {len(events):,}")
print(f"          Benign flows    : {benign_count:,}  (filtered from timeline)")
print(f"          Attack events   : {len(attack_events):,}  (shown in timeline)")
print(f"          Avg confidence  : {attack_events['confidence'].mean():.3f}")
print(f"          Max severity    : {attack_events['severity'].max()}")


# ── Step 4: Kill Chain Correlation ───────────────────────────────────────────
print("\n[4/6] Correlating events to Kill Chain stages...")

# Group attack events by kill chain stage
kill_chain_summary = {}
for category, info in KILL_CHAIN.items():
    if category == 'Benign':
        continue
    stage_events = attack_events[attack_events['predicted'] == category]
    if len(stage_events) == 0:
        continue

    kill_chain_summary[category] = {
        'stage':        info['stage'],
        'icon':         info['icon'],
        'color':        info['color'],
        'desc':         info['desc'],
        'event_count':  len(stage_events),
        'first_seen':   stage_events['timestamp'].min(),
        'last_seen':    stage_events['timestamp'].max(),
        'avg_confidence': stage_events['confidence'].mean(),
        'max_severity': stage_events['severity'].max(),
        'avg_rate':     stage_events['rate'].mean(),
        'avg_size':     stage_events['tot_size'].mean(),
    }

# Sort by kill chain stage
kill_chain_summary = dict(
    sorted(kill_chain_summary.items(), key=lambda x: x[1]['stage'])
)

print("\n       Kill Chain Stage Analysis:")
print(f"       {'Stage':<5} {'Category':<20} {'Events':>7} {'First Seen':<22} {'Confidence':>10}")
print(f"       {'-'*70}")
for cat, info in kill_chain_summary.items():
    print(f"       {info['icon']} S{info['stage']}  "
          f"{cat:<20} {info['event_count']:>7} "
          f"{str(info['first_seen']):<22} "
          f"{info['avg_confidence']:>10.3f}")


# ── Step 5: Generate Attack Narrative ────────────────────────────────────────
print("\n[5/6] Generating attack narrative...")

def generate_narrative(kill_chain_summary, attack_events, benign_count):
    """Generate a human-readable attack story from kill chain events."""

    lines = []
    lines.append("=" * 65)
    lines.append("  ATTACK TIMELINE NARRATIVE")
    lines.append("=" * 65)

    if not kill_chain_summary:
        lines.append("\n  ✅ No attacks detected — traffic appears benign")
        return '\n'.join(lines)

    # Overall assessment
    total_attacks  = len(attack_events)
    max_severity   = attack_events['severity'].max()
    stages_hit     = len(kill_chain_summary)
    threat_level   = 'CRITICAL' if max_severity >= 8 else \
                     'HIGH'     if max_severity >= 6 else \
                     'MEDIUM'   if max_severity >= 4 else 'LOW'

    lines.append(f"\n  ⚠️  THREAT LEVEL    : {threat_level}")
    lines.append(f"  📊 TOTAL EVENTS    : {total_attacks:,} attack flows detected")
    lines.append(f"  🔗 KILL CHAIN      : {stages_hit} of 6 stages observed")
    lines.append(f"  ✅ BENIGN TRAFFIC  : {benign_count:,} normal flows")

    # Attack start and end
    atk_start = attack_events['timestamp'].min()
    atk_end   = attack_events['timestamp'].max()
    duration  = atk_end - atk_start
    lines.append(f"\n  ⏱️  ATTACK WINDOW   : {atk_start.strftime('%H:%M:%S')} → "
                 f"{atk_end.strftime('%H:%M:%S')} ({str(duration).split('.')[0]})")

    lines.append(f"\n{'─'*65}")
    lines.append("  STAGE-BY-STAGE BREAKDOWN")
    lines.append(f"{'─'*65}")

    prev_time = None
    for cat, info in kill_chain_summary.items():
        time_str  = info['first_seen'].strftime('%H:%M:%S')
        gap_str   = ''
        if prev_time:
            gap = info['first_seen'] - prev_time
            # Clamp to zero: random timestamps can make later-stage first_seen
            # appear before the previous stage, giving a negative delta.
            if gap.total_seconds() < 0:
                gap = timedelta(0)
            gap_str = f"  (+{str(gap).split('.')[0]} after previous stage)"
        prev_time = info['first_seen']

        lines.append(f"\n  {info['icon']}  Stage {info['stage']} — {cat.upper()}")
        lines.append(f"     Time      : {time_str}{gap_str}")
        lines.append(f"     Events    : {info['event_count']:,} flows")
        lines.append(f"     Confidence: {info['avg_confidence']:.1%}")
        lines.append(f"     Severity  : {'█' * info['max_severity']} ({info['max_severity']}/10)")
        lines.append(f"     Meaning   : {info['desc']}")

        # Stage-specific insight
        if cat == 'Reconnaissance':
            lines.append(f"     Detail    : Avg packet rate {info['avg_rate']:.1f}/s — "
                        f"{'fast scan' if info['avg_rate'] > 100 else 'slow stealth scan'}")
        elif cat == 'WebAttack':
            lines.append(f"     Detail    : {info['event_count']} web attack attempts detected")
        elif cat == 'C2_Botnet':
            lines.append(f"     Detail    : Avg flow size {info['avg_size']:.0f} bytes — "
                        f"{'large C2 payload' if info['avg_size'] > 200 else 'small beaconing pattern'}")
        elif cat == 'LateralMovement':
            lines.append(f"     Detail    : Attacker pivoting to internal hosts")
        elif cat == 'Exfiltration':
            lines.append(f"     Detail    : Avg {info['avg_size']:.0f} bytes/flow outbound — "
                        f"{'high volume exfil' if info['avg_size'] > 500 else 'slow drip exfil'}")
        elif cat == 'DDoS':
            lines.append(f"     Detail    : Flood rate {info['avg_rate']:.1f}/s — "
                        f"likely smokescreen during exfiltration")

    # Kill chain completion assessment
    lines.append(f"\n{'─'*65}")
    lines.append("  KILL CHAIN COMPLETION")
    lines.append(f"{'─'*65}")

    all_stages   = ['Reconnaissance','WebAttack','C2_Botnet',
                    'LateralMovement','Exfiltration','DDoS']
    detected     = list(kill_chain_summary.keys())
    not_detected = [s for s in all_stages if s not in detected]

    chain_visual = ""
    for stage in all_stages:
        info = KILL_CHAIN[stage]
        if stage in detected:
            chain_visual += f"[{info['icon']} {stage[:4]}]→"
        else:
            chain_visual += f"[  ----  ]→"
    chain_visual = chain_visual.rstrip('→')

    lines.append(f"\n  {chain_visual}")
    lines.append(f"\n  Detected  : {', '.join(detected)}")
    if not_detected:
        lines.append(f"  Not seen  : {', '.join(not_detected)}")

    # Recommended actions
    lines.append(f"\n{'─'*65}")
    lines.append("  RECOMMENDED ACTIONS")
    lines.append(f"{'─'*65}")
    if 'Exfiltration' in detected:
        lines.append("  🚨 URGENT: Data exfiltration detected — isolate affected hosts immediately")
    if 'C2_Botnet' in detected:
        lines.append("  🚨 URGENT: C2 channel active — block outbound connections to C2 IPs")
    if 'LateralMovement' in detected:
        lines.append("  ⚠️  WARNING: Lateral movement detected — audit internal access logs")
    if 'WebAttack' in detected:
        lines.append("  ⚠️  WARNING: Web attacks detected — review WAF logs and patch vulnerabilities")
    if 'Reconnaissance' in detected:
        lines.append("  ℹ️  INFO: Reconnaissance detected — attacker is mapping your network")
    if 'DDoS' in detected:
        lines.append("  ℹ️  INFO: DDoS detected — may be smokescreen, check for simultaneous exfil")

    lines.append(f"\n{'='*65}")
    return '\n'.join(lines)


narrative = generate_narrative(kill_chain_summary, attack_events, benign_count)
print(narrative)

# Save narrative to file
narrative_path = OUTPUT_PATH + 'attack_narrative.txt'
with open(narrative_path, 'w', encoding='utf-8') as f:
    f.write(narrative)
print(f"\n       ✅ Saved narrative: {narrative_path}")

# Save events to CSV for dashboard
events_path = OUTPUT_PATH + 'attack_events.csv'
attack_events.to_csv(events_path, index=False)
print(f"       ✅ Saved events   : {events_path}")

# Save kill chain summary as JSON for dashboard
kc_path = OUTPUT_PATH + 'kill_chain_summary.json'
kc_json = {}
for cat, info in kill_chain_summary.items():
    kc_json[cat] = {
        'stage':          info['stage'],
        'icon':           info['icon'],
        'color':          info['color'],
        'desc':           info['desc'],
        'event_count':    int(info['event_count']),
        'first_seen':     str(info['first_seen']),
        'avg_confidence': float(info['avg_confidence']),
        'max_severity':   int(info['max_severity']),
    }
with open(kc_path, 'w') as f:
    json.dump(kc_json, f, indent=2)
print(f"       ✅ Saved kill chain: {kc_path}")


# ── Step 6: Visualizations ────────────────────────────────────────────────────
print("\n[6/6] Generating timeline visualizations...")
plt.style.use('dark_background')

# ── Plot 1: Kill Chain Progress Bar ──
fig, ax = plt.subplots(figsize=(16, 4))
fig.patch.set_facecolor('#0a0a0a')
ax.set_facecolor('#0a0a0a')
ax.set_xlim(0, 6)
ax.set_ylim(0, 1)
ax.axis('off')
fig.suptitle('Attack Kill Chain — Stage Detection',
             fontsize=14, color='white', fontweight='bold', y=0.98)

stages = ['Reconnaissance', 'WebAttack', 'C2_Botnet',
          'LateralMovement', 'Exfiltration', 'DDoS']

for i, stage in enumerate(stages):
    info      = KILL_CHAIN[stage]
    detected  = stage in kill_chain_summary
    x         = i + 0.5
    box_color = info['color'] if detected else '#333333'
    txt_color = 'white'     if detected else '#666666'
    alpha     = 1.0         if detected else 0.4

    # Draw box
    rect = mpatches.FancyBboxPatch(
        (i + 0.05, 0.15), 0.90, 0.70,
        boxstyle="round,pad=0.02",
        facecolor=box_color, edgecolor='white',
        linewidth=1.5, alpha=alpha
    )
    ax.add_patch(rect)

    # Stage label
    short = stage.replace('LateralMovement', 'Lateral').replace('Reconnaissance','Recon')
    ax.text(x, 0.65, f"S{i+1}", ha='center', va='center',
            fontsize=9, color=txt_color, fontweight='bold')
    ax.text(x, 0.50, info['icon'], ha='center', va='center', fontsize=14)
    ax.text(x, 0.32, short, ha='center', va='center',
            fontsize=7, color=txt_color)

    if detected:
        count = kill_chain_summary[stage]['event_count']
        ax.text(x, 0.18, f"{count} events", ha='center', va='center',
                fontsize=6, color=txt_color)

    # Arrow between stages
    if i < len(stages) - 1:
        ax.annotate('', xy=(i + 1.05, 0.50), xytext=(i + 0.95, 0.50),
                    arrowprops=dict(arrowstyle='->', color='white',
                                   lw=1.5, alpha=0.6))

plt.tight_layout()
plt.savefig(OUTPUT_PATH + 'plot_08_killchain.png',
            dpi=150, bbox_inches='tight', facecolor='#0a0a0a')
plt.show()
print("       Saved: plot_08_killchain.png")

# ── Plot 2: Attack Timeline (events over time) ──
fig, axes = plt.subplots(2, 1, figsize=(16, 10))
fig.patch.set_facecolor('#0a0a0a')
fig.suptitle('Attack Timeline — Events Over Time',
             fontsize=14, color='white', fontweight='bold')

# Top: Event scatter plot colored by category
ax1 = axes[0]
ax1.set_facecolor('#111')
for cat, info in KILL_CHAIN.items():
    if cat == 'Benign':
        continue
    cat_events = attack_events[attack_events['predicted'] == cat]
    if len(cat_events) == 0:
        continue
    ax1.scatter(
        cat_events['timestamp'],
        cat_events['severity'],
        c=info['color'], label=f"{info['icon']} {cat}",
        alpha=0.6, s=30, zorder=3
    )
ax1.set_ylabel('Severity (1-10)', color='white')
ax1.set_title('Attack Events by Severity', color='white', fontsize=10)
ax1.tick_params(colors='white', labelsize=7)
ax1.legend(fontsize=7, facecolor='#222', labelcolor='white',
           loc='upper right', ncol=3)
ax1.grid(axis='y', color='#333', linestyle='--', alpha=0.5)
for spine in ax1.spines.values():
    spine.set_edgecolor('#333')

# Bottom: Event count over time (histogram)
ax2 = axes[1]
ax2.set_facecolor('#111')
time_bins = pd.cut(
    attack_events['timestamp'].apply(lambda x: x.timestamp()),
    bins=30
)
bin_counts = attack_events.groupby(time_bins, observed=False).size()
bin_centers = [interval.mid for interval in bin_counts.index]
bin_times   = [datetime.fromtimestamp(t) for t in bin_centers]
ax2.bar(bin_times, bin_counts.values, color='#4488ff',
        alpha=0.7, width=timedelta(minutes=2))
ax2.set_ylabel('Event Count', color='white')
ax2.set_xlabel('Time', color='white')
ax2.set_title('Attack Event Volume Over Time', color='white', fontsize=10)
ax2.tick_params(colors='white', labelsize=7)
ax2.grid(axis='y', color='#333', linestyle='--', alpha=0.5)
for spine in ax2.spines.values():
    spine.set_edgecolor('#333')

plt.tight_layout()
plt.savefig(OUTPUT_PATH + 'plot_09_timeline.png',
            dpi=150, bbox_inches='tight', facecolor='#0a0a0a')
plt.show()
print("       Saved: plot_09_timeline.png")

# ── Plot 3: Severity heatmap by stage ──
fig, axes = plt.subplots(1, 2, figsize=(14, 5))
fig.patch.set_facecolor('#0a0a0a')
fig.suptitle('Attack Severity & Confidence Analysis',
             fontsize=13, color='white', fontweight='bold')

# Severity per category
ax1 = axes[0]
ax1.set_facecolor('#111')
cats_detected  = list(kill_chain_summary.keys())
severities     = [SEVERITY[c] for c in cats_detected]
colors_sev     = [KILL_CHAIN[c]['color'] for c in cats_detected]
bars = ax1.barh(cats_detected, severities, color=colors_sev)
ax1.set_xlim(0, 10)
ax1.set_title('Severity Score per Attack Stage', color='white')
ax1.set_xlabel('Severity (1-10)', color='white')
ax1.tick_params(colors='white', labelsize=8)
for bar, val in zip(bars, severities):
    ax1.text(val + 0.1, bar.get_y() + bar.get_height()/2,
             f'{val}/10', va='center', color='white', fontsize=8)
for spine in ax1.spines.values():
    spine.set_edgecolor('#333')

# Confidence per category
ax2 = axes[1]
ax2.set_facecolor('#111')
confidences = [kill_chain_summary[c]['avg_confidence'] for c in cats_detected]
bars2 = ax2.barh(cats_detected, confidences, color=colors_sev)
ax2.set_xlim(0, 1)
ax2.set_title('Average Model Confidence per Stage', color='white')
ax2.set_xlabel('Confidence (0-1)', color='white')
ax2.tick_params(colors='white', labelsize=8)
for bar, val in zip(bars2, confidences):
    ax2.text(val + 0.01, bar.get_y() + bar.get_height()/2,
             f'{val:.1%}', va='center', color='white', fontsize=8)
for spine in ax2.spines.values():
    spine.set_edgecolor('#333')

plt.tight_layout()
plt.savefig(OUTPUT_PATH + 'plot_10_severity.png',
            dpi=150, bbox_inches='tight', facecolor='#0a0a0a')
plt.show()
print("       Saved: plot_10_severity.png")

# ── Final Summary ──────────────────────────────────────────────────────────────
print("\n" + "=" * 65)
print("  PHASE 4 COMPLETE — TIMELINE ENGINE READY")
print("=" * 65)
print()
print("  Files saved:")
print(f"  ├── attack_events.csv        {len(attack_events):,} attack events")
print(f"  ├── attack_narrative.txt     Human-readable attack story")
print(f"  ├── kill_chain_summary.json  Machine-readable kill chain data")
print(f"  ├── plot_08_killchain.png    Kill chain progress visual")
print(f"  ├── plot_09_timeline.png     Events over time")
print(f"  └── plot_10_severity.png     Severity + confidence")
print()
print("  The timeline engine can now:")
print("  ✅ Classify any network flow into 7 threat categories")
print("  ✅ Map detections to kill chain stages")
print("  ✅ Generate human-readable attack narratives")
print("  ✅ Score severity and confidence per stage")
print("  ✅ Recommend actions based on detected stages")
print()
print("  Next step: Phase 5 — Streamlit Dashboard")
print("  File to build next: dashboard/app.py")
print("=" * 65)