"""
src/regen_narrative.py
Re-generate attack_narrative.txt + kill_chain_summary.json from the
already-saved attack_events.csv — NO model loading required.
Run: python src/regen_narrative.py
"""

import sys
import os
import json
import pandas as pd
from datetime import datetime, timedelta

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PROCESSED_PATH = 'data/processed/'

# ── Kill Chain definition ──────────────────────────────────────────────────
KILL_CHAIN = {
    'Reconnaissance':  {'stage': 1, 'icon': '🔍', 'color': '#ff8800',
                        'desc': 'Attacker maps the network'},
    'WebAttack':       {'stage': 2, 'icon': '🌐', 'color': '#ff4488',
                        'desc': 'Attacker exploits web vulnerabilities'},
    'C2_Botnet':       {'stage': 3, 'icon': '📡', 'color': '#ff44ff',
                        'desc': 'Attacker establishes command channel'},
    'LateralMovement': {'stage': 4, 'icon': '↔️',  'color': '#ffff00',
                        'desc': 'Attacker moves through network'},
    'Exfiltration':    {'stage': 5, 'icon': '📤', 'color': '#4488ff',
                        'desc': 'Attacker steals data'},
    'DDoS':            {'stage': 6, 'icon': '💥', 'color': '#ff4444',
                        'desc': 'Attacker floods as smokescreen'},
    'Benign':          {'stage': 0, 'icon': '✅', 'color': '#00ff88',
                        'desc': 'Normal traffic'},
}

SEVERITY = {
    'Reconnaissance': 3, 'WebAttack': 6, 'C2_Botnet': 8,
    'LateralMovement': 7, 'Exfiltration': 9, 'DDoS': 5, 'Benign': 0,
}

# ── Load existing events ───────────────────────────────────────────────────
print("Loading attack_events.csv ...")
events = pd.read_csv(PROCESSED_PATH + 'attack_events.csv')
events['timestamp'] = pd.to_datetime(events['timestamp'])

attack_events = events[events['predicted'] != 'Benign'].copy()
attack_events = attack_events.sort_values('timestamp').reset_index(drop=True)
benign_count  = (events['predicted'] == 'Benign').sum()

print(f"  Total rows   : {len(events):,}")
print(f"  Attack rows  : {len(attack_events):,}")
print(f"  Benign rows  : {benign_count:,}")

# ── Build kill chain summary ───────────────────────────────────────────────
kill_chain_summary = {}
for category, info in KILL_CHAIN.items():
    if category == 'Benign':
        continue
    stage_events = attack_events[attack_events['predicted'] == category]
    if len(stage_events) == 0:
        continue

    # Check which columns are available
    has_rate = 'rate' in stage_events.columns
    has_size = 'tot_size' in stage_events.columns

    kill_chain_summary[category] = {
        'stage':          info['stage'],
        'icon':           info['icon'],
        'color':          info['color'],
        'desc':           info['desc'],
        'event_count':    len(stage_events),
        'first_seen':     stage_events['timestamp'].min(),
        'last_seen':      stage_events['timestamp'].max(),
        'avg_confidence': float(stage_events['confidence'].mean()),
        'max_severity':   int(SEVERITY.get(category, 0)),
        'avg_rate':       float(stage_events['rate'].mean()) if has_rate else 0.0,
        'avg_size':       float(stage_events['tot_size'].mean()) if has_size else 0.0,
    }

# Sort by stage
kill_chain_summary = dict(
    sorted(kill_chain_summary.items(), key=lambda x: x[1]['stage'])
)

# ── Generate narrative ─────────────────────────────────────────────────────
def generate_narrative(kc_summary, attack_events, benign_count):
    lines = []
    lines.append("=" * 65)
    lines.append("  ATTACK TIMELINE NARRATIVE")
    lines.append("=" * 65)

    if not kc_summary:
        lines.append("\n  ✅ No attacks detected — traffic appears benign")
        return '\n'.join(lines)

    total_attacks = len(attack_events)
    max_severity  = attack_events['severity'].max() if 'severity' in attack_events.columns \
                    else max(SEVERITY.get(c, 0) for c in kc_summary)
    stages_hit    = len(kc_summary)
    threat_level  = ('CRITICAL' if max_severity >= 8 else
                     'HIGH'     if max_severity >= 6 else
                     'MEDIUM'   if max_severity >= 4 else 'LOW')

    lines.append(f"\n  ⚠️  THREAT LEVEL    : {threat_level}")
    lines.append(f"  📊 TOTAL EVENTS    : {total_attacks:,} attack flows detected")
    lines.append(f"  🔗 KILL CHAIN      : {stages_hit} of 6 stages observed")
    lines.append(f"  ✅ BENIGN TRAFFIC  : {benign_count:,} normal flows")

    atk_start = attack_events['timestamp'].min()
    atk_end   = attack_events['timestamp'].max()
    duration  = atk_end - atk_start
    lines.append(f"\n  ⏱️  ATTACK WINDOW   : {atk_start.strftime('%H:%M:%S')} → "
                 f"{atk_end.strftime('%H:%M:%S')} ({str(duration).split('.')[0]})")

    lines.append(f"\n{'─'*65}")
    lines.append("  STAGE-BY-STAGE BREAKDOWN")
    lines.append(f"{'─'*65}")

    prev_time = None
    for cat, info in kc_summary.items():
        first_seen = info['first_seen']
        if hasattr(first_seen, 'strftime'):
            time_str = first_seen.strftime('%H:%M:%S')
        else:
            time_str = str(first_seen)[:8]

        gap_str = ''
        if prev_time:
            gap = info['first_seen'] - prev_time
            # ✅ FIX: clamp negative deltas to zero
            if hasattr(gap, 'total_seconds') and gap.total_seconds() < 0:
                gap = timedelta(0)
            gap_str = f"  (+{str(gap).split('.')[0]} after previous stage)"
        prev_time = info['first_seen']

        lines.append(f"\n  {info['icon']}  Stage {info['stage']} — {cat.upper()}")
        lines.append(f"     Time      : {time_str}{gap_str}")
        lines.append(f"     Events    : {info['event_count']:,} flows")
        lines.append(f"     Confidence: {info['avg_confidence']:.1%}")
        lines.append(f"     Severity  : {'█' * info['max_severity']} ({info['max_severity']}/10)")
        lines.append(f"     Meaning   : {info['desc']}")

        if cat == 'Reconnaissance':
            rate = info['avg_rate']
            lines.append(f"     Detail    : Avg packet rate {rate:.1f}/s — "
                        f"{'fast scan' if rate > 100 else 'slow stealth scan'}")
        elif cat == 'WebAttack':
            lines.append(f"     Detail    : {info['event_count']} web attack attempts detected")
        elif cat == 'C2_Botnet':
            size = info['avg_size']
            lines.append(f"     Detail    : Avg flow size {size:.0f} bytes — "
                        f"{'large C2 payload' if size > 200 else 'small beaconing pattern'}")
        elif cat == 'LateralMovement':
            lines.append("     Detail    : Attacker pivoting to internal hosts")
        elif cat == 'Exfiltration':
            size = info['avg_size']
            lines.append(f"     Detail    : Avg {size:.0f} bytes/flow outbound — "
                        f"{'high volume exfil' if size > 500 else 'slow drip exfil'}")
        elif cat == 'DDoS':
            rate = info['avg_rate']
            lines.append(f"     Detail    : Flood rate {rate:.1f}/s — "
                        "likely smokescreen during exfiltration")

    # Kill chain completion
    all_stages   = ['Reconnaissance','WebAttack','C2_Botnet',
                    'LateralMovement','Exfiltration','DDoS']
    detected     = list(kc_summary.keys())

    lines.append(f"\n{'─'*65}")
    lines.append("  KILL CHAIN COMPLETION")
    lines.append(f"{'─'*65}")

    chain_visual = ''
    for stage in all_stages:
        info = KILL_CHAIN[stage]
        short = stage[:4]
        if stage in detected:
            chain_visual += f"[{info['icon']} {short}]→"
        else:
            chain_visual += f"[  {short}  ]→"
    lines.append(f"\n  {chain_visual.rstrip('→')}")
    lines.append(f"\n  Detected  : {', '.join(detected)}")

    lines.append(f"\n{'─'*65}")
    lines.append("  RECOMMENDED ACTIONS")
    lines.append(f"{'─'*65}")
    if 'Exfiltration'    in detected: lines.append("  🚨 URGENT: Data exfiltration detected — isolate affected hosts immediately")
    if 'C2_Botnet'       in detected: lines.append("  🚨 URGENT: C2 channel active — block outbound connections to C2 IPs")
    if 'LateralMovement' in detected: lines.append("  ⚠️  WARNING: Lateral movement detected — audit internal access logs")
    if 'WebAttack'       in detected: lines.append("  ⚠️  WARNING: Web attacks detected — review WAF logs and patch vulnerabilities")
    if 'Reconnaissance'  in detected: lines.append("  ℹ️  INFO: Reconnaissance detected — attacker is mapping your network")
    if 'DDoS'            in detected: lines.append("  ℹ️  INFO: DDoS detected — may be smokescreen, check for simultaneous exfil")

    lines.append("\n" + "=" * 65)
    return '\n'.join(lines)

narrative = generate_narrative(kill_chain_summary, attack_events, benign_count)

# ── Save outputs ───────────────────────────────────────────────────────────
narrative_path = PROCESSED_PATH + 'attack_narrative.txt'
with open(narrative_path, 'w', encoding='utf-8') as f:
    f.write(narrative)
print(f"\n✅ Saved: {narrative_path}")

# Save kill_chain_summary.json (convert timestamps to strings)
kc_json = {}
for cat, info in kill_chain_summary.items():
    kc_json[cat] = {k: str(v) if hasattr(v, 'strftime') else v
                    for k, v in info.items()}

kc_path = PROCESSED_PATH + 'kill_chain_summary.json'
with open(kc_path, 'w', encoding='utf-8') as f:
    json.dump(kc_json, f, indent=2)
print(f"✅ Saved: {kc_path}")

print("\n── Narrative Preview ──")
print(narrative[:800])
print("\n✅ Done! Refresh the dashboard to see clean timestamps.")
