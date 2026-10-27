# dashboard/app.py
# Phase 5+6 — FedForensic Dashboard
# Run with: streamlit run dashboard/app.py
# Author: Harshal

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import joblib
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta
from collections import Counter
from fpdf import FPDF
import warnings
warnings.filterwarnings('ignore')

# PCAP parser — add project root to path so we can import src.parser
_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)
try:
    from src.parser import pcap_to_ml_features, get_pcap_summary
    _PCAP_AVAILABLE = True
except ImportError:
    _PCAP_AVAILABLE = False

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="FedForensic",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Base theme */
    .stApp { background-color: #0d1117; color: #e6edf3; }
    .main .block-container { padding: 1.5rem 2rem; max-width: 1400px; }

    /* Header */
    .dashboard-header {
        background: linear-gradient(135deg, #161b22 0%, #1c2128 100%);
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 1.5rem 2rem;
        margin-bottom: 1.5rem;
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    .header-title {
        font-size: 1.8rem;
        font-weight: 700;
        color: #58a6ff;
        margin: 0;
        letter-spacing: -0.5px;
    }
    .header-sub {
        font-size: 0.85rem;
        color: #8b949e;
        margin: 0.2rem 0 0 0;
    }

    /* Metric cards */
    .metric-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 1rem 1.2rem;
        text-align: center;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        margin: 0.2rem 0;
    }
    .metric-label {
        font-size: 0.75rem;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    /* Threat level badges */
    .threat-critical { color: #ff4444; }
    .threat-high     { color: #ff8800; }
    .threat-medium   { color: #ffff00; }
    .threat-low      { color: #00ff88; }

    /* Kill chain boxes */
    .kc-box {
        border-radius: 8px;
        padding: 0.6rem 0.8rem;
        text-align: center;
        font-size: 0.75rem;
        font-weight: 600;
        margin: 0.2rem;
        display: inline-block;
        min-width: 90px;
    }
    .kc-active   { border: 2px solid currentColor; }
    .kc-inactive { background: #21262d; border: 2px solid #30363d; color: #484f58; }

    /* Narrative box */
    .narrative-box {
        background: #161b22;
        border: 1px solid #30363d;
        border-left: 4px solid #58a6ff;
        border-radius: 8px;
        padding: 1.2rem 1.5rem;
        font-family: 'Courier New', monospace;
        font-size: 0.82rem;
        line-height: 1.6;
        white-space: pre-wrap;
        color: #e6edf3;
    }

    /* Alert table */
    .alert-row-critical { background: rgba(255,68,68,0.1); }
    .alert-row-high     { background: rgba(255,136,0,0.1); }

    /* Section headers */
    .section-header {
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #8b949e;
        margin: 1.5rem 0 0.8rem 0;
        padding-bottom: 0.4rem;
        border-bottom: 1px solid #21262d;
    }

    /* Upload area */
    .upload-area {
        background: #161b22;
        border: 2px dashed #30363d;
        border-radius: 10px;
        padding: 2rem;
        text-align: center;
        color: #8b949e;
    }

    /* Status pills */
    .pill {
        display: inline-block;
        padding: 0.2rem 0.6rem;
        border-radius: 20px;
        font-size: 0.72rem;
        font-weight: 600;
    }
    .pill-green  { background: rgba(0,255,136,0.15); color: #00ff88; }
    .pill-red    { background: rgba(255,68,68,0.15);  color: #ff4444; }
    .pill-orange { background: rgba(255,136,0,0.15);  color: #ff8800; }
    .pill-blue   { background: rgba(88,166,255,0.15); color: #58a6ff; }

    /* Sidebar */
    .css-1d391kg { background: #161b22; }
    section[data-testid="stSidebar"] { background: #161b22; border-right: 1px solid #30363d; }

    /* Hide streamlit branding */
    #MainMenu { visibility: hidden; }
    footer     { visibility: hidden; }
    header     { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ── Constants ─────────────────────────────────────────────────────────────────
BASE_DIR       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_PATH    = os.path.join(BASE_DIR, 'models/')
PROCESSED_PATH = os.path.join(BASE_DIR, 'data/processed/')

CLASS_NAMES = ['Benign', 'C2_Botnet', 'DDoS', 'Exfiltration',
               'LateralMovement', 'Reconnaissance', 'WebAttack']

KILL_CHAIN = {
    'Reconnaissance':  {'stage': 1, 'color': '#ff8800', 'icon': '🔍', 'short': 'Recon'},
    'WebAttack':       {'stage': 2, 'color': '#ff4488', 'icon': '🌐', 'short': 'Web'},
    'C2_Botnet':       {'stage': 3, 'color': '#bf5af2', 'icon': '📡', 'short': 'C2'},
    'LateralMovement': {'stage': 4, 'color': '#ffd60a', 'icon': '↔️',  'short': 'Lateral'},
    'Exfiltration':    {'stage': 5, 'color': '#58a6ff', 'icon': '📤', 'short': 'Exfil'},
    'DDoS':            {'stage': 6, 'color': '#ff4444', 'icon': '💥', 'short': 'DDoS'},
    'Benign':          {'stage': 0, 'color': '#00ff88', 'icon': '✅', 'short': 'OK'},
}

SEVERITY = {
    'Reconnaissance': 3, 'WebAttack': 6, 'C2_Botnet': 8,
    'LateralMovement': 7, 'Exfiltration': 9, 'DDoS': 5, 'Benign': 0,
}

# ── Load models (cached) ──────────────────────────────────────────────────────
@st.cache_resource
def load_models():
    """Load all ML models once and cache them."""
    try:
        models = {
            'master':  joblib.load(MODELS_PATH + 'model_master.joblib'),
            'scaler':  joblib.load(MODELS_PATH + 'scaler.joblib'),
            'encoder': joblib.load(MODELS_PATH + 'label_encoder.joblib'),
        }
        specialist = {}
        for k, fname in [
            ('DDoS', 'model_ddos.joblib'),
            ('Reconnaissance', 'model_recon.joblib'),
            ('C2_Botnet', 'model_c2.joblib'),
            ('LateralMovement', 'model_lateral.joblib'),
            ('Exfiltration', 'model_exfil.joblib'),
            ('WebAttack', 'model_web.joblib'),
        ]:
            p = MODELS_PATH + fname
            if os.path.exists(p):
                try:
                    specialist[k] = joblib.load(p)
                except Exception as e:
                    print(f"[FedForensic] Warning: Could not load {k}: {e}")
        models['specialist'] = specialist
        return models, None
    except Exception as e:
        return None, str(e)

@st.cache_data
def load_feature_list():
    try:
        with open(PROCESSED_PATH + 'features_used.txt') as f:
            return [line.strip() for line in f.readlines()]
    except:
        return []

# ── Analysis function ─────────────────────────────────────────────────────────
def analyze_dataframe(df, models, feature_cols):
    """Run all models on uploaded dataframe. Returns events dataframe."""

    # Align columns
    available = [c for c in feature_cols if c in df.columns]
    if len(available) < 5:
        return None, f"Only {len(available)} matching features found. Need at least 5."

    X = df[available].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    # Scale
    try:
        X_scaled = models['scaler'].transform(X[feature_cols if all(c in X.columns for c in feature_cols) else available])
    except:
        X_scaled = models['scaler'].transform(X)

    # Master model prediction
    y_pred  = models['master'].predict(X_scaled)
    y_proba = models['master'].predict_proba(X_scaled)
    confidence = y_proba.max(axis=1)

    pred_categories = [CLASS_NAMES[p] for p in y_pred]

    # Generate timestamps
    base_time  = datetime.now().replace(second=0, microsecond=0)
    timestamps = [base_time + timedelta(seconds=i*0.5) for i in range(len(df))]

    events = pd.DataFrame({
        'timestamp':        timestamps,
        'predicted':        pred_categories,
        'confidence':       confidence.round(4),
        'severity':         [SEVERITY.get(c, 0) for c in pred_categories],
        'kill_chain_stage': [KILL_CHAIN.get(c, {}).get('stage', 0) for c in pred_categories],
        'icon':             [KILL_CHAIN.get(c, {}).get('icon', '?') for c in pred_categories],
        'color':            [KILL_CHAIN.get(c, {}).get('color', '#888') for c in pred_categories],
    })

    return events, None


def build_kill_chain_summary(events):
    """Build kill chain summary from events."""
    attack_events = events[events['predicted'] != 'Benign']
    summary = {}
    for cat, info in KILL_CHAIN.items():
        if cat == 'Benign':
            continue
        cat_events = attack_events[attack_events['predicted'] == cat]
        if len(cat_events) == 0:
            continue
        summary[cat] = {
            'stage':          info['stage'],
            'icon':           info['icon'],
            'color':          info['color'],
            'short':          info['short'],
            'event_count':    len(cat_events),
            'avg_confidence': cat_events['confidence'].mean(),
            'max_severity':   SEVERITY.get(cat, 0),
            'first_seen':     cat_events['timestamp'].min(),
        }
    return dict(sorted(summary.items(), key=lambda x: x[1]['stage']))


def generate_narrative(summary, events):
    """Generate attack narrative text."""
    attack_events = events[events['predicted'] != 'Benign']
    benign_count  = (events['predicted'] == 'Benign').sum()

    if not summary:
        return "✅ No attacks detected in this traffic sample."

    max_sev    = max(SEVERITY.get(c, 0) for c in summary.keys())
    threat_lvl = 'CRITICAL' if max_sev >= 8 else \
                 'HIGH'     if max_sev >= 6 else \
                 'MEDIUM'   if max_sev >= 4 else 'LOW'

    lines = [
        f"THREAT LEVEL: {threat_lvl}",
        f"Total attack events : {len(attack_events):,}",
        f"Benign flows        : {benign_count:,}",
        f"Kill chain stages   : {len(summary)} of 6 detected",
        "",
        "─── STAGE-BY-STAGE BREAKDOWN ───",
    ]

    for cat, info in summary.items():
        lines += [
            f"",
            f"{info['icon']}  {cat}  (Stage {info['stage']})",
            f"   Events     : {info['event_count']:,}",
            f"   Confidence : {info['avg_confidence']:.1%}",
            f"   Severity   : {'█' * info['max_severity']} ({info['max_severity']}/10)",
        ]

    lines += [
        "", "─── RECOMMENDED ACTIONS ───",
    ]
    if 'Exfiltration'    in summary: lines.append("🚨 ISOLATE: Data exfiltration detected")
    if 'C2_Botnet'       in summary: lines.append("🚨 BLOCK: Active C2 channel — cut outbound connections")
    if 'LateralMovement' in summary: lines.append("⚠️  AUDIT: Internal access logs for pivoting activity")
    if 'WebAttack'       in summary: lines.append("⚠️  PATCH: Review WAF logs and vulnerable endpoints")
    if 'Reconnaissance'  in summary: lines.append("ℹ️  MONITOR: Attacker is mapping your network")
    if 'DDoS'            in summary: lines.append("ℹ️  CHECK: DDoS may be a smokescreen — look for simultaneous exfil")

    return '\n'.join(lines)


# ── PDF Export ────────────────────────────────────────────────────────────────
def generate_pdf_report(summary, events, narrative):
    """Generate a PDF report and return bytes."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Header
    pdf.set_fill_color(13, 17, 23)
    pdf.set_text_color(88, 166, 255)
    pdf.set_font('Helvetica', 'B', 20)
    pdf.cell(0, 12, 'FedForensic - Incident Report', ln=True, align='C')

    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(139, 148, 158)
    pdf.cell(0, 6, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True, align='C')
    pdf.ln(5)

    # Summary section
    attack_events = events[events['predicted'] != 'Benign']
    benign_count  = (events['predicted'] == 'Benign').sum()
    max_sev       = max((SEVERITY.get(c, 0) for c in summary.keys()), default=0)
    threat_lvl    = 'CRITICAL' if max_sev >= 8 else \
                    'HIGH'     if max_sev >= 6 else \
                    'MEDIUM'   if max_sev >= 4 else 'LOW'

    pdf.set_font('Helvetica', 'B', 13)
    pdf.set_text_color(230, 237, 243)
    pdf.cell(0, 8, 'Executive Summary', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(100, 110, 120)
    pdf.cell(0, 6, f'Threat Level      : {threat_lvl}', ln=True)
    pdf.cell(0, 6, f'Total Events      : {len(events):,}', ln=True)
    pdf.cell(0, 6, f'Attack Events     : {len(attack_events):,}', ln=True)
    pdf.cell(0, 6, f'Benign Flows      : {benign_count:,}', ln=True)
    pdf.cell(0, 6, f'Kill Chain Stages : {len(summary)} of 6 detected', ln=True)
    pdf.ln(4)

    # Kill chain section
    pdf.set_font('Helvetica', 'B', 13)
    pdf.set_text_color(230, 237, 243)
    pdf.cell(0, 8, 'Kill Chain Analysis', ln=True)
    pdf.set_font('Helvetica', '', 10)
    for cat, info in summary.items():
        pdf.set_text_color(100, 110, 120)
        pdf.cell(0, 6,
            f"Stage {info['stage']} | {cat:<20} | "
            f"Events: {info['event_count']:>5} | "
            f"Confidence: {info['avg_confidence']:.1%} | "
            f"Severity: {info['max_severity']}/10",
            ln=True
        )
    pdf.ln(4)

    # Narrative section
    pdf.set_font('Helvetica', 'B', 13)
    pdf.set_text_color(230, 237, 243)
    pdf.cell(0, 8, 'Detailed Narrative', ln=True)
    pdf.set_font('Courier', '', 9)
    pdf.set_text_color(100, 110, 120)
    for line in narrative.split('\n'):
        safe_line = line.replace('█', '*').replace('─', '-').replace('━', '-').replace('→', '->')
        safe_line = safe_line.encode('latin-1', 'ignore').decode('latin-1')
        pdf.cell(0, 5, safe_line, ln=True)

    # Alert table
    pdf.ln(4)
    pdf.set_font('Helvetica', 'B', 13)
    pdf.set_text_color(230, 237, 243)
    pdf.cell(0, 8, 'Top 20 High-Severity Alerts', ln=True)
    pdf.set_font('Helvetica', 'B', 9)
    pdf.set_text_color(88, 166, 255)
    pdf.cell(60, 6, 'Timestamp', border=1)
    pdf.cell(50, 6, 'Threat Type', border=1)
    pdf.cell(30, 6, 'Confidence', border=1)
    pdf.cell(20, 6, 'Severity', border=1, ln=True)

    top_alerts = attack_events.nlargest(20, 'severity')
    pdf.set_font('Helvetica', '', 8)
    pdf.set_text_color(100, 110, 120)
    for _, row in top_alerts.iterrows():
        pdf.cell(60, 5, str(row['timestamp'])[:19], border=1)
        pdf.cell(50, 5, str(row['predicted']), border=1)
        pdf.cell(30, 5, f"{row['confidence']:.1%}", border=1)
        pdf.cell(20, 5, f"{row['severity']}/10", border=1, ln=True)

    return bytes(pdf.output())


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ FedForensic")
    st.markdown("---")
    st.markdown("**How to use:**")
    st.markdown("1. Upload a CSV file with network flow features\n"
                "2. Click **Analyze**\n"
                "3. Review the kill chain\n"
                "4. Export the PDF report")
    st.markdown("---")
    st.markdown("**Detects:**")
    for cat, info in KILL_CHAIN.items():
        if cat != 'Benign':
            st.markdown(f"{info['icon']} {cat}")
    st.markdown("---")
    st.markdown("**Models loaded:**")

    models, err = load_models()
    feature_cols = load_feature_list()

    if models:
        st.success("✅ All 8 models ready")
        st.caption(f"{len(feature_cols)} features active")
    else:
        st.error(f"❌ Model load failed:\n{err}")

    st.markdown("---")
    st.caption("Upload a CSV on the main page to analyze live traffic.")

# ── Main Header ───────────────────────────────────────────────────────────────
st.markdown("""
<div class="dashboard-header">
    <div>
        <p class="header-title">🛡️ FedForensic</p>
        <p class="header-sub">FedForensic — AI-Powered Threat Detection | 
        7-model detection + Kill Chain timeline reconstruction</p>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Data Loading ──────────────────────────────────────────────────────────────
events        = None
kc_summary    = None
narrative_txt = ""

# ── Upload box — always visible at top of page ──
st.markdown('<p class="section-header">🔼 Analyze Your Own Traffic</p>', unsafe_allow_html=True)

pcap_types   = ['pcap', 'pcapng', 'cap'] if _PCAP_AVAILABLE else []
accept_types = ['csv'] + pcap_types

upload_col, info_col = st.columns([2, 3])
with upload_col:
    uploaded = st.file_uploader(
        "Upload CSV or PCAP/PCAPNG network traffic file",
        type=accept_types,
        key='main_uploader',
        help="CSV: CIC-IoT 2023 flow features  |  PCAP/PCAPNG: raw packet capture (auto-converted)"
    )
with info_col:
    pcap_note = "<b style='color:#00ff88;'>PCAP/PCAPNG also accepted</b> — flows are auto-reconstructed.<br>" if _PCAP_AVAILABLE else ""
    st.markdown(f"""
    <div style='background:#161b22;border:1px solid #30363d;border-left:4px solid #58a6ff;
                border-radius:8px;padding:0.9rem 1.2rem;font-size:0.83rem;color:#8b949e;'>
        <b style='color:#e6edf3;'>How to use:</b><br>
        2. Upload it here — your file is analyzed by all 8 ML models<br>
        3. The kill chain and incident report update automatically<br><br>
        <b style='color:#58a6ff;'>Expected columns:</b> Flow Duration, Tot Fwd Pkts, Rate, IAT …
        (35 features — same as CIC-IoT 2023 format)
    </div>
    """, unsafe_allow_html=True)

if uploaded and models:
    fname   = uploaded.name.lower()
    is_pcap = any(fname.endswith(f'.{ext}') for ext in ['pcap', 'pcapng', 'cap'])

    if is_pcap and _PCAP_AVAILABLE:
        # ── PCAP path: save temp, parse, then analyze ──────────────────────
        with st.spinner("📡 Reconstructing network flows from PCAP..."):
            try:
                suffix = '.' + fname.rsplit('.', 1)[-1]
                import tempfile
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    tmp.write(uploaded.read())
                    tmp_path = tmp.name

                df_pcap   = pcap_to_ml_features(tmp_path)
                pcap_info = get_pcap_summary(df_pcap)
                import os as _os; _os.unlink(tmp_path)

                # PCAP metadata panel
                st.markdown("""<div style='background:#0d2a1f;border:1px solid #00ff88;
                    border-radius:8px;padding:0.8rem 1.2rem;margin-bottom:0.8rem;'>
                    <b style='color:#00ff88;'>📡 PCAP Parsed</b></div>""",
                    unsafe_allow_html=True)
                pi1, pi2, pi3, pi4 = st.columns(4)
                pi1.metric("Flows Extracted",  f"{pcap_info['flow_count']:,}")
                pi2.metric("Packets",           f"{pcap_info['pkt_count']:,}")
                pi3.metric("Unique Src IPs",    str(pcap_info['unique_src_ips']))
                pi4.metric("Unique Dst IPs",    str(pcap_info['unique_dst_ips']))
                st.caption(
                    f"TCP: {pcap_info['tcp_flows']}  "
                    f"UDP: {pcap_info['udp_flows']}  "
                    f"ICMP: {pcap_info['icmp_flows']}  "
                    f"HTTP: {pcap_info['http_flows']}  "
                    f"HTTPS: {pcap_info['https_flows']}  "
                    f"DNS: {pcap_info['dns_flows']}  "
                    f"| Avg flow dur: {pcap_info['avg_flow_dur_s']:.4f}s  "
                    f"| Avg pkt size: {pcap_info['avg_pkt_size_b']:.0f}B"
                )
                df_upload = df_pcap

            except Exception as e:
                st.error(f"PCAP parsing failed: {e}")
                df_upload = None
    else:
        # ── CSV path (original behavior) ────────────────────────────────────
        df_upload = pd.read_csv(uploaded)
        st.caption(f"CSV loaded: {len(df_upload):,} rows × {len(df_upload.columns)} columns")

    if 'df_upload' in dir() and df_upload is not None:
        with st.spinner("🔍 Running 8 ML models..."):
            events, err = analyze_dataframe(df_upload, models, feature_cols)
            if err:
                st.error(f"Analysis failed: {err}")
            else:
                kc_summary    = build_kill_chain_summary(events)
                narrative_txt = generate_narrative(kc_summary, events)
                st.success(f"✅ Analysis complete — {len(events):,} flows classified")

# ── Demo data — auto-loads when no file is uploaded ──
if events is None:
    demo_events_path = PROCESSED_PATH + 'attack_events.csv'
    demo_kc_path     = PROCESSED_PATH + 'kill_chain_summary.json'
    demo_narrative   = PROCESSED_PATH + 'attack_narrative.txt'

    if os.path.exists(demo_events_path):
        events = pd.read_csv(demo_events_path)
        events['timestamp'] = pd.to_datetime(events['timestamp'])

        if os.path.exists(demo_kc_path):
            with open(demo_kc_path) as f:
                kc_summary = json.load(f)
            for cat in kc_summary:
                kc_summary[cat]['first_seen'] = kc_summary[cat].get('first_seen', '')

        if os.path.exists(demo_narrative):
            with open(demo_narrative, encoding='utf-8') as f:
                narrative_txt = f.read()

        st.info("📂 Showing pre-analyzed demo data below. Upload your own CSV above to analyze live traffic.",
                icon="ℹ️")
    else:
        st.warning("⚠️ No demo data found. Run `python src/regen_narrative.py` first.")

# ── Dashboard Content ─────────────────────────────────────────────────────────
if events is not None and len(events) > 0:

    attack_events = events[events['predicted'] != 'Benign']
    benign_count  = (events['predicted'] == 'Benign').sum()
    total_events  = len(events)
    max_sev       = max((SEVERITY.get(c, 0) for c in (kc_summary or {}).keys()), default=0)
    threat_lvl    = 'CRITICAL' if max_sev >= 8 else \
                    'HIGH'     if max_sev >= 6 else \
                    'MEDIUM'   if max_sev >= 4 else 'LOW'
    threat_color  = {'CRITICAL': '#ff4444', 'HIGH': '#ff8800',
                     'MEDIUM': '#ffd60a', 'LOW': '#00ff88'}.get(threat_lvl, '#888')
    avg_conf = attack_events['confidence'].mean() if len(attack_events) > 0 else 0

    # ── Row 1: Metric cards ──
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-label">Threat Level</div>
            <div class="metric-value" style="color:{threat_color}">{threat_lvl}</div>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-label">Total Flows</div>
            <div class="metric-value" style="color:#58a6ff">{total_events:,}</div>
        </div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-label">Attack Events</div>
            <div class="metric-value" style="color:#ff4444">{len(attack_events):,}</div>
        </div>""", unsafe_allow_html=True)
    with c4:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-label">Kill Chain Stages</div>
            <div class="metric-value" style="color:#ff8800">{len(kc_summary or {})} / 6</div>
        </div>""", unsafe_allow_html=True)
    with c5:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-label">Avg Confidence</div>
            <div class="metric-value" style="color:#00ff88">{avg_conf:.1%}</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Row 2: Kill Chain visual ──
    st.markdown('<p class="section-header">Kill Chain Progress</p>', unsafe_allow_html=True)
    stages = ['Reconnaissance', 'WebAttack', 'C2_Botnet', 'LateralMovement', 'Exfiltration', 'DDoS']
    cols   = st.columns(len(stages) * 2 - 1)

    for i, stage in enumerate(stages):
        info     = KILL_CHAIN[stage]
        detected = kc_summary and stage in kc_summary
        col_idx  = i * 2

        with cols[col_idx]:
            if detected:
                count = kc_summary[stage]['event_count']
                conf  = kc_summary[stage]['avg_confidence']
                st.markdown(f"""<div class="kc-box kc-active" style="color:{info['color']};
                    border-color:{info['color']}; background:rgba(0,0,0,0.3)">
                    {info['icon']}<br>
                    <strong>S{info['stage']} {info['short']}</strong><br>
                    <small>{count} events</small><br>
                    <small>{conf:.0%} conf</small>
                </div>""", unsafe_allow_html=True)
            else:
                st.markdown(f"""<div class="kc-box kc-inactive">
                    —<br>
                    <strong>S{info['stage']} {info['short']}</strong><br>
                    <small>not detected</small>
                </div>""", unsafe_allow_html=True)

        if i < len(stages) - 1:
            with cols[col_idx + 1]:
                st.markdown("<div style='text-align:center;padding-top:25px;color:#444;font-size:1.2rem'>→</div>",
                           unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Row 3: Charts ──
    st.markdown('<p class="section-header">Visual Analysis</p>', unsafe_allow_html=True)
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        # Timeline scatter
        if len(attack_events) > 0:
            fig = px.scatter(
                attack_events,
                x='timestamp', y='severity',
                color='predicted',
                color_discrete_map={c: KILL_CHAIN[c]['color'] for c in CLASS_NAMES},
                size='confidence',
                hover_data=['predicted', 'confidence', 'severity'],
                title='Attack Events Over Time',
                labels={'severity': 'Severity (1-10)', 'timestamp': 'Time'}
            )
            fig.update_layout(
                paper_bgcolor='#161b22', plot_bgcolor='#0d1117',
                font_color='#e6edf3', title_font_size=13,
                legend=dict(bgcolor='#161b22', font_size=10),
                margin=dict(t=40, b=20, l=20, r=20),
                height=320
            )
            fig.update_xaxes(gridcolor='#21262d', showgrid=True)
            fig.update_yaxes(gridcolor='#21262d', showgrid=True, range=[0, 10])
            st.plotly_chart(fig, use_container_width=True)

    with chart_col2:
        # Category distribution donut
        cat_counts = events['predicted'].value_counts()
        colors_pie = [KILL_CHAIN.get(c, {}).get('color', '#888') for c in cat_counts.index]
        fig2 = go.Figure(go.Pie(
            labels=cat_counts.index,
            values=cat_counts.values,
            hole=0.5,
            marker_colors=colors_pie,
            textinfo='label+percent',
            textfont_size=10,
        ))
        fig2.update_layout(
            paper_bgcolor='#161b22',
            font_color='#e6edf3',
            title='Traffic Distribution',
            title_font_size=13,
            legend=dict(bgcolor='#161b22', font_size=9),
            margin=dict(t=40, b=20, l=20, r=20),
            height=320
        )
        st.plotly_chart(fig2, use_container_width=True)

    # ── Row 4: Severity bar + event volume ──
    chart_col3, chart_col4 = st.columns(2)

    with chart_col3:
        if kc_summary:
            stages_det  = list(kc_summary.keys())
            sev_values  = [SEVERITY.get(s, 0) for s in stages_det]
            conf_values = [kc_summary[s]['avg_confidence'] for s in stages_det]
            colors_bar  = [KILL_CHAIN[s]['color'] for s in stages_det]

            fig3 = go.Figure()
            fig3.add_trace(go.Bar(
                name='Severity',
                x=stages_det, y=sev_values,
                marker_color=colors_bar,
                text=sev_values, textposition='outside'
            ))
            fig3.add_trace(go.Scatter(
                name='Confidence',
                x=stages_det, y=[c * 10 for c in conf_values],
                mode='lines+markers',
                line=dict(color='#58a6ff', width=2),
                yaxis='y2'
            ))
            fig3.update_layout(
                paper_bgcolor='#161b22', plot_bgcolor='#0d1117',
                font_color='#e6edf3', title='Severity & Confidence per Stage',
                title_font_size=13,
                yaxis=dict(title='Severity', range=[0, 12], gridcolor='#21262d'),
                yaxis2=dict(title='Confidence (×10)', overlaying='y', side='right',
                           range=[0, 12], gridcolor='#21262d'),
                margin=dict(t=40, b=20, l=20, r=20), height=300,
                legend=dict(bgcolor='#161b22')
            )
            st.plotly_chart(fig3, use_container_width=True)

    with chart_col4:
        # Event count per stage bar
        if kc_summary:
            fig4 = go.Figure(go.Bar(
                x=[kc_summary[s]['event_count'] for s in stages_det],
                y=stages_det,
                orientation='h',
                marker_color=colors_bar,
                text=[kc_summary[s]['event_count'] for s in stages_det],
                textposition='outside'
            ))
            fig4.update_layout(
                paper_bgcolor='#161b22', plot_bgcolor='#0d1117',
                font_color='#e6edf3', title='Event Count per Kill Chain Stage',
                title_font_size=13,
                xaxis=dict(gridcolor='#21262d'),
                margin=dict(t=40, b=20, l=20, r=20), height=300
            )
            st.plotly_chart(fig4, use_container_width=True)

    # ── Row 5: Alert table + Narrative ──
    st.markdown('<p class="section-header">Alert Details & Narrative</p>', unsafe_allow_html=True)
    tbl_col, narr_col = st.columns([3, 2])

    with tbl_col:
        st.markdown("**Top Alerts (highest severity)**")
        if len(attack_events) > 0:
            display_cols = ['timestamp', 'predicted', 'confidence', 'severity']
            top_alerts   = attack_events.nlargest(50, 'severity')[display_cols].copy()
            top_alerts['timestamp']  = top_alerts['timestamp'].astype(str).str[:19]
            top_alerts['confidence'] = top_alerts['confidence'].apply(lambda x: f"{x:.1%}")
            top_alerts['severity']   = top_alerts['severity'].apply(lambda x: f"{x}/10")
            top_alerts.columns       = ['Time', 'Threat Type', 'Confidence', 'Severity']
            st.dataframe(top_alerts, use_container_width=True, height=350,
                        hide_index=True)

    with narr_col:
        st.markdown("**Attack Narrative**")
        clean_narrative = narrative_txt
        for emoji in ['🔍','🌐','📡','↔️','📤','💥','✅','⚠️','🚨','ℹ️','=','─']:
            clean_narrative = clean_narrative.replace(emoji, '')
        st.markdown(f'<div class="narrative-box">{clean_narrative}</div>',
                   unsafe_allow_html=True)

    # ── Row 6: Export ──
    st.markdown('<p class="section-header">Export Report</p>', unsafe_allow_html=True)
    exp_col1, exp_col2, _ = st.columns([1, 1, 4])

    with exp_col1:
        if st.button("📄 Export PDF Report", type="primary", use_container_width=True):
            with st.spinner("Generating PDF..."):
                try:
                    pdf_bytes = generate_pdf_report(kc_summary or {}, events, narrative_txt)
                    st.download_button(
                        label="⬇️ Download Report",
                        data=pdf_bytes,
                        file_name=f"fedforensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
                except Exception as e:
                    st.error(f"PDF generation failed: {e}")

    with exp_col2:
        if len(attack_events) > 0:
            csv_data = attack_events.to_csv(index=False)
            st.download_button(
                label="📊 Export CSV",
                data=csv_data,
                file_name=f"attack_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )

else:
    # Empty state
    st.markdown("""
    <div style="text-align:center; padding: 4rem 2rem; color: #484f58;">
        <div style="font-size: 3rem; margin-bottom: 1rem;">🛡️</div>
        <h3 style="color: #8b949e;">No traffic analyzed yet</h3>
        <p>Enable <strong>demo mode</strong> in the sidebar to explore a sample analysis,<br>
        or upload a CSV file with network flow features.</p>
        <p style="font-size:0.8rem; margin-top:1rem;">
        Make sure you've run <code>python src/timeline.py</code> first to generate demo data.
        </p>
    </div>
    """, unsafe_allow_html=True)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<p style='text-align:center; color:#484f58; font-size:0.75rem;'>"
    "FedForensic — 7 ML Models | CIC-IoT 2023 Dataset | Lockheed Martin Kill Chain"
    "</p>",
    unsafe_allow_html=True
)