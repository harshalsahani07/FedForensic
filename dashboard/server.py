# dashboard/server.py
# FedForensic — FastAPI REST Backend
# Start: uvicorn dashboard.server:app --host 0.0.0.0 --port 8501 --reload

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

ROOT          = Path(__file__).resolve().parent.parent
MODELS_DIR    = ROOT / "models"
PROCESSED_DIR = ROOT / "data" / "processed"
WEB_DIR       = Path(__file__).resolve().parent / "web"

sys.path.insert(0, str(ROOT))
from src.parser import pcap_to_ml_features, get_pcap_summary, ML_FEATURES  # noqa: E402

# ─────────────────────────────────────────────────────────────────────────────
# Domain knowledge: class names, kill chain metadata
# ─────────────────────────────────────────────────────────────────────────────
CLASS_NAMES = [
    "Benign", "C2_Botnet", "DDoS", "Exfiltration",
    "LateralMovement", "Reconnaissance", "WebAttack",
]

KILL_CHAIN_META = {
    "Reconnaissance":  {"stage": 1, "icon": "🔍", "color": "#f59e0b", "short": "Recon",    "severity": 3},
    "WebAttack":       {"stage": 2, "icon": "🌐", "color": "#ec4899", "short": "Web Atk",  "severity": 6},
    "C2_Botnet":       {"stage": 3, "icon": "📡", "color": "#8b5cf6", "short": "C2/Botnet","severity": 8},
    "LateralMovement": {"stage": 4, "icon": "↔",  "color": "#f97316", "short": "Lateral",  "severity": 7},
    "Exfiltration":    {"stage": 5, "icon": "📤", "color": "#3b82f6", "short": "Exfil",    "severity": 9},
    "DDoS":            {"stage": 6, "icon": "💥", "color": "#ef4444", "short": "DDoS",     "severity": 5},
    "Benign":          {"stage": 0, "icon": "✓",  "color": "#10b981", "short": "Benign",   "severity": 0},
}

app = FastAPI(title="FedForensic API", version="1.0.0", docs_url="/api/docs")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ─────────────────────────────────────────────────────────────────────────────
# Model cache — loaded once on startup, shared for all requests
# ─────────────────────────────────────────────────────────────────────────────
_models: dict = {}


def _load_models() -> dict:
    global _models
    if _models:
        return _models
    try:
        _models = {
            "master":  joblib.load(MODELS_DIR / "model_master.joblib"),
            "scaler":  joblib.load(MODELS_DIR / "scaler.joblib"),
            "encoder": joblib.load(MODELS_DIR / "label_encoder.joblib"),
        }
        specialist_names = ["ddos", "recon", "c2", "lateral", "exfil", "web", "malware"]
        loaded_specialists = []
        for name in specialist_names:
            p = MODELS_DIR / f"model_{name}.joblib"
            if p.exists():
                try:
                    _models[name] = joblib.load(p)
                    loaded_specialists.append(name)
                except Exception as spec_err:
                    print(f"[FedForensic] Warning: Specialist '{name}' could not be loaded ({spec_err}). Continuing without it.")
        print(f"[FedForensic] Models ready — master + {len(loaded_specialists)} specialists")
        return _models
    except Exception as exc:
        raise RuntimeError(f"Model load failed: {exc}") from exc


@app.on_event("startup")
async def on_startup():
    _load_models()


# ─────────────────────────────────────────────────────────────────────────────
# Core inference pipeline
# ─────────────────────────────────────────────────────────────────────────────
def _get_feature_list() -> list[str]:
    feat_path = PROCESSED_DIR / "features_used.txt"
    if feat_path.exists():
        return [l.strip() for l in feat_path.read_text().splitlines() if l.strip()]
    return ML_FEATURES


def _infer(df: pd.DataFrame, models: dict) -> pd.DataFrame:
    feature_list = _get_feature_list()
    available = [c for c in feature_list if c in df.columns]
    if len(available) < 5:
        raise ValueError(f"Only {len(available)} recognized feature columns found (need ≥5). "
                         "Make sure you're uploading a CIC-IoT 2023 formatted CSV.")

    X = df[available].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    X_sc       = models["scaler"].transform(X)
    y_pred     = models["master"].predict(X_sc)
    y_proba    = models["master"].predict_proba(X_sc)
    confidence = y_proba.max(axis=1)
    categories = [CLASS_NAMES[p] for p in y_pred]

    base_time  = datetime.now().replace(microsecond=0)
    timestamps = [
        (base_time + timedelta(seconds=i * 0.5)).isoformat()
        for i in range(len(df))
    ]

    return pd.DataFrame({
        "timestamp":  timestamps,
        "predicted":  categories,
        "confidence": confidence.round(4).tolist(),
        "severity":   [KILL_CHAIN_META.get(c, {}).get("severity", 0) for c in categories],
        "stage":      [KILL_CHAIN_META.get(c, {}).get("stage", 0) for c in categories],
        "color":      [KILL_CHAIN_META.get(c, {}).get("color", "#888") for c in categories],
        "icon":       [KILL_CHAIN_META.get(c, {}).get("icon", "?") for c in categories],
    })


def _generate_narrative(kc: dict, total: int, attacks: int, threat_level: str) -> str:
    """Build a plain-text narrative for the analysis — used when no saved file exists."""
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    pct  = round(attacks / total * 100, 1) if total else 0
    lines = [
        f"FedForensic — Incident Analysis Report",
        f"Generated  : {ts}",
        f"",
        f"THREAT LEVEL   : {threat_level}",
        f"Flows analyzed : {total:,}",
        f"Attack events  : {attacks:,} ({pct}%)",
        f"Kill chain     : {len(kc)} of 6 stages detected",
        "",
        "─" * 44,
        "  STAGE-BY-STAGE BREAKDOWN",
        "─" * 44,
    ]
    for cat, info in sorted(kc.items(), key=lambda x: x[1]["stage"]):
        lines += [
            "",
            f"  [{info['stage']}] {info['icon']}  {cat}",
            f"      Events     : {info['count']:,}",
            f"      Confidence : {info['confidence'] * 100:.1f}%",
            f"      Severity   : {'█' * info['severity']}{'░' * (10 - info['severity'])} {info['severity']}/10",
        ]
    lines += [
        "",
        "─" * 44,
        "  RECOMMENDED ACTIONS",
        "─" * 44,
    ]
    actions = {
        "Reconnaissance":  "  • Block scanning IPs — review firewall ingress rules",
        "WebAttack":       "  • Patch exposed web services — review WAF policies",
        "C2_Botnet":       "  • ISOLATE affected endpoints immediately",
        "LateralMovement": "  • Segment internal networks — rotate credentials",
        "Exfiltration":    "  • Block outbound to identified destinations",
        "DDoS":            "  • Activate rate-limiting — contact upstream provider",
    }
    for cat in kc:
        if cat in actions:
            lines.append(actions[cat])
    lines += ["", "─" * 44, "  END OF REPORT", "─" * 44]
    return "\n".join(lines)


def _build_response(events: pd.DataFrame, source: str, pcap_info=None,
                    narrative: str | None = None) -> dict:
    attack = events[events["predicted"] != "Benign"]

    # Build kill chain summary from events
    kc_out: dict = {}
    for cat, meta in KILL_CHAIN_META.items():
        if cat == "Benign":
            continue
        rows = attack[attack["predicted"] == cat]
        if rows.empty:
            continue
        kc_out[cat] = {
            "stage":      meta["stage"],
            "icon":       meta["icon"],
            "color":      meta["color"],
            "short":      meta["short"],
            "count":      int(len(rows)),
            "confidence": round(float(rows["confidence"].mean()), 4),
            "severity":   meta["severity"],
        }
    kc_out = dict(sorted(kc_out.items(), key=lambda x: x[1]["stage"]))

    max_sev = max((v["severity"] for v in kc_out.values()), default=0)
    threat_level = (
        "CRITICAL" if max_sev >= 8 else
        "HIGH"     if max_sev >= 6 else
        "MEDIUM"   if max_sev >= 4 else
        "LOW"
    )
    avg_conf  = round(float(attack["confidence"].mean()), 4) if len(attack) else 0.0
    total     = int(len(events))
    atk_count = int(len(attack))

    # Top alerts (highest severity first, cap at 500 for JSON size)
    events_sorted = events.nlargest(500, "severity")
    events_out    = events_sorted.to_dict(orient="records")

    if narrative is None:
        narrative = _generate_narrative(kc_out, total, atk_count, threat_level)

    return {
        "source":          source,
        "threat_level":    threat_level,
        "total_flows":     total,
        "attack_count":    atk_count,
        "benign_count":    int(len(events)) - atk_count,
        "avg_confidence":  avg_conf,
        "stages_detected": len(kc_out),
        "kill_chain":      kc_out,
        "events":          events_out,
        "narrative":       narrative,
        "pcap_info":       pcap_info,
        "analyzed_at":     datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# API Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    models = _models
    specialist_keys = {"ddos", "recon", "c2", "lateral", "exfil", "web", "malware"}
    return {
        "status":           "ok" if models else "degraded",
        "master_loaded":    "master" in models,
        "specialist_count": len([k for k in models if k in specialist_keys]),
        "total_models":     len([k for k in models if k not in ("scaler", "encoder")]),
    }


@app.get("/api/demo")
def demo():
    """Return the pre-computed demo analysis results."""
    events_path    = PROCESSED_DIR / "attack_events.csv"
    kc_path        = PROCESSED_DIR / "kill_chain_summary.json"
    narrative_path = PROCESSED_DIR / "attack_narrative.txt"

    if not events_path.exists():
        raise HTTPException(404, "Demo data not found. Run `python src/timeline.py` first.")

    ev = pd.read_csv(events_path)

    # Ensure required columns exist
    if "confidence" not in ev.columns:
        ev["confidence"] = 0.9
    if "severity" not in ev.columns:
        ev["severity"] = ev["predicted"].map(lambda c: KILL_CHAIN_META.get(c, {}).get("severity", 0))
    if "stage" not in ev.columns:
        ev["stage"] = ev["predicted"].map(lambda c: KILL_CHAIN_META.get(c, {}).get("stage", 0))
    if "color" not in ev.columns:
        ev["color"] = ev["predicted"].map(lambda c: KILL_CHAIN_META.get(c, {}).get("color", "#888"))
    if "icon" not in ev.columns:
        ev["icon"] = ev["predicted"].map(lambda c: KILL_CHAIN_META.get(c, {}).get("icon", "?"))

    narrative = None
    if narrative_path.exists():
        narrative = narrative_path.read_text(encoding="utf-8")

    response = _build_response(ev, "demo", narrative=narrative)

    # Override kill chain with richer pre-computed summary if available
    if kc_path.exists():
        raw_kc = json.loads(kc_path.read_text(encoding="utf-8"))
        normalized = {}
        for cat, info in raw_kc.items():
            meta = KILL_CHAIN_META.get(cat, {})
            normalized[cat] = {
                "stage":      info.get("stage", meta.get("stage", 0)),
                "icon":       meta.get("icon", info.get("icon", "?")),
                "color":      meta.get("color", info.get("color", "#888")),
                "short":      meta.get("short", cat),
                "count":      info.get("event_count", info.get("count", 0)),
                "confidence": info.get("avg_confidence", info.get("confidence", 0)),
                "severity":   meta.get("severity", info.get("max_severity", 0)),
            }
        response["kill_chain"] = dict(sorted(normalized.items(), key=lambda x: x[1]["stage"]))

    return response


@app.post("/api/analyze")
async def analyze_csv(file: UploadFile = File(...)):
    """Analyze an uploaded CSV of network flow features."""
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Only .csv files accepted here.")

    models  = _load_models()
    content = await file.read()

    try:
        df = pd.read_csv(io.BytesIO(content))
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)
        events = _infer(df, models)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"Analysis error: {exc}")

    return _build_response(events, "csv")


@app.post("/api/analyze/pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    """Analyze a raw PCAP capture — reconstructs flows, extracts features, runs models."""
    fname = file.filename.lower()
    if not any(fname.endswith(e) for e in (".pcap", ".pcapng", ".cap")):
        raise HTTPException(400, "Only .pcap / .pcapng / .cap files accepted here.")

    models  = _load_models()
    content = await file.read()
    suffix  = "." + fname.rsplit(".", 1)[-1]

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        df_feat   = pcap_to_ml_features(tmp_path)
        pcap_info = get_pcap_summary(df_feat)
    except Exception as exc:
        raise HTTPException(400, f"PCAP parsing error: {exc}")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    try:
        events = _infer(df_feat, models)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return _build_response(events, "pcap", pcap_info=pcap_info)


# Serve the frontend — must be mounted LAST so API routes take priority
app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="static")


if __name__ == "__main__":
    uvicorn.run("dashboard.server:app", host="0.0.0.0", port=8501, reload=True, reload_dirs=[str(ROOT)])
