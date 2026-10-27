# 🧠 PROJECT BRAIN — FedForensic
> **Last Updated:** Phase 5 — Dashboard VALIDATED ✅ (2026-09-02)
> **For AI Assistants:** Read this entire file before helping. It contains full context about the project, current status, decisions made, and what to do next.

---

## 📌 Project Overview

**Project Name:** FedForensic

**One-line description:**
A tool that ingests network traffic (PCAP files or CSV flow data), runs 7 ML models to detect different attack types, reconstructs the full attack timeline using a kill chain model, and presents everything in an interactive dashboard.

**SDG Tags:** SDG 9 (Industry & Innovation), SDG 16 (Peace & Security)

**Security Domains:** Network Security, IoT Security

---

## 👤 Developer Profile

| Field | Detail |
|---|---|
| Name | Harshal |
| Experience | Learning — building this solo with AI assistance |
| Daily Time | 2-3 hours/day |
| AI Tools Used | Claude, GitHub Copilot/Codex, Gemini CLI, Ollama (local) |
| Editor | VSCode |
| OS | Windows |
| GPU | RTX 5060 Ti — 16GB VRAM (can run local LLMs via Ollama) |
| RAM | 16GB DDR5 |
| Python Env | venv (not conda) |

---

## 🗂️ Project Structure

```
network-forensics/
│
├── venv/                          ← Python virtual environment
├── data/
│   ├── raw/
│   │   └── CIC(iot)/              ← 169 CSV files, ~13GB total
│   └── processed/                 ← cleaned CSVs, plots, feature list
├── models/                        ← saved ML models (.joblib)
├── src/
│   ├── __init__.py
│   ├── parser.py                  ← PCAP reader (scapy)
│   ├── explore.py                 ← dataset exploration ✅ DONE
│   ├── features.py                ← feature engineering
│   ├── models.py                  ← 7 ML models
│   └── timeline.py                ← attack timeline reconstruction
├── notebooks/                     ← Jupyter notebooks for experiments
├── dashboard/
│   └── app.py                     ← Streamlit UI
├── tests/
├── requirements.txt
└── PROJECT.md                     ← THIS FILE
```

---

## 📦 Dataset

| Field | Detail |
|---|---|
| Name | CIC-IoT 2023 (Kaggle version 2, updated 2024-10-08) |
| Source | https://www.kaggle.com/datasets/mdabdulalemo/cic-iot-dataset2023-updated-2024-10-08 |
| Location | `data/raw/CIC(iot)/` |
| Format | 169 CSV part files |
| Total Size | ~13GB uncompressed |
| Rows | ~47 million total |
| Features | 47 columns per row |
| Label Column | `label` |
| Total Attack Types | 34 unique labels |

### 47 Feature Columns
```
flow_duration, Header_Length, Protocol Type, Duration, Rate, Srate, Drate,
fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number,
ack_flag_number, ece_flag_number, cwr_flag_number,
ack_count, syn_count, fin_count, urg_count, rst_count,
HTTP, HTTPS, DNS, Telnet, SMTP, SSH, IRC, TCP, UDP, DHCP, ARP, ICMP, IPv, LLC,
Tot sum, Min, Max, AVG, Std, Tot size, IAT, Number,
Magnitue, Radius, Covariance, Variance, Weight,
label
```

### All 34 Attack Labels → 7 Threat Categories

| Raw Label | Threat Category | ML Model |
|---|---|---|
| BenignTraffic | Benign | — |
| DDoS-ACK_Fragmentation | DDoS | Model 1 |
| DDoS-HTTP_Flood | DDoS | Model 1 |
| DDoS-ICMP_Flood | DDoS | Model 1 |
| DDoS-ICMP_Fragmentation | DDoS | Model 1 |
| DDoS-PSHACK_Flood | DDoS | Model 1 |
| DDoS-RSTFINFlood | DDoS | Model 1 |
| DDoS-SYN_Flood | DDoS | Model 1 |
| DDoS-SlowLoris | DDoS | Model 1 |
| DDoS-SynonymousIP_Flood | DDoS | Model 1 |
| DDoS-TCP_Flood | DDoS | Model 1 |
| DDoS-UDP_Flood | DDoS | Model 1 |
| DDoS-UDP_Fragmentation | DDoS | Model 1 |
| DoS-HTTP_Flood | DDoS | Model 1 |
| DoS-SYN_Flood | DDoS | Model 1 |
| DoS-TCP_Flood | DDoS | Model 1 |
| DoS-UDP_Flood | DDoS | Model 1 |
| Recon-HostDiscovery | Reconnaissance | Model 2 |
| Recon-OSScan | Reconnaissance | Model 2 |
| Recon-PingSweep | Reconnaissance | Model 2 |
| Recon-PortScan | Reconnaissance | Model 2 |
| VulnerabilityScan | Reconnaissance | Model 2 |
| Mirai-greeth_flood | C2_Botnet | Model 3 |
| Mirai-greip_flood | C2_Botnet | Model 3 |
| Mirai-udpplain | C2_Botnet | Model 3 |
| Backdoor_Malware | C2_Botnet | Model 3 |
| MITM-ArpSpoofing | LateralMovement | Model 4 |
| BrowserHijacking | LateralMovement | Model 4 |
| Uploading_Attack | Exfiltration | Model 5 |
| DNS_Spoofing | Exfiltration | Model 5 |
| CommandInjection | WebAttack | Model 6 |
| SqlInjection | WebAttack | Model 6 |
| XSS | WebAttack | Model 6 |
| DictionaryBruteForce | WebAttack | Model 6 |

> Note: Model 7 (Malware/Intrusion) uses Backdoor_Malware as standalone detection separate from C2 context.

---

## 🎯 Project Goals

| # | Goal | Status |
|---|---|---|
| 1 | DDoS/DoS Detection | ✅ Complete — model_ddos.joblib |
| 2 | Reconnaissance Detection | ✅ Complete — model_recon.joblib |
| 3 | C2/Botnet Detection | ✅ Complete — model_c2.joblib |
| 4 | Lateral Movement Detection | ✅ Complete — model_lateral.joblib |
| 5 | Exfiltration Detection | ✅ Complete — model_exfil.joblib |
| 6 | Web Attack Detection | ✅ Complete — model_web.joblib |
| 7 | Malware/Intrusion Detection | ✅ Complete — model_malware.joblib |
| 8 | Attack Timeline Reconstruction | ✅ Complete — src/timeline.py |
| 9 | Interactive Dashboard + PDF Report | ✅ Complete + Validated |

---

## 🔪 Kill Chain Model (7 stages)

The project uses the Lockheed Martin Cyber Kill Chain adapted for IoT:

```
Stage 1 → Reconnaissance     (Recon scans, port sweeps, OS fingerprinting)
Stage 2 → Web Attack          (SQLi, XSS, brute force, command injection)
Stage 3 → C2 / Botnet         (Mirai beaconing, backdoor callbacks)
Stage 4 → Lateral Movement    (ARP spoofing, browser hijacking, pivoting)
Stage 5 → Exfiltration        (Large uploads, DNS tunneling)
Stage 6 → DDoS                (Flood attacks — often used as smokescreen)
Stage 7 → Malware Persistence (Backdoor installed, persistent access)
```

The timeline engine will map detected events to these stages and reconstruct the full attack story.

---

## 🤖 7 ML Models Plan

| Model | Target | Algorithm | Reason |
|---|---|---|---|
| Model 1 | DDoS/DoS | Random Forest | High volume patterns, supervised |
| Model 2 | Reconnaissance | Random Forest | Sequential scan patterns |
| Model 3 | C2/Botnet | Isolation Forest | Anomaly — beaconing is subtle |
| Model 4 | Lateral Movement | Random Forest | Internal IP patterns |
| Model 5 | Exfiltration | XGBoost | Rare events, high precision needed |
| Model 6 | Web Attack | XGBoost | Imbalanced, needs boosting |
| Model 7 | Malware/Intrusion | Isolation Forest | Unsupervised anomaly detection |

### RAM Strategy for Training (16GB RAM constraint)
- Load data in batches of 5 files (~350MB per batch)
- Use incremental/partial_fit where possible
- Save each model immediately after training
- Never load all 169 files at once

---

## 🏗️ Complete Roadmap

### Phase 1 — Foundation ✅ COMPLETE
- [x] VSCode + venv setup
- [x] Libraries installed
- [x] Dataset downloaded (CIC-IoT 2023, 169 files, 13GB)
- [x] Dataset explored — 34 labels, 47 features, 7 categories mapped
- [x] Run explore.py and verify outputs
- [x] Understand feature distributions from plots

### Phase 2 — Feature Engineering ✅ COMPLETE
- [x] Identify top features per threat category
- [x] Handle class imbalance (class_weight='balanced')
- [x] Normalize/scale features (StandardScaler → scaler.joblib)
- [x] Build reusable feature pipeline (src/features.py — 313 lines)
- [x] Save processed feature sets per category (sample_*.csv files)
- [x] Train/test split saved (X_train.csv 189MB, X_test.csv 47MB)

### Phase 3 — 7 ML Models ✅ COMPLETE
- [x] Model 1: DDoS/DoS — Random Forest → model_ddos.joblib
- [x] Model 2: Reconnaissance — Random Forest → model_recon.joblib
- [x] Model 3: C2/Botnet — Isolation Forest → model_c2.joblib
- [x] Model 4: Lateral Movement — Random Forest → model_lateral.joblib
- [x] Model 5: Exfiltration — XGBoost → model_exfil.joblib
- [x] Model 6: Web Attack — XGBoost → model_web.joblib
- [x] Model 7: Malware — Isolation Forest → model_malware.joblib
- [x] Master multi-class model → model_master.joblib (413MB)
- [x] Evaluate all models (plots 05-07 saved)
- [x] Save all models with joblib to models/

### Phase 4 — Timeline Engine ✅ COMPLETE
- [x] Design event schema: {timestamp, predicted, confidence, severity, stage}
- [x] Build kill chain mapper (maps events to 6 stages)
- [x] Build narrative generator → attack_narrative.txt
- [x] Build timeline visualizer (plotly) → plot_09_timeline.png
- [x] Kill chain summary saved → kill_chain_summary.json
- [x] Attack events saved → attack_events.csv (1,187 demo events)

### Phase 5 — Dashboard ✅ COMPLETE + VALIDATED (2026-09-02)
- [x] Streamlit UI — upload CSV (dashboard/app.py — 786 lines)
- [x] Run all 8 models on upload (master + 6 specialist)
- [x] Show kill chain progress boxes (S1–S6)
- [x] Show attack timeline scatter (plotly)
- [x] Show traffic distribution donut chart
- [x] Show severity & confidence per stage chart
- [x] Show alert table with confidence scores
- [x] Export PDF report (fpdf2)
- [x] Export CSV of attack events
- [x] Auto-loads demo data when no CSV uploaded
- [x] End-to-end validated: 1,700 flows → 6/6 kill chain stages, 86.9% avg confidence

### Phase 6 — Polish + IoT ⬜ IN PROGRESS
- [ ] Expand src/parser.py — PCAP file support (currently minimal stub)
- [ ] Add MQTT/CoAP protocol parsing
- [ ] Write full README.md with setup instructions + screenshots
- [ ] Update Project.md to final state
- [ ] Record demo video
- [ ] Optional: Docker container

---

## 🛠️ Tech Stack

| Category | Tool | Version |
|---|---|---|
| Language | Python | 3.11 |
| Environment | venv | — |
| Packet parsing | scapy | latest |
| Packet parsing | pyshark | latest |
| Data processing | pandas | latest |
| Data processing | numpy | latest |
| ML | scikit-learn | latest |
| ML | xgboost | latest |
| Visualization | matplotlib | latest |
| Visualization | seaborn | latest |
| Visualization | plotly | latest |
| Network graph | pyvis | latest |
| Dashboard | streamlit | latest |
| Model saving | joblib | latest |

### Local LLM Setup (for offline AI help)
- Tool: Ollama
- GPU: RTX 5060 Ti 16GB VRAM
- Recommended models: codellama:13b, deepseek-coder:33b, llama3:70b (Q4)

---

## 📁 Key Files Reference

| File | Purpose | Status |
|---|---|---|
| `src/explore.py` | Dataset exploration, label mapping, plots | ✅ Complete |
| `src/parser.py` | PCAP file reader using scapy | ⚠️ Minimal stub — needs expansion |
| `src/features.py` | Feature engineering pipeline (313 lines) | ✅ Complete |
| `src/models.py` | All 7 ML models + master model (539 lines) | ✅ Complete |
| `src/timeline.py` | Kill chain + timeline reconstruction (556 lines) | ✅ Complete |
| `src/regen_narrative.py` | Regenerates narrative from attack_events.csv | ✅ Complete |
| `dashboard/app.py` | Streamlit dashboard (786 lines) | ✅ Complete + Validated |
| `generate_report.py` | Markdown project report generator (648 lines) | ✅ Complete |
| `models/model_master.joblib` | Master multi-class RF model (413MB) | ✅ Saved |
| `data/processed/attack_events.csv` | 1,187 demo attack events | ✅ Generated |
| `data/processed/kill_chain_summary.json` | Kill chain summary for dashboard | ✅ Generated |
| `data/processed/attack_narrative.txt` | Human-readable attack story | ✅ Generated |

---

## ⚠️ Known Constraints & Decisions

| Constraint | Decision Made |
|---|---|
| 16GB RAM | Load max 5 files at a time (~350MB). Use batch/incremental training |
| 169 files × 13GB | Never load all at once. Always use glob + slice |
| Class imbalance | Will use class_weight='balanced' in sklearn models + SMOTE if needed |
| CICIDS 2017 issues | Switched to CIC-IoT 2023 (newer, better labeled, covers IoT) |
| 3 models → expanded | Expanded to 7 models to cover all 34 attack types properly |
| venv not conda | Developer prefers venv. All install commands use pip |

---

## 📝 How to Update This File

After completing each task, update:
1. The checkbox `[ ]` → `[x]` in the roadmap
2. The status column in Goals table
3. The "Last Updated" line at the top
4. Add any new decisions to the Constraints table
5. Add any new files to the Key Files Reference table

---

## 🚀 Current Status & Next Action

**Current Phase:** Phase 6 — Polish + IoT
**Last Completed Step:** Phase 5 dashboard fully validated end-to-end (2026-09-02).
- 1,700 flows classified from test_traffic_for_upload.csv
- 6/6 kill chain stages detected, 86.9% average model confidence
- PDF export, CSV export, demo auto-load — all working
**Next Action:** Expand `src/parser.py` for real PCAP support + write README.md

```bash
# Run the dashboard
venv\Scripts\activate
streamlit run dashboard\app.py
```

---

## 💬 Notes for AI Assistants

- Always check "Current Status" section before suggesting anything
- Developer is learning — explain WHY not just what code to write
- All paths use Windows format with forward slashes in Python strings
- Dataset path is always `data/raw/CIC(iot)/`
- Never suggest loading more than 5 files at once (16GB RAM constraint)
- The project uses venv not conda
- When writing new src/ files, follow the same style as explore.py (numbered steps, emoji checkmarks, clear section comments)
- Developer uses VSCode — suggest VSCode terminal commands not Jupyter