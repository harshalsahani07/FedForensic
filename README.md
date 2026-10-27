# FedForensic

> **AI-Powered Network Forensics & Packet Analysis — 7 specialist ML models, Lockheed Martin Kill Chain, interactive Streamlit dashboard**

[![Python](https://img.shields.io/badge/Python-3.11-3776ab?logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.58-ff4b4b?logo=streamlit&logoColor=white)](https://streamlit.io)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.x-f89422?logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.x-189fdd)](https://xgboost.readthedocs.io)
[![Dataset](https://img.shields.io/badge/Dataset-CIC--IoT%202023-blue)](https://www.kaggle.com/datasets/mdabdulalemo/cic-iot-dataset2023-updated-2024-10-08)
[![SDG](https://img.shields.io/badge/SDG-9%20%7C%2016-4CAF50)](https://sdgs.un.org)

---

## What This Tool Does

1. **Ingest** — Upload a `.pcap` / `.pcapng` raw packet capture OR a pre-computed `.csv` flow file
2. **Parse** — PCAP files are automatically reconstructed into network flows with 35 ML-ready features (matching CIC-IoT 2023 format)
3. **Detect** — 8 ML models classify every flow into one of 7 threat categories
4. **Map** — Detected threats are mapped onto the **Lockheed Martin Cyber Kill Chain** (6 stages)
5. **Report** — Interactive Streamlit dashboard shows timeline, charts, alert table, narrative, and PDF export

---

## System Architecture

```
Raw Network Traffic
      │
      ├─── .pcap / .pcapng ──▶  src/parser.py
      │                           Flow Reconstruction
      │                           35-Feature Extraction
      │
      └─── .csv (CICFlowMeter) ──▶  Direct load
                    │
                    ▼
         src/features.py  (StandardScaler)
                    │
                    ▼
        ┌───────────────────────┐
        │   8 ML Models         │
        │  ┌─────────────────┐  │
        │  │ Master RF (7-class) │  ← primary classifier
        │  │ model_ddos      │  │  ← Random Forest
        │  │ model_recon     │  │  ← Random Forest
        │  │ model_c2        │  │  ← Isolation Forest
        │  │ model_lateral   │  │  ← Random Forest
        │  │ model_exfil     │  │  ← XGBoost
        │  │ model_web       │  │  ← XGBoost
        │  │ model_malware   │  │  ← Isolation Forest
        │  └─────────────────┘  │
        └───────────────────────┘
                    │
                    ▼
         src/timeline.py
         Kill Chain Mapper (6 stages)
         Attack Narrative Generator
                    │
                    ▼
         dashboard/app.py  (Streamlit)
         ┌────────────────────────────────┐
         │  Kill Chain Progress Bar       │
         │  Attack Timeline (Plotly)      │
         │  Traffic Distribution Donut    │
         │  Severity & Confidence Chart   │
         │  Alert Table (Top 50)          │
         │  Attack Narrative Text         │
         │  PDF / CSV Export              │
         └────────────────────────────────┘
```

---

## Quick Start

### 1. Clone & Set Up

```powershell
git clone <repo-url>
cd network-forensics

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Dashboard

```powershell
venv\Scripts\activate
streamlit run dashboard\app.py
```

Open **http://localhost:8501** in your browser.

> The dashboard auto-loads demo data. Upload your own `.pcap` or `.csv` to analyze live traffic.

### 3. Analyze a PCAP File (CLI)

```powershell
# Extract 35 ML features from a raw PCAP capture
python src\parser.py path\to\capture.pcap

# Output: data/processed/pcap_features.csv (ready for model input)
```

---

## Dashboard Usage

| Action | How |
|---|---|
| **Upload CSV** | Click the uploader → select a `.csv` with CICFlowMeter flow features |
| **Upload PCAP** | Click the uploader → select `.pcap` or `.pcapng` — flows are auto-reconstructed |
| **View Kill Chain** | Six stage boxes show which attack stages were detected |
| **Export PDF** | Click "📄 Export PDF Report" → generates full incident report |
| **Export CSV** | Click "📊 Export CSV" → download attack events table |

> **No data uploaded?** The dashboard displays a pre-analyzed demo showing a 6/6 Kill Chain attack scenario.

---

## Dataset

| Field | Detail |
|---|---|
| **Name** | CIC-IoT 2023 (Kaggle, updated 2024-10-08) |
| **Source** | [Kaggle Link](https://www.kaggle.com/datasets/mdabdulalemo/cic-iot-dataset2023-updated-2024-10-08) |
| **Size** | 169 CSV files, ~13GB, ~47M rows |
| **Features** | 47 columns per row; 35 selected for ML |
| **Labels** | 34 unique attack types → 7 threat categories |

---

## 7 Threat Categories & Kill Chain Mapping

| Stage | Threat Category | ML Model | Algorithm |
|---|---|---|---|
| 1 | 🔍 Reconnaissance | model_recon | Random Forest |
| 2 | 🌐 Web Attack | model_web | XGBoost |
| 3 | 📡 C2 / Botnet | model_c2 | Isolation Forest |
| 4 | ↔️ Lateral Movement | model_lateral | Random Forest |
| 5 | 📤 Exfiltration | model_exfil | XGBoost |
| 6 | 💥 DDoS / DoS | model_ddos | Random Forest |
| — | 🦠 Malware | model_malware | Isolation Forest |
| — | ✅ Benign | — | — |

---

## Model Performance (Master Classifier)

Evaluated on **70,000 held-out test flows** (10,000 per class):

| Class | Precision | Recall | F1 |
|---|---|---|---|
| Benign | 0.843 | 0.891 | 0.866 |
| C2_Botnet | **1.000** | 0.996 | **0.998** |
| DDoS | **1.000** | 0.997 | **0.999** |
| Exfiltration | 0.894 | 0.860 | 0.877 |
| LateralMovement | 0.946 | 0.830 | 0.885 |
| Reconnaissance | 0.929 | 0.826 | 0.874 |
| WebAttack | 0.814 | 0.994 | 0.895 |
| **Overall** | **0.918** | **0.914** | **0.913** |

**Accuracy: 91.4% | F1 (weighted): 91.3%**

---

## 35 ML Features

```
Variance, ack_flag_number, Tot size, Header_Length, Covariance,
flow_duration, Rate, Srate, Drate, IAT, Number, Weight, Radius, Magnitue,
fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number,
ece_flag_number, cwr_flag_number, ack_count, syn_count, fin_count, rst_count,
TCP, UDP, ICMP, HTTP, DNS, HTTPS, Tot sum, Min, Max, AVG, Std
```

---

## Project Structure

```
network-forensics/
│
├── venv/                          ← Python virtual environment
├── data/
│   ├── raw/
│   │   └── CIC(iot)/              ← 169 CSV source files (~13GB)
│   └── processed/                 ← ML-ready data, plots, events
├── models/                        ← Saved model files (.joblib)
│   ├── model_master.joblib        ← Master 7-class RF (413MB)
│   ├── model_ddos.joblib
│   ├── model_recon.joblib
│   ├── model_c2.joblib
│   ├── model_lateral.joblib
│   ├── model_exfil.joblib
│   ├── model_web.joblib
│   ├── model_malware.joblib
│   ├── scaler.joblib
│   └── label_encoder.joblib
├── src/
│   ├── parser.py                  ← PCAP → flow features (35 ML columns)
│   ├── features.py                ← Feature engineering pipeline
│   ├── models.py                  ← 7 ML model training scripts
│   ├── timeline.py                ← Kill chain + timeline reconstruction
│   └── regen_narrative.py         ← Regenerate narrative from saved events
├── dashboard/
│   └── app.py                     ← Streamlit interactive dashboard
├── generate_report.py             ← Markdown project report generator
├── generate_test_csv.py           ← Synthetic CSV generator for testing
├── test_traffic_for_upload.csv    ← Ready-to-upload test file (1,700 flows)
├── requirements.txt
└── Project.md                     ← Live project brain / status tracker
```

---

## Tech Stack

| Category | Tool |
|---|---|
| Language | Python 3.11 |
| Packet parsing | scapy |
| Data processing | pandas, numpy |
| ML | scikit-learn, xgboost |
| Visualization | plotly, matplotlib, seaborn |
| Dashboard | streamlit |
| Model saving | joblib |
| PDF export | fpdf2 |

---

## SDG Alignment

- **SDG 9** — Industry, Innovation & Infrastructure: applying AI to strengthen cybersecurity infrastructure
- **SDG 16** — Peace, Justice & Strong Institutions: enabling detection of malicious network activity

---

## RAM / Hardware Notes

- Trained on Windows, RTX 5060 Ti 16GB VRAM, 16GB DDR5
- Dataset loaded in batches of 5 files (~350MB/batch) — never loads all 169 files at once
- Dashboard model loading: ~500MB RAM for all models combined
- Inference on 1,700 flows takes < 2 seconds

---

## Author

**Harshal** — FedForensic Project, 2026
