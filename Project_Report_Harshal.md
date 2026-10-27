# FedForensic
## Project Report - August 2026

**Submitted by:** Harshal
**Project Title:** FedForensic
**Domain:** Network Security / IoT Security
**SDG Alignment:** SDG 9 (Industry and Innovation), SDG 16 (Peace and Security)
**Report Date:** August 20, 2026

---

## Table of Contents

1. Project Overview
2. Problem Statement
3. Dataset
4. System Architecture
5. Phase 1 - Dataset Exploration
6. Phase 2 - Feature Engineering
7. Phase 3 - Machine Learning Models
8. Phase 4 - Attack Timeline Engine
9. Phase 5 - Interactive Dashboard
10. Technology Stack
11. Key Results
12. Challenges and Solutions
13. Current Status and Next Steps
14. File and Folder Structure

---

## 1. Project Overview

This project is **FedForensic** designed to automatically detect and classify cyberattacks from raw network traffic data using machine learning. The tool can ingest network flow data (CSV format from tools like Wireshark/CICFlowMeter, or PCAP files), run it through **7 specialist ML models**, reconstruct the **full attack lifecycle using the Lockheed Martin Cyber Kill Chain model**, and present everything in an **interactive, real-time Streamlit dashboard** with PDF report export.

The tool is specifically focused on **IoT network security** and can detect 34 distinct attack types grouped into 7 threat categories.

### End-to-End Flow

```
Raw Network Traffic (PCAP / CSV)
        |
  PCAP Parser (scapy) [src/parser.py]
        |
  Feature Engineering (35 ML-ready features) [src/features.py]
        |
  7 ML Models (Random Forest, XGBoost, Isolation Forest) [src/models.py]
        |
  Kill Chain Mapper (6 stages) [src/timeline.py]
        |
  Interactive Dashboard (Streamlit) + PDF Report [dashboard/app.py]
```

---

## 2. Problem Statement

Traditional intrusion detection systems (IDS) are:

- **Signature-based**: miss novel attack variants
- **Single-category**: do not understand the full attack lifecycle
- **Alert-only**: generate alerts but do not explain the attack story
- **Not IoT-aware**: focused on traditional enterprise traffic

This project solves these gaps by:

1. Using machine learning to detect attacks without fixed signatures
2. Using 7 specialized models, each focused on a different threat type
3. Reconstructing the full attack timeline using the Cyber Kill Chain model
4. Generating a human-readable attack narrative with recommended actions
5. Working specifically with CIC-IoT 2023 data (modern IoT benchmark)

---

## 3. Dataset

| Property           | Details                                              |
|-------------------|------------------------------------------------------|
| Dataset Name       | CIC-IoT 2023 (Kaggle version 2, October 2024)       |
| Source             | Communications Security Establishment Canada (CIC)  |
| Location           | data/raw/CIC(iot)/                                  |
| Format             | 169 CSV part files                                  |
| Total Size         | ~13 GB uncompressed                                 |
| Total Rows         | ~47 million network flow records                    |
| Features per Row   | 47 columns                                          |
| Label Column       | label                                               |
| Total Attack Types | 34 unique attack labels                             |

### Feature Groups (47 total)

| Group              | Features                                                    |
|--------------------|-------------------------------------------------------------|
| Flow timing        | flow_duration, Duration, IAT                                |
| Rate metrics       | Rate, Srate, Drate                                          |
| Packet stats       | Header_Length, Tot size, Tot sum, Min, Max, AVG, Std, Number|
| TCP flags          | fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number, ack_flag_number, ece_flag_number, cwr_flag_number |
| Flag counts        | ack_count, syn_count, fin_count, urg_count, rst_count       |
| Protocol           | HTTP, HTTPS, DNS, Telnet, SMTP, SSH, IRC, TCP, UDP, DHCP, ARP, ICMP, IPv, LLC |
| Statistical        | Magnitue, Radius, Covariance, Variance, Weight              |

### 34 Attack Labels -> 7 Threat Categories

| Threat Category  | Attack Labels Included                         | Model   |
|------------------|------------------------------------------------|---------|
| Benign           | BenignTraffic                                  | None    |
| DDoS             | DDoS-ACK_Fragmentation, DDoS-HTTP_Flood, DDoS-ICMP_Flood, DDoS-ICMP_Fragmentation, DDoS-PSHACK_Flood, DDoS-RSTFINFlood, DDoS-SYN_Flood, DDoS-SlowLoris, DDoS-SynonymousIP_Flood, DDoS-TCP_Flood, DDoS-UDP_Flood, DDoS-UDP_Fragmentation, DoS-HTTP_Flood, DoS-SYN_Flood, DoS-TCP_Flood, DoS-UDP_Flood | Model 1 |
| Reconnaissance   | Recon-HostDiscovery, Recon-OSScan, Recon-PingSweep, Recon-PortScan, VulnerabilityScan | Model 2 |
| C2_Botnet        | Mirai-greeth_flood, Mirai-greip_flood, Mirai-udpplain, Backdoor_Malware | Model 3 |
| LateralMovement  | MITM-ArpSpoofing, BrowserHijacking             | Model 4 |
| Exfiltration     | Uploading_Attack, DNS_Spoofing                 | Model 5 |
| WebAttack        | CommandInjection, SqlInjection, XSS, DictionaryBruteForce | Model 6 |

---

## 4. System Architecture

```
INPUT: PCAP Files (Wireshark) | CSV Flow Files (CICFlowMeter)
         src/parser.py        |
                  |
FEATURE ENGINEERING (src/features.py)
  - 35 features selected from 47
  - Class balance: 50,000 rows per class (7 classes)
  - StandardScaler normalization
  - 80/20 stratified train/test split
                  |
ML MODELS (src/models.py)
  Model 1: DDoS/DoS       - Random Forest (binary), 100 trees
  Model 2: Recon          - Random Forest (binary), 100 trees
  Model 3: C2/Botnet      - Isolation Forest (anomaly, benign-trained)
  Model 4: Lateral Mvmt   - Random Forest (binary), 150 trees
  Model 5: Exfiltration   - XGBoost (binary), 200 trees
  Model 6: Web Attack     - XGBoost (binary), 200 trees
  Model 7: Malware        - Isolation Forest (anomaly, benign-trained)
  Master:  All 7 classes  - Random Forest (multi-class), 200 trees
                  |
TIMELINE ENGINE (src/timeline.py)
  - Event log construction with timestamps
  - Kill chain stage mapping (Lockheed Martin 6-stage model)
  - Confidence + severity scoring per flow
  - Human-readable attack narrative generation
  - 3 visualization outputs
                  |
DASHBOARD (dashboard/app.py - Streamlit)
  - CSV upload + live analysis (real-time 8-model inference)
  - Kill chain progress (6 colored stage boxes)
  - 4 interactive Plotly charts
  - Alert table (top 50 by severity)
  - Attack narrative panel
  - PDF + CSV export
```

---

## 5. Phase 1 - Dataset Exploration

**File:** notebooks/explore.py | **Lines:** 375 | **Status:** COMPLETE

### Steps Executed

**Step 1 - Load Sample Files**
- Loaded 5 of 169 CSV files (~350MB) to stay within 16GB RAM limit
- Loaded 1,190,000+ rows for initial exploration

**Step 2 - Label Mapping**
- Mapped all 34 raw attack labels to 7 threat categories using LABEL_MAP dictionary
- Discovered severe class imbalance: DDoS = 90.1% of traffic, WebAttack = 0.1%

**Step 3 - Data Quality Check**
- Checked for missing values, infinite values, and duplicate rows
- Found infinity values in rate/duration features (fixed in Phase 2)

**Step 4 - Feature Analysis**
- Analyzed all 47 features with descriptive statistics
- Identified most ML-relevant features via domain knowledge

**Step 5 - Feature-Attack Correlation**
- Computed Pearson correlation between each feature and binary attack label
- Top correlated features: Variance, ack_flag_number, Tot size, Header_Length, Covariance

**Step 6 - Visualizations Generated**
- plot_01_overview.png: 6-panel dashboard (category distribution, top-15 attack labels, kill chain coverage, feature correlations, benign vs attack ratio)
- plot_02_features.png: Feature distribution histograms per threat category
- plot_03_correlation.png: 21x21 feature correlation heatmap

**Step 7 - Save Clean Sample**
- Saved data/processed/sample_clean.csv (cleaned sample ~200MB)
- Saved per-category CSV files: sample_ddos.csv, sample_webattack.csv, etc.
- Saved feature_list.txt with all 47 column names

### Key Finding
SEVERE CLASS IMBALANCE FOUND: DDoS = 90.1%, WebAttack = 0.1%.
A naive model predicting DDoS always achieves 90% accuracy but detects nothing else.
Class balancing became a critical requirement before any ML training.

---

## 6. Phase 2 - Feature Engineering

**File:** src/features.py | **Lines:** 313 | **Status:** COMPLETE

### Steps Executed

**Step 1 - Batch Data Loading**
- Batch strategy: 5 files x 10 batches = 50 files processed (~3.5GB)
- glob + slicing: never more than 5 files loaded at once (16GB RAM safe)

**Step 2 - Cleaning and Label Mapping**
- Mapped 34 raw labels to 7 categories
- Replaced np.inf and -np.inf with NaN
- Dropped NaN rows and duplicate rows

**Step 3 - Class Imbalance Correction**
- Target: 50,000 rows per class (7 classes = 350,000 balanced total)
- Large classes (DDoS): Undersampled via random sampling
- Tiny classes (WebAttack, Exfiltration): Oversampled via sklearn.utils.resample (bootstrap)
- Secondary: class_weight=balanced in Random Forest; scale_pos_weight in XGBoost

**Step 4 - Feature Selection**
- Selected 35 features from 47 based on attack correlation and domain knowledge
- Selected: Variance, ack_flag_number, Tot size, Header_Length, Covariance,
  flow_duration, Rate, Srate, Drate, IAT, Number, Weight, Radius, Magnitue,
  fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number,
  ece_flag_number, cwr_flag_number, ack_count, syn_count, fin_count, rst_count,
  TCP, UDP, ICMP, HTTP, DNS, HTTPS, Tot sum, Min, Max, AVG, Std

**Step 5 - Feature Scaling**
- Applied StandardScaler: zero mean, unit variance for all 35 features
- Prevents large-value features (Rate) from dominating binary flags
- Scaler saved as models/scaler.joblib for inference

**Step 6 - Train/Test Split and Save**
- 80/20 stratified split: 280,000 train rows, 70,000 test rows
- Labels encoded 0-6 by LabelEncoder, saved as models/label_encoder.joblib
- Outputs: X_train.csv, X_test.csv, y_train.csv, y_test.csv, features_used.txt

Visualization: plot_04_balancing.png - before vs after class balance comparison

---

## 7. Phase 3 - Machine Learning Models

**File:** src/models.py | **Lines:** 539 | **Status:** COMPLETE - All 8 models trained and saved

### Model Design Philosophy

7 specialist binary models (one per threat category) + 1 master multi-class model.
Binary models allow independent tuning per threat. Master model used for dashboard quick-scan.

### Model 1 - DDoS/DoS Detector

| Property       | Value                                                    |
|---------------|----------------------------------------------------------|
| Algorithm      | Random Forest (binary: DDoS=1 vs rest=0)                 |
| Configuration  | 100 trees, max_depth=15, class_weight=balanced, n_jobs=-1 |
| Why RF         | DDoS has clear high-rate, high-volume patterns            |
| Top features   | Rate, Variance, Tot size, syn_flag_number, IAT            |
| Saved as       | models/model_ddos.joblib (3.9 MB)                         |

### Model 2 - Reconnaissance Detector

| Property       | Value                                                    |
|---------------|----------------------------------------------------------|
| Algorithm      | Random Forest (binary: Recon=1 vs rest=0)                |
| Configuration  | 100 trees, max_depth=15, class_weight=balanced, n_jobs=-1 |
| Why RF         | Sequential scan patterns are clearly learnable supervised |
| Saved as       | models/model_recon.joblib (33.5 MB)                       |

### Model 3 - C2/Botnet Detector

| Property       | Value                                                    |
|---------------|----------------------------------------------------------|
| Algorithm      | Isolation Forest (unsupervised anomaly detection)         |
| Configuration  | 100 estimators, contamination=0.05                        |
| Strategy       | Trained ONLY on benign traffic; anomalies flagged as C2   |
| Why Iso Forest | Mirai beaconing is subtle; anomaly detection more robust  |
| Saved as       | models/model_c2.joblib (7.5 MB)                           |

### Model 4 - Lateral Movement Detector

| Property       | Value                                                    |
|---------------|----------------------------------------------------------|
| Algorithm      | Random Forest (binary: LateralMovement=1 vs rest=0)      |
| Configuration  | 150 trees (more than others), max_depth=20               |
| Why 150 trees  | ARP spoofing/browser hijacking have subtler patterns      |
| Saved as       | models/model_lateral.joblib (140 MB - largest specialist) |

### Model 5 - Exfiltration Detector

| Property       | Value                                                    |
|---------------|----------------------------------------------------------|
| Algorithm      | XGBoost (binary: Exfiltration=1 vs rest=0)               |
| Configuration  | 200 trees, max_depth=8, learning_rate=0.1                |
| Why XGBoost    | Rare event - gradient boosting gives better precision     |
| scale_pos_wt   | Auto-computed as neg/pos ratio for imbalance handling     |
| Saved as       | models/model_exfil.joblib (1.6 MB)                        |

### Model 6 - Web Attack Detector

| Property       | Value                                                    |
|---------------|----------------------------------------------------------|
| Algorithm      | XGBoost (binary: WebAttack=1 vs rest=0)                  |
| Configuration  | 200 trees, max_depth=8, learning_rate=0.1                |
| Why XGBoost    | SQLi/XSS/CMDi have subtle signatures; boosting focuses on hard cases |
| Saved as       | models/model_web.joblib (1.4 MB)                          |

### Model 7 - Malware/Intrusion Detector

| Property       | Value                                                    |
|---------------|----------------------------------------------------------|
| Algorithm      | Isolation Forest (unsupervised)                           |
| Configuration  | 150 estimators, contamination=0.02 (backdoors are rarer)  |
| Strategy       | Trained on benign only; very low contamination threshold  |
| Saved as       | models/model_malware.joblib (1.1 MB)                      |

### Master Model - Full 7-Class Classifier

| Property       | Value                                                    |
|---------------|----------------------------------------------------------|
| Algorithm      | Random Forest (multi-class, all 7 categories at once)    |
| Configuration  | 200 trees, max_depth=20, class_weight=balanced           |
| Purpose        | Dashboard quick-scan; predict_proba() gives 7-class confidence |
| Saved as       | models/model_master.joblib (433.6 MB - largest file)      |

### Evaluation Methodology

Each model evaluated on 70,000-row test set using:
- Accuracy: overall correct predictions
- Weighted F1-score: harmonic mean of precision/recall, weighted by class support
- Classification report: per-class precision, recall, F1, support
- Confusion matrix: visual breakdown of misclassifications

Plots: plot_05_model_performance.png, plot_06_confusion_matrix.png, plot_07_feature_importance.png

### All Saved Models

| File                   | Model                   | Size     |
|------------------------|-------------------------|----------|
| model_master.joblib    | Master 7-class RF       | 433.6 MB |
| model_lateral.joblib   | Lateral Movement RF     | 140.0 MB |
| model_recon.joblib     | Reconnaissance RF       |  33.5 MB |
| model_c2.joblib        | C2/Botnet Iso Forest    |   7.5 MB |
| model_ddos.joblib      | DDoS/DoS RF             |   3.9 MB |
| model_exfil.joblib     | Exfiltration XGBoost    |   1.6 MB |
| model_web.joblib       | Web Attack XGBoost      |   1.4 MB |
| model_malware.joblib   | Malware Iso Forest      |   1.1 MB |
| scaler.joblib          | StandardScaler          |   2.1 KB |
| label_encoder.joblib   | LabelEncoder            |   563 B  |

---

## 8. Phase 4 - Attack Timeline Engine

**File:** src/timeline.py | **Lines:** 556 | **Status:** COMPLETE

### The Cyber Kill Chain Model Used

| Stage   | Category        | Severity | Meaning                                    |
|---------|-----------------|----------|--------------------------------------------|
| Stage 1 | Reconnaissance  | 3/10     | Attacker maps network: port scans, OS fingerprinting |
| Stage 2 | WebAttack       | 6/10     | Exploits web: SQLi, XSS, CMDi, brute force |
| Stage 3 | C2_Botnet       | 8/10     | Establishes C2: Mirai beaconing, backdoor callbacks |
| Stage 4 | LateralMovement | 7/10     | Pivots internally: ARP spoofing, hijacking |
| Stage 5 | Exfiltration    | 9/10     | Steals data: DNS tunneling, upload attacks |
| Stage 6 | DDoS            | 5/10     | Floods as smokescreen during exfiltration  |

### Steps Executed

**Step 1 - Load All Models and Sample Data**
- Loaded master model + 6 specialist models
- Sampled 200 rows per class from test set = 1,400 flows for analysis

**Step 2 - Classify All Flows**
- Ran master model: classification + confidence via predict_proba()

**Step 3 - Build Event Log**
- Generated synthetic timestamps (90-minute attack window from 2:00 PM)
- Event DataFrame: timestamp, predicted, confidence, severity, kill_chain_stage

**Step 4 - Kill Chain Correlation**
- Grouped events by kill chain stage
- Per stage: event_count, first_seen, avg_confidence, max_severity, avg_rate, avg_size

**Step 5 - Attack Narrative Generation**
- generate_narrative() function produces human-readable attack report
- Includes: threat level, attack window, stage-by-stage breakdown, kill chain visual,
  and specific recommended response actions for the analyst

### Actual Narrative Output from Test Data

```
THREAT LEVEL    : CRITICAL
TOTAL EVENTS    : 1,187 attack flows detected
KILL CHAIN      : 6 of 6 stages observed
ATTACK WINDOW   : 14:00:30 to 15:29:59 (01:29:29)

Stage 1 RECONNAISSANCE  - 179 flows  | 79.7% confidence | Severity 3/10
Stage 2 WEBATTACK       - 243 flows  | 71.3% confidence | Severity 6/10
Stage 3 C2_BOTNET       - 198 flows  | 99.6% confidence | Severity 8/10
Stage 4 LATERALMOVEMENT - 178 flows  | 83.9% confidence | Severity 7/10
Stage 5 EXFILTRATION    - 189 flows  | 78.2% confidence | Severity 9/10
Stage 6 DDOS            - 200 flows  | 99.4% confidence | Severity 5/10

RECOMMENDED ACTIONS:
URGENT:  Data exfiltration detected - isolate affected hosts immediately
URGENT:  C2 channel active - block outbound connections to C2 IPs
WARNING: Lateral movement detected - audit internal access logs
WARNING: Web attacks detected - review WAF logs and patch vulnerabilities
INFO:    Reconnaissance detected - attacker is mapping your network
INFO:    DDoS may be a smokescreen - check for simultaneous exfiltration
```

**Step 6 - Visualizations Generated**
- plot_08_killchain.png: Kill chain progress bar
- plot_09_timeline.png: Attack events scatter + volume histogram over time
- plot_10_severity.png: Severity and confidence per stage

**Files Saved**
- data/processed/attack_events.csv - 1,187 attack events
- data/processed/attack_narrative.txt - Human-readable story
- data/processed/kill_chain_summary.json - Machine-readable data for dashboard

---

## 9. Phase 5 - Interactive Dashboard

**File:** dashboard/app.py | **Lines:** 786 | **Run:** streamlit run dashboard/app.py | **Status:** COMPLETE

### Dashboard Features

**Feature 1: CSV Upload and Live Analysis**
- Upload any CSV with network flow features
- Auto-aligns columns to trained 35-feature set
- Runs all 8 models in real time using @st.cache_resource caching

**Feature 2: Metric Cards (5 summary cards)**
- Threat Level (CRITICAL/HIGH/MEDIUM/LOW, color-coded)
- Total Flows, Attack Events, Kill Chain Stages (X of 6), Avg Confidence

**Feature 3: Kill Chain Progress Visual**
- 6 colored boxes, one per kill chain stage
- Detected stages: colored with icon, event count, confidence
- Undetected stages: grey, labelled 'not detected'
- Arrows between stages

**Feature 4: Interactive Plotly Charts (4 charts)**
1. Attack Events Over Time: scatter colored by category, size = confidence
2. Traffic Distribution: donut chart showing % of each threat type
3. Severity and Confidence per Stage: dual-axis bar+line chart
4. Event Count per Kill Chain Stage: horizontal bar chart

**Feature 5: Alert Table**
- Top 50 highest-severity alerts
- Columns: Timestamp, Threat Type, Confidence, Severity
- Interactive scrollable dataframe

**Feature 6: Attack Narrative Panel**
- Full text of the attack story in a monospace dark-themed box

**Feature 7: Export**
- PDF Export: Professional incident report via fpdf2 (executive summary,
  kill chain table, narrative, top 20 alerts)
- CSV Export: All attack events as downloadable CSV

**Feature 8: Demo Mode**
- Auto-loads pre-analyzed demo data when no file is uploaded
- Shows info banner explaining demo mode

### UI Technical Details
- Dark theme: #0d1117 background, GitHub-inspired palette
- Custom CSS: metric cards, kill chain boxes, narrative box, status pills
- @st.cache_resource: models loaded once, reused across all sessions

---

## 10. Technology Stack

| Category        | Technology         | Purpose                                   |
|-----------------|--------------------|--------------------------------------------|
| Language        | Python 3.11        | Core development language                  |
| Environment     | venv               | Virtual environment management             |
| Packet parsing  | scapy, pyshark     | PCAP file reading and parsing              |
| Data processing | pandas, numpy      | Data manipulation and numerical computing  |
| ML supervised   | scikit-learn       | Random Forest, Isolation Forest, scalers   |
| ML boosting     | xgboost            | XGBoost models for Exfil and WebAttack     |
| Static plots    | matplotlib, seaborn| Training-phase plot generation             |
| Interactive     | plotly             | Interactive charts in dashboard            |
| Dashboard       | streamlit          | Web application framework                  |
| Model saving    | joblib             | Save and load trained ML models            |
| PDF             | fpdf2              | PDF incident report export                 |
| IDE             | VS Code            | Development environment                    |
| GPU             | NVIDIA RTX 5060 Ti | 16GB VRAM, available for future LLM        |

---

## 11. Key Results

### Data Scale

| Metric                  | Value                           |
|-------------------------|---------------------------------|
| Raw dataset             | 47 million rows, 13 GB, 169 files |
| Files processed         | 50 of 169 (RAM-safe batches)    |
| Rows after balancing    | 350,000 (7 x 50,000)           |
| Training set            | 280,000 rows x 35 features      |
| Test set                | 70,000 rows x 35 features       |
| Models trained          | 8 (7 specialist + 1 master)     |
| Visualizations          | 10 plots                        |

### Detection Results from Timeline

| Stage         | Events | Confidence | Severity |
|---------------|--------|------------|----------|
| Reconnaissance| 179    | 79.7%      | 3/10     |
| WebAttack     | 243    | 71.3%      | 6/10     |
| C2_Botnet     | 198    | 99.6%      | 8/10     |
| LateralMvmt   | 178    | 83.9%      | 7/10     |
| Exfiltration  | 189    | 78.2%      | 9/10     |
| DDoS          | 200    | 99.4%      | 5/10     |
| **TOTAL**     | **1,187** | **Threat: CRITICAL** | **6/6 stages** |

---

## 12. Challenges and Solutions

### Challenge 1: 13 GB Dataset, Only 16 GB RAM
**Problem:** Cannot load all 169 CSV files into RAM simultaneously.
**Solution:** Batch loading strategy - BATCH_SIZE=5, TOTAL_BATCHES=10.
Only 50 of 169 files processed. RAM stayed under 3 GB throughout.

### Challenge 2: Severe Class Imbalance (DDoS = 90.1%)
**Problem:** Naive model gets 90% accuracy predicting DDoS always, missing rare attacks.
**Solution:** Dual-layer balancing:
- Undersample DDoS to 50,000 rows
- Oversample WebAttack, Exfiltration to 50,000 rows via sklearn.utils.resample
- class_weight=balanced in RF; scale_pos_weight in XGBoost

### Challenge 3: One Algorithm Cannot Fit All Threat Types
**Problem:** DDoS has loud clear patterns. C2 beaconing is subtle and unlabelled.
**Solution:** Used different algorithms per threat:
- Random Forest for supervised, clear-pattern threats (DDoS, Recon, Lateral)
- XGBoost for rare-event precision threats (Exfiltration, WebAttack)
- Isolation Forest for anomaly-based threats (C2/Botnet, Malware)

### Challenge 4: Windows Encoding Error (Emoji in Terminal Output)
**Problem:** cp1252 encoding caused UnicodeEncodeError for emoji in timeline.py output.
**Solution:** Added at top of timeline.py:
```python
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
```

### Challenge 5: Isolation Forest Has No Probability Score
**Problem:** Isolation Forest returns only +1/-1 (not probabilities). Dashboard needs 0-1 confidence.
**Solution:** IF predictions mapped to binary. decision_function() scores used to indicate anomaly strength.

---

## 13. Current Status and Next Steps

| Phase   | Description                                     | Status   |
|---------|-------------------------------------------------|----------|
| Phase 1 | Dataset exploration, label mapping, 3 plots     | DONE     |
| Phase 2 | Feature engineering, balancing, train/test split| DONE     |
| Phase 3 | 7 ML models + master - trained, saved, evaluated| DONE     |
| Phase 4 | Timeline engine, kill chain, narrative generator| DONE     |
| Phase 5 | Streamlit dashboard, 4 charts, PDF export       | DONE     |
| Phase 6 | MQTT/CoAP, live capture, Docker, README, demo   | PLANNED  |

---

## 14. File and Folder Structure

```
network-forensics/
|-- venv/                      <- Python virtual environment
|-- data/
|   |-- raw/CIC(iot)/          <- 169 CSV files (~13 GB)
|   `-- processed/
|       |-- X_train.csv        <- 280,000 rows x 35 features
|       |-- X_test.csv         <- 70,000 rows x 35 features
|       |-- y_train.csv / y_test.csv <- encoded labels
|       |-- features_used.txt  <- 35 feature names
|       |-- sample_clean.csv   <- cleaned sample (~200 MB)
|       |-- sample_ddos.csv / sample_webattack.csv etc.
|       |-- attack_events.csv  <- 1,187 attack events
|       |-- attack_narrative.txt <- human-readable story
|       |-- kill_chain_summary.json <- dashboard data
|       `-- plot_01 to plot_10 .png <- 10 visualizations
|-- models/
|   |-- model_master.joblib    <- 7-class RF (433 MB)
|   |-- model_ddos.joblib      <- DDoS RF (3.9 MB)
|   |-- model_recon.joblib     <- Recon RF (33.5 MB)
|   |-- model_c2.joblib        <- C2 Iso Forest (7.5 MB)
|   |-- model_lateral.joblib   <- Lateral RF (140 MB)
|   |-- model_exfil.joblib     <- Exfil XGBoost (1.6 MB)
|   |-- model_web.joblib       <- Web XGBoost (1.4 MB)
|   |-- model_malware.joblib   <- Malware Iso Forest (1.1 MB)
|   |-- scaler.joblib          <- StandardScaler
|   `-- label_encoder.joblib   <- LabelEncoder
|-- notebooks/explore.py       <- Phase 1 (375 lines)
|-- src/
|   |-- parser.py              <- PCAP reader (122 lines)
|   |-- features.py            <- Phase 2 (313 lines)
|   |-- models.py              <- Phase 3 (539 lines)
|   |-- timeline.py            <- Phase 4 (556 lines)
|   |-- fix_models.py          <- model repair utility
|   `-- regen_narrative.py     <- regenerate narrative
|-- dashboard/app.py           <- Phase 5 Streamlit (786 lines)
|-- generate_test_csv.py       <- test file generator
|-- test_traffic_for_upload.csv <- sample dashboard test file
|-- requirements.txt           <- all Python dependencies
|-- Project.md                 <- living project brain (338 lines)
`-- .gitignore
```

---

## Appendix: Cyber Kill Chain Stage Definitions

The Lockheed Martin Cyber Kill Chain models the stages of a cyberattack.
This project uses a 6-stage IoT-adapted variant:

```
Stage 1: Reconnaissance --> Stage 2: WebAttack --> Stage 3: C2/Botnet
                                                          |
Stage 4: Lateral Movement --> Stage 5: Exfiltration --> Stage 6: DDoS (smokescreen)
```

Each stage is detected by its specialist ML model, then the timeline engine
reconstructs the full attack narrative - showing which stages occurred, in what order,
with what confidence and severity. This gives a complete attack picture
rather than isolated, disconnected alerts.

---

*Report Date: August 20, 2026*
*Project: FedForensic*
*Developer: Harshal*