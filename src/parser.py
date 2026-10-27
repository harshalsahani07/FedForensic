# src/parser.py
# Phase 6 — Full PCAP -> ML Feature Pipeline
# Goal: Read a .pcap file, reconstruct network flows, compute the exact 35
#       features that the trained models expect (CIC-IoT 2023 format).
# Author: Harshal
#
# Integration:
#   from src.parser import pcap_to_ml_features
#   df = pcap_to_ml_features("capture.pcap")   # -> DataFrame with 35 columns
#
# Run standalone:
#   python src/parser.py path/to/capture.pcap

import os
import sys
import warnings
import math
from collections import defaultdict
from datetime import datetime

import numpy as np
import pandas as pd

warnings.filterwarnings('ignore')

# -- Feature names (must match features_used.txt exactly) ---------------------
ML_FEATURES = [
    'Variance', 'ack_flag_number', 'Tot size', 'Header_Length', 'Covariance',
    'flow_duration', 'Rate', 'Srate', 'Drate', 'IAT',
    'Number', 'Weight', 'Radius', 'Magnitue',
    'fin_flag_number', 'syn_flag_number', 'rst_flag_number',
    'psh_flag_number', 'ece_flag_number', 'cwr_flag_number',
    'ack_count', 'syn_count', 'fin_count', 'rst_count',
    'TCP', 'UDP', 'ICMP', 'HTTP', 'DNS', 'HTTPS',
    'Tot sum', 'Min', 'Max', 'AVG', 'Std',
]

# Protocol port maps
HTTP_PORTS  = {80, 8080, 8000, 8888}
HTTPS_PORTS = {443, 8443}
DNS_PORTS   = {53}

# TCP flag bits (Scapy bitmask)
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_ECE = 0x40
FLAG_CWR = 0x80


# == Step 1: Load PCAP ========================================================

def load_pcap(filepath: str):
    """Load a PCAP or PCAPNG file using scapy. Returns list of packets."""
    try:
        from scapy.all import rdpcap
    except ImportError:
        raise ImportError("scapy is not installed. Run: pip install scapy")

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"PCAP file not found: {filepath}")

    ext = os.path.splitext(filepath)[1].lower()
    if ext not in ('.pcap', '.pcapng', '.cap'):
        raise ValueError(f"Unsupported file type: {ext}. Expected .pcap / .pcapng / .cap")

    print(f"[1/4] Loading PCAP: {os.path.basename(filepath)}")
    from scapy.all import rdpcap
    packets = rdpcap(filepath)
    print(f"      OK  {len(packets):,} packets loaded")
    return packets


# == Step 2: Extract Flows ====================================================

def extract_flows(packets) -> dict:
    """
    Group raw packets into network flows by 5-tuple key:
      (src_ip, dst_ip, proto, src_port, dst_port)

    Each flow stores a list of packet dicts:
      {'time': float, 'size': int, 'header': int,
       'flags': int (TCP bitmask), 'direction': 'fwd' or 'bwd'}

    Returns: dict mapping flow_key -> list of packet dicts
    """
    try:
        from scapy.all import IP, TCP, UDP, ICMP
    except ImportError:
        raise ImportError("scapy is not installed.")

    flows = defaultdict(list)
    skipped = 0

    for pkt in packets:
        if not pkt.haslayer(IP):
            skipped += 1
            continue

        src_ip   = pkt[IP].src
        dst_ip   = pkt[IP].dst
        proto    = pkt[IP].proto      # 6=TCP, 17=UDP, 1=ICMP
        pkt_time = float(pkt.time)
        pkt_size = len(pkt)

        src_port = 0
        dst_port = 0
        flags    = 0
        hdr_len  = pkt[IP].ihl * 4   # IP header bytes

        if pkt.haslayer(TCP):
            src_port  = int(pkt[TCP].sport)
            dst_port  = int(pkt[TCP].dport)
            flags     = int(pkt[TCP].flags)
            hdr_len  += pkt[TCP].dataofs * 4

        elif pkt.haslayer(UDP):
            src_port  = int(pkt[UDP].sport)
            dst_port  = int(pkt[UDP].dport)
            hdr_len  += 8

        elif pkt.haslayer(ICMP):
            hdr_len  += 8

        # Canonical key: lower (IP, port) first so both directions map to same flow
        if (src_ip, src_port) <= (dst_ip, dst_port):
            key       = (src_ip, dst_ip, proto, src_port, dst_port)
            direction = 'fwd'
        else:
            key       = (dst_ip, src_ip, proto, dst_port, src_port)
            direction = 'bwd'

        flows[key].append({
            'time':      pkt_time,
            'size':      pkt_size,
            'header':    hdr_len,
            'flags':     flags,
            'direction': direction,
        })

    total_pkts = sum(len(v) for v in flows.values())
    print(f"[2/4] Flow extraction: {len(flows):,} flows "
          f"from {total_pkts:,} IP packets  ({skipped} non-IP skipped)")
    return dict(flows)


# == Step 3: Compute ML Features Per Flow =====================================

def _safe_std(vals):
    return float(np.std(vals)) if len(vals) > 1 else 0.0

def _safe_var(vals):
    return float(np.var(vals)) if len(vals) > 1 else 0.0

def _flag_count(pkts, bit):
    return sum(1 for p in pkts if (p['flags'] & bit))


def compute_flow_features(flow_key: tuple, packets: list) -> dict:
    """
    Compute all 35 ML features for a single reconstructed flow.
    Also adds metadata columns (_src_ip, _dst_ip, etc.) for dashboard display.
    """
    src_ip, dst_ip, proto, src_port, dst_port = flow_key

    pkts  = sorted(packets, key=lambda p: p['time'])
    n     = len(pkts)
    sizes   = [p['size']   for p in pkts]
    headers = [p['header'] for p in pkts]
    times   = [p['time']   for p in pkts]

    fwd_pkts  = [p for p in pkts if p['direction'] == 'fwd']
    bwd_pkts  = [p for p in pkts if p['direction'] == 'bwd']

    # -- Timing ---------------------------------------------------------------
    t_start       = times[0]
    t_end         = times[-1]
    flow_duration = max(t_end - t_start, 1e-6)

    iats    = [times[i+1] - times[i] for i in range(n - 1)]
    iat_mean = float(np.mean(iats)) if iats else 0.0

    # -- Size stats -----------------------------------------------------------
    tot_sum  = float(sum(sizes))
    pkt_min  = float(min(sizes))
    pkt_max  = float(max(sizes))
    pkt_avg  = float(np.mean(sizes))
    pkt_std  = _safe_std(sizes)
    variance = _safe_var(sizes)

    # -- CICFlowMeter-style derived features ----------------------------------
    # Magnitue (original dataset typo for "Magnitude"): vector magnitude of (mean, std)
    magnitue = math.sqrt(pkt_avg ** 2 + pkt_std ** 2)

    # Radius: measure of spread in 2D space = sqrt(2 * variance)
    radius = math.sqrt(2.0 * variance)

    # Weight: traffic intensity = packets * mean_size / duration
    weight = (n * pkt_avg) / flow_duration

    # Covariance: relationship between packet size and position in flow
    if n > 1:
        indices    = np.arange(n, dtype=float)
        covariance = float(np.cov(np.array(sizes, dtype=float), indices)[0, 1])
    else:
        covariance = 0.0

    header_length = float(np.mean(headers))
    tot_size      = tot_sum   # same value, different column name in CIC dataset

    # -- Rates ----------------------------------------------------------------
    rate  = n              / flow_duration
    srate = len(fwd_pkts)  / flow_duration
    drate = len(bwd_pkts)  / flow_duration

    # -- TCP flags ------------------------------------------------------------
    syn_count = _flag_count(pkts, FLAG_SYN)
    ack_count = _flag_count(pkts, FLAG_ACK)
    fin_count = _flag_count(pkts, FLAG_FIN)
    rst_count = _flag_count(pkts, FLAG_RST)
    psh_count = _flag_count(pkts, FLAG_PSH)
    ece_count = _flag_count(pkts, FLAG_ECE)
    cwr_count = _flag_count(pkts, FLAG_CWR)

    # Normalised (fraction of packets that have each flag set)
    syn_flag_number = syn_count / n
    ack_flag_number = ack_count / n
    fin_flag_number = fin_count / n
    rst_flag_number = rst_count / n
    psh_flag_number = psh_count / n
    ece_flag_number = ece_count / n
    cwr_flag_number = cwr_count / n

    # -- Protocol indicators --------------------------------------------------
    is_tcp  = 1 if proto == 6  else 0
    is_udp  = 1 if proto == 17 else 0
    is_icmp = 1 if proto == 1  else 0

    ports = {src_port, dst_port}
    http  = 1 if ports & HTTP_PORTS  else 0
    https = 1 if ports & HTTPS_PORTS else 0
    dns   = 1 if ports & DNS_PORTS   else 0

    return {
        # -- 35 ML features ---------------------------------------------------
        'Variance':         variance,
        'ack_flag_number':  ack_flag_number,
        'Tot size':         tot_size,
        'Header_Length':    header_length,
        'Covariance':       covariance,
        'flow_duration':    flow_duration,
        'Rate':             rate,
        'Srate':            srate,
        'Drate':            drate,
        'IAT':              iat_mean,
        'Number':           float(n),
        'Weight':           weight,
        'Radius':           radius,
        'Magnitue':         magnitue,
        'fin_flag_number':  fin_flag_number,
        'syn_flag_number':  syn_flag_number,
        'rst_flag_number':  rst_flag_number,
        'psh_flag_number':  psh_flag_number,
        'ece_flag_number':  ece_flag_number,
        'cwr_flag_number':  cwr_flag_number,
        'ack_count':        float(ack_count),
        'syn_count':        float(syn_count),
        'fin_count':        float(fin_count),
        'rst_count':        float(rst_count),
        'TCP':              float(is_tcp),
        'UDP':              float(is_udp),
        'ICMP':             float(is_icmp),
        'HTTP':             float(http),
        'DNS':              float(dns),
        'HTTPS':            float(https),
        'Tot sum':          tot_sum,
        'Min':              pkt_min,
        'Max':              pkt_max,
        'AVG':              pkt_avg,
        'Std':              pkt_std,
        # -- Metadata for dashboard display (not fed to models) ---------------
        '_src_ip':          src_ip,
        '_dst_ip':          dst_ip,
        '_proto':           proto,
        '_src_port':        src_port,
        '_dst_port':        dst_port,
        '_pkt_count':       n,
        '_flow_start':      datetime.fromtimestamp(t_start).strftime('%H:%M:%S.%f')[:12],
    }


# == Step 4: Master one-call function =========================================

def pcap_to_ml_features(filepath: str, min_packets: int = 1) -> pd.DataFrame:
    """
    Master function: PCAP file -> DataFrame with 35 ML feature columns.

    Parameters
    ----------
    filepath    : path to .pcap or .pcapng file
    min_packets : minimum packets required to include a flow (default: 1)

    Returns
    -------
    pd.DataFrame containing exactly the 35 ML_FEATURES columns
    plus metadata columns prefixed with '_' for display in the dashboard.
    """
    # 1. Load raw packets
    packets = load_pcap(filepath)

    # 2. Group into flows
    flows = extract_flows(packets)

    # 3. Compute features per flow
    print(f"[3/4] Computing {len(ML_FEATURES)} ML features for {len(flows):,} flows...")
    records = []
    for key, pkt_list in flows.items():
        if len(pkt_list) < min_packets:
            continue
        try:
            records.append(compute_flow_features(key, pkt_list))
        except Exception:
            pass   # skip malformed flows silently

    if not records:
        raise ValueError(
            "No valid flows found in the PCAP file. "
            "Make sure the file contains IP (TCP/UDP/ICMP) traffic."
        )

    df = pd.DataFrame(records)

    # 4. Sanitise
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    # Ensure all 35 ML columns exist (fill 0 if somehow missing)
    for col in ML_FEATURES:
        if col not in df.columns:
            df[col] = 0.0

    print(f"[4/4] Done:  {len(df):,} flows  |  {len(ML_FEATURES)} ML features  |  "
          f"TCP={int(df['TCP'].sum())}  UDP={int(df['UDP'].sum())}  "
          f"ICMP={int(df['ICMP'].sum())}")
    return df


def get_pcap_summary(df: pd.DataFrame) -> dict:
    """
    Return a human-readable summary dict from a pcap-derived feature DataFrame.
    Used by the dashboard to display PCAP metadata before showing ML results.
    """
    return {
        'flow_count':      len(df),
        'pkt_count':       int(df['_pkt_count'].sum()) if '_pkt_count' in df.columns else '?',
        'tcp_flows':       int(df['TCP'].sum()),
        'udp_flows':       int(df['UDP'].sum()),
        'icmp_flows':      int(df['ICMP'].sum()),
        'http_flows':      int(df['HTTP'].sum()),
        'https_flows':     int(df['HTTPS'].sum()),
        'dns_flows':       int(df['DNS'].sum()),
        'unique_src_ips':  df['_src_ip'].nunique() if '_src_ip' in df.columns else '?',
        'unique_dst_ips':  df['_dst_ip'].nunique() if '_dst_ip' in df.columns else '?',
        'avg_flow_dur_s':  round(float(df['flow_duration'].mean()), 4),
        'avg_pkt_size_b':  round(float(df['AVG'].mean()), 1),
    }


# == Standalone CLI ===========================================================

if __name__ == '__main__':
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else 'data/raw/sample.pcap'

    print('=' * 55)
    print('  PCAP -> ML Feature Extractor')
    print('=' * 55)

    df = pcap_to_ml_features(pcap_file)

    summary = get_pcap_summary(df)
    print('\n-- PCAP Summary --')
    for k, v in summary.items():
        print(f"  {k.replace('_', ' ').title():<22}: {v}")

    print('\n-- Feature Sample (first 3 flows) --')
    print(df[ML_FEATURES].head(3).to_string(index=False))

    out = 'data/processed/pcap_features.csv'
    df[ML_FEATURES].to_csv(out, index=False)
    print(f'\nSaved ML features to: {out}')
    print('=' * 55)