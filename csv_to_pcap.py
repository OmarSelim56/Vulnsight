"""
csv_to_pcap.py
==============
Convert a processed CIC-IDS feature CSV into a synthetic pcap file.

Each CSV row = one network flow.
The script synthesises raw TCP/UDP packets whose aggregate statistics
(packet sizes, inter-arrival times, flag counts) match the 20 flow features
the VulnSight model was trained on.

Usage
-----
    python csv_to_pcap.py --input dataset.csv --output attack.pcap
    python csv_to_pcap.py --input dataset.csv --output attack.pcap --rows 200 --delay 0.01
    python csv_to_pcap.py --input dataset.csv --output attack.pcap --malicious-only

Dependencies
------------
    pip install scapy pandas numpy
"""

import argparse
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

try:
    from scapy.all import wrpcap
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.packet import Raw
except ImportError:
    sys.exit("[!] Scapy not found.  Run:  pip install scapy")

# ---------------------------------------------------------------------------
# Column-name aliases
# CIC-IDS2017/2018 datasets ship with slightly different header spellings
# depending on which CICFlowMeter version was used.  Add your own here if
# your CSV uses different names.
# ---------------------------------------------------------------------------

COL_ALIASES: dict[str, list[str]] = {
    "flow_duration":     ["Flow Duration", "flow_duration", "FlowDuration"],
    "total_fwd_pkts":    ["Total Fwd Packets", "total_fwd_packets", "TotFwdPkts"],
    "total_bwd_pkts":    ["Total Backward Packets", "total_bwd_packets", "TotBwdPkts"],
    "total_len_fwd":     ["Total Length of Fwd Packets", "total_length_of_fwd_packets", "TotLenFwdPkts"],
    "total_len_bwd":     ["Total Length of Bwd Packets", "total_length_of_bwd_packets", "TotLenBwdPkts"],
    "fwd_pkt_len_mean":  ["Fwd Packet Length Mean", "fwd_pkt_len_mean", "FwdPktLenMean"],
    "bwd_pkt_len_mean":  ["Bwd Packet Length Mean", "bwd_pkt_len_mean", "BwdPktLenMean"],
    "pkt_len_mean":      ["Packet Length Mean", "packet_length_mean", "PktLenMean"],
    "pkt_len_std":       ["Packet Length Std", "packet_length_std", "PktLenStd"],
    "pkt_len_var":       ["Packet Length Variance", "packet_length_variance", "PktLenVar"],
    "flow_bytes_s":      ["Flow Bytes/s", "flow_bytes/s", "FlowByts/s", "flow_byts_s"],
    "flow_pkts_s":       ["Flow Packets/s", "flow_packets/s", "FlowPkts/s", "flow_pkts_s"],
    "flow_iat_mean":     ["Flow IAT Mean", "flow_iat_mean", "FlowIATMean"],
    "flow_iat_std":      ["Flow IAT Std", "flow_iat_std", "FlowIATStd"],
    "fwd_iat_mean":      ["Fwd IAT Mean", "fwd_iat_mean", "FwdIATMean", "Fwd IAT Tot"],
    "bwd_iat_mean":      ["Bwd IAT Mean", "bwd_iat_mean", "BwdIATMean", "Bwd IAT Tot"],
    "active_mean":       ["Active Mean", "active_mean", "ActiveMean"],
    "fin_flag_count":    ["FIN Flag Count", "fin_flag_count", "FinFlagCnt"],
    "syn_flag_count":    ["SYN Flag Count", "syn_flag_count", "SynFlagCnt"],
    "rst_flag_count":    ["RST Flag Count", "rst_flag_count", "RstFlagCnt"],
    "label":             ["Label", "label", " Label"],
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def resolve_columns(df: pd.DataFrame) -> dict[str, str]:
    """Return a mapping canonical_key → actual_csv_column."""
    mapping: dict[str, str] = {}
    for key, aliases in COL_ALIASES.items():
        for alias in aliases:
            if alias in df.columns:
                mapping[key] = alias
                break
    return mapping


def get(row, col_map: dict, key: str, default=0.0) -> float:
    col = col_map.get(key)
    if col is None:
        return default
    val = row.get(col, default)
    try:
        v = float(val)
        return 0.0 if (np.isnan(v) or np.isinf(v)) else v
    except (TypeError, ValueError):
        return default


def clamp(val: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, val))


def rand_private_ip() -> str:
    return f"192.168.{random.randint(1, 10)}.{random.randint(2, 254)}"


def rand_attack_ip() -> str:
    pools = ["45.33.", "23.94.", "185.220.", "198.199."]
    prefix = random.choice(pools)
    return prefix + f"{random.randint(1,254)}.{random.randint(1,254)}"


def synthesise_sizes(n: int, mean: float, std: float) -> list[int]:
    """Return n positive integer packet sizes centred on mean±std."""
    if n <= 0:
        return []
    mean = clamp(mean, 20, 1460)
    std  = clamp(std,  0,  mean * 0.8)
    sizes = np.random.normal(mean, std, n)
    sizes = np.clip(sizes, 20, 1460).astype(int).tolist()
    return sizes


def synthesise_iats(n: int, mean_us: float, std_us: float) -> list[float]:
    """Return n inter-arrival times in seconds (input in microseconds)."""
    if n <= 0:
        return []
    mean_s = clamp(mean_us, 0, 1e9) / 1e6
    std_s  = clamp(std_us,  0, mean_us * 1.5) / 1e6
    iats = np.random.exponential(max(mean_s, 1e-6), n)
    return iats.tolist()


# ---------------------------------------------------------------------------
# Core: build a list of Scapy packets from one CSV row
# ---------------------------------------------------------------------------

def flow_to_packets(
    row,
    col_map: dict,
    base_ts: float,
    inter_flow_gap: float,
) -> list:
    """Synthesise raw Scapy packets for a single flow row."""

    # ── feature extraction ────────────────────────────────────────────────
    duration_us   = get(row, col_map, "flow_duration",    1_000_000)
    n_fwd         = max(1, int(get(row, col_map, "total_fwd_pkts",   1)))
    n_bwd         = max(0, int(get(row, col_map, "total_bwd_pkts",   0)))
    fwd_len_mean  = get(row, col_map, "fwd_pkt_len_mean", 64)
    bwd_len_mean  = get(row, col_map, "bwd_pkt_len_mean", 64)
    pkt_len_std   = get(row, col_map, "pkt_len_std",      20)
    flow_iat_mean = get(row, col_map, "flow_iat_mean",    100_000)
    flow_iat_std  = get(row, col_map, "flow_iat_std",     50_000)
    fwd_iat_mean  = get(row, col_map, "fwd_iat_mean",     flow_iat_mean)
    bwd_iat_mean  = get(row, col_map, "bwd_iat_mean",     flow_iat_mean)
    fin_count     = int(get(row, col_map, "fin_flag_count", 0))
    syn_count     = int(get(row, col_map, "syn_flag_count", 0))
    rst_count     = int(get(row, col_map, "rst_flag_count", 0))
    label         = str(row.get(col_map.get("label", "Label"), "BENIGN")).strip().upper()

    is_tcp = (syn_count > 0 or fin_count > 0 or rst_count > 0)

    # ── addressing ────────────────────────────────────────────────────────
    if "BENIGN" in label:
        src_ip  = rand_private_ip()
        dst_ip  = rand_private_ip()
        dst_port = random.choice([80, 443, 22, 53, 8080, 3306])
    else:
        src_ip  = rand_attack_ip()
        dst_ip  = rand_private_ip()
        dst_port = random.choice([80, 443, 22, 23, 53, 3389, 8080])

    src_port = random.randint(1024, 65535)

    # ── packet sizes ──────────────────────────────────────────────────────
    fwd_sizes = synthesise_sizes(n_fwd, fwd_len_mean, pkt_len_std)
    bwd_sizes = synthesise_sizes(n_bwd, bwd_len_mean, pkt_len_std)

    # ── timestamps ────────────────────────────────────────────────────────
    # Forward IATs
    fwd_iats = synthesise_iats(n_fwd - 1, fwd_iat_mean, flow_iat_std)
    fwd_ts   = [base_ts]
    for iat in fwd_iats:
        fwd_ts.append(fwd_ts[-1] + iat)

    # Backward IATs  (start slightly after first forward packet)
    bwd_iats = synthesise_iats(n_bwd - 1, bwd_iat_mean, flow_iat_std) if n_bwd > 1 else []
    bwd_ts   = []
    if n_bwd > 0:
        bwd_start = base_ts + clamp(fwd_iat_mean / 1e6 / 2, 0.001, 0.5)
        bwd_ts = [bwd_start]
        for iat in bwd_iats:
            bwd_ts.append(bwd_ts[-1] + iat)

    # ── TCP flag assignment ────────────────────────────────────────────────
    def tcp_flags(idx: int, total: int, direction: str) -> str:
        flags = "A"  # default ACK
        if direction == "fwd":
            if idx == 0 and syn_count > 0:
                flags = "S"
            elif idx == total - 1 and fin_count > 0:
                flags = "FA"
            elif rst_count > 0 and idx == total - 1 and fin_count == 0:
                flags = "RA"
        elif direction == "bwd":
            if idx == 0 and syn_count > 0:
                flags = "SA"
        return flags

    # ── build Scapy packets ───────────────────────────────────────────────
    packets = []

    for i, (ts, size) in enumerate(zip(fwd_ts, fwd_sizes)):
        payload_size = max(0, size - 40)   # subtract IP+TCP/UDP header
        payload = bytes(random.getrandbits(8) for _ in range(payload_size))

        if is_tcp:
            flags = tcp_flags(i, n_fwd, "fwd")
            pkt = (
                Ether() /
                IP(src=src_ip, dst=dst_ip) /
                TCP(sport=src_port, dport=dst_port, flags=flags) /
                Raw(load=payload)
            )
        else:
            pkt = (
                Ether() /
                IP(src=src_ip, dst=dst_ip) /
                UDP(sport=src_port, dport=dst_port) /
                Raw(load=payload)
            )

        pkt.time = ts
        packets.append(pkt)

    for i, (ts, size) in enumerate(zip(bwd_ts, bwd_sizes)):
        payload_size = max(0, size - 40)
        payload = bytes(random.getrandbits(8) for _ in range(payload_size))

        if is_tcp:
            flags = tcp_flags(i, n_bwd, "bwd")
            pkt = (
                Ether() /
                IP(src=dst_ip, dst=src_ip) /
                TCP(sport=dst_port, dport=src_port, flags=flags) /
                Raw(load=payload)
            )
        else:
            pkt = (
                Ether() /
                IP(src=dst_ip, dst=src_ip) /
                UDP(sport=dst_port, dport=src_port) /
                Raw(load=payload)
            )

        pkt.time = ts
        packets.append(pkt)

    # sort by timestamp so pcap is chronological
    packets.sort(key=lambda p: float(p.time))
    return packets


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Convert a CIC-IDS feature CSV to a synthetic pcap for tcpreplay"
    )
    parser.add_argument("--input",          required=True,         help="Path to input CSV file")
    parser.add_argument("--output",         default="output.pcap", help="Path to output pcap file")
    parser.add_argument("--rows",           type=int, default=500, help="Number of flows to process (default 500)")
    parser.add_argument("--delay",          type=float, default=0.01, help="Gap between flows in seconds (default 0.01)")
    parser.add_argument("--malicious-only", action="store_true",   help="Only include malicious/attack flows")
    parser.add_argument("--benign-only",    action="store_true",   help="Only include benign flows")
    parser.add_argument("--seed",           type=int, default=42,  help="Random seed for reproducibility")
    args = parser.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)

    # ── load CSV ──────────────────────────────────────────────────────────
    print(f"[→] Loading {args.input} …")
    df = pd.read_csv(args.input, low_memory=False)
    df.columns = df.columns.str.strip()   # remove stray whitespace in headers
    print(f"    {len(df):,} rows  ×  {len(df.columns)} columns")

    col_map = resolve_columns(df)
    missing = [k for k in COL_ALIASES if k not in col_map]
    if missing:
        print(f"[!] Could not find columns for: {missing}")
        print(f"    Available columns: {list(df.columns)}")

    # ── filter ────────────────────────────────────────────────────────────
    label_col = col_map.get("label")
    if label_col:
        if args.malicious_only:
            df = df[~df[label_col].str.strip().str.upper().eq("BENIGN")]
            print(f"[→] After malicious-only filter: {len(df):,} rows")
        elif args.benign_only:
            df = df[df[label_col].str.strip().str.upper().eq("BENIGN")]
            print(f"[→] After benign-only filter: {len(df):,} rows")

    if len(df) == 0:
        sys.exit("[!] No rows remaining after filter. Check your CSV labels.")

    # ── sample ────────────────────────────────────────────────────────────
    if args.rows and args.rows < len(df):
        df = df.sample(n=args.rows, random_state=args.seed).reset_index(drop=True)
        print(f"[→] Sampled {len(df):,} rows")

    # ── synthesise packets ────────────────────────────────────────────────
    all_packets = []
    base_ts     = datetime.now(timezone.utc).timestamp()
    label_counts: dict[str, int] = {}

    print(f"\n[→] Synthesising packets …")
    t0 = time.time()

    for idx, (_, row) in enumerate(df.iterrows()):
        pkts = flow_to_packets(row, col_map, base_ts, args.delay)
        all_packets.extend(pkts)

        label_col = col_map.get("label")
        lbl = str(row.get(label_col, "UNKNOWN")).strip() if label_col else "UNKNOWN"
        label_counts[lbl] = label_counts.get(lbl, 0) + 1

        # advance base timestamp by flow duration + inter-flow gap
        duration_us = get(row, col_map, "flow_duration", 100_000)
        base_ts += (duration_us / 1e6) + args.delay

        if (idx + 1) % 50 == 0 or (idx + 1) == len(df):
            pct = (idx + 1) / len(df) * 100
            print(f"    {idx + 1:>5}/{len(df)}  ({pct:.0f}%)  packets so far: {len(all_packets):,}")

    elapsed = time.time() - t0

    # ── sort all packets globally by timestamp ────────────────────────────
    all_packets.sort(key=lambda p: float(p.time))

    # ── write pcap ────────────────────────────────────────────────────────
    out = Path(args.output)
    print(f"\n[→] Writing {len(all_packets):,} packets to {out} …")
    wrpcap(str(out), all_packets)

    size_kb = out.stat().st_size / 1024

    # ── summary ───────────────────────────────────────────────────────────
    print(f"""
╔══════════════════════════════════════════════╗
║              csv_to_pcap  done               ║
╠══════════════════════════════════════════════╣
  Input CSV   : {args.input}
  Output pcap : {out}  ({size_kb:.1f} KB)
  Flows       : {len(df):,}
  Packets     : {len(all_packets):,}
  Elapsed     : {elapsed:.1f}s

  Label breakdown:""")
    for lbl, cnt in sorted(label_counts.items(), key=lambda x: -x[1]):
        bar = "█" * min(30, int(cnt / max(label_counts.values()) * 30))
        print(f"    {lbl:<35} {cnt:>5}  {bar}")

    print(f"""
  Next steps:
    # Verify the pcap
    tcpdump -r {out} -n | head -20

    # Replay on your network interface (run as root / admin)
    tcpreplay --intf=eth0 --multiplier=1.0 {out}

    # Slow replay for easier capture
    tcpreplay --intf=eth0 --pps=100 {out}
╚══════════════════════════════════════════════╝""")


if __name__ == "__main__":
    main()
