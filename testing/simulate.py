"""
simulate.py — Feed dataset CSVs through VulnSight's real model and push alerts to the API.

Usage (from project root OR from testing/):
    python testing/simulate.py                                         # all CSVs in dataset/processed/
    python testing/simulate.py --file Friday-WorkingHours-Morning.pcap_ISCX.csv  # single file
    python testing/simulate.py --rows 200 --delay 0.2                 # slower, fewer rows
    python testing/simulate.py --malicious-only                        # skip benign rows
    python testing/simulate.py --scenario org                          # realistic org deployment scenario
    python testing/simulate.py --scenario org --rate 3                 # 3 alerts/second (default 5)
"""

import argparse
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── project root is one level up from this file ───────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
import requests

try:
    from src.core.feature_config import FEATURE_NAMES
    from src.detection.engine import InferenceEngine
    from src.detection.classifier import infer_attack_type_from_label
except ModuleNotFoundError as e:
    sys.exit(f"[!] Import error: {e}\n    Make sure you are inside the Vulnsight project.")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DATASET_DIR   = PROJECT_ROOT / "dataset" / "processed"
MODEL_PATH    = str(PROJECT_ROOT / "model" / "vulnsight_cnn_bilstm.pth")
SCALER_PATH   = str(PROJECT_ROOT / "model" / "scaler.pkl")
VULNSIGHT_URL = "http://localhost:8000"
USERNAME      = "admin"
PASSWORD      = "admin12345"

# ---------------------------------------------------------------------------
# Org scenario: scripted phases that mimic a realistic attack campaign
# ---------------------------------------------------------------------------
ORG_SCENARIO_PHASES = [
    {
        "name":           "Baseline — Normal Working Hours",
        "csv_glob":       "Monday*",
        "malicious_only": False,
        "rows":           150,
        "pause_before":   0,
        "description":    "Quiet Monday morning: only benign traffic flowing through.",
    },
    {
        "name":           "DDoS Attack Surge",
        "csv_glob":       "Friday*DDos*",
        "malicious_only": True,
        "rows":           120,
        "pause_before":   3,
        "description":    "Attacker launches volumetric DDoS.  Alert rate spikes.",
    },
    {
        "name":           "Port Scan Recon",
        "csv_glob":       "Friday*PortScan*",
        "malicious_only": True,
        "rows":           80,
        "pause_before":   3,
        "description":    "Post-DDoS recon: attacker sweeps internal port ranges.",
    },
    {
        "name":           "Brute Force — SSH & FTP",
        "csv_glob":       "Tuesday*",
        "malicious_only": True,
        "rows":           100,
        "pause_before":   3,
        "description":    "Credential stuffing on SSH (port 22) and FTP (port 21).",
    },
    {
        "name":           "Web Application Attacks",
        "csv_glob":       "Thursday*WebAttacks*",
        "malicious_only": True,
        "rows":           60,
        "pause_before":   3,
        "description":    "SQL injection and XSS attempts against the web tier.",
    },
    {
        "name":           "C2 Beacon Campaign",
        "csv_glob":       "Friday*Morning*",
        "malicious_only": True,
        "rows":           80,
        "pause_before":   3,
        "description":    "Compromised host phones home — regular heartbeat intervals.",
    },
    {
        "name":           "Data Exfiltration Attempt",
        "csv_glob":       "Thursday*Infilter*",
        "malicious_only": True,
        "rows":           30,
        "pause_before":   3,
        "description":    "Large outbound transfers — attacker exfiltrates data.",
    },
]

SEVERITY_MAP = {
    "ddos":              "critical",
    "port_scan":         "medium",
    "brute_force":       "medium",
    "data_exfiltration": "high",
    "c2_beacon":         "high",
    "intrusion":         "high",
    "normal":            "info",
}

LABEL_DISPLAY = {
    "ddos":              "DDoS DETECTED",
    "port_scan":         "PORT SCAN DETECTED",
    "brute_force":       "BRUTE FORCE DETECTED",
    "data_exfiltration": "DATA EXFILTRATION DETECTED",
    "c2_beacon":         "C2 BEACON DETECTED",
    "intrusion":         "INTRUSION DETECTED",
    "normal":            "NORMAL",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def login(url: str, username: str, password: str) -> str:
    resp = requests.post(
        f"{url}/api/v1/auth/login",
        json={"username": username, "password": password},
        timeout=10,
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]
    print(f"[+] Logged in as {username}")
    return token


def build_alert(
    features: list,
    is_malicious: bool,
    confidence: float,
    attack_type: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    shap_features: list,
) -> dict:
    severity = SEVERITY_MAP.get(attack_type, "medium")
    label    = LABEL_DISPLAY.get(attack_type, "INTRUSION DETECTED")
    if is_malicious:
        if confidence >= 0.95:
            conf_level = "very_high"
        elif confidence >= 0.89:
            conf_level = "high"
        else:
            conf_level = "medium"
    else:
        conf_level = "high" if confidence >= 0.85 else "medium" if confidence >= 0.70 else "low"
    triage = "block_and_investigate" if is_malicious else "allow"

    return {
        "timestamp":         datetime.now(timezone.utc).isoformat(),
        "source_ip":         src_ip,
        "destination_ip":    dst_ip,
        "protocol":          6,
        "dst_port":          int(dst_port),
        "interface":         "eth0",
        "prediction":        1 if is_malicious else 0,
        "label":             label,
        "attack_type":       attack_type,
        "confidence":        round(confidence, 4),
        "confidence_level":  conf_level,
        "severity":          severity,
        "triage_action":     triage,
        "is_malicious":      is_malicious,
        "shap_top_features": shap_features or [
            {"feature": FEATURE_NAMES[10], "impact": round(random.uniform(0.2, 0.7), 3), "direction": "positive"},
            {"feature": FEATURE_NAMES[11], "impact": round(random.uniform(0.1, 0.5), 3), "direction": "positive"},
        ],
    }


def load_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=FEATURE_NAMES)
    return df


def fake_ip(malicious: bool) -> tuple[str, str]:
    if malicious:
        src = f"{random.choice([45,185,23,198])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    else:
        src = f"192.168.{random.randint(1,5)}.{random.randint(2,254)}"
    dst = f"192.168.1.{random.randint(2, 50)}"
    return src, dst


# ---------------------------------------------------------------------------
# Scenario runner (Layer 2 — realistic org deployment)
# ---------------------------------------------------------------------------

def run_phase(phase: dict, engine: InferenceEngine, headers: dict, url: str,
              rate: float, sent_by_type: dict, detected_by_type: dict):
    matches = sorted(DATASET_DIR.glob(phase["csv_glob"]))
    if not matches:
        print(f"    [!] No CSV matching '{phase['csv_glob']}' in {DATASET_DIR} — skipping")
        return

    csv_path = matches[0]
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=FEATURE_NAMES)

    label_col = "Label"
    if label_col not in df.columns:
        print(f"    [!] No Label column — skipping")
        return

    if phase["malicious_only"]:
        df = df[df[label_col].str.upper() != "BENIGN"]

    if len(df) == 0:
        print(f"    [!] No rows after filter — skipping")
        return

    df = df.sample(n=min(phase["rows"], len(df)), random_state=42).reset_index(drop=True)
    engine.flow_buffer.clear()
    delay = 1.0 / rate if rate > 0 else 0.0

    for _, row in df.iterrows():
        features  = [float(row[col]) for col in FEATURE_NAMES]
        dst_port  = int(features[0])

        prediction, confidence = engine.process_flow(features)
        if prediction is None:
            continue

        is_malicious = prediction == 1
        csv_label    = str(row.get("Label", "")).strip().upper()
        attack_type  = infer_attack_type_from_label(csv_label, is_malicious)
        src_ip, dst_ip = fake_ip(is_malicious)

        alert = build_alert(features, is_malicious, confidence,
                            attack_type, src_ip, dst_ip, dst_port, [])
        sent_by_type[attack_type] = sent_by_type.get(attack_type, 0) + 1

        try:
            resp = requests.post(f"{url}/api/v1/alerts", json=alert,
                                 headers=headers, timeout=5)
            resp.raise_for_status()
            if is_malicious:
                detected_by_type[attack_type] = detected_by_type.get(attack_type, 0) + 1
        except Exception as e:
            print(f"      [!] POST error: {e}")

        time.sleep(delay)


def run_org_scenario(engine: InferenceEngine, headers: dict, url: str, rate: float):
    sent_by_type: dict     = {}
    detected_by_type: dict = {}

    print(f"\n{'='*60}")
    print(f"  VulnSight -- Org Deployment Scenario")
    print(f"  Injection rate: {rate:.0f} alerts/s")
    print(f"{'='*60}\n")

    for i, phase in enumerate(ORG_SCENARIO_PHASES, 1):
        if phase["pause_before"] > 0:
            print(f"  [pause {phase['pause_before']}s before next phase ...]")
            time.sleep(phase["pause_before"])

        print(f"\n  -- Phase {i}/{len(ORG_SCENARIO_PHASES)}: {phase['name']} --")
        print(f"     {phase['description']}")
        print(f"     Rows: {phase['rows']}  |  Malicious-only: {phase['malicious_only']}")
        run_phase(phase, engine, headers, url, rate, sent_by_type, detected_by_type)
        print(f"     Done.")

    print(f"\n{'='*60}")
    print(f"  SCENARIO COMPLETE -- Detection Summary")
    print(f"{'='*60}")
    print(f"  {'Attack Type':<22}  {'Detected':>8}  {'Sent':>6}  {'Rate':>8}")
    print(f"  {'-'*50}")

    all_types = sorted(set(list(sent_by_type.keys()) + list(detected_by_type.keys())))
    for atype in all_types:
        if atype == "normal":
            continue
        sent     = sent_by_type.get(atype, 0)
        detected = detected_by_type.get(atype, 0)
        rate_str = f"{detected/sent:.1%}" if sent > 0 else "N/A"
        print(f"  {atype:<22}  {detected:>8,}  {sent:>6,}  {rate_str:>8}")

    total_sent = sum(v for k, v in sent_by_type.items() if k != "normal")
    total_det  = sum(v for k, v in detected_by_type.items() if k != "normal")
    overall    = f"{total_det/total_sent:.1%}" if total_sent > 0 else "N/A"
    print(f"  {'-'*50}")
    print(f"  {'TOTAL (malicious)':<22}  {total_det:>8,}  {total_sent:>6,}  {overall:>8}")
    print(f"{'='*60}\n")
    print("  Open the VulnSight dashboard -> Alerts tab to review detections.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Simulate VulnSight alert ingestion from dataset CSVs")
    parser.add_argument("--file",           default=None,  help="Single CSV filename inside dataset/processed/")
    parser.add_argument("--rows",           type=int, default=300, help="Max rows per CSV (default 300)")
    parser.add_argument("--delay",          type=float, default=0.1, help="Seconds between alerts (default 0.1)")
    parser.add_argument("--malicious-only", action="store_true", help="Skip benign rows")
    parser.add_argument("--url",            default=VULNSIGHT_URL, help="VulnSight base URL")
    parser.add_argument("--username",       default=USERNAME)
    parser.add_argument("--password",       default=PASSWORD)
    parser.add_argument("--scenario",       default=None, choices=["org"],
                        help="Run a scripted scenario instead of raw CSV replay")
    parser.add_argument("--rate",           type=float, default=5.0,
                        help="Alerts per second for --scenario mode (default 5)")
    args = parser.parse_args()

    # ── scenario shortcut ─────────────────────────────────────────────────
    if args.scenario == "org":
        try:
            token = login(args.url, args.username, args.password)
        except Exception as e:
            sys.exit(f"[!] Login failed: {e}\n    Is VulnSight running?  python main.py")
        headers = {"Authorization": f"Bearer {token}"}
        print("[*] Loading model ...")
        try:
            engine = InferenceEngine(MODEL_PATH, SCALER_PATH, use_shap=False)
            print("[+] Model loaded\n")
        except Exception as e:
            sys.exit(f"[!] Failed to load model: {e}")
        run_org_scenario(engine, headers, args.url, args.rate)
        return

    # ── pick CSV files ────────────────────────────────────────────────────
    if args.file:
        csv_files = [DATASET_DIR / args.file]
    else:
        csv_files = sorted(DATASET_DIR.glob("*.csv"))

    if not csv_files:
        sys.exit(f"[!] No CSV files found in {DATASET_DIR}/")

    print(f"\n{'='*55}")
    print(f"  VulnSight Simulation")
    print(f"{'='*55}")
    print(f"  Dataset dir : {DATASET_DIR}")
    print(f"  CSV files   : {len(csv_files)}")
    print(f"  Rows/file   : {args.rows}")
    print(f"  Delay       : {args.delay}s")
    print(f"  Target      : {args.url}")
    print(f"{'='*55}\n")

    try:
        token = login(args.url, args.username, args.password)
    except Exception as e:
        sys.exit(f"[!] Login failed: {e}\n    Is VulnSight running?  python main.py")

    headers = {"Authorization": f"Bearer {token}"}

    print(f"[*] Loading model from {MODEL_PATH} ...")
    try:
        engine = InferenceEngine(model_path=MODEL_PATH, scaler_path=SCALER_PATH, use_shap=False)
        print("[+] Model loaded\n")
    except Exception as e:
        sys.exit(f"[!] Failed to load model: {e}")

    total_stats = {"sent": 0, "malicious": 0, "benign": 0, "skipped": 0, "errors": 0}

    for csv_path in csv_files:
        print(f"[>] {csv_path.name}")

        try:
            df = load_csv(csv_path)
        except Exception as e:
            print(f"    [!] Could not read file: {e}")
            continue

        label_col = "Label"
        if label_col not in df.columns:
            print(f"    [!] No 'Label' column found -- skipping")
            continue

        if args.malicious_only:
            df = df[df[label_col].str.upper() != "BENIGN"]

        if len(df) == 0:
            print(f"    [!] No rows after filter -- skipping")
            continue

        df = df.sample(n=min(args.rows, len(df)), random_state=42).reset_index(drop=True)
        print(f"    Rows to process: {len(df):,}")

        engine.flow_buffer.clear()
        file_stats = {"sent": 0, "malicious": 0, "benign": 0, "skipped": 0, "errors": 0}

        for _, row in df.iterrows():
            csv_label = str(row[label_col]).strip().upper()
            features  = [float(row[col]) for col in FEATURE_NAMES]
            dst_port  = int(features[0])

            prediction, confidence = engine.process_flow(features)

            if prediction is None:
                file_stats["skipped"] += 1
                continue

            is_malicious = bool(prediction == 1)
            # Use the ground-truth CSV label to derive attack type — far more
            # reliable than the feature-based classifier for dataset replay.
            attack_type  = infer_attack_type_from_label(csv_label, is_malicious)
            src_ip, dst_ip = fake_ip(is_malicious)

            shap_features = []
            try:
                shap_features = engine.explain_latest_window(top_k=3)
            except Exception:
                pass

            alert = build_alert(features, is_malicious, confidence,
                                 attack_type, src_ip, dst_ip, dst_port, shap_features)

            try:
                resp = requests.post(f"{args.url}/api/v1/alerts", json=alert,
                                     headers=headers, timeout=5)
                resp.raise_for_status()

                tag   = "[MALICIOUS]" if is_malicious else "[BENIGN]   "
                match = "OK" if (is_malicious == (csv_label != "BENIGN")) else "MISS"
                print(f"    {tag}  {attack_type:<20}  conf={confidence:.0%}  gt={csv_label:<20}  {match}")

                file_stats["sent"] += 1
                file_stats["malicious" if is_malicious else "benign"] += 1

            except Exception as e:
                print(f"    [!] POST error: {e}")
                file_stats["errors"] += 1

            time.sleep(args.delay)

        print(f"    -- sent={file_stats['sent']}  malicious={file_stats['malicious']}  "
              f"benign={file_stats['benign']}  skipped(warmup)={file_stats['skipped']}  "
              f"errors={file_stats['errors']}\n")

        for k in total_stats:
            total_stats[k] += file_stats[k]

    print(f"""
{'='*55}
  Simulation Complete
{'='*55}
  Alerts sent   : {total_stats['sent']}
  Malicious     : {total_stats['malicious']}
  Benign        : {total_stats['benign']}
  Warmup skipped: {total_stats['skipped']}
  Errors        : {total_stats['errors']}
{'='*55}
  Open VulnSight -> Alerts tab to see results
{'='*55}
""")


if __name__ == "__main__":
    main()
