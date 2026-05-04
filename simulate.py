"""
simulate.py — Feed dataset CSVs through VulnSight's real model and push alerts to the API.

Run from the project root:
    python simulate.py                          # all CSVs in dataset/
    python simulate.py --file friday_ddos.csv   # single file
    python simulate.py --rows 200 --delay 0.2   # slower, fewer rows
    python simulate.py --malicious-only         # skip benign rows
"""

import argparse
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import requests

# ---------------------------------------------------------------------------
# VulnSight imports (run from project root)
# ---------------------------------------------------------------------------
try:
    from src.core.feature_config import FEATURE_NAMES
    from src.detection.engine import InferenceEngine
    from src.detection.classifier import classify_attack_type
except ModuleNotFoundError:
    sys.exit("[!] Run this script from the project root:  python simulate.py")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DATASET_DIR   = Path("dataset")
MODEL_PATH    = "model/vulnsight_cnn_bilstm.pth"
SCALER_PATH   = "model/scaler.pkl"
VULNSIGHT_URL = "http://localhost:8000"
USERNAME      = "admin"
PASSWORD      = "admin12345"

SEVERITY_MAP = {
    "ddos":             "critical",
    "port_scan":        "medium",
    "brute_force":      "medium",
    "data_exfiltration":"high",
    "c2_beacon":        "high",
    "intrusion":        "high",
    "normal":           "info",
}

LABEL_DISPLAY = {
    "ddos":             "DDoS DETECTED",
    "port_scan":        "PORT SCAN DETECTED",
    "brute_force":      "BRUTE FORCE DETECTED",
    "data_exfiltration":"DATA EXFILTRATION DETECTED",
    "c2_beacon":        "C2 BEACON DETECTED",
    "intrusion":        "INTRUSION DETECTED",
    "normal":           "NORMAL",
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
    print(f"[✓] Logged in as {username}")
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
    severity     = SEVERITY_MAP.get(attack_type, "medium")
    label        = LABEL_DISPLAY.get(attack_type, "INTRUSION DETECTED")
    conf_level   = "high" if confidence >= 0.85 else "medium" if confidence >= 0.65 else "low"
    triage       = "block_and_investigate" if is_malicious else "allow"

    return {
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "source_ip":        src_ip,
        "destination_ip":   dst_ip,
        "protocol":         int(dst_port),
        "interface":        "eth0",
        "prediction":       1 if is_malicious else 0,
        "label":            label,
        "confidence":       round(confidence, 4),
        "confidence_level": conf_level,
        "severity":         severity,
        "triage_action":    triage,
        "is_malicious":     is_malicious,
        "shap_top_features": shap_features or [
            {"feature": FEATURE_NAMES[10], "impact": round(random.uniform(0.2, 0.7), 3), "direction": "positive"},
            {"feature": FEATURE_NAMES[11], "impact": round(random.uniform(0.1, 0.5), 3), "direction": "positive"},
        ],
    }


def load_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()          # remove stray whitespace
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
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Simulate VulnSight alert ingestion from dataset CSVs")
    parser.add_argument("--file",           default=None,   help="Single CSV filename inside dataset/ (default: all)")
    parser.add_argument("--rows",           type=int, default=300, help="Max rows per CSV (default 300)")
    parser.add_argument("--delay",          type=float, default=0.1, help="Seconds between alerts (default 0.1)")
    parser.add_argument("--malicious-only", action="store_true",    help="Skip benign rows")
    parser.add_argument("--url",            default=VULNSIGHT_URL,  help="VulnSight base URL")
    parser.add_argument("--username",       default=USERNAME)
    parser.add_argument("--password",       default=PASSWORD)
    args = parser.parse_args()

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
    print(f"  Dataset dir : {DATASET_DIR}/")
    print(f"  CSV files   : {len(csv_files)}")
    print(f"  Rows/file   : {args.rows}")
    print(f"  Delay       : {args.delay}s")
    print(f"  Target      : {args.url}")
    print(f"{'='*55}\n")

    # ── login ─────────────────────────────────────────────────────────────
    try:
        token = login(args.url, args.username, args.password)
    except Exception as e:
        sys.exit(f"[!] Login failed: {e}\n    Is VulnSight running?  python main.py")

    headers = {"Authorization": f"Bearer {token}"}

    # ── load model ────────────────────────────────────────────────────────
    print(f"[→] Loading model from {MODEL_PATH} …")
    try:
        engine = InferenceEngine(
            model_path=MODEL_PATH,
            scaler_path=SCALER_PATH,
            use_shap=False,   # disable for speed; enable if shap is installed
        )
        print("[✓] Model loaded\n")
    except Exception as e:
        sys.exit(f"[!] Failed to load model: {e}")

    # ── process files ─────────────────────────────────────────────────────
    total_stats = {"sent": 0, "malicious": 0, "benign": 0, "skipped": 0, "errors": 0}

    for csv_path in csv_files:
        print(f"[►] {csv_path.name}")

        try:
            df = load_csv(csv_path)
        except Exception as e:
            print(f"    [!] Could not read file: {e}")
            continue

        label_col = "Label"
        if label_col not in df.columns:
            print(f"    [!] No 'Label' column found — skipping")
            continue

        if args.malicious_only:
            df = df[df[label_col].str.upper() != "BENIGN"]

        if len(df) == 0:
            print(f"    [!] No rows after filter — skipping")
            continue

        df = df.sample(n=min(args.rows, len(df)), random_state=42).reset_index(drop=True)
        print(f"    Rows to process: {len(df):,}")

        # reset the engine's sliding window between files
        engine.flow_buffer.clear()

        file_stats = {"sent": 0, "malicious": 0, "benign": 0, "skipped": 0, "errors": 0}

        for _, row in df.iterrows():
            csv_label = str(row[label_col]).strip().upper()
            features  = [float(row[col]) for col in FEATURE_NAMES]
            dst_port  = int(features[0])   # feature[0] = Destination Port

            # ── run through the real model ────────────────────────────────
            prediction, confidence = engine.process_flow(features)

            if prediction is None:
                # window not full yet (needs 10 flows to warm up)
                file_stats["skipped"] += 1
                continue

            is_malicious = bool(prediction == 1)
            attack_type  = classify_attack_type(features, is_malicious)
            src_ip, dst_ip = fake_ip(is_malicious)

            # ── try SHAP (optional) ───────────────────────────────────────
            shap_features = []
            try:
                shap_features = engine.explain_latest_window(top_k=3)
            except Exception:
                pass

            # ── build and POST alert ──────────────────────────────────────
            alert = build_alert(
                features, is_malicious, confidence,
                attack_type, src_ip, dst_ip, dst_port,
                shap_features,
            )

            try:
                resp = requests.post(
                    f"{args.url}/api/v1/alerts",
                    json=alert,
                    headers=headers,
                    timeout=5,
                )
                resp.raise_for_status()

                tag   = "🔴 MALICIOUS" if is_malicious else "🟢 BENIGN   "
                match = "✓" if (is_malicious == (csv_label != "BENIGN")) else "✗"
                print(f"    {tag}  {attack_type:<20}  conf={confidence:.0%}  gt={csv_label:<20}  {match}")

                file_stats["sent"] += 1
                file_stats["malicious" if is_malicious else "benign"] += 1

            except Exception as e:
                print(f"    [!] POST error: {e}")
                file_stats["errors"] += 1

            time.sleep(args.delay)

        print(f"    ── sent={file_stats['sent']}  malicious={file_stats['malicious']}  "
              f"benign={file_stats['benign']}  skipped(warmup)={file_stats['skipped']}  "
              f"errors={file_stats['errors']}\n")

        for k in total_stats:
            total_stats[k] += file_stats[k]

    # ── final summary ─────────────────────────────────────────────────────
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
  Open VulnSight → Alerts tab to see results
{'='*55}
""")


if __name__ == "__main__":
    main()
