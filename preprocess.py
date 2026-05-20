"""
preprocess.py — Clean raw CIC-IDS CSVs and save 21-column processed files.

What it does
------------
1. Loads every CSV from  dataset/raw/
2. Strips whitespace from column headers
3. Selects exactly the 20 model features (in order) + Label column
4. Drops rows with NaN or Inf values
5. Saves one clean CSV per input file to  dataset/processed/
   with columns: [Feature_1, Feature_2, ..., Feature_20, Label]

The windowing, scaler fitting, and train/val/test splitting are done
separately in train.py so the processed CSVs stay human-readable.

Usage
-----
    python preprocess.py                   # all CSVs
    python preprocess.py --max-rows 50000  # cap rows per file (quick test)
"""

import argparse
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

from src.core.feature_config import FEATURE_NAMES

DATASET_DIR = Path(r"C:\AAST\Vulnsight\dataset\raw")
OUT_DIR     = Path(r"C:\AAST\Vulnsight\dataset\processed")

# 21 output columns: 20 features in order + Label
OUTPUT_COLS = FEATURE_NAMES + ["Label"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-rows", type=int, default=None,
                        help="Max rows to keep per CSV (default: all)")
    args = parser.parse_args()

    csv_files = sorted(DATASET_DIR.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {DATASET_DIR}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  VulnSight Preprocessor")
    print(f"{'='*60}")
    print(f"  Input    : {DATASET_DIR}")
    print(f"  Output   : {OUT_DIR}")
    print(f"  Files    : {len(csv_files)}")
    print(f"  Columns  : {len(OUTPUT_COLS)}  ({len(FEATURE_NAMES)} features + Label)")
    print(f"  Max rows : {args.max_rows or 'all'}")
    print(f"{'='*60}\n")

    total_in  = 0
    total_out = 0

    for path in csv_files:
        print(f"[→] {path.name}")

        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()
        rows_in = len(df)

        # check required columns
        if "Label" not in df.columns:
            print(f"    [!] No 'Label' column — skipping\n")
            continue

        missing = [c for c in FEATURE_NAMES if c not in df.columns]
        if missing:
            print(f"    [!] Missing features: {missing} — skipping\n")
            continue

        # select exactly 21 columns in the right order
        df = df[OUTPUT_COLS].copy()

        # clean
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.dropna(subset=FEATURE_NAMES)
        rows_after_clean = len(df)

        # optional cap
        if args.max_rows and len(df) > args.max_rows:
            df = df.sample(n=args.max_rows, random_state=42).reset_index(drop=True)

        rows_out = len(df)

        # label stats
        label_counts = df["Label"].value_counts()
        benign = int(label_counts.get("BENIGN", 0))
        attack = rows_out - benign

        # save
        out_path = OUT_DIR / path.name
        df.to_csv(out_path, index=False)

        total_in  += rows_in
        total_out += rows_out

        print(f"    in={rows_in:,}  →  after clean={rows_after_clean:,}  →  saved={rows_out:,}")
        print(f"    benign={benign:,}  attack={attack:,}")
        print(f"    columns: {list(df.columns)}")
        print(f"    saved → {out_path.name}\n")

    print(f"{'='*60}")
    print(f"  Done")
    print(f"  Total rows in  : {total_in:,}")
    print(f"  Total rows out : {total_out:,}")
    print(f"  Output folder  : {OUT_DIR}")
    print(f"\n  Next step:  python train.py")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
