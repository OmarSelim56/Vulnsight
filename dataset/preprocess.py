"""
preprocess.py — Clean raw CIC-IDS2017 CSVs into trainable feature CSVs.

Input  : dataset/raw/*.csv      (original CIC-IDS2017 dumps, 78+ columns)
Output : dataset/processed/*.csv (only the 34 features in FEATURE_NAMES + Label)

What it does
------------
1. Reads each raw CSV.
2. Strips whitespace from column names (CIC-IDS2017 has leading spaces).
3. Drops duplicate columns — CIC-IDS2017 famously lists "Fwd Header Length"
   twice; we keep the first occurrence.
4. Confirms all 34 required feature columns are present; aborts loudly if
   anything is missing rather than silently producing a broken dataset.
5. Replaces inf / -inf with NaN, then drops rows that are NaN in any of
   the 34 features or in Label.
6. Casts the 34 features to float32 and Label to string.
7. Writes the trimmed CSV (35 columns: 34 features + Label) to
   dataset/processed/, preserving the original filename.

Usage
-----
    python preprocess.py
    python preprocess.py --raw dataset/raw --out dataset/processed
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.feature_config import FEATURE_NAMES

DEFAULT_RAW = PROJECT_ROOT / "dataset" / "raw"
DEFAULT_OUT = PROJECT_ROOT / "dataset" / "processed"


def clean_one(path: Path) -> pd.DataFrame | None:
    df = pd.read_csv(path, low_memory=False, encoding_errors="replace")

    # 1. Normalize column names (strip leading/trailing whitespace).
    df.columns = df.columns.str.strip()

    # 2. Drop duplicate columns (CIC-IDS2017 has "Fwd Header Length" twice).
    if df.columns.duplicated().any():
        dups = df.columns[df.columns.duplicated()].tolist()
        print(f"    Removing duplicate columns: {dups}")
        df = df.loc[:, ~df.columns.duplicated()]

    # 3. Verify required columns are present.
    cols = set(df.columns)
    missing_features = [f for f in FEATURE_NAMES if f not in cols]
    if missing_features:
        print(f"    [!] MISSING feature columns: {missing_features}")
        print(f"    [!] Skipping {path.name}")
        return None
    if "Label" not in cols:
        print(f"    [!] No Label column — skipping {path.name}")
        return None

    # 4. Trim to just what we need.
    keep_cols = FEATURE_NAMES + ["Label"]
    df = df[keep_cols].copy()

    # 5. Clean numerical columns.
    df[FEATURE_NAMES] = df[FEATURE_NAMES].replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df = df.dropna(subset=FEATURE_NAMES + ["Label"])
    dropped = before - len(df)
    if dropped > 0:
        print(f"    Dropped {dropped:,} rows with NaN/inf")

    # 6. Cast types.
    df[FEATURE_NAMES] = df[FEATURE_NAMES].astype(np.float32)
    df["Label"] = df["Label"].astype(str).str.strip()

    return df


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", type=Path, default=DEFAULT_RAW,
                        help="Folder containing raw CIC-IDS2017 CSVs")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="Folder to write cleaned CSVs into")
    args = parser.parse_args()

    if not args.raw.exists():
        sys.exit(f"[!] Raw folder not found: {args.raw}")
    args.out.mkdir(parents=True, exist_ok=True)

    raw_csvs = sorted(args.raw.glob("*.csv"))
    if not raw_csvs:
        sys.exit(f"[!] No CSVs in {args.raw}")

    print(f"\n{'='*60}")
    print(f"  VulnSight preprocess  ({len(FEATURE_NAMES)} features)")
    print(f"{'='*60}")
    print(f"  Raw : {args.raw}")
    print(f"  Out : {args.out}")
    print(f"  Files: {len(raw_csvs)}\n")

    total_in  = 0
    total_out = 0
    written   = 0

    for path in raw_csvs:
        print(f"[>] {path.name}")
        try:
            df = clean_one(path)
        except Exception as e:
            print(f"    [!] Failed: {e}")
            continue

        if df is None or len(df) == 0:
            continue

        out_path = args.out / path.name
        df.to_csv(out_path, index=False)

        attack_pct = (df["Label"].str.upper() != "BENIGN").mean() * 100
        print(f"    Wrote {len(df):,} rows ({attack_pct:.1f}% attack)  ->  {out_path.name}")
        total_in  += sum(1 for _ in open(path, encoding="utf-8", errors="ignore")) - 1
        total_out += len(df)
        written   += 1

    print(f"\n{'='*60}")
    print(f"  Done.  {written}/{len(raw_csvs)} files written")
    print(f"  Total rows: {total_out:,} (kept) of {total_in:,} (input)")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
