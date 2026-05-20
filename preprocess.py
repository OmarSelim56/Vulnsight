"""
preprocess.py — Build training-ready windowed arrays from the raw CIC-IDS CSVs.

What it does
------------
1. Loads every CSV in dataset/  (skips dataset/processed/)
2. Extracts the exact 20 features the model uses
3. Drops NaN / Inf rows
4. Binary-encodes labels  (BENIGN=0, everything else=1)
5. Builds sliding windows of 10 consecutive flows *per file*
6. Shuffles and splits  70 / 15 / 15  with stratification
7. Fits a StandardScaler on training windows ONLY
8. Scales all three splits
9. Saves to  dataset/processed/  as  X_train.npy, y_train.npy, etc.
   and overwrites  model/scaler.pkl  with the newly fitted scaler

Usage
-----
    python preprocess.py                   # all CSVs, all rows
    python preprocess.py --max-rows 50000  # cap rows per file (quick test)
"""

import argparse
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

from src.core.feature_config import FEATURE_NAMES

DATASET_DIR = Path("dataset")
OUT_DIR     = DATASET_DIR / "processed"
WINDOW      = 10          # must match engine.py window_size

BENIGN_LABELS = {"benign", "normal"}


def binary_label(label: str) -> int:
    return 0 if label.strip().lower() in BENIGN_LABELS else 1


def make_windows(features: np.ndarray, labels: np.ndarray, window: int):
    """Return (X, y) where X.shape = (N, window, n_features), y.shape = (N,)."""
    X, y = [], []
    for i in range(len(features) - window + 1):
        X.append(features[i : i + window])
        y.append(labels[i + window - 1])   # label of the LAST flow in the window
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-rows", type=int, default=None,
                        help="Max rows to sample per CSV (default: all)")
    args = parser.parse_args()

    # only grab CSVs directly in dataset/ — skip the processed/ subfolder
    csv_files = sorted(f for f in DATASET_DIR.glob("*.csv") if f.parent == DATASET_DIR)
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {DATASET_DIR}/")

    print(f"\n{'='*55}")
    print(f"  VulnSight Preprocessor")
    print(f"{'='*55}")
    print(f"  Input   : {DATASET_DIR}/")
    print(f"  Output  : {OUT_DIR}/")
    print(f"  Files   : {len(csv_files)}")
    print(f"  Features: {len(FEATURE_NAMES)}")
    print(f"  Window  : {WINDOW}")
    print(f"  Max rows: {args.max_rows or 'all'}")
    print(f"{'='*55}\n")

    all_X, all_y = [], []
    total_benign = 0
    total_attack = 0

    for path in csv_files:
        print(f"[→] {path.name}")
        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()

        if "Label" not in df.columns:
            print(f"    [!] No 'Label' column — skipping")
            continue

        missing = [f for f in FEATURE_NAMES if f not in df.columns]
        if missing:
            print(f"    [!] Missing columns: {missing} — skipping")
            continue

        df = df[FEATURE_NAMES + ["Label"]].copy()
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.dropna(subset=FEATURE_NAMES)

        if args.max_rows and len(df) > args.max_rows:
            df = df.sample(n=args.max_rows, random_state=42)

        features = df[FEATURE_NAMES].values.astype(np.float32)
        labels   = df["Label"].apply(binary_label).values.astype(np.int64)

        b = int((labels == 0).sum())
        a = int((labels == 1).sum())
        total_benign += b
        total_attack += a
        print(f"    rows={len(df):,}  benign={b:,}  attack={a:,}")

        X, y = make_windows(features, labels, WINDOW)
        all_X.append(X)
        all_y.append(y)

    if not all_X:
        raise RuntimeError("No data loaded. Check dataset/ folder.")

    X = np.concatenate(all_X, axis=0)
    y = np.concatenate(all_y, axis=0)

    print(f"\n  Total windows : {len(X):,}")
    print(f"  Benign        : {total_benign:,}  ({total_benign/(total_benign+total_attack)*100:.1f}%)")
    print(f"  Attack        : {total_attack:,}  ({total_attack/(total_benign+total_attack)*100:.1f}%)\n")

    # stratified split 70 / 15 / 15
    X_train, X_tmp, y_train, y_tmp = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_tmp, y_tmp, test_size=0.50, stratify=y_tmp, random_state=42
    )
    print(f"  Split  →  train={len(X_train):,}  val={len(X_val):,}  test={len(X_test):,}")

    # fit scaler on training data ONLY then apply to all splits
    n_feat    = len(FEATURE_NAMES)
    scaler    = StandardScaler()
    scaler.fit(X_train.reshape(-1, n_feat))

    def scale(arr):
        n, w, f = arr.shape
        return scaler.transform(arr.reshape(-1, f)).reshape(n, w, f).astype(np.float32)

    X_train = scale(X_train)
    X_val   = scale(X_val)
    X_test  = scale(X_test)

    # save
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    np.save(OUT_DIR / "X_train.npy", X_train)
    np.save(OUT_DIR / "y_train.npy", y_train)
    np.save(OUT_DIR / "X_val.npy",   X_val)
    np.save(OUT_DIR / "y_val.npy",   y_val)
    np.save(OUT_DIR / "X_test.npy",  X_test)
    np.save(OUT_DIR / "y_test.npy",  y_test)
    joblib.dump(scaler, "model/scaler.pkl")

    print(f"\n  Saved to {OUT_DIR}/")
    for f in ["X_train.npy", "y_train.npy", "X_val.npy", "y_val.npy", "X_test.npy", "y_test.npy"]:
        mb = (OUT_DIR / f).stat().st_size / 1e6
        print(f"    {f:<20} {mb:.1f} MB")
    print(f"    model/scaler.pkl  (overwritten)")
    print(f"\n  Done. Run:  python train.py\n")


if __name__ == "__main__":
    main()
