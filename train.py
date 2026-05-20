"""
train.py — Train the CNN-BiLSTM model from the processed 21-column CSVs.

What it does
------------
1. Loads all CSVs from dataset/processed/  (output of preprocess.py)
2. Builds sliding windows of 10 consecutive flows per file
3. Stratified 70 / 15 / 15 split
4. Fits StandardScaler on training windows ONLY → saves model/scaler.pkl
5. Computes class weights to handle the BENIGN / ATTACK imbalance
6. Trains with weighted CrossEntropyLoss + Adam + ReduceLROnPlateau
7. Saves the best checkpoint (lowest val loss) to model/vulnsight_cnn_bilstm.pth
8. Evaluates on the test set
9. Finds the optimal decision threshold by F1 on the validation set
10. Prints the full classification report and all key metrics

Usage
-----
    python train.py
    python train.py --epochs 100 --batch 128 --lr 0.001
"""

import argparse
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.amp import GradScaler, autocast
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight
from torch.optim.lr_scheduler import ReduceLROnPlateau
from torch.utils.data import DataLoader, TensorDataset

warnings.filterwarnings("ignore")

from src.core.feature_config import FEATURE_NAMES
from src.core.model_arch import HybridCNNBiLSTM

DATA_DIR   = Path(r"C:\AAST\Vulnsight\dataset\processed")
MODEL_PATH = Path("model/vulnsight_cnn_bilstm.pth")
SCALER_PATH = Path("model/scaler.pkl")
WINDOW     = 10

BENIGN_LABELS = {"benign", "normal"}


def binary_label(label: str) -> int:
    return 0 if label.strip().lower() in BENIGN_LABELS else 1


def make_windows(features: np.ndarray, labels: np.ndarray):
    X, y = [], []
    for i in range(len(features) - WINDOW + 1):
        X.append(features[i : i + WINDOW])
        y.append(labels[i + WINDOW - 1])
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64)


def load_data():
    csv_files = sorted(DATA_DIR.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSVs in {DATA_DIR}. Run: python preprocess.py")

    print(f"[→] Loading {len(csv_files)} processed CSVs from {DATA_DIR} …")

    all_X, all_y = [], []
    for path in csv_files:
        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()
        df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURE_NAMES)

        features = df[FEATURE_NAMES].values.astype(np.float32)
        labels   = df["Label"].apply(binary_label).values.astype(np.int64)

        X, y = make_windows(features, labels)
        all_X.append(X)
        all_y.append(y)
        print(f"    {path.name:<55}  windows={len(X):,}  attack%={labels.mean()*100:.1f}%")

    X = np.concatenate(all_X)
    y = np.concatenate(all_y)

    # stratified split 70 / 15 / 15
    X_train, X_tmp, y_train, y_tmp = train_test_split(X, y, test_size=0.30, stratify=y, random_state=42)
    X_val, X_test, y_val, y_test   = train_test_split(X_tmp, y_tmp, test_size=0.50, stratify=y_tmp, random_state=42)

    print(f"\n    Total windows : {len(X):,}")
    print(f"    Split  →  train={len(X_train):,}  val={len(X_val):,}  test={len(X_test):,}")

    # fit scaler on train ONLY
    n_feat  = len(FEATURE_NAMES)
    scaler  = StandardScaler()
    scaler.fit(X_train.reshape(-1, n_feat))
    joblib.dump(scaler, SCALER_PATH)
    print(f"    Scaler saved → {SCALER_PATH}\n")

    def scale(arr):
        n, w, f = arr.shape
        return scaler.transform(arr.reshape(-1, f)).reshape(n, w, f).astype(np.float32)

    return scale(X_train), y_train, scale(X_val), y_val, scale(X_test), y_test


def make_loader(X, y, batch_size, shuffle, pin_memory=False):
    X_t = torch.tensor(X, dtype=torch.float32)
    y_t = torch.tensor(y, dtype=torch.long)
    return DataLoader(
        TensorDataset(X_t, y_t),
        batch_size=batch_size,
        shuffle=shuffle,
        num_workers=0,          # keep 0 on Windows to avoid multiprocessing issues
        pin_memory=pin_memory,  # pre-pin CPU tensors for faster GPU transfer
        persistent_workers=False,
    )


def find_best_threshold(model, val_loader, device):
    """Find threshold that maximises F1 on the validation set."""
    cuda = device.type == "cuda"
    model.eval()
    probs_all, labels_all = [], []
    with torch.no_grad():
        for X_b, y_b in val_loader:
            X_b = X_b.to(device, non_blocking=True)
            if cuda:
                with autocast(device_type="cuda"):
                    out = model(X_b)
            else:
                out = model(X_b)
            probs = torch.softmax(out, dim=1)[:, 1].cpu().numpy()
            probs_all.extend(probs)
            labels_all.extend(y_b.numpy())

    probs_all  = np.array(probs_all)
    labels_all = np.array(labels_all)

    best_t, best_f1 = 0.5, 0.0
    for t in np.arange(0.20, 0.81, 0.01):
        preds = (probs_all >= t).astype(int)
        f1    = f1_score(labels_all, preds, zero_division=0)
        if f1 > best_f1:
            best_f1, best_t = f1, t

    return round(float(best_t), 2), round(float(best_f1), 4), probs_all, labels_all


def evaluate(model, loader, device, threshold=0.5):
    cuda = device.type == "cuda"
    model.eval()
    probs_all, labels_all = [], []
    with torch.no_grad():
        for X_b, y_b in loader:
            X_b = X_b.to(device, non_blocking=True)
            if cuda:
                with autocast(device_type="cuda"):
                    out = model(X_b)
            else:
                out = model(X_b)
            probs = torch.softmax(out, dim=1)[:, 1].cpu().numpy()
            probs_all.extend(probs)
            labels_all.extend(y_b.numpy())

    probs_all  = np.array(probs_all)
    labels_all = np.array(labels_all)
    preds      = (probs_all >= threshold).astype(int)
    return preds, labels_all, probs_all


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs",   type=int,   default=100,  help="Max epochs (default 100)")
    parser.add_argument("--batch",    type=int,   default=512,  help="Batch size (default 512 for GPU)")
    parser.add_argument("--lr",       type=float, default=1e-3, help="Initial learning rate (default 0.001)")
    parser.add_argument("--patience", type=int,   default=10,   help="Early stopping patience (default 10)")
    args = parser.parse_args()

    cuda_available = torch.cuda.is_available()
    device = torch.device("cuda" if cuda_available else "cpu")

    # GPU speed-ups
    if cuda_available:
        torch.backends.cudnn.benchmark = True   # auto-tune cuDNN kernels for fixed input sizes

    print(f"\n{'='*60}")
    print(f"  VulnSight Trainer")
    print(f"{'='*60}")
    print(f"  Device   : {device}", end="")
    if cuda_available:
        props = torch.cuda.get_device_properties(0)
        vram  = props.total_memory / 1024**3
        print(f"  ({props.name}, {vram:.1f} GB VRAM)")
        print(f"  AMP      : enabled  (float16 compute)")
        print(f"  cuDNN    : benchmark mode enabled")
    else:
        print()
        print(f"  AMP      : disabled  (CPU training)")
    print(f"  Epochs   : {args.epochs}  (early stopping patience={args.patience})")
    print(f"  Batch    : {args.batch}")
    print(f"  LR       : {args.lr}")
    print(f"{'='*60}\n")

    if not DATA_DIR.exists():
        raise FileNotFoundError(f"{DATA_DIR} not found. Run:  python preprocess.py  first.")

    X_train, y_train, X_val, y_val, X_test, y_test = load_data()

    # class weights to handle imbalance
    weights   = compute_class_weight("balanced", classes=np.array([0, 1]), y=y_train)
    w_tensor  = torch.tensor(weights, dtype=torch.float32).to(device)
    print(f"[→] Class weights  benign={weights[0]:.3f}  attack={weights[1]:.3f}\n")

    pin = cuda_available   # pin_memory only useful with CUDA
    train_loader = make_loader(X_train, y_train, args.batch, shuffle=True,  pin_memory=pin)
    val_loader   = make_loader(X_val,   y_val,   args.batch, shuffle=False, pin_memory=pin)
    test_loader  = make_loader(X_test,  y_test,  args.batch, shuffle=False, pin_memory=pin)

    model     = HybridCNNBiLSTM(feature_size=20, num_classes=2).to(device)
    criterion = nn.CrossEntropyLoss(weight=w_tensor)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
    scheduler = ReduceLROnPlateau(optimizer, mode="min", patience=5, factor=0.5)
    scaler    = GradScaler(device="cuda") if cuda_available else None  # AMP gradient scaler

    best_val_loss  = float("inf")
    patience_count = 0

    print(f"{'Epoch':>6}  {'Train Loss':>10}  {'Val Loss':>9}  {'Val F1':>7}  {'LR':>8}  {'Time':>6}")
    print("-" * 58)

    for epoch in range(1, args.epochs + 1):
        t0 = time.time()

        # ── train (with AMP on GPU) ───────────────────────────────────────────
        model.train()
        train_loss = 0.0
        for X_b, y_b in train_loader:
            X_b = X_b.to(device, non_blocking=True)
            y_b = y_b.to(device, non_blocking=True)
            optimizer.zero_grad()

            if cuda_available:
                with autocast(device_type="cuda"):
                    out  = model(X_b)
                    loss = criterion(out, y_b)
                scaler.scale(loss).backward()
                scaler.step(optimizer)
                scaler.update()
            else:
                out  = model(X_b)
                loss = criterion(out, y_b)
                loss.backward()
                optimizer.step()

            train_loss += loss.item()
        train_loss /= len(train_loader)

        # ── validate ─────────────────────────────────────────────────────────
        model.eval()
        val_loss = 0.0
        val_probs, val_labels = [], []
        with torch.no_grad():
            for X_b, y_b in val_loader:
                X_b = X_b.to(device, non_blocking=True)
                y_b = y_b.to(device, non_blocking=True)
                if cuda_available:
                    with autocast(device_type="cuda"):
                        out  = model(X_b)
                        loss = criterion(out, y_b)
                else:
                    out  = model(X_b)
                    loss = criterion(out, y_b)
                val_loss += loss.item()
                probs = torch.softmax(out, dim=1)[:, 1].cpu().numpy()
                val_probs.extend(probs)
                val_labels.extend(y_b.cpu().numpy())
        val_loss /= len(val_loader)

        val_preds = (np.array(val_probs) >= 0.5).astype(int)
        val_f1    = f1_score(val_labels, val_preds, zero_division=0)
        lr_now    = optimizer.param_groups[0]["lr"]
        elapsed   = time.time() - t0

        scheduler.step(val_loss)

        marker = " ✓" if val_loss < best_val_loss else ""
        print(f"{epoch:>6}  {train_loss:>10.4f}  {val_loss:>9.4f}  {val_f1:>7.4f}  {lr_now:>8.2e}  {elapsed:>5.1f}s{marker}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), MODEL_PATH)
            patience_count = 0
        else:
            patience_count += 1
            if patience_count >= args.patience:
                print(f"\n  Early stopping at epoch {epoch} (no improvement for {args.patience} epochs)")
                break

    # ── reload best checkpoint ────────────────────────────────────────────────
    print(f"\n[→] Loading best checkpoint from {MODEL_PATH} …")
    model.load_state_dict(torch.load(MODEL_PATH, map_location=device))

    # ── find optimal threshold on validation set ──────────────────────────────
    print("[→] Finding optimal decision threshold …")
    best_t, best_f1, _, _ = find_best_threshold(model, val_loader, device)
    print(f"    Best threshold = {best_t}  (val F1 = {best_f1})\n")

    # ── final evaluation on test set ──────────────────────────────────────────
    preds, labels, probs = evaluate(model, test_loader, device, threshold=best_t)

    tp = int(((preds == 1) & (labels == 1)).sum())
    tn = int(((preds == 0) & (labels == 0)).sum())
    fp = int(((preds == 1) & (labels == 0)).sum())
    fn = int(((preds == 0) & (labels == 1)).sum())
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"{'='*55}")
    print(f"  Test Set Results  (threshold = {best_t})")
    print(f"{'='*55}")
    print(f"\n{classification_report(labels, preds, target_names=['Benign', 'Attack'], digits=4)}")
    print(f"  Confusion Matrix")
    print(f"  ┌──────────────┬───────────────────┬───────────────────┐")
    print(f"  │              │  Pred Benign      │  Pred Attack      │")
    print(f"  ├──────────────┼───────────────────┼───────────────────┤")
    print(f"  │ Actual Benign│  TN = {tn:<10,}  │  FP = {fp:<10,}  │")
    print(f"  │ Actual Attack│  FN = {fn:<10,}  │  TP = {tp:<10,}  │")
    print(f"  └──────────────┴───────────────────┴───────────────────┘")
    print(f"\n  False Positive Rate : {fpr*100:.2f}%")
    print(f"  Best threshold      : {best_t}")
    print(f"  Model saved to      : {MODEL_PATH}")
    print(f"""
  Next step — update engine.py:
    Replace the argmax block with:

      THRESHOLD  = {best_t}
      mal_prob   = probabilities[0][1].item()
      prediction = 1 if mal_prob >= THRESHOLD else 0
      confidence = mal_prob if prediction == 1 else probabilities[0][0].item()
""")


if __name__ == "__main__":
    main()
