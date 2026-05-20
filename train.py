"""
train.py — Train the CNN-BiLSTM model on preprocessed windowed data.

What it does
------------
1. Loads X_train / y_train / X_val / y_val from dataset/processed/
2. Computes class weights to handle the BENIGN / ATTACK imbalance
3. Trains with weighted CrossEntropyLoss + Adam + ReduceLROnPlateau
4. Saves the best checkpoint (lowest val loss) to model/vulnsight_cnn_bilstm.pth
5. Evaluates on X_test / y_test
6. Finds the optimal decision threshold by F1 on the validation set
7. Prints the final classification report and all key metrics

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
import torch
import torch.nn as nn
from sklearn.metrics import classification_report, f1_score
from sklearn.utils.class_weight import compute_class_weight
from torch.optim.lr_scheduler import ReduceLROnPlateau
from torch.utils.data import DataLoader, TensorDataset

warnings.filterwarnings("ignore")

from src.core.model_arch import HybridCNNBiLSTM

DATA_DIR   = Path("dataset/processed")
MODEL_PATH = Path("model/vulnsight_cnn_bilstm.pth")


def load_data():
    print("[→] Loading preprocessed data …")
    X_train = np.load(DATA_DIR / "X_train.npy")
    y_train = np.load(DATA_DIR / "y_train.npy")
    X_val   = np.load(DATA_DIR / "X_val.npy")
    y_val   = np.load(DATA_DIR / "y_val.npy")
    X_test  = np.load(DATA_DIR / "X_test.npy")
    y_test  = np.load(DATA_DIR / "y_test.npy")
    print(f"    train={len(X_train):,}  val={len(X_val):,}  test={len(X_test):,}")
    print(f"    attack ratio  train={y_train.mean()*100:.1f}%  val={y_val.mean()*100:.1f}%  test={y_test.mean()*100:.1f}%\n")
    return X_train, y_train, X_val, y_val, X_test, y_test


def make_loader(X, y, batch_size, shuffle):
    X_t = torch.tensor(X, dtype=torch.float32)
    y_t = torch.tensor(y, dtype=torch.long)
    return DataLoader(TensorDataset(X_t, y_t), batch_size=batch_size, shuffle=shuffle, num_workers=0)


def find_best_threshold(model, val_loader, device):
    """Find threshold that maximises F1 on the validation set."""
    model.eval()
    probs_all, labels_all = [], []
    with torch.no_grad():
        for X_b, y_b in val_loader:
            out   = model(X_b.to(device))
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
    model.eval()
    probs_all, labels_all = [], []
    with torch.no_grad():
        for X_b, y_b in loader:
            out   = model(X_b.to(device))
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
    parser.add_argument("--batch",    type=int,   default=128,  help="Batch size (default 128)")
    parser.add_argument("--lr",       type=float, default=1e-3, help="Initial learning rate (default 0.001)")
    parser.add_argument("--patience", type=int,   default=10,   help="Early stopping patience (default 10)")
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    print(f"\n{'='*55}")
    print(f"  VulnSight Trainer")
    print(f"{'='*55}")
    print(f"  Device  : {device}")
    print(f"  Epochs  : {args.epochs} (+ early stopping patience={args.patience})")
    print(f"  Batch   : {args.batch}")
    print(f"  LR      : {args.lr}")
    print(f"{'='*55}\n")

    if not DATA_DIR.exists():
        raise FileNotFoundError(f"{DATA_DIR} not found. Run:  python preprocess.py  first.")

    X_train, y_train, X_val, y_val, X_test, y_test = load_data()

    # class weights to handle imbalance
    weights   = compute_class_weight("balanced", classes=np.array([0, 1]), y=y_train)
    w_tensor  = torch.tensor(weights, dtype=torch.float32).to(device)
    print(f"[→] Class weights  benign={weights[0]:.3f}  attack={weights[1]:.3f}\n")

    train_loader = make_loader(X_train, y_train, args.batch, shuffle=True)
    val_loader   = make_loader(X_val,   y_val,   args.batch, shuffle=False)
    test_loader  = make_loader(X_test,  y_test,  args.batch, shuffle=False)

    model     = HybridCNNBiLSTM(feature_size=20, num_classes=2).to(device)
    criterion = nn.CrossEntropyLoss(weight=w_tensor)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
    scheduler = ReduceLROnPlateau(optimizer, mode="min", patience=5, factor=0.5, verbose=False)

    best_val_loss  = float("inf")
    patience_count = 0
    history        = []

    print(f"{'Epoch':>6}  {'Train Loss':>10}  {'Val Loss':>9}  {'Val F1':>7}  {'LR':>8}")
    print("-" * 50)

    for epoch in range(1, args.epochs + 1):
        t0 = time.time()

        # ── train ────────────────────────────────────────────────────────────
        model.train()
        train_loss = 0.0
        for X_b, y_b in train_loader:
            optimizer.zero_grad()
            out  = model(X_b.to(device))
            loss = criterion(out, y_b.to(device))
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
                out   = model(X_b.to(device))
                loss  = criterion(out, y_b.to(device))
                val_loss += loss.item()
                probs = torch.softmax(out, dim=1)[:, 1].cpu().numpy()
                val_probs.extend(probs)
                val_labels.extend(y_b.numpy())
        val_loss /= len(val_loader)

        val_preds = (np.array(val_probs) >= 0.5).astype(int)
        val_f1    = f1_score(val_labels, val_preds, zero_division=0)
        lr_now    = optimizer.param_groups[0]["lr"]

        scheduler.step(val_loss)
        history.append((train_loss, val_loss, val_f1))

        marker = " ✓" if val_loss < best_val_loss else ""
        print(f"{epoch:>6}  {train_loss:>10.4f}  {val_loss:>9.4f}  {val_f1:>7.4f}  {lr_now:>8.2e}{marker}")

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
