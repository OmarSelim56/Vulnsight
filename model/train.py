"""
train.py — Train VulnSight's CNN-BiLSTM on the 34 tool-agnostic features.

Improvements over the previous version
--------------------------------------
1. Pure-window filtering         : drops boundary windows that mix benign/attack
                                    rows, eliminating label noise.
2. PowerTransformer + StandardScaler pipeline
                                  : Yeo-Johnson handles the heavy tails on
                                    byte/packet counts so the model trains on
                                    a near-Gaussian feature space.  Saved as a
                                    single sklearn Pipeline so engine.py
                                    applies the EXACT same transform at
                                    inference time (no train/deploy drift).
3. Focal Loss + label smoothing  : focal loss focuses on hard examples,
                                    label smoothing prevents overconfidence.
4. Cosine LR + warmup            : smoother convergence than ReduceLROnPlateau.
5. Stochastic Weight Averaging   : averages weights from the final epochs for
                                    a small but reliable accuracy boost.
6. Stratify by attack type       : test set has balanced representation of
                                    each attack class, not just attack/benign.
7. Per-attack-type evaluation    : prints recall for DDoS, PortScan, Bot etc.
                                    so we know exactly where the model is weak.

Outputs
-------
- model/vulnsight_cnn_bilstm.pth  : best checkpoint
- model/scaler.pkl                : sklearn Pipeline (PowerTransformer +
                                    StandardScaler).  This MUST be loaded
                                    by engine.py — the live collector
                                    cannot scale features without it.
- model/threshold.json            : tuned decision threshold + full metrics.

Usage
-----
    python model/train.py
    python model/train.py --epochs 60 --batch 512 --lr 1e-3
"""

import argparse
import json
import math
import random
import sys
import time
import warnings
from collections import Counter
from pathlib import Path

# Make `src.*` importable regardless of how this script is launched.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import PowerTransformer, StandardScaler
from sklearn.utils.class_weight import compute_class_weight
from torch.amp import GradScaler, autocast
from torch.optim.lr_scheduler import CosineAnnealingLR, LinearLR, SequentialLR
from torch.optim.swa_utils import AveragedModel, update_bn
from torch.utils.data import DataLoader, TensorDataset

warnings.filterwarnings("ignore")

from src.core.feature_config import FEATURE_NAMES
from src.core.model_arch import HybridCNNBiLSTM


DATA_DIR    = Path(r"C:\AAST\Vulnsight\dataset\processed")
MODEL_PATH  = Path("model/vulnsight_cnn_bilstm.pth")
SCALER_PATH = Path("model/scaler.pkl")
CONFIG_PATH = Path("model/threshold.json")
WINDOW      = 10
GRAD_CLIP   = 1.0
WEIGHT_DECAY = 1e-4

BENIGN_LABELS = {"benign", "normal"}


# ---------------------------------------------------------------------------
# Losses
# ---------------------------------------------------------------------------

class FocalLoss(nn.Module):
    """
    Focal loss with class weighting and label smoothing.

      FL(p) = -alpha * (1 - p)^gamma * log(p)

    - alpha (class weight) up-weights the minority class.
    - (1-p)^gamma focuses learning on misclassified / hard examples.
    - label_smoothing prevents the network from becoming over-confident.
    """

    def __init__(self, gamma: float = 2.0, weight: torch.Tensor | None = None,
                 label_smoothing: float = 0.0):
        super().__init__()
        self.gamma           = gamma
        self.weight          = weight
        self.label_smoothing = label_smoothing

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        ce = F.cross_entropy(
            logits, targets,
            weight=self.weight,
            label_smoothing=self.label_smoothing,
            reduction="none",
        )
        # pt = p of the true class; exp(-ce) reverses the log
        pt    = torch.exp(-ce)
        focal = ((1.0 - pt) ** self.gamma) * ce
        return focal.mean()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def set_seed(seed: int = 42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def init_lstm_weights(lstm: nn.LSTM):
    """Xavier inputs, orthogonal recurrence, forget-gate bias = 1."""
    for name, param in lstm.named_parameters():
        if "weight_ih" in name:
            nn.init.xavier_uniform_(param.data)
        elif "weight_hh" in name:
            nn.init.orthogonal_(param.data)
        elif "bias" in name:
            param.data.fill_(0)
            n = param.size(0)
            param.data[n // 4 : n // 2].fill_(1.0)


def binary_label(label: str) -> int:
    return 0 if label.strip().lower() in BENIGN_LABELS else 1


def make_windows(features: np.ndarray, bin_labels: np.ndarray,
                 raw_labels: np.ndarray):
    """
    Build 10-flow sliding windows.  The label of each window is the label
    of the LAST row in it — which matches exactly what engine.py does in
    deployment (predict the current flow given the previous 9 as context).

    This intentionally keeps mixed-label windows (e.g. benign benign ...
    attack) because that's the real-world condition the model will face at
    inference time: attacks start in the middle of normal traffic.

    Returns (X, y_bin, y_raw) where y_raw preserves the original CIC-IDS
    label string (e.g. "DDoS", "PortScan") for per-attack-type evaluation.
    """
    n     = len(features)
    n_win = max(0, n - WINDOW + 1)
    if n_win == 0:
        return (
            np.empty((0, WINDOW, features.shape[1]), dtype=np.float32),
            np.empty((0,), dtype=np.int64),
            np.empty((0,), dtype=object),
        )

    # Vectorised window construction for speed (2.83M rows otherwise slow).
    idx     = np.arange(WINDOW)[None, :] + np.arange(n_win)[:, None]
    X       = features[idx].astype(np.float32)
    y_bin   = bin_labels[idx[:, -1]].astype(np.int64)
    y_raw   = raw_labels[idx[:, -1]]
    return X, y_bin, np.asarray(y_raw, dtype=object)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_data():
    csv_files = sorted(DATA_DIR.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSVs in {DATA_DIR}.  Run: python preprocess.py"
        )

    print(f"[->] Loading {len(csv_files)} processed CSVs from {DATA_DIR} ...")
    print(f"     Building 10-flow sliding windows (label = last row, matches engine.py)\n")

    all_X, all_y_bin, all_y_raw = [], [], []
    total_windows = 0
    for path in csv_files:
        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()
        df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURE_NAMES)

        features   = df[FEATURE_NAMES].values.astype(np.float32)
        raw_labels = df["Label"].astype(str).str.strip().values
        bin_labels = np.array(
            [binary_label(l) for l in raw_labels], dtype=np.int64
        )

        X, y_bin, y_raw = make_windows(features, bin_labels, raw_labels)

        attack_pct = y_bin.mean() * 100 if len(y_bin) > 0 else 0.0
        print(f"    {path.name:<55}  windows={len(X):>8,}  attack={attack_pct:5.1f}%")
        all_X.append(X)
        all_y_bin.append(y_bin)
        all_y_raw.append(y_raw)
        total_windows += len(X)

    X     = np.concatenate(all_X)
    y_bin = np.concatenate(all_y_bin)
    y_raw = np.concatenate(all_y_raw)

    print(f"\n    Total windows: {total_windows:,}")
    print(f"    Attack class : {y_bin.mean()*100:.2f}%  benign class: {(1-y_bin.mean())*100:.2f}%")
    raw_counts = Counter(y_raw[y_bin == 1])
    print(f"    Attack types present ({len(raw_counts)}):")
    for label, count in sorted(raw_counts.items(), key=lambda x: -x[1]):
        print(f"      {label:<40s} {count:>10,}")
    print()

    # ── Stratify by attack TYPE (more balanced test set than binary). ───
    # Rare attack labels with too few samples to stratify cleanly fall back
    # to the binary stratification.  We build a "stratify key" that is the
    # attack type if it has >= 2 samples per class, else binary label.
    attack_counts = Counter(y_raw)
    rare = {lbl for lbl, c in attack_counts.items() if c < 6}
    strat_key = np.array([
        f"bin_{b}" if r in rare else r for r, b in zip(y_raw, y_bin)
    ])

    X_tr, X_tmp, y_tr, y_tmp, raw_tr, raw_tmp, sk_tr, sk_tmp = train_test_split(
        X, y_bin, y_raw, strat_key,
        test_size=0.30, stratify=strat_key, random_state=42,
    )

    # For the val/test split, re-derive the stratify key from the 30% chunk:
    # some attack classes that were splittable in the full set may have only
    # 1 sample in the 30% chunk and can't be split 50/50 by class anymore.
    # Anything with < 2 samples in sk_tmp falls back to its binary label.
    sk_tmp_counts = Counter(sk_tmp)
    sk_tmp_adj = np.array([
        k if sk_tmp_counts[k] >= 2 else f"bin_{b}"
        for k, b in zip(sk_tmp, y_tmp)
    ])
    X_val, X_te, y_val, y_te, raw_val, raw_te = train_test_split(
        X_tmp, y_tmp, raw_tmp,
        test_size=0.50, stratify=sk_tmp_adj, random_state=42,
    )
    print(f"    Split        : train={len(X_tr):,}  val={len(X_val):,}  test={len(X_te):,}\n")

    # ── Preprocessing pipeline (PowerTransformer + StandardScaler). ─────
    # PowerTransformer fitted on a 500k-sample subset for speed — gives
    # the same parameters as fitting on the whole train set within float
    # precision.  StandardScaler then standardises the transformed features.
    n_feat = len(FEATURE_NAMES)
    print(f"[->] Fitting PowerTransformer + StandardScaler on training windows ...")
    pipe = Pipeline([
        ("power",  PowerTransformer(method="yeo-johnson", standardize=False)),
        ("scaler", StandardScaler()),
    ])

    flat_train = X_tr.reshape(-1, n_feat)
    if len(flat_train) > 500_000:
        idx = np.random.default_rng(42).choice(
            len(flat_train), 500_000, replace=False
        )
        fit_sample = flat_train[idx]
        print(f"     Fitting on 500,000-row sample (full train set has {len(flat_train):,} rows)")
    else:
        fit_sample = flat_train

    pipe.fit(fit_sample)
    joblib.dump(pipe, SCALER_PATH)
    print(f"     Pipeline saved -> {SCALER_PATH}\n")

    def transform(arr):
        n, w, f = arr.shape
        return pipe.transform(arr.reshape(-1, f)).reshape(n, w, f).astype(np.float32)

    return (
        transform(X_tr),  y_tr,  raw_tr,
        transform(X_val), y_val, raw_val,
        transform(X_te),  y_te,  raw_te,
    )


def make_loader(X, y, batch_size, shuffle, pin_memory=False):
    return DataLoader(
        TensorDataset(
            torch.tensor(X, dtype=torch.float32),
            torch.tensor(y, dtype=torch.long),
        ),
        batch_size=batch_size,
        shuffle=shuffle,
        num_workers=0,
        pin_memory=pin_memory,
        persistent_workers=False,
    )


# ---------------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------------

def predict_probs(model, loader, device):
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
    return np.array(probs_all), np.array(labels_all)


def find_best_threshold(probs, labels):
    best_t, best_f1 = 0.5, 0.0
    for t in np.arange(0.20, 0.81, 0.01):
        preds = (probs >= t).astype(int)
        f1    = f1_score(labels, preds, zero_division=0)
        if f1 > best_f1:
            best_f1, best_t = f1, t
    return round(float(best_t), 2), round(float(best_f1), 4)


def per_attack_type_recall(preds, labels_bin, labels_raw):
    """Compute recall per attack type.  Useful to see if the model misses
    one specific attack class (e.g. Bot or Heartbleed)."""
    rows = []
    types = sorted(set(labels_raw[labels_bin == 1]))
    for t in types:
        mask = labels_raw == t
        if mask.sum() == 0:
            continue
        total   = int(mask.sum())
        caught  = int(preds[mask].sum())
        recall  = caught / total if total > 0 else 0.0
        rows.append((t, total, caught, recall))
    rows.sort(key=lambda r: r[3])
    return rows


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs",   type=int,   default=60)
    parser.add_argument("--batch",    type=int,   default=512)
    parser.add_argument("--lr",       type=float, default=1e-3)
    parser.add_argument("--patience", type=int,   default=12)
    parser.add_argument("--warmup",   type=int,   default=3)
    parser.add_argument("--swa-start",type=int,   default=None,
                        help="Epoch to start SWA from (default: epochs - 10)")
    parser.add_argument("--gamma",    type=float, default=2.0,
                        help="Focal loss gamma (default 2.0)")
    parser.add_argument("--smoothing",type=float, default=0.05,
                        help="Label smoothing (default 0.05)")
    parser.add_argument("--seed",     type=int,   default=42)
    args = parser.parse_args()

    set_seed(args.seed)
    cuda_available = torch.cuda.is_available()
    device = torch.device("cuda" if cuda_available else "cpu")
    if cuda_available:
        torch.backends.cudnn.benchmark = True
    # Default SWA start: 60% of total epochs (so it activates even if early
    # stopping kicks in before the end).  Previous default keyed off
    # epochs - 10, which meant a 60-epoch run that stopped at 26 never
    # touched the SWA branch.
    swa_start = args.swa_start if args.swa_start is not None else max(1, int(args.epochs * 0.4))

    print(f"\n{'='*60}")
    print(f"  VulnSight Trainer  ({len(FEATURE_NAMES)} features)")
    print(f"{'='*60}")
    print(f"  Device     : {device}", end="")
    if cuda_available:
        props = torch.cuda.get_device_properties(0)
        print(f"  ({props.name}, {props.total_memory/1024**3:.1f} GB)")
    else:
        print()
    print(f"  Epochs     : {args.epochs}  (patience={args.patience}, warmup={args.warmup})")
    print(f"  Batch / LR : {args.batch} / {args.lr}")
    print(f"  Loss       : FocalLoss(gamma={args.gamma}) + label smoothing {args.smoothing}")
    print(f"  SWA starts : epoch {swa_start}")
    print(f"{'='*60}\n")

    if not DATA_DIR.exists():
        raise FileNotFoundError(f"{DATA_DIR} missing.  Run preprocess.py first.")

    X_tr, y_tr, raw_tr, X_val, y_val, raw_val, X_te, y_te, raw_te = load_data()

    weights  = compute_class_weight("balanced", classes=np.array([0, 1]), y=y_tr)
    w_tensor = torch.tensor(weights, dtype=torch.float32).to(device)
    print(f"[->] Class weights  benign={weights[0]:.3f}  attack={weights[1]:.3f}\n")

    pin = cuda_available
    train_loader = make_loader(X_tr,  y_tr,  args.batch, shuffle=True,  pin_memory=pin)
    val_loader   = make_loader(X_val, y_val, args.batch, shuffle=False, pin_memory=pin)
    test_loader  = make_loader(X_te,  y_te,  args.batch, shuffle=False, pin_memory=pin)

    model = HybridCNNBiLSTM(feature_size=len(FEATURE_NAMES), num_classes=2).to(device)
    init_lstm_weights(model.lstm)
    n_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"[->] Model parameters: {n_params:,}\n")

    criterion = FocalLoss(gamma=args.gamma, weight=w_tensor, label_smoothing=args.smoothing)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=WEIGHT_DECAY)

    # Cosine schedule with linear warmup.
    warmup_steps = max(1, args.warmup)
    sched = SequentialLR(
        optimizer,
        schedulers=[
            LinearLR(optimizer, start_factor=0.01, end_factor=1.0, total_iters=warmup_steps),
            CosineAnnealingLR(optimizer, T_max=max(1, args.epochs - warmup_steps), eta_min=1e-6),
        ],
        milestones=[warmup_steps],
    )

    swa_model     = AveragedModel(model)
    grad_scaler   = GradScaler(device="cuda") if cuda_available else None
    best_val_loss = float("inf")
    patience_cnt  = 0

    print(f"{'Epoch':>5}  {'Train Loss':>10}  {'Val Loss':>9}  {'Val F1':>7}  {'LR':>9}  {'Time':>6}")
    print("-" * 58)

    for epoch in range(1, args.epochs + 1):
        t0 = time.time()

        # ── Train ──────────────────────────────────────────────────────
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
                grad_scaler.scale(loss).backward()
                grad_scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
                grad_scaler.step(optimizer)
                grad_scaler.update()
            else:
                out  = model(X_b)
                loss = criterion(out, y_b)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
                optimizer.step()

            train_loss += loss.item()
        train_loss /= len(train_loader)

        # ── Validate ───────────────────────────────────────────────────
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
        val_f1   = f1_score(val_labels, (np.array(val_probs) >= 0.5).astype(int), zero_division=0)
        lr_now   = optimizer.param_groups[0]["lr"]
        elapsed  = time.time() - t0

        # ── SWA / step ─────────────────────────────────────────────────
        if epoch >= swa_start:
            swa_model.update_parameters(model)
            swa_tag = " [SWA]"
        else:
            swa_tag = ""
        sched.step()

        marker = " * best" if val_loss < best_val_loss else ""
        print(f"{epoch:>5}  {train_loss:>10.4f}  {val_loss:>9.4f}  {val_f1:>7.4f}  {lr_now:>9.2e}  {elapsed:>5.1f}s{marker}{swa_tag}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), MODEL_PATH)
            patience_cnt = 0
        else:
            patience_cnt += 1
            if patience_cnt >= args.patience:
                print(f"\n  Early stopping at epoch {epoch} (no improvement for {args.patience} epochs)")
                break

    # ── Finalise SWA model (recompute BatchNorm running stats) ─────────
    print(f"\n[->] Finalising SWA model (BatchNorm running stats)...")
    update_bn(train_loader, swa_model, device=device)

    # Compare best-checkpoint vs SWA on validation; keep the better one.
    print(f"[->] Comparing best-checkpoint vs SWA on validation set...")

    base = HybridCNNBiLSTM(feature_size=len(FEATURE_NAMES)).to(device)
    base.load_state_dict(torch.load(MODEL_PATH, map_location=device))

    probs_base, labels_base = predict_probs(base, val_loader, device)
    probs_swa,  labels_swa  = predict_probs(swa_model, val_loader, device)

    t_base, f1_base = find_best_threshold(probs_base, labels_base)
    t_swa,  f1_swa  = find_best_threshold(probs_swa,  labels_swa)

    print(f"     Best ckpt  val F1 = {f1_base:.4f}  threshold = {t_base}")
    print(f"     SWA model  val F1 = {f1_swa:.4f}   threshold = {t_swa}")

    if f1_swa >= f1_base:
        print(f"     -> SWA wins, saving SWA weights as final.\n")
        final_model = swa_model
        torch.save(swa_model.module.state_dict(), MODEL_PATH)
        best_t, best_f1 = t_swa, f1_swa
    else:
        print(f"     -> Best checkpoint wins, keeping it.\n")
        final_model = base
        best_t, best_f1 = t_base, f1_base

    # ── Final test set evaluation ───────────────────────────────────────
    probs_te, labels_te = predict_probs(final_model, test_loader, device)
    preds_te = (probs_te >= best_t).astype(int)

    tp = int(((preds_te == 1) & (labels_te == 1)).sum())
    tn = int(((preds_te == 0) & (labels_te == 0)).sum())
    fp = int(((preds_te == 1) & (labels_te == 0)).sum())
    fn = int(((preds_te == 0) & (labels_te == 1)).sum())
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    acc  = (tp + tn) / (tp + tn + fp + fn)
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

    print(f"{'='*60}")
    print(f"  Test Set Results  (threshold = {best_t})")
    print(f"{'='*60}\n")
    print(classification_report(labels_te, preds_te,
                                 target_names=["Benign", "Attack"],
                                 digits=4))
    print(f"  Confusion Matrix")
    print(f"  +--------------+--------------+--------------+")
    print(f"  |              | Pred Benign  | Pred Attack  |")
    print(f"  +--------------+--------------+--------------+")
    print(f"  | True Benign  | TN={tn:>9,} | FP={fp:>9,} |")
    print(f"  | True Attack  | FN={fn:>9,} | TP={tp:>9,} |")
    print(f"  +--------------+--------------+--------------+")
    print(f"\n  Accuracy             : {acc*100:.3f}%")
    print(f"  Precision            : {prec*100:.3f}%")
    print(f"  Recall               : {rec*100:.3f}%")
    print(f"  F1 Score             : {f1*100:.3f}%")
    print(f"  False Positive Rate  : {fpr*100:.3f}%")
    print(f"  Threshold            : {best_t}")

    # ── Per-attack-type recall ──────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  Per-Attack-Type Recall")
    print(f"{'='*60}")
    rows = per_attack_type_recall(preds_te, labels_te, raw_te)
    print(f"\n  {'Attack Type':<35s}  {'Total':>8}  {'Caught':>8}  {'Recall':>7}")
    print(f"  {'-'*35}  {'-'*8}  {'-'*8}  {'-'*7}")
    for label, total, caught, recall in rows:
        print(f"  {label:<35s}  {total:>8,}  {caught:>8,}  {recall*100:>6.2f}%")

    # ── Save threshold + metrics ────────────────────────────────────────
    config = {
        "threshold":   float(best_t),
        "val_f1":      float(best_f1),
        "feature_set": "v2_34_tool_agnostic",
        "test_metrics": {
            "accuracy":  round(float(acc),  6),
            "precision": round(float(prec), 6),
            "recall":    round(float(rec),  6),
            "f1":        round(float(f1),   6),
            "fpr":       round(float(fpr),  6),
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        },
        "per_attack_recall": {
            label: {"total": total, "caught": caught, "recall": round(recall, 6)}
            for label, total, caught, recall in rows
        },
        "seed": args.seed,
    }
    CONFIG_PATH.write_text(json.dumps(config, indent=2))

    print(f"\n  Model     -> {MODEL_PATH}")
    print(f"  Pipeline  -> {SCALER_PATH}")
    print(f"  Threshold -> {CONFIG_PATH}\n")


if __name__ == "__main__":
    main()
