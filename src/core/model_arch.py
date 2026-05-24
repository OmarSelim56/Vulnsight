"""
Hybrid CNN-BiLSTM with BatchNorm, LayerNorm, and additive attention.

Architecture
------------
Input (B, 10, 34)
  ── Conv1d(34→64, k=3) + BatchNorm + ReLU
  ── Conv1d(64→64, k=3) + BatchNorm + ReLU
  ── BiLSTM(64→128, 2 layers, dropout=0.3) → (B, 10, 256)
  ── LayerNorm(256)
  ── AttentionPooling(256)             → (B, 256)   weighted combination of timesteps
  ── Linear(256→64) + ReLU + Dropout(0.5)
  ── Linear(64→2)

Improvements over the previous architecture
-------------------------------------------
- BatchNorm after each CNN layer    : stabilises training, allows higher LR
- Second CNN layer                  : richer local feature extraction
- LayerNorm on LSTM output          : reduces gradient pathology
- Attention pooling instead of last : the model learns WHICH of the 10 flows
                                      in a window matter most for the verdict
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class AttentionPooling(nn.Module):
    """Additive (Bahdanau-style) attention that summarises a sequence of
    timesteps into a single context vector via learned soft weights."""

    def __init__(self, hidden_dim: int):
        super().__init__()
        self.score = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.Tanh(),
            nn.Linear(hidden_dim // 2, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, T, H)
        scores  = self.score(x).squeeze(-1)        # (B, T)
        weights = F.softmax(scores, dim=1)         # (B, T)
        context = torch.bmm(weights.unsqueeze(1), x).squeeze(1)  # (B, H)
        return context


class HybridCNNBiLSTM(nn.Module):
    def __init__(self, feature_size: int = 34, num_classes: int = 2):
        super().__init__()

        # ── CNN block: extract local patterns within the 10-flow window ─
        self.cnn = nn.Sequential(
            nn.Conv1d(in_channels=feature_size, out_channels=64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Conv1d(in_channels=64, out_channels=64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
        )

        # ── BiLSTM: model temporal dependencies across the 10 flows ─────
        self.lstm = nn.LSTM(
            input_size=64,
            hidden_size=128,
            num_layers=2,
            batch_first=True,
            bidirectional=True,
            dropout=0.3,
        )

        # ── Normalisation + attention pooling over timesteps ───────────
        self.norm      = nn.LayerNorm(128 * 2)
        self.attention = AttentionPooling(128 * 2)

        # ── Classifier head ────────────────────────────────────────────
        self.fc = nn.Sequential(
            nn.Linear(128 * 2, 64),
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(64, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, 10, F)  -> permute to (B, F, 10) for Conv1d
        x = x.permute(0, 2, 1)
        x = self.cnn(x)            # (B, 64, 10)
        x = x.permute(0, 2, 1)     # (B, 10, 64)

        lstm_out, _ = self.lstm(x) # (B, 10, 256)
        lstm_out    = self.norm(lstm_out)
        context     = self.attention(lstm_out)  # (B, 256)

        return self.fc(context)
