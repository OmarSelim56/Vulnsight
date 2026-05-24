"""
The 34 tool-agnostic flow features Vulnsight uses for training and inference.

Selection criteria
------------------
All 78 columns in CIC-IDS2017 CSVs were audited.  Features were kept only if
both CICFlowMeter (which produced the training CSVs) and nfstream (which
extracts features in deployment) compute them in a way that yields the same
numerical distribution.

DROPPED — all timing-derived features (Flow Duration, all IAT columns, all
rate-per-second columns, bulk-rate, Active/Idle period stats).  These features
are sensitive to flow-termination timing, sub-millisecond packet handling, and
aggregation logic — exactly the things that differ between CICFlowMeter and
nfstream.  Including any of them collapses live inference to mal_prob = 0.

KEPT — counts, byte sums, packet-size statistics, TCP flag counts, and
deterministic ratios derived from those.  These are computed identically by
both tools, so a model trained on CIC-IDS CSVs deploys cleanly on nfstream
live captures.

The rate/IAT-based signals lost by this trade-off are recovered by the
SignatureEngine (signatures.py), which detects rate-driven attacks (DDoS,
brute force, beacons) using its own stateful tracking.
"""

FEATURE_NAMES = [
    # ── Basic flow identification ────────────────────────────────────────
    "Destination Port",

    # ── Packet / byte counts (per direction and total) ───────────────────
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",

    # ── Forward packet length distribution ───────────────────────────────
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",

    # ── Backward packet length distribution ──────────────────────────────
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",

    # ── Bidirectional packet length distribution ─────────────────────────
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",

    # ── TCP flag counts (bidirectional) ──────────────────────────────────
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",

    # ── Directional PSH / URG flag counts ────────────────────────────────
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",

    # ── Derived ratios and averages ──────────────────────────────────────
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
]
