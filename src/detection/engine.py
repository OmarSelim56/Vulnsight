"""
Inference engine for VulnSight.

Loads the trained CNN-BiLSTM, the StandardScaler, and the tuned decision
threshold (from model/threshold.json) at startup.  Every incoming flow is
scaled, buffered into a sliding window of 10, and classified.

Threshold-based decisions
-------------------------
We do NOT use argmax (which is equivalent to threshold=0.5).  Instead the
threshold tuned on the validation set is loaded from model/threshold.json
and applied to the malicious probability.  This is what gave us the
0.15% FPR on the test set.

Confidence reporting
--------------------
We return the raw malicious probability for malicious predictions, and
the benign probability for benign predictions.  Because the threshold
is high (typically 0.78+), genuine attacks usually score very close to
1.0, so reported confidence is high and meaningful.
"""

import json
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import torch

from src.core.feature_config import FEATURE_NAMES
from src.core.model_arch import HybridCNNBiLSTM

try:
    import shap
except Exception:  # pragma: no cover - optional runtime dependency
    shap = None


DEFAULT_THRESHOLD = 0.5     # safe fallback if threshold.json is missing


class InferenceEngine:
    def __init__(self, model_path, scaler_path, threshold_path=None, device=None, use_shap=True):
        # 1. Device (auto-detect GPU)
        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        # 2. Preprocessing pipeline (must be the same fitted during training).
        # train.py saves an sklearn Pipeline:
        #   PowerTransformer(yeo-johnson) -> StandardScaler
        # both transforms must run identically at inference, otherwise we
        # recreate the same train/deploy distribution gap that broke the
        # earlier 20-feature model on live nfstream traffic.
        self.scaler = joblib.load(scaler_path)

        # 3. Model architecture + trained weights
        self.model = HybridCNNBiLSTM(feature_size=len(FEATURE_NAMES)).to(self.device)
        self.model.load_state_dict(torch.load(model_path, map_location=self.device), strict=False)
        self.model.eval()  # disables dropout

        # 4. Tuned decision threshold — loaded from JSON so engine.py never
        #    needs hand-editing after each training run.
        if threshold_path is None:
            threshold_path = Path(model_path).parent / "threshold.json"
        self.threshold = self._load_threshold(threshold_path)

        # 5. Per-conversation sliding window buffers.
        #
        # Each (src_ip, dst_ip) tuple gets its own 10-flow buffer.  This is
        # critical for live traffic: a global buffer would mix unrelated
        # concurrent connections (Netflix, Windows Update, attacker traffic)
        # into the same prediction window, diluting attack signal.  Per-tuple
        # windows give the model a clean view of each conversation.
        self.window_size   = 10
        self.feature_size  = len(FEATURE_NAMES)
        self.flow_buffers  = defaultdict(lambda: deque(maxlen=self.window_size))
        self.last_seen     = {}
        self.max_tuples    = 5000
        # Backward-compatible alias used by callers that don't pass metadata
        # (e.g. simulate.py replaying sequential CSV rows).
        self.flow_buffer   = self.flow_buffers[("__global__", "__global__")]

        # 6. SHAP state (optional explainability) — kept global since SHAP
        # needs a pool of background windows from across the traffic mix.
        self.use_shap            = use_shap and shap is not None
        self.background_windows  = deque(maxlen=50)

    # ── helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _load_threshold(path) -> float:
        """Load the tuned threshold from model/threshold.json, falling back to 0.5."""
        try:
            with open(path) as f:
                config = json.load(f)
                t = float(config["threshold"])
                if 0.0 < t < 1.0:
                    return t
        except (FileNotFoundError, KeyError, json.JSONDecodeError, ValueError):
            pass
        return DEFAULT_THRESHOLD

    # ── main entry ──────────────────────────────────────────────────────────

    def process_flow(self, raw_features, meta: Optional[dict] = None):
        """
        Score a single flow.

        Parameters
        ----------
        raw_features : list[float]
            The 20 nfstream-derived features in FEATURE_NAMES order.
        meta : dict, optional
            Flow metadata.  When present, the (src_ip, dst_ip) tuple is used
            to select a per-conversation sliding window.  When absent
            (e.g. CSV replay), all flows share the global buffer.

        Returns
        -------
        (prediction, confidence) | (None, 0.0)
            prediction : 0 = benign, 1 = malicious
            confidence : probability of the predicted class (0..1)
                         high values indicate a strong, trustworthy decision
            (None, 0.0) is returned while the conversation is still in its
            10-flow warm-up window.
        """
        # A. Scale the raw features.
        #    The scaler was fitted on a plain numpy array (no feature names),
        #    so we pass a numpy array here too to avoid sklearn's feature-name
        #    mismatch warning.
        features_array  = np.asarray([raw_features], dtype=np.float32)
        scaled_features = self.scaler.transform(features_array)[0]

        # B. Select per-conversation buffer (or global when no metadata).
        if meta is not None and meta.get("src_ip") and meta.get("dst_ip"):
            key = (str(meta["src_ip"]), str(meta["dst_ip"]))
        else:
            key = ("__global__", "__global__")

        buffer = self.flow_buffers[key]
        buffer.append(scaled_features)
        self.last_seen[key] = time.time()
        self._maybe_evict()

        # C. Wait until this conversation has 10 flows before predicting.
        if len(buffer) < self.window_size:
            return None, 0.0

        # D. Build (1, 10, 20) input tensor
        current_window = np.array(list(buffer), dtype=np.float32)
        self.background_windows.append(current_window.flatten())
        input_tensor = torch.from_numpy(np.array([current_window], dtype=np.float32)).to(self.device)

        # E. Inference
        with torch.no_grad():
            output        = self.model(input_tensor)
            probabilities = torch.softmax(output, dim=1)
            mal_prob      = float(probabilities[0][1].item())
            ben_prob      = float(probabilities[0][0].item())

        # F. Apply tuned threshold (NOT argmax)
        if mal_prob >= self.threshold:
            prediction = 1
            confidence = mal_prob   # how certain are we it's malicious
        else:
            prediction = 0
            confidence = ben_prob   # how certain are we it's benign

        return prediction, confidence

    # ── Per-tuple buffer eviction ───────────────────────────────────────────

    def _maybe_evict(self) -> None:
        """Cap memory by dropping conversation buffers that have gone idle."""
        if len(self.flow_buffers) <= self.max_tuples:
            return
        # Evict tuples not touched in the last 5 minutes.
        cutoff = time.time() - 300
        stale  = [k for k, t in self.last_seen.items() if t < cutoff]
        for k in stale:
            self.flow_buffers.pop(k, None)
            self.last_seen.pop(k, None)
        # Still over the cap?  Drop the oldest 10% by last-seen time.
        if len(self.flow_buffers) > self.max_tuples:
            ordered = sorted(self.last_seen.items(), key=lambda x: x[1])
            for k, _ in ordered[: len(ordered) // 10]:
                self.flow_buffers.pop(k, None)
                self.last_seen.pop(k, None)

    # ── SHAP explainability ─────────────────────────────────────────────────

    def _predict_malicious_probability(self, flattened_batch):
        batch = np.array(flattened_batch, dtype=np.float32).reshape(
            -1, self.window_size, self.feature_size
        )
        input_tensor = torch.from_numpy(batch).to(self.device)
        with torch.no_grad():
            logits        = self.model(input_tensor)
            probabilities = torch.softmax(logits, dim=1).cpu().numpy()
        return probabilities[:, 1]

    def explain_latest_window(self, top_k=5):
        if not self.use_shap or len(self.flow_buffer) < self.window_size:
            return []

        if len(self.background_windows) < 5:
            return []

        background = np.array(list(self.background_windows), dtype=np.float32)
        sample     = np.array([background[-1]], dtype=np.float32)

        explainer = shap.KernelExplainer(self._predict_malicious_probability, background)
        raw_shap  = explainer.shap_values(sample, nsamples=100)

        if isinstance(raw_shap, list):
            shap_values = np.array(raw_shap[-1])[0]
        else:
            raw_shap = np.array(raw_shap)
            if raw_shap.ndim == 3:
                shap_values = raw_shap[0, :, -1]
            else:
                shap_values = raw_shap[0]

        shap_by_feature = []
        for idx, feature_name in enumerate(FEATURE_NAMES):
            indices          = np.arange(idx, self.window_size * self.feature_size, self.feature_size)
            feature_contribs = shap_values[indices]
            signed_impact    = float(np.mean(feature_contribs))
            abs_impact       = float(np.sum(np.abs(feature_contribs)))
            shap_by_feature.append({
                "feature":   feature_name,
                "impact":    abs_impact,
                "direction": "increases_risk" if signed_impact >= 0 else "decreases_risk",
            })

        shap_by_feature.sort(key=lambda x: x["impact"], reverse=True)
        return shap_by_feature[:top_k]
