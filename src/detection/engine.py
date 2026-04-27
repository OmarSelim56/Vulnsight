import torch
import joblib
import numpy as np
import pandas as pd
from collections import deque
from src.core.model_arch import HybridCNNBiLSTM
from src.core.feature_config import FEATURE_NAMES

try:
    import shap
except Exception:  # pragma: no cover - optional runtime dependency
    shap = None

class InferenceEngine:
    def __init__(self, model_path, scaler_path, device=None, use_shap=True):
        # 1. Setup Device (Auto-detect GPU)
        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        # 2. Load the Scaler (Crucial: Must be the same one from training!)
        self.scaler = joblib.load(scaler_path)

        # 3. Load Model Architecture and Weights
        self.model = HybridCNNBiLSTM(feature_size=20).to(self.device)
        self.model.load_state_dict(torch.load(model_path, map_location=self.device), strict=False)
        self.model.eval() # Set to evaluation mode (disables Dropout)

        # 4. Temporal Buffer: Stores the last 10 flows
        self.window_size = 10
        self.flow_buffer = deque(maxlen=self.window_size)
        self.feature_size = len(FEATURE_NAMES)

        # 5. SHAP state
        self.use_shap = use_shap and shap is not None
        self.background_windows = deque(maxlen=50)

    def process_flow(self, raw_features):
        """
        Takes one flow, scales it, adds to window, and predicts.
        Returns: (is_malicious, confidence_score) or (None, 0.0)
        """
        # A. Wrap in a DataFrame with the named columns the scaler was fitted on.
        #    Passing a plain numpy array causes a UserWarning because the scaler
        #    was trained with feature names; matching them here suppresses it cleanly.
        features_df = pd.DataFrame([raw_features], columns=FEATURE_NAMES)

        # B. Scale the raw features
        scaled_features = self.scaler.transform(features_df)[0]
        
        # C. Append to our sliding window (deque handles maxlen automatically)
        self.flow_buffer.append(scaled_features)

        # D. Check if we have enough context (need 10 flows)
        if len(self.flow_buffer) < self.window_size:
            return None, 0.0

        # E. Convert window to 3D Tensor (Batch, Window, Features)
        # Final shape: (1, 10, 20)
        current_window = np.array(list(self.flow_buffer), dtype=np.float32)
        self.background_windows.append(current_window.flatten())
        input_tensor = torch.tensor([current_window], dtype=torch.float32).to(self.device)

        # F. Perform Prediction
        with torch.no_grad():
            output = self.model(input_tensor)
            probabilities = torch.softmax(output, dim=1)
            prediction = torch.argmax(probabilities, dim=1).item()
            confidence = probabilities[0][prediction].item()

        return prediction, confidence

    def _predict_malicious_probability(self, flattened_batch):
        batch = np.array(flattened_batch, dtype=np.float32).reshape(
            -1, self.window_size, self.feature_size
        )
        input_tensor = torch.tensor(batch, dtype=torch.float32).to(self.device)
        with torch.no_grad():
            logits = self.model(input_tensor)
            probabilities = torch.softmax(logits, dim=1).cpu().numpy()
        return probabilities[:, 1]

    def explain_latest_window(self, top_k=5):
        if not self.use_shap or len(self.flow_buffer) < self.window_size:
            return []

        if len(self.background_windows) < 5:
            return []

        background = np.array(list(self.background_windows), dtype=np.float32)
        sample = np.array([background[-1]], dtype=np.float32)

        explainer = shap.KernelExplainer(self._predict_malicious_probability, background)
        raw_shap = explainer.shap_values(sample, nsamples=100)

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
            indices = np.arange(idx, self.window_size * self.feature_size, self.feature_size)
            feature_contribs = shap_values[indices]
            signed_impact = float(np.mean(feature_contribs))
            abs_impact = float(np.sum(np.abs(feature_contribs)))
            shap_by_feature.append(
                {
                    "feature": feature_name,
                    "impact": abs_impact,
                    "direction": "increases_risk" if signed_impact >= 0 else "decreases_risk",
                }
            )

        shap_by_feature.sort(key=lambda x: x["impact"], reverse=True)
        return shap_by_feature[:top_k]