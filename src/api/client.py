import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import requests
from src.core.settings import settings


def _load_threshold() -> float:
    """Load the trained decision threshold from model/threshold.json (fallback 0.5)."""
    try:
        path = Path(__file__).resolve().parents[2] / "model" / "threshold.json"
        with open(path) as f:
            t = float(json.load(f)["threshold"])
        if 0.0 < t < 1.0:
            return t
    except Exception:
        pass
    return 0.5


# Tuned threshold loaded once at module import — same value the engine uses
TRAINED_THRESHOLD = _load_threshold()


class DashboardReporter:
    def __init__(self, base_url: str = settings.api_base_url, timeout: int = 3):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._token = settings.api_auth_token.strip()

    def _login_for_token(self) -> str:
        username = settings.api_auth_username.strip()
        password = settings.api_auth_password
        if not username or not password:
            return ""
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/auth/login",
                json={"username": username, "password": password},
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
            return payload.get("access_token", "")
        except requests.RequestException:
            return ""

    def _auth_headers(self) -> Dict[str, str]:
        if not self._token:
            self._token = self._login_for_token()
        if not self._token:
            return {}
        return {"Authorization": f"Bearer {self._token}"}

    @staticmethod
    def _classify_confidence(prediction: int, confidence: float) -> Dict[str, str]:
        """
        Turn (prediction, confidence) into UI-friendly fields.

        For malicious predictions we bucket relative to the trained threshold:
          - very_high  : confidence ≥ 0.95            → near-perfect certainty
          - high       : confidence ≥ midpoint(t, 1)  → solidly above threshold
          - medium     : confidence ≥ threshold       → just past threshold (borderline)

        Anything below threshold is, by definition, not classified as malicious,
        so the "low malicious" branch is never taken in practice — kept only as
        a defensive fallback.
        """
        t = TRAINED_THRESHOLD
        midpoint = (t + 1.0) / 2.0    # e.g. for t=0.78 → 0.89

        if prediction == 1:
            if confidence >= 0.95:
                return {
                    "confidence_level": "very_high",
                    "severity": "critical",
                    "triage_action": "isolate_host_immediately",
                }
            if confidence >= midpoint:
                return {
                    "confidence_level": "high",
                    "severity": "high",
                    "triage_action": "investigate_now",
                }
            if confidence >= t:
                return {
                    "confidence_level": "medium",
                    "severity": "medium",
                    "triage_action": "review_packet_context",
                }
            return {
                "confidence_level": "low",
                "severity": "low",
                "triage_action": "monitor_and_revalidate",
            }

        # benign branch: confidence here = benign probability
        if confidence >= 0.95:
            return {
                "confidence_level": "very_high",
                "severity": "info",
                "triage_action": "no_action_needed",
            }
        if confidence >= 0.85:
            return {
                "confidence_level": "high",
                "severity": "info",
                "triage_action": "no_action_needed",
            }
        if confidence >= 0.70:
            return {
                "confidence_level": "medium",
                "severity": "info",
                "triage_action": "observe_traffic_pattern",
            }
        return {
            "confidence_level": "low",
            "severity": "warning",
            "triage_action": "mark_as_uncertain_benign",
        }

    def post_alert(
        self,
        metadata: Dict[str, Any],
        prediction: int,
        confidence: float,
        shap_top_features: List[Dict[str, Any]],
    ) -> bool:
        is_malicious = prediction == 1
        classification = self._classify_confidence(prediction=prediction, confidence=confidence)
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": metadata.get("src_ip", ""),
            "destination_ip": metadata.get("dst_ip", ""),
            "protocol": metadata.get("protocol"),
            "interface": metadata.get("interface"),
            "prediction": prediction,
            "label": "ATTACK DETECTED" if is_malicious else "NORMAL",
            "confidence": confidence,
            "confidence_level": classification["confidence_level"],
            "severity": classification["severity"],
            "triage_action": classification["triage_action"],
            "is_malicious": is_malicious,
            "shap_top_features": shap_top_features,
        }

        try:
            response = requests.post(
                f"{self.base_url}/api/v1/alerts",
                json=payload,
                headers=self._auth_headers(),
                timeout=self.timeout,
            )
            if response.status_code == 401:
                self._token = self._login_for_token()
                response = requests.post(
                    f"{self.base_url}/api/v1/alerts",
                    json=payload,
                    headers=self._auth_headers(),
                    timeout=self.timeout,
                )
            response.raise_for_status()
            return True
        except requests.RequestException:
            return False

    def generate_report(self) -> Dict[str, Any]:
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/reports/generate",
                headers=self._auth_headers(),
                timeout=self.timeout,
            )
            if response.status_code == 401:
                self._token = self._login_for_token()
                response = requests.post(
                    f"{self.base_url}/api/v1/reports/generate",
                    headers=self._auth_headers(),
                    timeout=self.timeout,
                )
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            return {}
