"""
VulnSight Sensor Agent
======================
A standalone agent that runs on any Linux machine, captures live network
traffic with NFStreamer, classifies each flow using the CNN-BiLSTM model,
and reports malicious (and optionally benign) events to a central VulnSight
server via the REST API.

Quick start
-----------
1. Copy the sensor/ folder, model/ folder and requirements.txt to the target host.
2. pip install -r sensor/requirements.txt
3. cp sensor/.env.example sensor/.env   # then fill in your values
4. sudo python -m sensor.agent          # requires CAP_NET_RAW / root for NFStreamer

Environment variables (or .env file)
-------------------------------------
VS_SERVER_URL      VulnSight server base URL, e.g. https://ids.example.com
VS_SENSOR_KEY      Sensor API key (vs_<64hex>)
VS_SENSOR_NAME     Display name for this node (default: hostname)
VS_INTERFACE       Network interface to capture (default: first active NIC)
VS_MODEL_PATH      Path to vulnsight_cnn_bilstm.pth  (default: model/vulnsight_cnn_bilstm.pth)
VS_SCALER_PATH     Path to scaler.pkl                (default: model/scaler.pkl)
VS_CONFIDENCE_MIN  Minimum confidence to report (default: 0.5)
VS_REPORT_BENIGN   Set to '1' to also report benign flows (default: 0)
VS_BATCH_SIZE      POST up to N alerts before flushing (default: 10)
VS_RETRY_LIMIT     Number of POST retries on network error (default: 3)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("vulnsight.sensor")


# ---------------------------------------------------------------------------
# Config (env / .env file)
# ---------------------------------------------------------------------------

def _load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader — no external dependency needed."""
    env_path = Path(path)
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(os.environ.get("VS_ENV_FILE", ".env"))
_load_dotenv(os.environ.get("VS_ENV_FILE", "sensor/.env"))


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


SERVER_URL      = _env("VS_SERVER_URL", "http://localhost:8000").rstrip("/")
SENSOR_KEY      = _env("VS_SENSOR_KEY")
SENSOR_NAME     = _env("VS_SENSOR_NAME") or socket.gethostname()
INTERFACE       = _env("VS_INTERFACE") or None
MODEL_PATH      = _env("VS_MODEL_PATH", "model/vulnsight_cnn_bilstm.pth")
SCALER_PATH     = _env("VS_SCALER_PATH", "model/scaler.pkl")
CONFIDENCE_MIN  = float(_env("VS_CONFIDENCE_MIN", "0.5"))
REPORT_BENIGN   = _env("VS_REPORT_BENIGN", "0") == "1"
BATCH_SIZE      = int(_env("VS_BATCH_SIZE", "10"))
RETRY_LIMIT     = int(_env("VS_RETRY_LIMIT", "3"))


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_config() -> None:
    if not SENSOR_KEY:
        log.error("VS_SENSOR_KEY is not set. Generate one in the VulnSight admin panel.")
        sys.exit(1)
    if not SENSOR_KEY.startswith("vs_"):
        log.warning("VS_SENSOR_KEY does not start with 'vs_' — double-check the value.")
    if not Path(MODEL_PATH).exists():
        log.error("Model file not found: %s", MODEL_PATH)
        sys.exit(1)
    if not Path(SCALER_PATH).exists():
        log.error("Scaler file not found: %s", SCALER_PATH)
        sys.exit(1)


# ---------------------------------------------------------------------------
# HTTP helper (no external requests library required on Python ≥3.9)
# ---------------------------------------------------------------------------

import urllib.request
import urllib.error


def _post_alert(payload: Dict[str, Any]) -> bool:
    """POST a single alert to the server. Returns True on success."""
    url = f"{SERVER_URL}/api/v1/alerts"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Sensor-Key": SENSOR_KEY,
        },
        method="POST",
    )
    for attempt in range(1, RETRY_LIMIT + 1):
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    return True
                log.warning("Server returned %s for alert POST", resp.status)
                return False
        except urllib.error.HTTPError as exc:
            log.warning("HTTP %s from server (attempt %d/%d): %s", exc.code, attempt, RETRY_LIMIT, exc.reason)
            if exc.code in (401, 403):
                log.error("Authentication failed — check VS_SENSOR_KEY")
                return False
        except (urllib.error.URLError, OSError) as exc:
            log.warning("Network error (attempt %d/%d): %s", attempt, RETRY_LIMIT, exc)
            if attempt < RETRY_LIMIT:
                time.sleep(2 ** attempt)
    return False


def _post_batch(batch: List[Dict[str, Any]]) -> int:
    """Post a list of alerts; returns count of successfully posted."""
    ok = 0
    for payload in batch:
        if _post_alert(payload):
            ok += 1
    return ok


# ---------------------------------------------------------------------------
# Alert payload builder
# ---------------------------------------------------------------------------

def _build_payload(
    *,
    src_ip: str,
    dst_ip: str,
    protocol: Optional[int],
    interface: str,
    prediction: int,
    confidence: float,
    label: str,
    attack_type: Optional[str],
    shap_features: list,
) -> Dict[str, Any]:
    if prediction == 1:
        if confidence >= 0.90:
            lvl, sev, action = "very_high", "critical", "isolate_host_immediately"
        elif confidence >= 0.75:
            lvl, sev, action = "high", "high", "block_and_investigate"
        elif confidence >= 0.60:
            lvl, sev, action = "medium", "medium", "monitor_closely"
        else:
            lvl, sev, action = "low", "low", "log_and_review"
    else:
        lvl, sev, action = "very_high", "info", "no_action_required"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol": protocol,
        "interface": interface,
        "prediction": prediction,
        "label": label,
        "confidence": float(confidence),
        "confidence_level": lvl,
        "severity": sev,
        "triage_action": action,
        "is_malicious": prediction == 1,
        "attack_type": attack_type or ("unknown" if prediction == 1 else "normal"),
        "dedup_count": 1,
        "shap_top_features": shap_features,
        "sensor_id": SENSOR_NAME,
    }


# ---------------------------------------------------------------------------
# Main capture loop
# ---------------------------------------------------------------------------

def run() -> None:
    _validate_config()
    log.info("VulnSight sensor agent starting on %s (node: %s)", platform.node(), SENSOR_NAME)
    log.info("Server : %s", SERVER_URL)
    log.info("Key    : %s…", SENSOR_KEY[:10])

    # Lazy imports so the module can be imported without nfstream/torch installed
    try:
        from nfstream import NFStreamer  # type: ignore
    except ImportError:
        log.error("nfstream is not installed. Run: pip install nfstream")
        sys.exit(1)

    # Add the project root to sys.path so src.detection.* can be imported
    _project_root = Path(__file__).resolve().parent.parent
    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))

    try:
        from src.detection.engine import InferenceEngine
        from src.detection.classifier import classify_attack_type
    except ImportError as exc:
        log.error("Cannot import detection modules: %s", exc)
        sys.exit(1)

    engine = InferenceEngine(
        model_path=MODEL_PATH,
        scaler_path=SCALER_PATH,
        use_shap=False,
    )
    log.info("Inference engine loaded (model: %s)", MODEL_PATH)

    iface = INTERFACE or "any"
    log.info("Listening on interface: %s", iface)

    batch: List[Dict[str, Any]] = []
    flows_seen = 0
    alerts_sent = 0

    streamer_kwargs: Dict[str, Any] = {
        "statistical_analysis": True,
        "idle_timeout": 15,
        "active_timeout": 60,
    }
    if iface != "any":
        streamer_kwargs["source"] = iface

    try:
        while True:
            log.info("Starting NFStreamer capture (Ctrl-C to stop)")
            streamer = NFStreamer(**streamer_kwargs)
            for flow in streamer:
                flows_seen += 1
                try:
                    # Build the feature vector the same way TrafficCollector does
                    raw_features = [
                        getattr(flow, "bidirectional_duration_ms", 0) or 0,
                        getattr(flow, "bidirectional_packets", 0) or 0,
                        getattr(flow, "bidirectional_bytes", 0) or 0,
                        getattr(flow, "src2dst_packets", 0) or 0,
                        getattr(flow, "src2dst_bytes", 0) or 0,
                        getattr(flow, "dst2src_packets", 0) or 0,
                        getattr(flow, "dst2src_bytes", 0) or 0,
                        getattr(flow, "bidirectional_min_ps", 0) or 0,
                        getattr(flow, "bidirectional_mean_ps", 0) or 0,
                        getattr(flow, "bidirectional_stddev_ps", 0) or 0,
                        getattr(flow, "bidirectional_max_ps", 0) or 0,
                        getattr(flow, "bidirectional_min_piat_ms", 0) or 0,
                        getattr(flow, "bidirectional_mean_piat_ms", 0) or 0,
                        getattr(flow, "bidirectional_stddev_piat_ms", 0) or 0,
                        getattr(flow, "bidirectional_max_piat_ms", 0) or 0,
                        getattr(flow, "src2dst_min_ps", 0) or 0,
                        getattr(flow, "src2dst_mean_ps", 0) or 0,
                        getattr(flow, "src2dst_stddev_ps", 0) or 0,
                        getattr(flow, "src2dst_max_ps", 0) or 0,
                        getattr(flow, "protocol", 0) or 0,
                    ]

                    prediction, confidence = engine.process_flow(raw_features)
                    if prediction is None:
                        continue

                    if prediction == 1 and confidence < CONFIDENCE_MIN:
                        prediction = 0

                    if prediction == 0 and not REPORT_BENIGN:
                        continue

                    attack_type = classify_attack_type(raw_features, prediction == 1)
                    label = "ATTACK DETECTED" if prediction == 1 else "NORMAL"

                    payload = _build_payload(
                        src_ip=str(getattr(flow, "src_ip", "0.0.0.0")),
                        dst_ip=str(getattr(flow, "dst_ip", "0.0.0.0")),
                        protocol=getattr(flow, "protocol", None),
                        interface=iface,
                        prediction=prediction,
                        confidence=float(confidence),
                        label=label,
                        attack_type=attack_type,
                        shap_features=[],
                    )

                    batch.append(payload)
                    if len(batch) >= BATCH_SIZE:
                        sent = _post_batch(batch)
                        alerts_sent += sent
                        log.info(
                            "Flushed %d/%d alerts to server  [total sent: %d, flows: %d]",
                            sent, len(batch), alerts_sent, flows_seen,
                        )
                        batch.clear()

                except Exception as exc:
                    log.debug("Error processing flow: %s", exc)

            # NFStreamer exhausted (shouldn't happen on live iface, but flush remaining)
            if batch:
                sent = _post_batch(batch)
                alerts_sent += sent
                batch.clear()

            log.info("Streamer cycle ended — restarting in 5 s")
            time.sleep(5)

    except KeyboardInterrupt:
        log.info("Sensor agent stopped (Ctrl-C). Flushing %d pending alerts…", len(batch))
        if batch:
            _post_batch(batch)
        log.info("Done. Total flows: %d | alerts sent: %d", flows_seen, alerts_sent)


if __name__ == "__main__":
    run()
