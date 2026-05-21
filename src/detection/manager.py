import asyncio
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent.parent.parent


def _classify(prediction: int, confidence: float) -> Dict[str, str]:
    if prediction == 1:
        if confidence >= 0.90:
            level, severity, action = "very_high", "critical", "isolate_host_immediately"
        elif confidence >= 0.75:
            level, severity, action = "high", "high", "block_and_investigate"
        elif confidence >= 0.60:
            level, severity, action = "medium", "medium", "monitor_closely"
        else:
            level, severity, action = "low", "low", "log_and_review"
    else:
        level, severity, action = "very_high", "info", "no_action_required"
    return {"confidence_level": level, "severity": severity, "triage_action": action}


@dataclass
class DetectionStatus:
    running: bool = False
    interface: Optional[str] = None
    flows_processed: int = 0
    predictions_made: int = 0
    malicious_detected: int = 0
    last_flow_at: Optional[str] = None
    last_alert_at: Optional[str] = None
    error: Optional[str] = None
    started_at: Optional[str] = None


class DetectionManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._status = DetectionStatus()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(
        self,
        repository: Any,
        ws_manager: Any,
        loop: asyncio.AbstractEventLoop,
        interface: Optional[str] = None,
    ) -> None:
        with self._lock:
            if self._status.running:
                return
            self._stop_event.clear()
            self._status = DetectionStatus(
                running=True,
                interface=interface,
                started_at=datetime.now(timezone.utc).isoformat(),
            )
        self._thread = threading.Thread(
            target=self._run,
            args=(repository, ws_manager, loop, interface),
            daemon=True,
            name="detection-worker",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            self._status.running = False

    def status(self) -> Dict[str, Any]:
        with self._lock:
            s = self._status
            return {
                "running": s.running,
                "interface": s.interface,
                "flows_processed": s.flows_processed,
                "predictions_made": s.predictions_made,
                "malicious_detected": s.malicious_detected,
                "last_flow_at": s.last_flow_at,
                "last_alert_at": s.last_alert_at,
                "error": s.error,
                "started_at": s.started_at,
            }

    # ------------------------------------------------------------------
    # Background thread
    # ------------------------------------------------------------------

    def _run(
        self,
        repository: Any,
        ws_manager: Any,
        loop: asyncio.AbstractEventLoop,
        interface: Optional[str],
    ) -> None:
        try:
            from src.detection.collector import TrafficCollector
            from src.detection.engine import InferenceEngine
            from src.detection.classifier import classify_attack_type
        except Exception as exc:
            self._set_error(f"Import failed: {exc}")
            return

        model_path = str(_PROJECT_ROOT / "model" / "vulnsight_cnn_bilstm.pth")
        scaler_path = str(_PROJECT_ROOT / "model" / "scaler.pkl")
        try:
            engine = InferenceEngine(
                model_path=model_path,
                scaler_path=scaler_path,
                use_shap=True,
            )
        except Exception as exc:
            self._set_error(f"Engine init failed: {exc}")
            return

        try:
            collector = TrafficCollector(interface=interface)
        except Exception as exc:
            self._set_error(f"Collector init failed: {exc}")
            return

        with self._lock:
            if collector.interface:
                self._status.interface = collector.interface

        logger.info("DetectionManager: starting capture on %s", collector.interface)

        try:
            for features, metadata in collector.get_flows():
                if self._stop_event.is_set():
                    break

                with self._lock:
                    self._status.flows_processed += 1
                    self._status.last_flow_at = datetime.now(timezone.utc).isoformat()

                # Engine applies the tuned threshold (from model/threshold.json) internally.
                # No second-pass thresholding here — the trained operating point is the
                # source of truth, and re-thresholding from the DB silently broke
                # detections when the slider was set above the trained value.
                prediction, confidence = engine.process_flow(features)
                if prediction is None:
                    continue

                with self._lock:
                    self._status.predictions_made += 1

                shap_features: List[Dict] = []
                if prediction == 1:
                    try:
                        shap_features = engine.explain_latest_window(top_k=5)
                    except Exception:
                        pass

                attack_type = classify_attack_type(features, prediction == 1)
                meta = _classify(prediction, confidence)
                now = datetime.now(timezone.utc)

                from src.api.schemas import AlertPayload, ShapInsight

                alert = AlertPayload(
                    timestamp=now,
                    source_ip=metadata.get("src_ip", "0.0.0.0"),
                    destination_ip=metadata.get("dst_ip", "0.0.0.0"),
                    protocol=metadata.get("protocol"),
                    interface=metadata.get("interface") or collector.interface,
                    prediction=prediction,
                    label="ATTACK DETECTED" if prediction == 1 else "NORMAL",
                    confidence=float(confidence),
                    confidence_level=meta["confidence_level"],
                    severity=meta["severity"],
                    triage_action=meta["triage_action"],
                    is_malicious=prediction == 1,
                    attack_type=attack_type,
                    shap_top_features=[
                        ShapInsight(
                            feature=f.get("feature", ""),
                            impact=float(f.get("impact", 0.0)),
                            direction=f.get("direction", ""),
                        )
                        for f in shap_features
                    ],
                )

                try:
                    dedup_window = int(repository.get_setting("dedup_window_seconds") or 60)
                    is_new = repository.save_alert_with_dedup(alert, window_seconds=dedup_window)
                except Exception as exc:
                    logger.warning("DetectionManager: save_alert failed: %s", exc)
                    is_new = True

                # Only broadcast truly new (non-deduplicated) alerts over WS
                if is_new:
                    payload = alert.model_dump(mode="json")
                    asyncio.run_coroutine_threadsafe(
                        ws_manager.broadcast_json(payload), loop
                    )

                if prediction == 1:
                    with self._lock:
                        self._status.malicious_detected += 1
                        self._status.last_alert_at = now.isoformat()

        except Exception as exc:
            self._set_error(f"Capture error: {exc}")
            return

        with self._lock:
            self._status.running = False
        logger.info("DetectionManager: stopped")

    def _set_error(self, msg: str) -> None:
        logger.error("DetectionManager: %s", msg)
        with self._lock:
            self._status.running = False
            self._status.error = msg


detection_manager = DetectionManager()
