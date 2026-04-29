import asyncio
import csv
import io
import json
import threading
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from src.api.auth.dependencies import require_roles, set_auth_repository as set_auth_dep_repository
from src.api.auth.routes import router as auth_router
from src.api.auth.routes import set_auth_repository as set_auth_routes_repository
from src.api.schemas import AlertPayload, ReportPayload
from src.core.settings import settings
from src.db.auth_repository import AuthRepository
from src.db.repository import AlertRepository
from src.detection.manager import detection_manager

# In-memory PCAP job tracker
_pcap_jobs: Dict[str, Dict[str, Any]] = {}
_UPLOAD_DIR = Path(settings.database_path).parent / "pcap_uploads"


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.event_loop = asyncio.get_running_loop()
    yield


app = FastAPI(title="VulnSight Reporting API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
repository = AlertRepository(db_path=settings.database_path)
auth_repository = AuthRepository(db_path=settings.database_path)
auth_repository.ensure_default_user(
    username=settings.auth_bootstrap_admin_username,
    password=settings.auth_bootstrap_admin_password,
    role="admin",
)
set_auth_dep_repository(auth_repository)
set_auth_routes_repository(auth_repository)
app.include_router(auth_router)


class ConnectionManager:
    def __init__(self):
        self._connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self._connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self._connections:
            self._connections.remove(websocket)

    async def broadcast_json(self, payload: dict):
        if not self._connections:
            return

        stale_connections = []
        for websocket in self._connections:
            try:
                await websocket.send_json(payload)
            except Exception:
                stale_connections.append(websocket)

        for websocket in stale_connections:
            self.disconnect(websocket)


ws_manager = ConnectionManager()


@app.get("/api/v1/health")
def health():
    counts = repository.db_counts()
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc),
        "database_path": settings.database_path,
        "counts": counts,
    }


@app.post("/api/v1/alerts")
async def ingest_alert(
    alert: AlertPayload,
    _=Depends(require_roles("admin")),
):
    # Derive attack_type from the alert label when the caller hasn't set it
    if not alert.attack_type:
        from src.detection.classifier import infer_attack_type_from_label
        alert = alert.model_copy(
            update={"attack_type": infer_attack_type_from_label(alert.label, alert.is_malicious)}
        )
    repository.save_alert(alert)
    payload = alert.model_dump(mode="json") if hasattr(alert, "model_dump") else alert.dict()
    await ws_manager.broadcast_json(payload)
    return {"stored": True}


@app.get("/api/v1/alerts", response_model=List[AlertPayload])
def get_alerts(
    limit: int = 100,
    _=Depends(require_roles("admin", "analyst", "client")),
):
    if limit <= 0:
        return []
    return repository.get_recent_alerts(limit=limit)


@app.post("/api/v1/reports/generate", response_model=ReportPayload)
def generate_report(_=Depends(require_roles("admin", "analyst"))):
    alerts = repository.get_recent_alerts(limit=5000)
    total = len(alerts)
    malicious = sum(1 for a in alerts if a.is_malicious)
    benign = total - malicious
    ratio = (malicious / total) if total else 0.0

    dst_counter = Counter(a.destination_ip for a in alerts if a.destination_ip)
    top_targets = dict(dst_counter.most_common(5))
    severity_counter = Counter(
        a.severity for a in alerts if a.severity and a.severity != "info"
    )

    report = ReportPayload(
        generated_at=datetime.now(timezone.utc),
        total_events=total,
        malicious_events=malicious,
        benign_events=benign,
        malicious_ratio=ratio,
        severity_breakdown=dict(severity_counter),
        top_targets=top_targets,
    )

    # Save to history
    now = datetime.now(timezone.utc)
    report_name = f"Threat Report — {now.strftime('%Y-%m-%d %H:%M')}"
    report_data = report.model_dump(mode="json")
    repository.save_report(
        name=report_name,
        report_type="Full Analysis",
        period="All time",
        alert_count=total,
        report_data=report_data,
    )

    return report


@app.get("/api/v1/reports/history")
def list_reports(
    limit: int = 50,
    _=Depends(require_roles("admin", "analyst", "client")),
):
    return repository.list_reports(limit=limit)


@app.get("/api/v1/reports/{report_id}/download")
def download_report(
    report_id: int,
    _=Depends(require_roles("admin", "analyst")),
):
    rec = repository.get_report(report_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Report not found")
    export = {
        "id": rec["id"],
        "name": rec["name"],
        "type": rec["type"],
        "period": rec["period"],
        "alert_count": rec["alert_count"],
        "generated_at": rec["generated_at"],
        "report": rec["report_data"],
    }
    filename = f"vulnsight_report_{report_id}_{rec['generated_at'][:10]}.json"
    content = json.dumps(export, indent=2)
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.delete("/api/v1/reports/{report_id}")
def delete_report(
    report_id: int,
    _=Depends(require_roles("admin")),
):
    if not repository.delete_report(report_id):
        raise HTTPException(status_code=404, detail="Report not found")
    return {"deleted": True}


@app.post("/api/v1/admin/import-flows")
def import_flows(
    limit: int = 1000,
    _=Depends(require_roles("admin", "analyst")),
):
    imported = repository.import_flows_as_alerts(limit=limit)
    return {"imported": imported, "counts": repository.db_counts()}


@app.websocket("/api/v1/ws/alerts")
async def alerts_ws(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ------------------------------------------------------------------
# Analytics endpoints
# ------------------------------------------------------------------

@app.get("/api/v1/analytics/timeline")
def analytics_timeline(
    hours: int = 24,
    _=Depends(require_roles("admin", "analyst", "client")),
):
    return repository.get_timeline(hours=hours)


@app.get("/api/v1/analytics/top-attackers")
def analytics_top_attackers(
    limit: int = 10,
    _=Depends(require_roles("admin", "analyst", "client")),
):
    return repository.get_top_attackers(limit=limit)


@app.get("/api/v1/analytics/severity-breakdown")
def analytics_severity_breakdown(_=Depends(require_roles("admin", "analyst", "client"))):
    return repository.get_severity_breakdown()


@app.get("/api/v1/analytics/attack-types")
def analytics_attack_types(_=Depends(require_roles("admin", "analyst", "client"))):
    return repository.get_attack_type_breakdown()


@app.get("/api/v1/analytics/top-ports")
def analytics_top_ports(
    limit: int = 10,
    _=Depends(require_roles("admin", "analyst", "client")),
):
    return repository.get_top_ports(limit=limit)


# ------------------------------------------------------------------
# CSV export
# ------------------------------------------------------------------

@app.get("/api/v1/reports/export/csv")
def export_csv(
    limit: int = 5000,
    _=Depends(require_roles("admin", "analyst")),
):
    rows = repository.get_all_alerts_raw(limit=limit)

    FIELDS = [
        "timestamp", "source_ip", "destination_ip", "protocol",
        "severity", "attack_type", "label", "confidence",
        "confidence_level", "triage_action", "is_malicious",
        "dedup_count", "interface",
    ]

    def generate():
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        yield buf.getvalue()
        for row in rows:
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction="ignore")
            writer.writerow(row)
            yield buf.getvalue()

    filename = f"vulnsight_alerts_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ------------------------------------------------------------------
# Thresholds / app settings
# ------------------------------------------------------------------

@app.post("/api/v1/admin/cleanup")
def cleanup_alerts(
    older_than_days: int = 30,
    _=Depends(require_roles("admin")),
):
    deleted = repository.cleanup_old_alerts(older_than_days)
    return {"deleted": deleted, "older_than_days": older_than_days}


@app.get("/api/v1/admin/cleanup/preview")
def preview_cleanup(
    older_than_days: int = 30,
    _=Depends(require_roles("admin", "analyst")),
):
    count = repository.count_alerts_older_than(older_than_days)
    return {"count": count, "older_than_days": older_than_days}


# ------------------------------------------------------------------
# User management
# ------------------------------------------------------------------

@app.get("/api/v1/admin/users")
def list_users(_=Depends(require_roles("admin"))):
    return auth_repository.list_users()


@app.put("/api/v1/admin/users/{user_id}/active")
def toggle_user_active(
    user_id: int,
    body: Dict[str, Any],
    _=Depends(require_roles("admin")),
):
    is_active = bool(body.get("is_active", True))
    if not auth_repository.set_user_active(user_id, is_active):
        raise HTTPException(status_code=404, detail="User not found")
    user = auth_repository.get_user_by_id(user_id)
    roles = auth_repository.get_user_roles(user_id)
    return {**user, "roles": roles}


@app.delete("/api/v1/admin/users/{user_id}")
def delete_user(
    user_id: int,
    _=Depends(require_roles("admin")),
):
    user = auth_repository.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not auth_repository.delete_user(user_id):
        raise HTTPException(status_code=500, detail="Failed to delete user")
    return {"deleted": True}


@app.put("/api/v1/admin/users/{user_id}/roles")
def update_user_roles(
    user_id: int,
    body: Dict[str, Any],
    _=Depends(require_roles("admin")),
):
    roles = body.get("roles", [])
    if not isinstance(roles, list):
        raise HTTPException(status_code=400, detail="roles must be a list")
    auth_repository.update_user_roles(user_id, roles)
    user = auth_repository.get_user_by_id(user_id)
    return {**user, "roles": auth_repository.get_user_roles(user_id)}


@app.get("/api/v1/admin/thresholds")
def get_thresholds(_=Depends(require_roles("admin", "analyst"))):
    return repository.get_all_settings()


@app.put("/api/v1/admin/thresholds")
def set_thresholds(
    body: Dict[str, Any],
    _=Depends(require_roles("admin")),
):
    allowed = {
        "malicious_confidence_min",
        "dedup_window_seconds",
        "alert_notification_severities",
        "max_alerts_per_page",
    }
    for key, value in body.items():
        if key in allowed:
            repository.set_setting(key, value)
    return repository.get_all_settings()


# ------------------------------------------------------------------
# PCAP upload
# ------------------------------------------------------------------

def _process_pcap_background(
    job_id: str,
    filepath: str,
    repository_ref: AlertRepository,
    ws_manager_ref: Any,
    loop: asyncio.AbstractEventLoop,
):
    """Background thread: run nfstream on uploaded PCAP and classify flows."""
    _pcap_jobs[job_id]["status"] = "processing"
    try:
        from pathlib import Path as _Path
        _PROJECT_ROOT = _Path(__file__).parent.parent.parent
        from src.detection.collector import TrafficCollector
        from src.detection.engine import InferenceEngine
        from src.detection.classifier import classify_attack_type
        from src.api.schemas import AlertPayload as _AlertPayload, ShapInsight as _ShapInsight

        engine = InferenceEngine(
            model_path=str(_PROJECT_ROOT / "model" / "vulnsight_cnn_bilstm.pth"),
            scaler_path=str(_PROJECT_ROOT / "model" / "scaler.pkl"),
            use_shap=False,
        )
        collector = TrafficCollector(use_pcap=filepath)

        processed = 0
        alerts_saved = 0
        threshold = repository_ref.get_setting("malicious_confidence_min") or 0.5
        dedup_window = int(repository_ref.get_setting("dedup_window_seconds") or 60)

        for features, metadata in collector.get_flows():
            prediction, confidence = engine.process_flow(features)
            if prediction is None:
                continue
            processed += 1
            if prediction == 1 and confidence < threshold:
                prediction = 0

            attack_type = classify_attack_type(features, prediction == 1)

            def _cls(p, c):
                if p == 1:
                    if c >= 0.90: return "very_high", "critical", "isolate_host_immediately"
                    if c >= 0.75: return "high", "high", "block_and_investigate"
                    if c >= 0.60: return "medium", "medium", "monitor_closely"
                    return "low", "low", "log_and_review"
                return "very_high", "info", "no_action_required"

            lvl, sev, action = _cls(prediction, confidence)
            alert = _AlertPayload(
                timestamp=datetime.now(timezone.utc),
                source_ip=metadata.get("src_ip", "0.0.0.0"),
                destination_ip=metadata.get("dst_ip", "0.0.0.0"),
                protocol=metadata.get("protocol"),
                interface=f"pcap_upload:{Path(filepath).name}",
                prediction=prediction,
                label="ATTACK DETECTED" if prediction == 1 else "NORMAL",
                confidence=float(confidence),
                confidence_level=lvl,
                severity=sev,
                triage_action=action,
                is_malicious=prediction == 1,
                attack_type=attack_type,
            )
            is_new = repository_ref.save_alert_with_dedup(alert, window_seconds=dedup_window)
            if is_new:
                alerts_saved += 1
                payload = alert.model_dump(mode="json")
                asyncio.run_coroutine_threadsafe(ws_manager_ref.broadcast_json(payload), loop)

        _pcap_jobs[job_id].update(
            status="done",
            flows_processed=processed,
            alerts_saved=alerts_saved,
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        _pcap_jobs[job_id].update(status="error", error=str(exc))


@app.post("/api/v1/upload/pcap")
async def upload_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    _=Depends(require_roles("admin", "analyst")),
):
    if not file.filename or not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="File must be a .pcap / .pcapng / .cap file")

    _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    job_id = str(uuid.uuid4())[:8]
    save_path = _UPLOAD_DIR / f"{job_id}_{file.filename}"

    content = await file.read()
    if len(content) > 200 * 1024 * 1024:  # 200 MB guard
        raise HTTPException(status_code=413, detail="File exceeds 200 MB limit")
    save_path.write_bytes(content)

    loop = app.state.event_loop
    _pcap_jobs[job_id] = {
        "job_id": job_id,
        "filename": file.filename,
        "status": "queued",
        "flows_processed": 0,
        "alerts_saved": 0,
        "error": None,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
    }

    t = threading.Thread(
        target=_process_pcap_background,
        args=(job_id, str(save_path), repository, ws_manager, loop),
        daemon=True,
    )
    t.start()

    return _pcap_jobs[job_id]


@app.get("/api/v1/upload/pcap/{job_id}")
def pcap_job_status(
    job_id: str,
    _=Depends(require_roles("admin", "analyst")),
):
    job = _pcap_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


# ------------------------------------------------------------------
# Detection control endpoints
# ------------------------------------------------------------------

@app.post("/api/v1/detection/start")
def detection_start(
    interface: Optional[str] = None,
    _=Depends(require_roles("admin")),
):
    loop = app.state.event_loop
    detection_manager.start(
        repository=repository,
        ws_manager=ws_manager,
        loop=loop,
        interface=interface,
    )
    return detection_manager.status()


@app.post("/api/v1/detection/stop")
def detection_stop(_=Depends(require_roles("admin"))):
    detection_manager.stop()
    return detection_manager.status()


@app.get("/api/v1/detection/status")
def detection_status(_=Depends(require_roles("admin", "analyst", "client"))):
    return detection_manager.status()
