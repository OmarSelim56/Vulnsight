import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.api.schemas import AlertPayload
from src.db.schema import ensure_schema, table_exists


class AlertRepository:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            ensure_schema(conn)
            conn.commit()

    @staticmethod
    def _to_payload_dict(alert: AlertPayload) -> Dict:
        if hasattr(alert, "model_dump"):
            return alert.model_dump(mode="json")
        return alert.dict()

    def save_alert(self, alert: AlertPayload):
        payload = self._to_payload_dict(alert)
        attack_type = payload.get("attack_type") or "unknown"
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO alerts (
                        timestamp, source_ip, destination_ip, severity,
                        is_malicious, payload_json, attack_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload["timestamp"],
                        payload["source_ip"],
                        payload["destination_ip"],
                        payload["severity"],
                        1 if payload["is_malicious"] else 0,
                        json.dumps(payload),
                        attack_type,
                    ),
                )
                conn.commit()

    # ------------------------------------------------------------------
    # Deduplication-aware save  (used by the live detection engine)
    # ------------------------------------------------------------------

    @staticmethod
    def _dedup_key(src_ip: str, dst_ip: str, attack_type: str) -> str:
        raw = f"{src_ip}|{dst_ip}|{attack_type}"
        return hashlib.sha1(raw.encode()).hexdigest()

    def save_alert_with_dedup(self, alert: AlertPayload, window_seconds: int = 60) -> bool:
        """
        Save an alert with deduplication.

        If an alert with the same (src_ip, dst_ip, attack_type) already exists
        within `window_seconds`, increment its dedup_count instead of inserting
        a new row.

        Returns True if a new row was inserted, False if an existing row was
        updated (deduplicated).
        """
        payload = self._to_payload_dict(alert)
        attack_type = payload.get("attack_type") or "unknown"
        dk = self._dedup_key(
            payload["source_ip"], payload["destination_ip"], attack_type
        )
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._connect() as conn:
                existing = conn.execute(
                    """
                    SELECT id, dedup_count FROM alerts
                    WHERE dedup_key = ?
                      AND last_seen_at >= datetime(?, '-' || ? || ' seconds')
                    ORDER BY id DESC LIMIT 1
                    """,
                    (dk, now_iso, window_seconds),
                ).fetchone()

                if existing:
                    new_count = existing["dedup_count"] + 1
                    conn.execute(
                        """
                        UPDATE alerts
                        SET dedup_count = ?, last_seen_at = ?
                        WHERE id = ?
                        """,
                        (new_count, now_iso, existing["id"]),
                    )
                    conn.commit()
                    return False
                else:
                    conn.execute(
                        """
                        INSERT INTO alerts (
                            timestamp, source_ip, destination_ip, severity,
                            is_malicious, payload_json, attack_type,
                            dedup_key, last_seen_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            payload["timestamp"],
                            payload["source_ip"],
                            payload["destination_ip"],
                            payload["severity"],
                            1 if payload["is_malicious"] else 0,
                            json.dumps(payload),
                            attack_type,
                            dk,
                            now_iso,
                        ),
                    )
                    conn.commit()
                    return True

    def get_recent_alerts(self, limit: int = 100) -> List[AlertPayload]:
        query_limit = max(1, min(limit, 5000))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT payload_json
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (query_limit,),
            ).fetchall()

        payloads = [json.loads(r["payload_json"]) for r in rows]
        payloads.reverse()
        return [AlertPayload(**payload) for payload in payloads]

    def import_flows_as_alerts(self, limit: int = 1000) -> int:
        """
        Import flow rows into canonical alerts table.
        Safe to run repeatedly; already imported sessions are skipped.
        """
        query_limit = max(1, min(limit, 10_000))
        imported = 0
        with self._lock:
            with self._connect() as conn:
                if not table_exists(conn, "flow"):
                    return 0
                rows = conn.execute(
                    """
                    SELECT ns.id, ns.start_time, ns.src_ip, ns.dst_ip, ns.protocol,
                           ns.packet_per_sec, ns.bytes_per_sec, ns.total_packets, ns.total_bytes
                    FROM flow ns
                    LEFT JOIN imported_sessions imp ON imp.session_id = ns.id
                    WHERE imp.session_id IS NULL
                    ORDER BY ns.start_time DESC
                    LIMIT ?
                    """,
                    (query_limit,),
                ).fetchall()

                for row in rows:
                    packets_per_sec = float(row["packet_per_sec"] or 0.0)
                    bytes_per_sec = float(row["bytes_per_sec"] or 0.0)
                    total_packets = int(row["total_packets"] or 0)
                    total_bytes = int(row["total_bytes"] or 0)
                    is_malicious = packets_per_sec > 400 or bytes_per_sec > 500_000
                    severity = "high" if is_malicious else "info"
                    confidence = min(0.99, 0.55 + (packets_per_sec / 2000.0))
                    if not is_malicious:
                        attack_type = "normal"
                    elif packets_per_sec > 1000 or bytes_per_sec > 1_000_000:
                        attack_type = "ddos"
                    elif packets_per_sec > 400:
                        attack_type = "ddos"
                    else:
                        attack_type = "intrusion"
                    payload = {
                        "timestamp": row["start_time"] or "1970-01-01T00:00:00Z",
                        "source_ip": row["src_ip"] or "0.0.0.0",
                        "destination_ip": row["dst_ip"] or "0.0.0.0",
                        "protocol": None,
                        "interface": "flow_import",
                        "prediction": 1 if is_malicious else 0,
                        "label": "ATTACK DETECTED" if is_malicious else "NORMAL",
                        "confidence": float(confidence),
                        "confidence_level": "high" if confidence >= 0.8 else "medium",
                        "severity": severity,
                        "triage_action": (
                            "investigate_flow_now"
                            if is_malicious
                            else "monitor_traffic_pattern"
                        ),
                        "is_malicious": bool(is_malicious),
                        "attack_type": attack_type,
                        "shap_top_features": [],
                        "session_context": {
                            "session_id": row["id"],
                            "packet_per_sec": packets_per_sec,
                            "bytes_per_sec": bytes_per_sec,
                            "total_packets": total_packets,
                            "total_bytes": total_bytes,
                        },
                    }
                    cursor = conn.execute(
                        """
                        INSERT INTO alerts (
                            timestamp, source_ip, destination_ip, severity, is_malicious, payload_json
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            payload["timestamp"],
                            payload["source_ip"],
                            payload["destination_ip"],
                            payload["severity"],
                            1 if payload["is_malicious"] else 0,
                            json.dumps(payload),
                        ),
                    )
                    conn.execute(
                        "INSERT OR REPLACE INTO imported_sessions (session_id, alert_id) VALUES (?, ?)",
                        (row["id"], cursor.lastrowid),
                    )
                    imported += 1
                conn.commit()
        return imported

    def db_counts(self) -> Dict[str, int]:
        with self._connect() as conn:
            counts = {
                "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
                "flow": 0,
                "packet": 0,
                "pcap_file": 0,
            }
            for table in ("flow", "packet", "pcap_file"):
                if table_exists(conn, table):
                    counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        return counts

    # ------------------------------------------------------------------
    # Analytics queries
    # ------------------------------------------------------------------

    def get_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Return per-hour alert counts for the last `hours` hours.
        Each bucket: {"bucket": "2024-06-01 12:00", "count": N, "malicious": M}
        """
        hours = max(1, min(hours, 168))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT strftime('%Y-%m-%d %H:00', timestamp) AS bucket,
                       COUNT(*) AS count,
                       SUM(is_malicious) AS malicious
                FROM alerts
                WHERE timestamp >= datetime('now', '-' || ? || ' hours')
                GROUP BY bucket
                ORDER BY bucket ASC
                """,
                (hours,),
            ).fetchall()
        return [
            {
                "bucket": r["bucket"],
                "count": r["count"],
                "malicious": r["malicious"] or 0,
            }
            for r in rows
        ]

    def get_top_attackers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Top source IPs by total alert count (malicious only).
        """
        limit = max(1, min(limit, 100))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT source_ip,
                       COUNT(*) AS total,
                       SUM(is_malicious) AS malicious,
                       SUM(dedup_count) AS event_count
                FROM alerts
                WHERE is_malicious = 1
                GROUP BY source_ip
                ORDER BY event_count DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "source_ip": r["source_ip"],
                "total": r["total"],
                "malicious": r["malicious"] or 0,
                "event_count": r["event_count"] or r["total"],
            }
            for r in rows
        ]

    def get_top_ports(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Top destination ports extracted from payload_json."""
        limit = max(1, min(limit, 100))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT json_extract(payload_json, '$.protocol') AS proto,
                       COUNT(*) AS count
                FROM alerts
                WHERE is_malicious = 1
                  AND json_extract(payload_json, '$.protocol') IS NOT NULL
                GROUP BY proto
                ORDER BY count DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [{"protocol": r["proto"], "count": r["count"]} for r in rows]

    def get_severity_breakdown(self) -> List[Dict[str, Any]]:
        """Count of alerts per severity level (info excluded)."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT severity,
                       COUNT(*) AS count,
                       SUM(dedup_count) AS event_count
                FROM alerts
                WHERE severity != 'info'
                GROUP BY severity
                ORDER BY count DESC
                """,
            ).fetchall()
        return [
            {
                "severity": r["severity"],
                "count": r["count"],
                "event_count": r["event_count"] or r["count"],
            }
            for r in rows
        ]

    def get_attack_type_breakdown(self) -> List[Dict[str, Any]]:
        """Count of alerts per attack_type."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT attack_type,
                       COUNT(*) AS count,
                       SUM(dedup_count) AS event_count
                FROM alerts
                WHERE is_malicious = 1
                GROUP BY attack_type
                ORDER BY event_count DESC
                """,
            ).fetchall()
        return [
            {
                "attack_type": r["attack_type"] or "unknown",
                "count": r["count"],
                "event_count": r["event_count"] or r["count"],
            }
            for r in rows
        ]

    def get_all_alerts_raw(self, limit: int = 5000) -> List[Dict[str, Any]]:
        """Return raw payload dicts for CSV export."""
        query_limit = max(1, min(limit, 10_000))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload_json, attack_type, dedup_count FROM alerts ORDER BY id DESC LIMIT ?",
                (query_limit,),
            ).fetchall()
        result = []
        for r in rows:
            d = json.loads(r["payload_json"])
            d["attack_type"] = r["attack_type"] or d.get("attack_type", "unknown")
            d["dedup_count"] = r["dedup_count"] or 1
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # App settings (configurable thresholds)
    # ------------------------------------------------------------------

    _DEFAULT_SETTINGS: Dict[str, Any] = {
        "malicious_confidence_min": 0.5,
        "dedup_window_seconds": 60,
        "alert_notification_severities": ["critical", "high"],
        "max_alerts_per_page": 200,
    }

    def get_setting(self, key: str) -> Any:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM app_settings WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return self._DEFAULT_SETTINGS.get(key)
        return json.loads(row["value"])

    def set_setting(self, key: str, value: Any) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO app_settings (key, value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                                   updated_at = excluded.updated_at
                    """,
                    (key, json.dumps(value), now_iso),
                )
                conn.commit()

    def get_all_settings(self) -> Dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute("SELECT key, value FROM app_settings").fetchall()
        stored = {r["key"]: json.loads(r["value"]) for r in rows}
        return {**self._DEFAULT_SETTINGS, **stored}

    # ------------------------------------------------------------------
    # Data retention / cleanup
    # ------------------------------------------------------------------

    def cleanup_old_alerts(self, older_than_days: int) -> int:
        """Delete alerts older than `older_than_days` days. Returns deleted count."""
        older_than_days = max(1, older_than_days)
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "DELETE FROM alerts WHERE timestamp < datetime('now', '-' || ? || ' days')",
                    (older_than_days,),
                )
                conn.commit()
                return cur.rowcount

    def count_alerts_older_than(self, days: int) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE timestamp < datetime('now', '-' || ? || ' days')",
                (days,),
            ).fetchone()
        return row[0]

    # ------------------------------------------------------------------
    # Report history
    # ------------------------------------------------------------------

    def save_report(self, name: str, report_type: str, period: str,
                    alert_count: int, report_data: Dict[str, Any]) -> int:
        now_iso = datetime.now(timezone.utc).isoformat()
        report_json = json.dumps(report_data)
        report_size = len(report_json.encode("utf-8"))
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO saved_reports
                        (name, type, period, alert_count, generated_at, report_json, report_size)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (name, report_type, period, alert_count, now_iso,
                     report_json, report_size),
                )
                conn.commit()
                return cur.lastrowid

    def list_reports(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, name, type, period, alert_count, generated_at, report_size
                FROM saved_reports
                ORDER BY generated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_report(self, report_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM saved_reports WHERE id = ?", (report_id,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["report_data"] = json.loads(d.pop("report_json"))
        return d

    def delete_report(self, report_id: int) -> bool:
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "DELETE FROM saved_reports WHERE id = ?", (report_id,)
                )
                conn.commit()
                return cur.rowcount > 0

