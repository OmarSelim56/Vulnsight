import json
import sqlite3


def table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = ? AND name = ? LIMIT 1",
        ("table", table_name),
    ).fetchone()
    return row is not None


def _column_exists(conn: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(r["name"] == column_name for r in rows)


def _ensure_column(conn: sqlite3.Connection, table_name: str, column_name: str, column_ddl: str):
    if not _column_exists(conn, table_name, column_name):
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_ddl}")


def ensure_schema(conn: sqlite3.Connection) -> None:
    """
    Single source of truth for DB tables and compatibility migrations.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            severity TEXT NOT NULL,
            is_malicious INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            attack_type TEXT DEFAULT 'unknown',
            dedup_count INTEGER DEFAULT 1,
            dedup_key TEXT,
            last_seen_at TEXT
        )
        """
    )
    # Migrate existing tables to add new columns safely
    _ensure_column(conn, "alerts", "attack_type",  "attack_type TEXT DEFAULT 'unknown'")
    _ensure_column(conn, "alerts", "dedup_count",  "dedup_count INTEGER DEFAULT 1")
    _ensure_column(conn, "alerts", "dedup_key",    "dedup_key TEXT")
    _ensure_column(conn, "alerts", "last_seen_at", "last_seen_at TEXT")
    _ensure_column(conn, "alerts", "sensor_id",    "sensor_id TEXT DEFAULT NULL")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp  ON alerts(timestamp DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ip     ON alerts(source_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_dst_ip     ON alerts(destination_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_dedup_key  ON alerts(dedup_key, last_seen_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sensor_id   ON alerts(sensor_id)")

    # Sensor API keys — used by remote sensor agents to POST alerts
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sensor_keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            key_hash    TEXT NOT NULL UNIQUE,
            key_prefix  TEXT NOT NULL,
            is_active   INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT NOT NULL,
            last_seen_at TEXT,
            alerts_sent INTEGER DEFAULT 0
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_sensor_keys_hash ON sensor_keys(key_hash)"
    )

    # Key-value store for configurable thresholds / app settings
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    # Saved report history
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS saved_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'Full Analysis',
            period TEXT,
            alert_count INTEGER DEFAULT 0,
            generated_at TEXT NOT NULL,
            report_json TEXT NOT NULL,
            report_size INTEGER DEFAULT 0
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_saved_reports_generated_at ON saved_reports(generated_at DESC)"
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, role_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (role_id) REFERENCES roles(id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name)")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS imported_sessions (
            session_id TEXT PRIMARY KEY,
            alert_id INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS imported_legacy_alerts (
            legacy_alert_id TEXT PRIMARY KEY,
            alert_id INTEGER
        )
        """
    )

    # Teammate pipeline compatibility tables
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pcap_file (
            id TEXT PRIMARY KEY,
            filename TEXT,
            filepath TEXT,
            file_size INTEGER,
            uploaded_at TEXT,
            source TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS packet (
            id TEXT PRIMARY KEY,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            packet_length INTEGER,
            tcp_flags TEXT,
            pcap_id TEXT,
            session_id TEXT
        )
        """
    )
    # Migrate old teammate name: network_session -> flow
    if table_exists(conn, "network_session") and not table_exists(conn, "flow"):
        conn.execute("ALTER TABLE network_session RENAME TO flow")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS flow (
            id TEXT PRIMARY KEY,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            start_time TEXT,
            end_time TEXT,
            pcap_id TEXT,
            total_packets INTEGER,
            total_bytes INTEGER,
            duration REAL,
            packet_per_sec REAL,
            bytes_per_sec REAL,
            avg_packet_size REAL
        )
        """
    )
    _ensure_column(conn, "flow", "start_time", "start_time TEXT")
    _ensure_column(conn, "flow", "src_ip", "src_ip TEXT")
    _ensure_column(conn, "flow", "dst_ip", "dst_ip TEXT")
    _ensure_column(conn, "flow", "protocol", "protocol TEXT")
    _ensure_column(conn, "flow", "total_packets", "total_packets INTEGER")
    _ensure_column(conn, "flow", "total_bytes", "total_bytes INTEGER")
    _ensure_column(conn, "flow", "packet_per_sec", "packet_per_sec REAL")
    _ensure_column(conn, "flow", "bytes_per_sec", "bytes_per_sec REAL")
    _ensure_column(conn, "flow", "avg_packet_size", "avg_packet_size REAL")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_flow_start_time ON flow(start_time)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packet_session_id ON packet(session_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packet_pcap_id ON packet(pcap_id)")

    # Legacy teammate `alert` table migration
    if table_exists(conn, "alert"):
        legacy_rows = conn.execute(
            """
            SELECT id, timestamp, severity, label, confidence, description, session_id
            FROM alert
            """
        ).fetchall()
        for row in legacy_rows:
            legacy_id = str(row["id"])
            already = conn.execute(
                "SELECT 1 FROM imported_legacy_alerts WHERE legacy_alert_id = ? LIMIT 1",
                (legacy_id,),
            ).fetchone()
            if already:
                continue
            payload = {
                "timestamp": row["timestamp"] or "1970-01-01T00:00:00Z",
                "source_ip": "0.0.0.0",
                "destination_ip": "0.0.0.0",
                "protocol": None,
                "interface": "legacy_alert_migration",
                "prediction": 1,
                "label": row["label"] or "LEGACY ALERT",
                "confidence": float(row["confidence"] or 0.5),
                "confidence_level": "high" if float(row["confidence"] or 0.0) >= 0.8 else "medium",
                "severity": str(row["severity"] or "medium"),
                "triage_action": row["description"] or "review_legacy_alert",
                "is_malicious": True,
                "shap_top_features": [],
                "legacy_context": {"session_id": row["session_id"], "legacy_alert_id": legacy_id},
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
                    1,
                    json.dumps(payload),
                ),
            )
            conn.execute(
                "INSERT OR REPLACE INTO imported_legacy_alerts (legacy_alert_id, alert_id) VALUES (?, ?)",
                (legacy_id, cursor.lastrowid),
            )

