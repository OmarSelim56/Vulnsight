"""Tests for the database layer: schema, AlertRepository, AuthRepository."""
import json
import sqlite3

import pytest

from src.db.auth_repository import hash_password, verify_password, AuthRepository
from src.db.repository import AlertRepository
from src.db.schema import ensure_schema, table_exists
from src.api.schemas import AlertPayload

from tests.conftest import SAMPLE_ALERT


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

def _in_memory_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


class TestSchema:
    def test_ensure_schema_creates_core_tables(self):
        conn = _in_memory_conn()
        ensure_schema(conn)
        for table in ("alerts", "users", "roles", "user_roles", "flow", "packet", "pcap_file"):
            assert table_exists(conn, table), f"Table '{table}' was not created"

    def test_ensure_schema_is_idempotent(self):
        conn = _in_memory_conn()
        ensure_schema(conn)
        ensure_schema(conn)  # second call must not raise

    def test_table_exists_false_for_unknown(self):
        conn = _in_memory_conn()
        assert not table_exists(conn, "nonexistent_table")


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

class TestPasswordHashing:
    def test_hash_produces_hex_colon_hex(self):
        h = hash_password("secret")
        parts = h.split(":")
        assert len(parts) == 2
        assert all(c in "0123456789abcdef" for c in parts[0])

    def test_verify_correct_password(self):
        h = hash_password("correct")
        assert verify_password("correct", h) is True

    def test_verify_wrong_password(self):
        h = hash_password("correct")
        assert verify_password("wrong", h) is False

    def test_same_password_different_hashes(self):
        h1 = hash_password("password")
        h2 = hash_password("password")
        assert h1 != h2  # different random salts

    def test_verify_malformed_hash_returns_false(self):
        assert verify_password("any", "not_a_valid_hash") is False


# ---------------------------------------------------------------------------
# AuthRepository
# ---------------------------------------------------------------------------

class TestAuthRepository:
    def test_create_and_get_user(self, auth_repo):
        uid = auth_repo.create_user("bob", "BobPass1", ["analyst"])
        user = auth_repo.get_user_by_username("bob")
        assert user is not None
        assert user["username"] == "bob"
        assert user["id"] == uid
        assert user["is_active"] == 1

    def test_get_user_by_id(self, auth_repo):
        uid = auth_repo.create_user("carol", "CarolPass1", ["viewer"])
        user = auth_repo.get_user_by_id(uid)
        assert user["username"] == "carol"

    def test_get_user_by_id_missing_returns_none(self, auth_repo):
        assert auth_repo.get_user_by_id(99999) is None

    def test_get_user_by_username_missing_returns_none(self, auth_repo):
        assert auth_repo.get_user_by_username("ghost") is None

    def test_get_user_roles(self, auth_repo):
        uid = auth_repo.create_user("dave", "DavePass1", ["analyst", "viewer"])
        roles = auth_repo.get_user_roles(uid)
        assert set(roles) == {"analyst", "viewer"}

    def test_roles_are_lowercased(self, auth_repo):
        uid = auth_repo.create_user("eve", "EvePass1", ["ADMIN", "Analyst"])
        roles = auth_repo.get_user_roles(uid)
        assert all(r == r.lower() for r in roles)

    def test_ensure_default_user_creates_once(self, tmp_db):
        repo = AuthRepository(db_path=tmp_db)
        repo.ensure_default_user("sysadmin", "Pass1234", "admin")
        repo.ensure_default_user("sysadmin", "Pass1234", "admin")  # second call is no-op
        # Only one user with that name should exist
        user = repo.get_user_by_username("sysadmin")
        assert user is not None

    def test_duplicate_username_raises(self, auth_repo):
        auth_repo.create_user("unique", "Pass1234", ["viewer"])
        with pytest.raises(Exception):
            auth_repo.create_user("unique", "OtherPass", ["analyst"])

    def test_password_stored_as_hash(self, auth_repo):
        auth_repo.create_user("frank", "PlainText", ["viewer"])
        user = auth_repo.get_user_by_username("frank")
        assert user["password_hash"] != "PlainText"
        assert verify_password("PlainText", user["password_hash"])


# ---------------------------------------------------------------------------
# AlertRepository
# ---------------------------------------------------------------------------

def _make_alert(**overrides) -> AlertPayload:
    data = {**SAMPLE_ALERT, **overrides}
    return AlertPayload(**data)


class TestAlertRepository:
    def test_save_and_retrieve_alert(self, alert_repo):
        alert = _make_alert()
        alert_repo.save_alert(alert)
        results = alert_repo.get_recent_alerts(limit=10)
        assert len(results) == 1
        assert results[0].source_ip == alert.source_ip
        assert results[0].destination_ip == alert.destination_ip

    def test_get_recent_alerts_empty(self, alert_repo):
        assert alert_repo.get_recent_alerts() == []

    def test_get_recent_alerts_limit(self, alert_repo):
        for i in range(10):
            alert_repo.save_alert(_make_alert(source_ip=f"10.0.0.{i}"))
        results = alert_repo.get_recent_alerts(limit=5)
        assert len(results) == 5

    def test_get_recent_alerts_zero_limit_clamps_to_one(self, alert_repo):
        # Repository clamps limit via max(1, ...) — zero-guard lives in the API layer
        alert_repo.save_alert(_make_alert())
        results = alert_repo.get_recent_alerts(limit=0)
        assert len(results) == 1

    def test_get_recent_alerts_returns_alert_payload_objects(self, alert_repo):
        alert_repo.save_alert(_make_alert())
        results = alert_repo.get_recent_alerts()
        assert all(isinstance(a, AlertPayload) for a in results)

    def test_save_benign_alert(self, alert_repo):
        alert = _make_alert(is_malicious=False, severity="info", prediction=0, label="NORMAL")
        alert_repo.save_alert(alert)
        results = alert_repo.get_recent_alerts()
        assert results[0].is_malicious is False

    def test_db_counts_reflect_data(self, alert_repo):
        counts = alert_repo.db_counts()
        assert counts["alerts"] == 0
        alert_repo.save_alert(_make_alert())
        counts = alert_repo.db_counts()
        assert counts["alerts"] == 1

    def test_db_counts_includes_all_tables(self, alert_repo):
        counts = alert_repo.db_counts()
        for key in ("alerts", "flow", "packet", "pcap_file"):
            assert key in counts

    def test_import_flows_empty_table(self, alert_repo):
        imported = alert_repo.import_flows_as_alerts()
        assert imported == 0

    def test_import_flows_as_alerts(self, tmp_db, alert_repo):
        conn = sqlite3.connect(tmp_db)
        conn.row_factory = sqlite3.Row
        conn.execute(
            """
            INSERT INTO flow (id, src_ip, dst_ip, src_port, dst_port, protocol,
                start_time, total_packets, total_bytes, packet_per_sec, bytes_per_sec)
            VALUES ('flow-001', '1.2.3.4', '5.6.7.8', 1234, 80, 'TCP',
                '2024-01-01T00:00:00Z', 100, 50000, 10.0, 5000.0)
            """
        )
        conn.commit()
        conn.close()

        imported = alert_repo.import_flows_as_alerts()
        assert imported == 1
        alerts = alert_repo.get_recent_alerts()
        assert len(alerts) == 1
        assert alerts[0].source_ip == "1.2.3.4"

    def test_import_flows_idempotent(self, tmp_db, alert_repo):
        conn = sqlite3.connect(tmp_db)
        conn.execute(
            """
            INSERT INTO flow (id, src_ip, dst_ip, src_port, dst_port, protocol,
                start_time, total_packets, total_bytes, packet_per_sec, bytes_per_sec)
            VALUES ('flow-002', '9.9.9.9', '8.8.8.8', 443, 443, 'TCP',
                '2024-01-01T00:00:00Z', 50, 25000, 5.0, 2500.0)
            """
        )
        conn.commit()
        conn.close()

        first = alert_repo.import_flows_as_alerts()
        second = alert_repo.import_flows_as_alerts()
        assert first == 1
        assert second == 0  # already imported

    def test_high_traffic_flow_marked_malicious(self, tmp_db, alert_repo):
        conn = sqlite3.connect(tmp_db)
        conn.execute(
            """
            INSERT INTO flow (id, src_ip, dst_ip, src_port, dst_port, protocol,
                start_time, total_packets, total_bytes, packet_per_sec, bytes_per_sec)
            VALUES ('flow-high', '1.1.1.1', '2.2.2.2', 1000, 80, 'UDP',
                '2024-01-01T00:00:00Z', 9999, 9999999, 500.0, 600000.0)
            """
        )
        conn.commit()
        conn.close()

        alert_repo.import_flows_as_alerts()
        alerts = alert_repo.get_recent_alerts()
        assert alerts[0].is_malicious is True
        assert alerts[0].severity == "high"
