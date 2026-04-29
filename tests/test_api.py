"""Tests for the FastAPI endpoints: health, auth, alerts, reports, import-flows."""
import pytest

from tests.conftest import SAMPLE_ALERT


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_returns_200(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_health_body_structure(self, client):
        body = client.get("/api/v1/health").json()
        assert body["status"] == "ok"
        assert "timestamp" in body
        assert "counts" in body

    def test_health_counts_keys(self, client):
        counts = client.get("/api/v1/health").json()["counts"]
        for key in ("alerts", "flow", "packet", "pcap_file"):
            assert key in counts

    def test_health_no_auth_required(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code != 401


# ---------------------------------------------------------------------------
# Auth – login
# ---------------------------------------------------------------------------

class TestLogin:
    def test_login_success(self, client):
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin12345"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert "expires_at" in body

    def test_login_wrong_password(self, client):
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "wrongpassword"},
        )
        assert resp.status_code == 401

    def test_login_unknown_user(self, client):
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "nobody", "password": "anything1"},
        )
        assert resp.status_code == 401

    def test_login_short_password_fails_validation(self, client):
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "short"},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Auth – /me
# ---------------------------------------------------------------------------

class TestMe:
    def test_me_returns_current_user(self, client, admin_headers):
        resp = client.get("/api/v1/auth/me", headers=admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["username"] == "admin"
        assert "admin" in body["roles"]

    def test_me_requires_auth(self, client):
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    def test_me_invalid_token(self, client):
        resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer totally.invalid.token"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Auth – register
# ---------------------------------------------------------------------------

class TestRegister:
    def test_register_new_user_as_admin(self, client, admin_headers):
        resp = client.post(
            "/api/v1/auth/register",
            json={"username": "newuser", "password": "NewPass123", "roles": ["viewer"]},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["username"] == "newuser"
        assert "viewer" in body["roles"]

    def test_register_requires_admin_role(self, client, viewer_headers):
        resp = client.post(
            "/api/v1/auth/register",
            json={"username": "hacker", "password": "Hack1234", "roles": ["admin"]},
            headers=viewer_headers,
        )
        assert resp.status_code == 403

    def test_register_without_auth_returns_401(self, client):
        resp = client.post(
            "/api/v1/auth/register",
            json={"username": "anon", "password": "Anon1234", "roles": ["viewer"]},
        )
        assert resp.status_code == 401

    def test_register_duplicate_username_returns_409(self, client, admin_headers):
        payload = {"username": "duplicate", "password": "Pass1234", "roles": ["viewer"]}
        client.post("/api/v1/auth/register", json=payload, headers=admin_headers)
        resp = client.post("/api/v1/auth/register", json=payload, headers=admin_headers)
        assert resp.status_code == 409

    def test_registered_user_can_login(self, client, admin_headers):
        client.post(
            "/api/v1/auth/register",
            json={"username": "logintest", "password": "LoginPass1", "roles": ["viewer"]},
            headers=admin_headers,
        )
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "logintest", "password": "LoginPass1"},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Alerts – ingest
# ---------------------------------------------------------------------------

class TestIngestAlert:
    def test_ingest_alert_as_admin(self, client, admin_headers):
        resp = client.post("/api/v1/alerts", json=SAMPLE_ALERT, headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["stored"] is True

    def test_ingest_alert_analyst_forbidden(self, client, auth_repo):
        """Only admins may ingest alerts; analyst should be rejected."""
        auth_repo.create_user("analyst1", "AnalystPass1", ["analyst"])
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "analyst1", "password": "AnalystPass1"},
        )
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        resp = client.post("/api/v1/alerts", json=SAMPLE_ALERT, headers=headers)
        assert resp.status_code == 403

    def test_ingest_alert_viewer_forbidden(self, client, viewer_headers):
        resp = client.post("/api/v1/alerts", json=SAMPLE_ALERT, headers=viewer_headers)
        assert resp.status_code == 403

    def test_ingest_alert_no_auth(self, client):
        resp = client.post("/api/v1/alerts", json=SAMPLE_ALERT)
        assert resp.status_code == 401

    def test_ingest_alert_missing_required_field(self, client, admin_headers):
        bad = {k: v for k, v in SAMPLE_ALERT.items() if k != "source_ip"}
        resp = client.post("/api/v1/alerts", json=bad, headers=admin_headers)
        assert resp.status_code == 422

    def test_ingest_alert_persists_in_db(self, client, admin_headers, alert_repo):
        client.post("/api/v1/alerts", json=SAMPLE_ALERT, headers=admin_headers)
        alerts = alert_repo.get_recent_alerts()
        assert len(alerts) == 1
        assert alerts[0].source_ip == SAMPLE_ALERT["source_ip"]


# ---------------------------------------------------------------------------
# Alerts – list
# ---------------------------------------------------------------------------

class TestGetAlerts:
    def test_get_alerts_as_admin(self, client, admin_headers):
        resp = client.get("/api/v1/alerts", headers=admin_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_alerts_as_analyst(self, client, analyst_headers):
        resp = client.get("/api/v1/alerts", headers=analyst_headers)
        assert resp.status_code == 200

    def test_get_alerts_as_viewer(self, client, viewer_headers):
        resp = client.get("/api/v1/alerts", headers=viewer_headers)
        assert resp.status_code == 200

    def test_get_alerts_no_auth(self, client):
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 401

    def test_get_alerts_after_ingest(self, client, admin_headers):
        client.post("/api/v1/alerts", json=SAMPLE_ALERT, headers=admin_headers)
        resp = client.get("/api/v1/alerts", headers=admin_headers)
        alerts = resp.json()
        assert len(alerts) == 1
        assert alerts[0]["source_ip"] == SAMPLE_ALERT["source_ip"]

    def test_get_alerts_limit_param(self, client, admin_headers):
        for _ in range(5):
            client.post("/api/v1/alerts", json=SAMPLE_ALERT, headers=admin_headers)
        resp = client.get("/api/v1/alerts?limit=3", headers=admin_headers)
        assert len(resp.json()) == 3

    def test_get_alerts_limit_zero_returns_empty(self, client, admin_headers):
        client.post("/api/v1/alerts", json=SAMPLE_ALERT, headers=admin_headers)
        resp = client.get("/api/v1/alerts?limit=0", headers=admin_headers)
        assert resp.json() == []


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

class TestReports:
    def test_generate_report_empty_db(self, client, admin_headers):
        resp = client.post("/api/v1/reports/generate", headers=admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_events"] == 0
        assert body["malicious_events"] == 0
        assert body["malicious_ratio"] == 0.0

    def test_generate_report_with_alerts(self, client, admin_headers):
        client.post("/api/v1/alerts", json=SAMPLE_ALERT, headers=admin_headers)
        benign = {**SAMPLE_ALERT, "is_malicious": False, "severity": "info", "prediction": 0, "label": "NORMAL"}
        client.post("/api/v1/alerts", json=benign, headers=admin_headers)

        resp = client.post("/api/v1/reports/generate", headers=admin_headers)
        body = resp.json()
        assert body["total_events"] == 2
        assert body["malicious_events"] == 1
        assert body["benign_events"] == 1
        assert body["malicious_ratio"] == pytest.approx(0.5)

    def test_generate_report_structure(self, client, admin_headers):
        resp = client.post("/api/v1/reports/generate", headers=admin_headers)
        body = resp.json()
        for key in ("generated_at", "total_events", "malicious_events", "benign_events",
                    "malicious_ratio", "severity_breakdown", "top_targets"):
            assert key in body

    def test_generate_report_viewer_forbidden(self, client, viewer_headers):
        resp = client.post("/api/v1/reports/generate", headers=viewer_headers)
        assert resp.status_code == 403

    def test_generate_report_no_auth(self, client):
        resp = client.post("/api/v1/reports/generate")
        assert resp.status_code == 401

    def test_generate_report_as_analyst(self, client, analyst_headers):
        resp = client.post("/api/v1/reports/generate", headers=analyst_headers)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Import flows
# ---------------------------------------------------------------------------

class TestImportFlows:
    def test_import_flows_empty(self, client, admin_headers):
        resp = client.post("/api/v1/admin/import-flows", headers=admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["imported"] == 0
        assert "counts" in body

    def test_import_flows_requires_admin_or_analyst(self, client, viewer_headers):
        resp = client.post("/api/v1/admin/import-flows", headers=viewer_headers)
        assert resp.status_code == 403

    def test_import_flows_no_auth(self, client):
        resp = client.post("/api/v1/admin/import-flows")
        assert resp.status_code == 401

    def test_import_flows_as_analyst(self, client, analyst_headers):
        resp = client.post("/api/v1/admin/import-flows", headers=analyst_headers)
        assert resp.status_code == 200
