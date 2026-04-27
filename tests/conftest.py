import pytest
from fastapi.testclient import TestClient

from src.db.repository import AlertRepository
from src.db.auth_repository import AuthRepository


ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin12345"

SAMPLE_ALERT = {
    "timestamp": "2024-06-01T12:00:00Z",
    "source_ip": "192.168.1.50",
    "destination_ip": "10.0.0.1",
    "protocol": 443,
    "interface": "eth0",
    "prediction": 1,
    "label": "ATTACK DETECTED",
    "confidence": 0.95,
    "confidence_level": "high",
    "severity": "high",
    "triage_action": "block_and_investigate",
    "is_malicious": True,
    "shap_top_features": [
        {"feature": "packet_rate", "impact": 0.42, "direction": "positive"}
    ],
}


@pytest.fixture()
def tmp_db(tmp_path):
    return str(tmp_path / "test_vulnsight.db")


@pytest.fixture()
def alert_repo(tmp_db):
    return AlertRepository(db_path=tmp_db)


@pytest.fixture()
def auth_repo(tmp_db):
    repo = AuthRepository(db_path=tmp_db)
    repo.ensure_default_user(ADMIN_USERNAME, ADMIN_PASSWORD, "admin")
    return repo


@pytest.fixture()
def client(tmp_db, alert_repo, auth_repo, monkeypatch):
    import src.api.server as server_module
    import src.api.auth.routes as routes_module
    import src.api.auth.dependencies as deps_module

    monkeypatch.setattr(server_module, "repository", alert_repo)
    monkeypatch.setattr(server_module, "auth_repository", auth_repo)
    monkeypatch.setattr(routes_module, "auth_repository", auth_repo)
    monkeypatch.setattr(deps_module, "auth_repository", auth_repo)

    from src.api.server import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin_token(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture()
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture()
def analyst_headers(client, auth_repo, admin_headers):
    auth_repo.create_user("analyst_user", "Analyst@pass1", ["analyst"])
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst_user", "password": "Analyst@pass1"},
    )
    assert resp.status_code == 200
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


@pytest.fixture()
def viewer_headers(client, auth_repo, admin_headers):
    auth_repo.create_user("viewer_user", "Viewer@pass1", ["viewer"])
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "viewer_user", "password": "Viewer@pass1"},
    )
    assert resp.status_code == 200
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}
