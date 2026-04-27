import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    api_host: str = os.getenv("VULNSIGHT_API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("VULNSIGHT_API_PORT", "8000"))
    api_base_url: str = os.getenv("VULNSIGHT_API_BASE_URL", "http://127.0.0.1:8000")
    database_path: str = os.getenv("VULNSIGHT_DB_PATH", "database/vulnsight.db")
    ws_alerts_path: str = os.getenv("VULNSIGHT_WS_ALERTS_PATH", "/api/v1/ws/alerts")
    auth_jwt_secret: str = os.getenv("VULNSIGHT_AUTH_JWT_SECRET", "change-me-in-production")
    auth_jwt_algorithm: str = os.getenv("VULNSIGHT_AUTH_JWT_ALGORITHM", "HS256")
    auth_token_exp_minutes: int = int(os.getenv("VULNSIGHT_AUTH_TOKEN_EXP_MINUTES", "60"))
    auth_bootstrap_admin_username: str = os.getenv("VULNSIGHT_BOOTSTRAP_ADMIN_USERNAME", "admin")
    auth_bootstrap_admin_password: str = os.getenv("VULNSIGHT_BOOTSTRAP_ADMIN_PASSWORD", "admin12345")
    api_auth_token: str = os.getenv("VULNSIGHT_API_AUTH_TOKEN", "")
    api_auth_username: str = os.getenv("VULNSIGHT_API_AUTH_USERNAME", "admin")
    api_auth_password: str = os.getenv("VULNSIGHT_API_AUTH_PASSWORD", "admin12345")


settings = Settings()
