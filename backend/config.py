"""
config.py – Application settings for API Sentinel.
All values can be overridden via environment variables or a .env file.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Server ────────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = True

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./sentinel.db"

    # ── Security / Auth ───────────────────────────────────────────────────────
    secret_key: str = "sentinel-super-secret-key-change-in-prod"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # ── CORS ──────────────────────────────────────────────────────────────────
    cors_origins: list[str] = ["*"]

    # ── OpenAPI Contract ──────────────────────────────────────────────────────
    openapi_contract_path: str = "openapi_contract.yaml"

    # ── Enforcement ───────────────────────────────────────────────────────────
    # When True: BLOCK decision returns HTTP 403.
    # When False: BLOCK downgrades to ALERT (passive / learning mode).
    enforcement_mode: bool = True

    # ── Detection Thresholds ─────────────────────────────────────────────────
    anomaly_score_threshold: float = Field(default=60.0, ge=0, le=100)

    # Enumeration: N distinct object IDs in T seconds triggers signal
    enum_window_seconds: int = 60
    enum_threshold: int = 5

    # ── Risk Score Weights (sum does not need to equal 1) ────────────────────
    # BOLA weights
    w_ownership_mismatch: float = 50.0
    w_enumeration_signal: float = 25.0
    w_role_mismatch: float = 20.0

    # Shadow API weights
    w_endpoint_novelty: float = 40.0
    w_sensitive_data_signal: float = 30.0
    w_admin_function_signal: float = 30.0

    # ── Event Store ───────────────────────────────────────────────────────────
    max_events_in_memory: int = 10_000
    max_alerts_in_memory: int = 1_000


settings = Settings()


