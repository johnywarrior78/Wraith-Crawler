from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, SecretStr, field_validator
from sqlalchemy.engine import URL

from .enums import ScanProfile


class DatabaseConfig(BaseModel):
    url: SecretStr | None = None
    host: str = "127.0.0.1"
    port: int = 5432
    name: str = "wraith_crawler"
    username: str = "wraith_crawler"
    password: SecretStr | None = None
    pool_size: int = 10
    pool_timeout: int = 30

    def sqlalchemy_url(self) -> str:
        if self.url:
            return self.url.get_secret_value()
        if not self.password:
            raise ValueError("database password or WRAITH_DATABASE_URL is required")
        return URL.create(
            "postgresql+psycopg",
            username=self.username,
            password=self.password.get_secret_value(),
            host=self.host,
            port=self.port,
            database=self.name,
        ).render_as_string(hide_password=False)


class RateConfig(BaseModel):
    global_requests_per_second: float = 5.0
    target_concurrency: int = 2
    plugin_concurrency: int = 4
    request_timeout_seconds: float = 15.0
    tool_timeout_seconds: float = 300.0
    retries: int = 2
    crawl_depth: int = 3
    max_endpoints: int = 1000
    max_candidates: int = 250


class ToolConfig(BaseModel):
    httpx: str = "httpx"
    katana: str = "katana"
    nuclei: str = "nuclei"
    nuclei_target_mode: Literal["auto", "origins", "endpoints"] = "auto"
    dalfox: str = "dalfox"
    sqlmap: str = "sqlmap"
    nikto: str = "nikto"
    retire: str = "retire"


class LLMConfig(BaseModel):
    enabled: bool = False
    provider: str = "ollama"
    endpoint: str = "http://127.0.0.1:11434"
    model: str = "qwen2.5:7b"
    timeout_seconds: float = 30.0
    retries: int = 1


class MetabaseConfig(BaseModel):
    enabled: bool = True
    url: str = "http://127.0.0.1:3000"
    health_timeout_seconds: float = 10.0


class AppConfig(BaseModel):
    environment: str = "production"
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    rate: RateConfig = Field(default_factory=RateConfig)
    tools: ToolConfig = Field(default_factory=ToolConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    metabase: MetabaseConfig = Field(default_factory=MetabaseConfig)
    profile: ScanProfile = ScanProfile.STANDARD
    log_level: str = "INFO"
    session_ttl_minutes: int = 480
    session_cookie_secure: bool = True
    allowed_origins: list[str] = Field(default_factory=list)
    report_output_directory: Path = Path("output")

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, value: str) -> str:
        value = value.lower()
        if value not in {"production", "staging", "development", "test"}:
            raise ValueError("unsupported environment")
        return value


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str | Path | None = None) -> AppConfig:
    data: dict[str, Any] = {}
    if path:
        config_path = Path(path)
        if not config_path.is_file():
            raise FileNotFoundError(config_path)
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError("configuration root must be a mapping")
        data = loaded

    env_overlay: dict[str, Any] = {}
    if url := os.getenv("WRAITH_DATABASE_URL"):
        env_overlay.setdefault("database", {})["url"] = url
    if environment := os.getenv("WRAITH_ENVIRONMENT"):
        env_overlay["environment"] = environment
    if log_level := os.getenv("WRAITH_LOG_LEVEL"):
        env_overlay["log_level"] = log_level
    if metabase_url := os.getenv("WRAITH_METABASE_URL"):
        env_overlay.setdefault("metabase", {})["url"] = metabase_url
    return AppConfig.model_validate(_deep_merge(data, env_overlay))
