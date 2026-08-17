from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SENSITIVE_KEYS = ("password", "authorization", "cookie", "token", "secret", "api_key")


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "severity": record.levelname.lower(),
            "event": record.getMessage(),
            "logger": record.name,
        }
        for name in ("assessment_id", "target", "plugin"):
            if value := getattr(record, name, None):
                payload[name] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(redact(payload), sort_keys=True)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if any(marker in key.lower() for marker in SENSITIVE_KEYS) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def configure_logging(level: str = "INFO", path: Path | None = None) -> None:
    formatter = JSONFormatter()
    root = logging.getLogger()
    root.setLevel(level.upper())
    root.handlers.clear()
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(path, maxBytes=10_000_000, backupCount=5)
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
