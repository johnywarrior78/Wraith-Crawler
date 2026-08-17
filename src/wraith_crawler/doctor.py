from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from typing import Any

import httpx
from sqlalchemy import inspect, text

from .config import AppConfig
from .persistence.database import Database
from .persistence.reporting_views import VIEW_DEFINITIONS, verify_reporting_views
from .tool_identity import projectdiscovery_httpx_version, strip_ansi


@dataclass(frozen=True, slots=True)
class HealthCheck:
    name: str
    status: str
    message: str
    required: bool
    metadata: dict[str, Any] | None = None


class Doctor:
    CORE_TABLES = {"users", "applications", "assessments", "findings", "plugin_executions", "attack_paths"}
    TOOLS = {
        "httpx": True,
        "katana": False,
        "nuclei": False,
        "dalfox": False,
        "sqlmap": False,
        "nikto": False,
        "retire": False,
    }
    VERSION_ARGUMENTS = {
        "httpx": (("-version",),),
        "katana": (("-version",),),
        "nuclei": (("-version",),),
        "dalfox": (("version",), ("--version",)),
        "sqlmap": (("--version",),),
        "nikto": (("-Version",), ("-h",)),
        "retire": (("--version",),),
    }

    def __init__(self, database: Database, config: AppConfig) -> None:
        self.database = database
        self.config = config

    def run(self) -> list[HealthCheck]:
        checks = [self._python(), self._database(), self._migrations(), self._reporting_views()]
        checks.extend(self._tool(name, required) for name, required in self.TOOLS.items())
        checks.append(self._metabase())
        return checks

    def healthy(self, checks: list[HealthCheck]) -> bool:
        return all(check.status == "ok" for check in checks if check.required)

    @staticmethod
    def as_dicts(checks: list[HealthCheck]) -> list[dict[str, Any]]:
        return [asdict(check) for check in checks]

    def _python(self) -> HealthCheck:
        current = sys.version_info
        ok = current >= (3, 12)
        return HealthCheck(
            "python",
            "ok" if ok else "failed",
            f"Python {current.major}.{current.minor}.{current.micro}",
            True,
        )

    def _database(self) -> HealthCheck:
        try:
            ok = self.database.ping()
            dialect = self.database.engine.dialect.name
            production_ok = dialect == "postgresql" or self.config.environment in {"development", "test"}
            return HealthCheck(
                "database",
                "ok" if ok and production_ok else "failed",
                f"Connected using {dialect}" + ("; PostgreSQL is mandatory outside development/test" if not production_ok else ""),
                True,
            )
        except Exception as exc:
            return HealthCheck("database", "failed", f"{type(exc).__name__}: {exc}", True)

    def _migrations(self) -> HealthCheck:
        try:
            tables = set(inspect(self.database.engine).get_table_names())
            missing = self.CORE_TABLES.difference(tables)
            with self.database.engine.connect() as connection:
                revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
            ok = not missing and revision is not None
            return HealthCheck(
                "migrations",
                "ok" if ok else "failed",
                f"revision={revision}; missing={','.join(sorted(missing)) or 'none'}",
                True,
            )
        except Exception as exc:
            return HealthCheck("migrations", "failed", f"{type(exc).__name__}: {exc}", True)

    def _reporting_views(self) -> HealthCheck:
        if self.database.engine.dialect.name != "postgresql":
            required = self.config.environment not in {"development", "test"}
            return HealthCheck(
                "reporting_views",
                "failed" if required else "skipped",
                "Reporting views require PostgreSQL",
                required,
            )
        try:
            with self.database.engine.connect() as connection:
                results = verify_reporting_views(connection)
            missing = [name for name, valid in results.items() if not valid]
            return HealthCheck(
                "reporting_views",
                "ok" if not missing else "failed",
                f"{len(results) - len(missing)}/{len(VIEW_DEFINITIONS)} views queryable",
                True,
                {"missing": missing},
            )
        except Exception as exc:
            return HealthCheck("reporting_views", "failed", f"{type(exc).__name__}: {exc}", True)

    def _tool(self, name: str, required: bool) -> HealthCheck:
        configured = getattr(self.config.tools, name if name != "retire" else "retire", name)
        path = shutil.which(configured)
        if not path:
            return HealthCheck(name, "failed" if required else "disabled", "binary not found", required)
        version = self._version(name, path)
        if not version:
            return HealthCheck(
                name,
                "failed",
                f"binary found at {path}, but its version command failed",
                required,
                {"path": path},
            )
        if name == "httpx" and not projectdiscovery_httpx_version(version):
            return HealthCheck(name, "failed", f"wrong httpx binary at {path}", True, {"output": version[:200]})
        if name == "httpx":
            identity = projectdiscovery_httpx_version(version)
            message = f"ProjectDiscovery HTTPX {identity}"
        else:
            message = self._version_summary(version)
        return HealthCheck(name, "ok", message[:200], required, {"path": path, "output": version[:500]})

    @classmethod
    def _version(cls, name: str, path: str) -> str:
        for args in cls.VERSION_ARGUMENTS.get(name, (("--version",),)):
            try:
                # The executable is resolved with shutil.which and no shell is involved.
                completed = subprocess.run(  # noqa: S603
                    [path, *args], capture_output=True, text=True, timeout=10, check=False
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            output = strip_ansi((completed.stdout + completed.stderr).strip())
            if completed.returncode == 0 and output:
                return output[:2000]
        return ""

    @staticmethod
    def _version_summary(output: str) -> str:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        for line in lines:
            if "version" in line.lower() or line.lower().startswith("v"):
                return line
        return lines[0] if lines else "binary executable"

    def _metabase(self) -> HealthCheck:
        if not self.config.metabase.enabled:
            return HealthCheck("metabase", "disabled", "disabled in configuration", False)
        try:
            response = httpx.get(
                f"{self.config.metabase.url.rstrip('/')}/api/health",
                timeout=self.config.metabase.health_timeout_seconds,
            )
            ok = response.status_code == 200 and response.json().get("status") == "ok"
            return HealthCheck(
                "metabase",
                "ok" if ok else "failed",
                f"health endpoint returned HTTP {response.status_code}",
                True,
            )
        except (httpx.HTTPError, ValueError) as exc:
            return HealthCheck("metabase", "failed", f"{type(exc).__name__}: {exc}", True)
