from __future__ import annotations

import asyncio
import json
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import AppConfig
from ..domain import PluginResult, TargetInput
from ..enums import FailureReason, PluginState, ScanProfile
from ..inventory import SharedInventory
from ..scope import ScopeManager


@dataclass(slots=True)
class HTTPResponseSnapshot:
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: int
    redirect_chain: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CandidateQueues:
    xss: list[tuple[str, str]] = field(default_factory=list)
    sqli: list[tuple[str, str]] = field(default_factory=list)
    ssrf: list[tuple[str, str]] = field(default_factory=list)
    idor: list[tuple[str, str]] = field(default_factory=list)
    path: list[tuple[str, str]] = field(default_factory=list)
    redirect: list[tuple[str, str]] = field(default_factory=list)


@dataclass(slots=True)
class PluginContext:
    assessment_id: str
    target: TargetInput
    config: AppConfig
    scope: ScopeManager
    inventory: SharedInventory
    capabilities: set[str] = field(default_factory=lambda: {"seed_url"})
    http_snapshots: dict[str, HTTPResponseSnapshot] = field(default_factory=dict)
    javascript_content: dict[str, str] = field(default_factory=dict)
    queues: CandidateQueues = field(default_factory=CandidateQueues)
    scratch_dir: Path | None = None


class AssessmentPlugin(ABC):
    name: str
    description: str = ""
    requires: frozenset[str] = frozenset()
    produces: frozenset[str] = frozenset()
    profiles: frozenset[ScanProfile] = frozenset(ScanProfile)
    timeout_seconds: float | None = None
    external_tool: str | None = None
    owasp: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    automation_level: str = "automated"
    validation_strength: str = "observational"

    @abstractmethod
    async def run(self, context: PluginContext) -> PluginResult:
        raise NotImplementedError

    def applicable(self, context: PluginContext) -> bool:
        return context.config.profile in self.profiles

    @staticmethod
    def success(name: str, **kwargs: Any) -> PluginResult:
        return PluginResult(plugin=name, state=PluginState.COMPLETED, **kwargs)

    @staticmethod
    def blocked(name: str, reason: FailureReason, message: str) -> PluginResult:
        return PluginResult(
            plugin=name, state=PluginState.BLOCKED, failure_reason=reason, message=message
        )


class ExternalToolPlugin(AssessmentPlugin):
    version_args: tuple[str, ...] = ("-version",)

    def resolve_tool(self, context: PluginContext) -> str | None:
        configured = getattr(context.config.tools, self.external_tool or "", None)
        if not configured:
            return None
        return shutil.which(configured) if not Path(configured).is_file() else str(Path(configured))

    async def execute(
        self,
        command: list[str],
        *,
        timeout: float,
        stdin: bytes | None = None,
        cwd: Path | None = None,
    ) -> tuple[int, bytes, bytes, bool]:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(stdin), timeout=timeout)
            return process.returncode or 0, stdout, stderr, False
        except TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
            return process.returncode or -1, stdout, stderr, True

    @staticmethod
    def parse_jsonl(payload: bytes) -> tuple[list[dict[str, Any]], int]:
        rows: list[dict[str, Any]] = []
        malformed = 0
        for raw_line in payload.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                malformed += 1
                continue
            if isinstance(parsed, dict):
                rows.append(parsed)
            else:
                malformed += 1
        return rows, malformed
