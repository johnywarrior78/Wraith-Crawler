from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from ..domain import PluginResult
from ..enums import FailureReason, PluginState
from .base import AssessmentPlugin, PluginContext

ATTACKER_CAPABILITY_BY_FINDING = {
    "sql_injection": "sql_query_manipulation",
    "cross_site_scripting": "arbitrary_javascript_execution",
    "secret_exposure": "secret_acquisition",
    "source_map_exposure": "sensitive_information_disclosure",
    "sensitive_file_exposure": "file_disclosure",
    "directory_listing": "file_discovery",
    "idor_bola": "authorization_bypass",
    "ssrf": "internal_service_interaction",
    "anonymous_sensitive_api": "api_access",
    "debug_interface_exposure": "debug_surface_access",
    "management_metrics_exposure": "operational_information_disclosure",
    "detailed_health_exposure": "service_topology_disclosure",
}


@dataclass(slots=True)
class TimedPluginResult:
    result: PluginResult
    duration_ms: int
    started_at: datetime
    completed_at: datetime


class PluginRuntime:
    """Capability-driven scheduler with strict per-plugin failure isolation."""

    def __init__(self, plugins: list[AssessmentPlugin], concurrency: int = 4) -> None:
        self.plugins = plugins
        self.concurrency = max(1, concurrency)

    async def run(self, context: PluginContext) -> list[TimedPluginResult]:
        results: list[TimedPluginResult] = []
        pending: dict[str, AssessmentPlugin] = {}
        for plugin in self.plugins:
            if plugin.applicable(context):
                pending[plugin.name] = plugin
                continue
            now = datetime.now(UTC)
            results.append(
                TimedPluginResult(
                    PluginResult(
                        plugin=plugin.name,
                        state=PluginState.NOT_APPLICABLE,
                        message=f"Plugin is not enabled for the {context.config.profile.value} profile",
                        security_question=plugin.security_question,
                    ),
                    0,
                    now,
                    now,
                )
            )
        while pending:
            ready = [
                plugin
                for plugin in pending.values()
                if plugin.requires.issubset(context.capabilities)
            ]
            if not ready:
                for plugin in pending.values():
                    missing = sorted(plugin.requires.difference(context.capabilities))
                    result = PluginResult(
                        plugin=plugin.name,
                        state=PluginState.BLOCKED,
                        failure_reason=FailureReason.REQUIRED_CAPABILITY_UNAVAILABLE,
                        message=f"Missing capabilities: {', '.join(missing)}",
                    )
                    now = datetime.now(UTC)
                    results.append(TimedPluginResult(result, 0, now, now))
                break
            # A phase barrier makes discovery output available before active
            # validators start, while preserving concurrency within a phase.
            earliest_stage = min((plugin.phase.order, plugin.stage) for plugin in ready)
            ready = [
                plugin
                for plugin in ready
                if (plugin.phase.order, plugin.stage) == earliest_stage
            ]
            semaphore = asyncio.Semaphore(self.concurrency)

            async def guarded(
                plugin: AssessmentPlugin, limiter: asyncio.Semaphore = semaphore
            ) -> TimedPluginResult:
                async with limiter:
                    return await self._run_one(plugin, context)

            batch = await asyncio.gather(*(guarded(plugin) for plugin in ready))
            for item in batch:
                results.append(item)
                result = item.result
                if result.state in {PluginState.COMPLETED, PluginState.PARTIAL}:
                    context.capabilities.update(result.capabilities_produced)
                    for asset in result.assets:
                        context.inventory.add_asset(asset)
                    for endpoint in result.endpoints:
                        if context.scope.check(endpoint.url).allowed:
                            context.inventory.add_endpoint(endpoint)
                    for technology in result.technologies:
                        context.inventory.add_technology(technology)
                pending.pop(result.plugin, None)
        return results

    async def _run_one(
        self, plugin: AssessmentPlugin, context: PluginContext
    ) -> TimedPluginResult:
        started = time.monotonic()
        started_at = datetime.now(UTC)
        timeout = plugin.timeout_seconds or context.config.rate.tool_timeout_seconds
        try:
            result = await asyncio.wait_for(plugin.run(context), timeout=timeout)
        except TimeoutError:
            result = PluginResult(
                plugin=plugin.name,
                state=PluginState.TIMED_OUT,
                failure_reason=FailureReason.TIMEOUT,
                message=f"Plugin exceeded {timeout:.1f}s timeout",
            )
        except Exception as exc:
            result = PluginResult(
                plugin=plugin.name,
                state=PluginState.FAILED,
                failure_reason=FailureReason.INTERNAL_PLUGIN_ERROR,
                message=f"{type(exc).__name__}: {exc}",
            )
        rejected = sum(1 for finding in result.findings if not finding.evidence)
        if rejected:
            result.findings = [finding for finding in result.findings if finding.evidence]
            result.metrics["findings_rejected_without_evidence"] = rejected
            result.message = (
                f"{result.message + '; ' if result.message else ''}"
                f"Rejected {rejected} finding(s) without structured evidence"
            )
            result.state = PluginState.PARTIAL if result.findings else PluginState.FAILED
            result.failure_reason = FailureReason.PARSING_ERROR
        elapsed = int((time.monotonic() - started) * 1000)
        completed_at = datetime.now(UTC)
        result.security_question = result.security_question or plugin.security_question
        result.tests_attempted = result.tests_attempted or int(result.metrics.get("requests", 0))
        result.tests_completed = result.tests_completed or max(
            0, result.tests_attempted - int(result.metrics.get("failed_requests", 0))
        )
        if not result.targets_tested:
            targets = {asset.url for asset in result.assets}
            targets.update(endpoint.url for endpoint in result.endpoints)
            for finding in result.findings:
                targets.update(finding.affected_endpoints or [finding.asset])
            result.targets_tested = sorted(targets)
        for observation in result.observations:
            for evidence in observation.evidence:
                evidence.source_plugin = evidence.source_plugin or plugin.name
                evidence.target = evidence.target or observation.target
                evidence.endpoint = evidence.endpoint or evidence.location
        for finding in result.findings:
            for evidence in finding.evidence:
                evidence.source_plugin = evidence.source_plugin or plugin.name
                evidence.target = evidence.target or finding.asset
                evidence.endpoint = evidence.endpoint or evidence.location
                evidence.method = evidence.method or finding.method
                if not evidence.parameter and finding.parameters:
                    evidence.parameter = finding.parameters[0]
        if not result.attacker_capabilities:
            result.attacker_capabilities = sorted(
                {
                    ATTACKER_CAPABILITY_BY_FINDING[finding.finding_type]
                    for finding in result.findings
                    if finding.finding_type in ATTACKER_CAPABILITY_BY_FINDING
                }
            )
        if not result.next_tests:
            next_tests: list[str] = []
            if result.endpoints:
                next_tests.append("Merge new endpoints and parameters into the canonical attack surface")
            if any(finding.manual_review for finding in result.findings):
                next_tests.append("Queue evidence-bounded analyst validation for unconfirmed candidates")
            if result.findings:
                next_tests.append("Correlate findings with attacker capabilities and attack-path rules")
            result.next_tests = next_tests
        return TimedPluginResult(result, elapsed, started_at, completed_at)
