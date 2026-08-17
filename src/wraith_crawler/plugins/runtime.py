from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from ..domain import PluginResult
from ..enums import FailureReason, PluginState
from .base import AssessmentPlugin, PluginContext


@dataclass(slots=True)
class TimedPluginResult:
    result: PluginResult
    duration_ms: int


class PluginRuntime:
    """Capability-driven scheduler with strict per-plugin failure isolation."""

    def __init__(self, plugins: list[AssessmentPlugin], concurrency: int = 4) -> None:
        self.plugins = plugins
        self.concurrency = max(1, concurrency)

    async def run(self, context: PluginContext) -> list[TimedPluginResult]:
        pending = {plugin.name: plugin for plugin in self.plugins if plugin.applicable(context)}
        results: list[TimedPluginResult] = []
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
                    results.append(TimedPluginResult(result, 0))
                break
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
        elapsed = int((time.monotonic() - started) * 1000)
        return TimedPluginResult(result, elapsed)
