from __future__ import annotations

import asyncio

import pytest

from wraith_crawler.config import AppConfig, DatabaseConfig, MetabaseConfig
from wraith_crawler.domain import PluginResult, TargetInput
from wraith_crawler.enums import FailureReason, PluginState
from wraith_crawler.inventory import SharedInventory
from wraith_crawler.plugins.base import AssessmentPlugin, ExternalToolPlugin, PluginContext
from wraith_crawler.plugins.external import NiktoPlugin, NucleiPlugin, ProjectDiscoveryHTTPXPlugin
from wraith_crawler.plugins.runtime import PluginRuntime
from wraith_crawler.scope import ScopeManager


class CompletedPlugin(AssessmentPlugin):
    name = "completed"
    requires = frozenset({"seed_url"})
    produces = frozenset({"independent"})

    async def run(self, context: PluginContext) -> PluginResult:
        return self.success(self.name, capabilities_produced={"independent"})


class FailingKatana(AssessmentPlugin):
    name = "katana"
    requires = frozenset({"seed_url"})

    async def run(self, context: PluginContext) -> PluginResult:
        raise RuntimeError("crawler failed")


class DependentPlugin(AssessmentPlugin):
    name = "headers"
    requires = frozenset({"independent"})

    async def run(self, context: PluginContext) -> PluginResult:
        return self.success(self.name)


def context() -> PluginContext:
    target = TargetInput(url="https://example.com")
    config = AppConfig(environment="test", database=DatabaseConfig(url="sqlite+pysqlite:///:memory:"), metabase=MetabaseConfig(enabled=False))
    return PluginContext("assessment", target, config, ScopeManager(target), SharedInventory())


@pytest.mark.asyncio
async def test_failure_isolation_katana_does_not_block_independent_plugins() -> None:
    results = await PluginRuntime([FailingKatana(), CompletedPlugin(), DependentPlugin()], concurrency=3).run(context())
    by_name = {item.result.plugin: item.result for item in results}
    assert by_name["katana"].state == PluginState.FAILED
    assert by_name["completed"].state == PluginState.COMPLETED
    assert by_name["headers"].state == PluginState.COMPLETED


class SlowPlugin(AssessmentPlugin):
    name = "slow"
    timeout_seconds = 0.01

    async def run(self, context: PluginContext) -> PluginResult:
        await asyncio.sleep(1)
        return self.success(self.name)


@pytest.mark.asyncio
async def test_plugin_timeout_is_structured() -> None:
    result = (await PluginRuntime([SlowPlugin()]).run(context()))[0].result
    assert result.state == PluginState.TIMED_OUT
    assert result.failure_reason == FailureReason.TIMEOUT


def test_capability_deadlock_becomes_blocked() -> None:
    class Impossible(CompletedPlugin):
        name = "impossible"
        requires = frozenset({"never"})

    result = asyncio.run(PluginRuntime([Impossible()]).run(context()))[0].result
    assert result.state == PluginState.BLOCKED
    assert result.failure_reason == FailureReason.REQUIRED_CAPABILITY_UNAVAILABLE


def test_partial_jsonl_parser_preserves_valid_rows() -> None:
    rows, malformed = ExternalToolPlugin.parse_jsonl(b'{"ok": 1}\nnot json\n{"ok": 2}\n')
    assert rows == [{"ok": 1}, {"ok": 2}]
    assert malformed == 1


def test_nuclei_origin_dedup() -> None:
    origins = NucleiPlugin.collapse_origins([
        "https://example.com/a", "https://example.com/b?x=1", "http://example.com:8080/c"
    ])
    assert origins == ["http://example.com:8080", "https://example.com"]


def test_nuclei_parser() -> None:
    row = {
        "template-id": "test-template",
        "matched-at": "https://example.com/a",
        "info": {
            "name": "Test finding",
            "severity": "high",
            "classification": {"cwe-id": ["CWE-200"], "cve-id": ["CVE-2020-0001"], "cvss-score": 8.1},
            "reference": ["https://example.test/reference"],
        },
    }
    finding = NucleiPlugin().parse_finding(row)
    assert finding is not None
    assert finding.finding_type == "nuclei:test-template"
    assert finding.cvss == 8.1
    assert finding.validation_status.value == "suspected"


def test_nikto_unknown_observation_goes_to_manual_review() -> None:
    findings = NiktoPlugin().parse_output("+ Unknown behavior at /odd", "https://example.com")
    assert findings[0].finding_type == "nikto_manual_review"
    assert findings[0].manual_review is True


@pytest.mark.asyncio
async def test_wrong_httpx_identity_rejected(monkeypatch) -> None:
    plugin = ProjectDiscoveryHTTPXPlugin()

    async def fake_execute(*args, **kwargs):
        return 0, b"httpx version 0.28 python client", b"", False

    monkeypatch.setattr(plugin, "execute", fake_execute)
    assert await plugin._identity("httpx") is None


@pytest.mark.asyncio
async def test_projectdiscovery_httpx_current_version_identity_accepted(monkeypatch) -> None:
    plugin = ProjectDiscoveryHTTPXPlugin()

    async def fake_execute(*args, **kwargs):
        return 0, b"[INF] Current Version: v1.7.2\n", b"", False

    monkeypatch.setattr(plugin, "execute", fake_execute)
    assert await plugin._identity("httpx") == "1.7.2"
