from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import httpx
import pytest
import respx
from sqlalchemy import select

from wraith_crawler.domain import TargetInput
from wraith_crawler.engine import ScanEngine
from wraith_crawler.enums import FailureReason, PluginState
from wraith_crawler.inventory import SharedInventory
from wraith_crawler.persistence.models import Finding, PluginExecution
from wraith_crawler.plugins.base import PluginContext
from wraith_crawler.plugins.builtins import BUILTIN_PLUGINS, SeedHTTPPlugin
from wraith_crawler.scope import ScopeManager


class DetectionFixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        if path == "/fetch":
            body = (
                b"<html><title>Detection fixture</title><body>"
                b'<a href="/proxy?url=https%3A%2F%2Fone.example">proxy</a>'
                b'<a href="/callback?url=https%3A%2F%2Ftwo.example">callback</a>'
                b"</body></html>"
            )
            self.send_response(200)
        else:
            body = b"not found"
            self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.send_response(204)
        self.send_header("Allow", "GET, OPTIONS")
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


@pytest.fixture
def detection_target() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), DetectionFixtureHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/fetch?url=https%3A%2F%2Fexample.org"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


async def test_full_builtin_scan_retains_security_headers_and_ssrf_findings(
    database, config, detection_target: str
) -> None:
    builtin_names = [plugin_type.name for plugin_type in BUILTIN_PLUGINS]
    assessment_id = await ScanEngine(database, config).scan(
        TargetInput(url=detection_target),
        include_plugins=builtin_names,
    )

    with database.session() as session:
        findings = list(
            session.scalars(select(Finding).where(Finding.assessment_id == assessment_id))
        )
        executions = {
            row.plugin_name: row.state
            for row in session.scalars(
                select(PluginExecution).where(PluginExecution.assessment_id == assessment_id)
            )
        }

    assert any(finding.finding_type == "missing_security_headers" for finding in findings)
    assert len([finding for finding in findings if finding.finding_type == "ssrf"]) == 3
    assert executions["seed_http"] == "completed"
    assert executions["security_headers"] == "completed"
    assert executions["parameter_analysis"] == "completed"


def seed_context(config, url: str) -> PluginContext:
    target = TargetInput(url=url)
    return PluginContext(
        assessment_id="assessment",
        target=target,
        config=config,
        scope=ScopeManager(target),
        inventory=SharedInventory(),
    )


@respx.mock
async def test_seed_http_retries_accepted_placeholder_until_real_page(config) -> None:
    url = "https://example.com/"
    route = respx.get(url).mock(
        side_effect=[
            httpx.Response(202, text="accepted", headers={"Retry-After": "0"}),
            httpx.Response(200, text="<html><title>Ready</title></html>"),
        ]
    )

    result = await SeedHTTPPlugin().run(seed_context(config, url))

    assert route.call_count == 2
    assert result.state is PluginState.COMPLETED
    assert result.metrics["status_code"] == 200
    assert result.metrics["requests"] == 2
    assert result.capabilities_produced == set(SeedHTTPPlugin.produces)


@respx.mock
async def test_seed_http_withholds_discovery_for_persistent_accepted_placeholder(config) -> None:
    url = "https://example.com/"
    route = respx.get(url).mock(
        return_value=httpx.Response(202, text="accepted", headers={"Retry-After": "0"})
    )

    result = await SeedHTTPPlugin().run(seed_context(config, url))

    assert route.call_count == config.rate.retries + 1
    assert result.state is PluginState.PARTIAL
    assert result.failure_reason is FailureReason.INCOMPLETE_RESPONSE
    assert result.capabilities_produced == set()
    assert result.partial_output_trustworthy is True
