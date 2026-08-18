from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest
from sqlalchemy import select

from wraith_crawler.domain import TargetInput
from wraith_crawler.engine import ScanEngine
from wraith_crawler.persistence.models import Finding, PluginExecution
from wraith_crawler.plugins.builtins import BUILTIN_PLUGINS


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
