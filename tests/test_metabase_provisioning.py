from __future__ import annotations

import json
import runpy
from pathlib import Path

import httpx

MetabaseProvisioner = runpy.run_path(
    Path(__file__).resolve().parents[1] / "scripts" / "provision_metabase.py"
)["MetabaseProvisioner"]


def test_initial_setup_uses_current_metabase_contract(monkeypatch) -> None:
    setup_payload: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/session":
            return httpx.Response(401, json={"message": "unauthenticated"})
        if request.url.path == "/api/session/properties":
            return httpx.Response(200, json={"setup-token": "setup-token"})
        if request.url.path == "/api/setup":
            setup_payload.update(json.loads(request.content))
            return httpx.Response(200, json={"id": "session-id"})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    monkeypatch.setenv("METABASE_ADMIN_EMAIL", "admin@wraith.local")
    monkeypatch.setenv("METABASE_ADMIN_PASSWORD", "ValidPassword123")
    provisioner = MetabaseProvisioner("http://metabase.test")
    provisioner.client.close()
    provisioner.client = httpx.Client(
        base_url="http://metabase.test", transport=httpx.MockTransport(handler)
    )

    assert provisioner.session() == "session-id"
    assert setup_payload["token"] == "setup-token"
    assert setup_payload["prefs"] == {"site_name": "Wraith Crawler"}
    assert setup_payload["user"] == {
        "first_name": "Wraith",
        "last_name": "Administrator",
        "email": "admin@wraith.local",
        "password": "ValidPassword123",
    }
    assert "database" not in setup_payload


def test_existing_legacy_metabase_admin_remains_usable(monkeypatch) -> None:
    attempted_users: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/session"
        username = json.loads(request.content)["username"]
        attempted_users.append(username)
        if username == "admin@localhost":
            return httpx.Response(200, json={"id": "legacy-session"})
        return httpx.Response(401, json={"message": "unauthenticated"})

    monkeypatch.setenv("METABASE_ADMIN_EMAIL", "admin@wraith.local")
    monkeypatch.setenv("METABASE_ADMIN_PASSWORD", "ValidPassword123")
    provisioner = MetabaseProvisioner("http://metabase.test")
    provisioner.client.close()
    provisioner.client = httpx.Client(
        base_url="http://metabase.test", transport=httpx.MockTransport(handler)
    )

    assert provisioner.session() == "legacy-session"
    assert attempted_users == ["admin@wraith.local", "admin@localhost"]
