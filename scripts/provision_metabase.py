#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

import httpx

DASHBOARDS = (
    "Executive Dashboard",
    "Risk Dashboard",
    "OWASP Top 10 Dashboard",
    "Attack Paths Dashboard",
    "Technology / Vulnerable Components Dashboard",
    "Plugin Health Dashboard",
    "Historical Trends Dashboard",
    "Assessment Operations Dashboard",
    "Manual Review Dashboard",
)
CONTRACT_PATH = Path(__file__).resolve().parents[1] / "deploy" / "metabase" / "dashboards.json"


class MetabaseProvisioner:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(base_url=self.base_url, timeout=30)

    def wait(self) -> None:
        for _ in range(60):
            try:
                response = self.client.get("/api/health")
                if response.status_code == 200 and response.json().get("status") == "ok":
                    return
            except httpx.HTTPError:
                pass
            time.sleep(2)
        raise RuntimeError("Metabase did not become healthy")

    def session(self) -> str:
        email = required_env("METABASE_ADMIN_EMAIL")
        password = required_env("METABASE_ADMIN_PASSWORD")
        # A previous installer used admin@localhost, which newer Metabase
        # releases reject for first-time setup. Still accept that login if an
        # older Metabase instance already created it successfully.
        for candidate in dict.fromkeys((email, "admin@localhost")):
            response = self.client.post(
                "/api/session", json={"username": candidate, "password": password}
            )
            if response.status_code == 200:
                return response.json()["id"]
        properties = self.client.get("/api/session/properties").json()
        token = properties.get("setup-token")
        if not token:
            response.raise_for_status()
            raise RuntimeError("Metabase is initialized but the configured administrator cannot sign in")
        setup = {
            "token": token,
            "prefs": {"site_name": "Wraith Crawler"},
            "user": {
                "first_name": "Wraith",
                "last_name": "Administrator",
                "email": email,
                "password": password,
            },
        }
        response = self.client.post("/api/setup", json=setup)
        if response.is_error:
            detail = response.text.replace(password, "[REDACTED]")[:1000]
            raise RuntimeError(f"Metabase setup returned HTTP {response.status_code}: {detail}")
        return response.json().get("id") or self.client.post("/api/session", json={"username": email, "password": password}).json()["id"]

    def provision(self) -> None:
        session_id = self.session()
        self.client.headers["X-Metabase-Session"] = session_id
        database_id = self.ensure_database()
        collection_id = self.ensure_collection()
        self.client.post(f"/api/database/{database_id}/sync_schema").raise_for_status()
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        for name in DASHBOARDS:
            dashboard_id = self.ensure_dashboard(name, collection_id)
            for position, view_name in enumerate(contract["dashboards"][name]):
                card_id = self.ensure_card(view_name, database_id, collection_id)
                self.ensure_dashboard_card(dashboard_id, card_id, position)

    def ensure_database(self) -> int:
        databases = self.client.get("/api/database").json().get("data", [])
        for database in databases:
            if database.get("name") == "Wraith Crawler Reporting":
                return int(database["id"])
        payload = {
            "name": "Wraith Crawler Reporting",
            "engine": "postgres",
            "is_full_sync": True,
            "is_on_demand": False,
            "details": {
                "host": required_env("WRAITH_REPORTING_HOST"),
                "port": int(required_env("WRAITH_REPORTING_PORT")),
                "dbname": required_env("WRAITH_REPORTING_DB"),
                "user": required_env("WRAITH_REPORTING_USER"),
                "password": required_env("WRAITH_REPORTING_PASSWORD"),
                "schema-filters-type": "inclusion",
                "schema-filters-patterns": "reporting",
                "ssl": False,
            },
        }
        response = self.client.post("/api/database", json=payload)
        response.raise_for_status()
        return int(response.json()["id"])

    def ensure_collection(self) -> int:
        collections = self.client.get("/api/collection").json()
        for collection in collections:
            if collection.get("name") == "Wraith Crawler":
                return int(collection["id"])
        response = self.client.post("/api/collection", json={"name": "Wraith Crawler", "description": "Reproducible Wraith Crawler analytics", "parent_id": None})
        response.raise_for_status()
        return int(response.json()["id"])

    def ensure_dashboard(self, name: str, collection_id: int) -> int:
        response = self.client.get("/api/search", params={"q": name, "models": "dashboard"})
        if response.status_code == 200:
            for item in response.json().get("data", response.json() if isinstance(response.json(), list) else []):
                if item.get("name") == name:
                    return int(item["id"])
        response = self.client.post("/api/dashboard", json={"name": name, "description": dashboard_description(name), "collection_id": collection_id})
        response.raise_for_status()
        return int(response.json()["id"])

    def ensure_card(self, view_name: str, database_id: int, collection_id: int) -> int:
        if not re.fullmatch(r"vw_[a-z0-9_]+", view_name):
            raise ValueError(f"Invalid reporting view name in dashboard contract: {view_name}")
        name = f"Wraith — {view_name}"
        response = self.client.get("/api/search", params={"q": name, "models": "card"})
        if response.status_code == 200:
            payload = response.json()
            for item in payload.get("data", payload if isinstance(payload, list) else []):
                if item.get("name") == name:
                    return int(item["id"])
        question = {
            "name": name,
            "description": f"Versioned reporting view reporting.{view_name}",
            "collection_id": collection_id,
            "display": "table",
            "type": "question",
            "visualization_settings": {},
            "dataset_query": {
                "type": "native",
                "database": database_id,
                "native": {
                    "query": f'SELECT * FROM reporting."{view_name}" LIMIT 500',  # noqa: S608
                    "template-tags": {},
                },
            },
        }
        response = self.client.post("/api/card", json=question)
        response.raise_for_status()
        return int(response.json()["id"])

    def ensure_dashboard_card(self, dashboard_id: int, card_id: int, position: int) -> None:
        response = self.client.get(f"/api/dashboard/{dashboard_id}")
        response.raise_for_status()
        dashboard = response.json()
        current = dashboard.get("dashcards") or dashboard.get("ordered_cards") or []
        if any(int(item.get("card_id") or item.get("card", {}).get("id") or 0) == card_id for item in current):
            return
        cards = [self._dashboard_card_payload(item) for item in current]
        cards.append(
            {
                "id": -(position + 1),
                "card_id": card_id,
                "row": position * 8,
                "col": 0,
                "size_x": 24,
                "size_y": 8,
                "parameter_mappings": [],
                "visualization_settings": {},
                "series": [],
            }
        )
        response = self.client.put(f"/api/dashboard/{dashboard_id}/cards", json={"cards": cards})
        response.raise_for_status()

    @staticmethod
    def _dashboard_card_payload(item: dict[str, object]) -> dict[str, object]:
        allowed = {
            "id", "card_id", "row", "col", "size_x", "size_y", "parameter_mappings",
            "visualization_settings", "series", "dashboard_tab_id", "action_id",
        }
        payload = {key: value for key, value in item.items() if key in allowed}
        if not payload.get("card_id") and isinstance(item.get("card"), dict):
            payload["card_id"] = item["card"].get("id")  # type: ignore[union-attr]
        return payload


def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable {name}")
    return value


def dashboard_description(name: str) -> str:
    return f"Wraith Crawler {name} backed exclusively by versioned reporting schema views. Add or revise cards from deploy/metabase/dashboards.json."


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:3000")
    args = parser.parse_args()
    try:
        provisioner = MetabaseProvisioner(args.url)
        provisioner.wait()
        provisioner.provision()
    except (httpx.HTTPError, RuntimeError, KeyError, ValueError) as exc:
        print(f"Metabase provisioning failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print("Metabase reporting database, collection, questions, and dashboards are provisioned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
