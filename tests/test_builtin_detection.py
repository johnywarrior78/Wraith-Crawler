from __future__ import annotations

import pytest

from wraith_crawler.config import AppConfig, DatabaseConfig, MetabaseConfig, RateConfig
from wraith_crawler.domain import EndpointRecord, TargetInput
from wraith_crawler.enums import Confidence
from wraith_crawler.inventory import SharedInventory
from wraith_crawler.plugins.base import HTTPResponseSnapshot, PluginContext
from wraith_crawler.plugins.builtins import (
    CMSDetectionPlugin,
    CookieSecurityPlugin,
    DirectoryListingPlugin,
    _safe_response_headers,
)
from wraith_crawler.plugins.registry import build_default_registry
from wraith_crawler.scope import ScopeManager


def context(
    *,
    url: str = "https://example.com/",
    body: str = "<html></html>",
    headers: dict[str, str] | None = None,
) -> PluginContext:
    target = TargetInput(url=url)
    config = AppConfig(
        environment="test",
        database=DatabaseConfig(url="sqlite+pysqlite:///:memory:"),
        metabase=MetabaseConfig(enabled=False),
        rate=RateConfig(global_requests_per_second=1000),
    )
    result = PluginContext(
        "assessment",
        target,
        config,
        ScopeManager(target),
        SharedInventory(),
    )
    result.http_snapshots[target.url] = HTTPResponseSnapshot(
        url=target.url,
        status_code=200,
        headers=headers or {"content-type": "text/html"},
        body=body,
        elapsed_ms=10,
    )
    return result


@pytest.mark.asyncio
async def test_session_cookie_inventory_discards_values_and_checks_authentication_controls() -> (
    None
):
    plugin_context = context(
        headers={
            "content-type": "text/html",
            "set-cookie": (
                "PHPSESSID=top-secret-value; Path=/; HttpOnly, "
                "analytics=tracking-value; Expires=Wed, 09 Jun 2030 10:18:14 GMT; "
                "Path=/; Secure; SameSite=Lax"
            ),
        }
    )

    result = await CookieSecurityPlugin().run(plugin_context)

    assert result.metrics == {
        "cookies_observed": 2,
        "authentication_cookies": 1,
        "cookies_with_issues": 1,
    }
    assert len(result.findings) == 1
    assert result.findings[0].finding_type == "insecure_cookie"
    assert result.findings[0].metadata["cookie_class"] == "authentication_session"
    assert result.findings[0].metadata["missing_attributes"] == ["Secure", "SameSite"]
    assert "top-secret-value" not in result.model_dump_json()
    assert "tracking-value" not in result.model_dump_json()
    cookies = result.observations[0].data["cookies"]
    assert cookies[0]["cookie_name"] == "PHPSESSID"
    assert cookies[0]["session_lifetime"] is True
    assert cookies[1]["session_lifetime"] is False


@pytest.mark.asyncio
async def test_secure_session_cookie_has_no_finding() -> None:
    plugin_context = context(
        headers={
            "content-type": "text/html",
            "set-cookie": "__Host-session=secret; Path=/; Secure; HttpOnly; SameSite=Lax",
        }
    )

    result = await CookieSecurityPlugin().run(plugin_context)

    assert result.findings == []
    assert result.metrics["authentication_cookies"] == 1


def test_sensitive_response_headers_are_redacted_before_evidence_storage() -> None:
    assert _safe_response_headers(
        {"server": "nginx", "set-cookie": "session=secret", "authorization": "Bearer secret"}
    ) == {
        "server": "nginx",
        "set-cookie": "[REDACTED]",
        "authorization": "[REDACTED]",
    }


def test_cms_detection_uses_multiple_passive_signals_and_extracts_generator_version() -> None:
    snapshot = HTTPResponseSnapshot(
        url="https://example.com/",
        status_code=200,
        headers={
            "content-type": "text/html",
            "link": "<https://example.com/wp-json/>; rel=https://api.w.org/",
        },
        body=(
            '<meta content="WordPress 6.6.1" name="generator">'
            '<link rel="stylesheet" href="/wp-content/themes/site/style.css">'
        ),
        elapsed_ms=10,
    )

    technologies = CMSDetectionPlugin.detect(snapshot)

    assert len(technologies) == 1
    assert technologies[0].product == "WordPress"
    assert technologies[0].version == "6.6.1"
    assert technologies[0].category == "cms"
    assert technologies[0].confidence == Confidence.HIGH
    assert len(technologies[0].evidence) == 3


def test_cms_detection_does_not_match_plain_text_product_mentions() -> None:
    snapshot = HTTPResponseSnapshot(
        url="https://example.com/",
        status_code=200,
        headers={"content-type": "text/html"},
        body="<p>This article compares WordPress, Drupal, Joomla and Ghost.</p>",
        elapsed_ms=10,
    )

    assert CMSDetectionPlugin.detect(snapshot) == []


def test_directory_listing_requires_index_and_structure_markers() -> None:
    apache_index = """
    <html><head><title>Index of /downloads/</title></head>
    <body><h1>Index of /downloads/</h1>
    <table><tr><th>Name</th><th>Last modified</th><th>Size</th></tr>
    <tr><td><a href="../">Parent Directory</a></td></tr></table></body></html>
    """

    signatures = DirectoryListingPlugin.detect_signatures(apache_index)

    assert {"index_title", "index_heading", "parent_directory", "listing_columns"}.issubset(
        signatures
    )
    assert DirectoryListingPlugin.detect_signatures("<h1>Index of products</h1>") == []


@pytest.mark.asyncio
async def test_directory_listing_plugin_reuses_seed_response_without_extra_request() -> None:
    plugin_context = context(
        body=(
            "<title>Index of /</title><h1>Index of /</h1>"
            '<a href="../">Parent Directory</a><span>Last modified</span>'
        )
    )

    result = await DirectoryListingPlugin().run(plugin_context)

    assert len(result.findings) == 1
    assert result.findings[0].finding_type == "directory_listing"
    assert result.metrics["network_requests"] == 0
    assert result.metrics["directory_listings"] == 1


def test_directory_listing_candidates_are_derived_from_discovered_paths() -> None:
    plugin_context = context()
    plugin_context.inventory.add_endpoint(
        EndpointRecord(
            url="https://example.com/uploads/image.png",
            origin="https://example.com",
            path="/uploads/image.png",
            sources=["html_discovery"],
        )
    )

    assert DirectoryListingPlugin.candidate_urls(plugin_context) == [
        "https://example.com/",
        "https://example.com/uploads/",
    ]


def test_default_registry_exposes_cms_and_directory_plugins() -> None:
    names = {plugin.name for plugin in build_default_registry().all()}
    assert {"cookie_security", "cms_detection", "directory_listing"}.issubset(names)
