from __future__ import annotations

import pytest
from sqlalchemy.engine import make_url

from wraith_crawler.cli import build_config, main, parser
from wraith_crawler.config import AppConfig, DatabaseConfig, ToolConfig
from wraith_crawler.domain import FindingCandidate, TargetInput, canonical_url, redact_text
from wraith_crawler.enums import Confidence, Severity, ValidationStatus
from wraith_crawler.scope import ScopeManager


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTPS://Example.COM", "https://example.com/"),
        ("https://example.com:443/a?x=1#fragment", "https://example.com/a?x=1"),
        ("http://example.com:8080", "http://example.com:8080/"),
    ],
)
def test_canonical_url(raw: str, expected: str) -> None:
    assert canonical_url(raw) == expected


@pytest.mark.parametrize("value", ["example.com", "ftp://example.com", "https:///missing", "javascript:alert(1)", "https://user:pass@example.com"])
def test_canonical_url_rejects_invalid(value: str) -> None:
    with pytest.raises(ValueError):
        canonical_url(value)


def test_report_text_redacts_secret_query_values() -> None:
    value = redact_text("See https://example.com/callback?token=abc123&item=42 password=hunter2")
    assert "abc123" not in value
    assert "hunter2" not in value
    assert "item=42" in value


def test_database_url_handles_special_password() -> None:
    config = DatabaseConfig(username="wraith", password="P@ss:/?#[]!Long", name="wraith")
    parsed = make_url(config.sqlalchemy_url())
    assert parsed.password == "P@ss:/?#[]!Long"
    assert parsed.database == "wraith"


def test_no_database_password_is_default() -> None:
    assert DatabaseConfig().password is None
    with pytest.raises(ValueError):
        DatabaseConfig().sqlalchemy_url()


def test_scope_same_host_and_explicit_include() -> None:
    manager = ScopeManager(
        TargetInput(
            url="https://app.example/base",
            include_hosts=["api.example"],
            exclude_paths=["/logout*"],
        )
    )
    assert manager.check("https://app.example/account").allowed
    assert manager.check("https://api.example/v1").allowed
    assert not manager.check("https://cdn.third-party.example/lib.js").allowed
    assert manager.check("https://app.example/logout").reason == "excluded_path"


def test_scope_does_not_pivot_to_subdomain_implicitly() -> None:
    manager = ScopeManager(TargetInput(url="https://example.com/"))
    assert not manager.check("https://admin.example.com/").allowed


def test_public_address_guard() -> None:
    assert not ScopeManager.is_public_address("127.0.0.1")
    assert not ScopeManager.is_public_address("10.0.0.1")
    assert ScopeManager.is_public_address("8.8.8.8")


def test_finding_fingerprint_is_deterministic() -> None:
    base = dict(
        finding_type="x",
        family="test",
        title="Title",
        description="Description",
        asset="https://example.com",
        affected_endpoints=["https://example.com/b", "https://example.com/a"],
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        validation_status=ValidationStatus.SUSPECTED,
        source_plugins=["one"],
        remediation="Fix",
    )
    left = FindingCandidate(**base)
    right = FindingCandidate(**{**base, "affected_endpoints": list(reversed(base["affected_endpoints"]))})
    assert left.fingerprint == right.fingerprint


def test_configuration_rejects_unknown_environment() -> None:
    with pytest.raises(ValueError):
        AppConfig(environment="unknown")


def test_nuclei_target_mode_is_bounded_to_supported_choices() -> None:
    assert ToolConfig(nuclei_target_mode="endpoints").nuclei_target_mode == "endpoints"
    with pytest.raises(ValueError):
        ToolConfig(nuclei_target_mode="unbounded")


def test_report_output_is_accepted_after_subcommand() -> None:
    args = parser().parse_args(["report", "assessment-id", "--output", "reports"])
    assert args.output == "reports"


def test_explicit_cli_database_url_remains_a_secret_value() -> None:
    args = parser().parse_args(
        ["--database-url", "sqlite+pysqlite:///:memory:", "--environment", "test", "coverage"]
    )
    assert build_config(args).database.sqlalchemy_url() == "sqlite+pysqlite:///:memory:"


def test_coverage_does_not_require_database_credentials(capsys, monkeypatch) -> None:
    monkeypatch.setattr("wraith_crawler.cli.configure_logging", lambda *_args, **_kwargs: None)
    assert main(["coverage"]) == 0
    assert '"category": "A01:2021"' in capsys.readouterr().out


def test_explicit_viewer_role_does_not_implicitly_add_admin() -> None:
    args = parser().parse_args(["admin", "create", "--role", "viewer"])
    assert args.role == ["viewer"]
