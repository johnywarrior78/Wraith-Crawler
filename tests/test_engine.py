from __future__ import annotations

import pytest
from sqlalchemy import func, select

from wraith_crawler.domain import EvidenceRecord, FindingCandidate, PluginResult, TargetInput
from wraith_crawler.engine import ScanEngine
from wraith_crawler.enums import (
    Confidence,
    FailureReason,
    FindingStatus,
    PluginState,
    Severity,
    ValidationStatus,
)
from wraith_crawler.persistence.models import Assessment, Finding, PluginExecution
from wraith_crawler.plugins.base import AssessmentPlugin, PluginContext
from wraith_crawler.plugins.registry import PluginRegistry


class SyntheticPlugin(AssessmentPlugin):
    name = "synthetic"
    requires = frozenset({"seed_url"})
    produces = frozenset({"synthetic_complete"})

    async def run(self, context: PluginContext) -> PluginResult:
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            findings=[
                FindingCandidate(
                    finding_type="sql_injection",
                    family="injection",
                    title="Synthetic SQL injection",
                    description="Fixture finding",
                    asset="https://example.com",
                    affected_endpoints=["https://example.com/?id=1"],
                    parameters=["id"],
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    validation_status=ValidationStatus.CONFIRMED,
                    evidence=[EvidenceRecord(kind="fixture", summary="Validated by test fixture")],
                    source_plugins=[self.name],
                    remediation="Use parameterized queries",
                )
            ],
        )


class CoverageHistoryPlugin(AssessmentPlugin):
    name = "coverage_history"

    def __init__(self, outcome: str) -> None:
        self.outcome = outcome

    async def run(self, context: PluginContext) -> PluginResult:
        if self.outcome in {"failed", "partial"}:
            return PluginResult(
                plugin=self.name,
                state=(
                    PluginState.FAILED if self.outcome == "failed" else PluginState.PARTIAL
                ),
                failure_reason=FailureReason.INCOMPLETE_RESPONSE,
            )
        findings = []
        if self.outcome == "finding":
            findings.append(
                FindingCandidate(
                    finding_type="missing_security_headers",
                    family="security_misconfiguration",
                    title="Historical fixture finding",
                    description="Fixture finding used to verify coverage-aware history",
                    asset=context.target.url,
                    affected_endpoints=[context.target.url],
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    validation_status=ValidationStatus.CONFIRMED,
                    evidence=[EvidenceRecord(kind="fixture", summary="Historical fixture evidence")],
                    source_plugins=[self.name],
                    remediation="Apply the missing control",
                )
            )
        return self.success(self.name, findings=findings)


async def test_engine_persists_canonical_state(database, config) -> None:
    registry = PluginRegistry()
    registry.register(SyntheticPlugin())
    assessment_id = await ScanEngine(database, config, registry).scan(TargetInput(url="https://example.com"))
    with database.session() as session:
        assessment = session.get(Assessment, assessment_id)
        assert assessment.status == "completed"
        assert session.scalar(select(func.count()).select_from(Finding).where(Finding.assessment_id == assessment_id)) == 1
        execution = session.scalar(select(PluginExecution).where(PluginExecution.assessment_id == assessment_id))
        assert execution.state == PluginState.COMPLETED.value
        finding = session.scalar(select(Finding).where(Finding.assessment_id == assessment_id))
        assert finding.cwe == ["CWE-89"]
        assert finding.attack_path_participation is True


async def test_invalid_plugin_selection_closes_assessment_as_failed(database, config) -> None:
    registry = PluginRegistry()
    registry.register(SyntheticPlugin())
    with pytest.raises(ValueError, match="unknown plugins"):
        await ScanEngine(database, config, registry).scan(
            TargetInput(url="https://example.com"), include_plugins=["does-not-exist"]
        )
    with database.session() as session:
        assessment = session.scalar(select(Assessment).order_by(Assessment.created_at.desc()))
        assert assessment.status == "failed"
        assert "unknown plugins" in assessment.failure_summary


async def test_incomplete_plugin_does_not_resolve_historical_finding(database, config) -> None:
    target = TargetInput(url="https://history.example/")

    first_registry = PluginRegistry()
    first_registry.register(CoverageHistoryPlugin("finding"))
    first_id = await ScanEngine(database, config, first_registry).scan(target)

    failed_registry = PluginRegistry()
    failed_registry.register(CoverageHistoryPlugin("failed"))
    await ScanEngine(database, config, failed_registry).scan(target)

    with database.session() as session:
        first = session.scalar(select(Finding).where(Finding.assessment_id == first_id))
        assert first.status == FindingStatus.NEW.value

    complete_registry = PluginRegistry()
    complete_registry.register(CoverageHistoryPlugin("empty"))
    await ScanEngine(database, config, complete_registry).scan(target)

    with database.session() as session:
        first = session.scalar(select(Finding).where(Finding.assessment_id == first_id))
        assert first.status == FindingStatus.RESOLVED.value


async def test_partial_plugin_marks_assessment_partial(database, config) -> None:
    registry = PluginRegistry()
    registry.register(CoverageHistoryPlugin("partial"))

    assessment_id = await ScanEngine(database, config, registry).scan(
        TargetInput(url="https://partial.example/")
    )

    with database.session() as session:
        assessment = session.get(Assessment, assessment_id)
        assert assessment.status == "partial"
