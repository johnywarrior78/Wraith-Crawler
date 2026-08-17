from __future__ import annotations

import pytest
from sqlalchemy import func, select

from wraith_crawler.domain import EvidenceRecord, FindingCandidate, PluginResult, TargetInput
from wraith_crawler.engine import ScanEngine
from wraith_crawler.enums import Confidence, PluginState, Severity, ValidationStatus
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
