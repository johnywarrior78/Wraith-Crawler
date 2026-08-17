from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..coverage import coverage_matrix
from ..persistence.models import (
    Application,
    Assessment,
    AttackPath,
    AttackPathEdge,
    AttackPathFinding,
    AttackPathNode,
    Endpoint,
    Evidence,
    Finding,
    ManualReviewItem,
    PluginExecution,
    ScanMetric,
    Technology,
)


@dataclass(slots=True)
class ReportData:
    assessment_id: str
    application_name: str
    target: str
    status: str
    profile: str
    started_at: datetime | None
    completed_at: datetime | None
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    plugin_executions: list[PluginExecution] = field(default_factory=list)
    manual_reviews: list[ManualReviewItem] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    attack_nodes: list[AttackPathNode] = field(default_factory=list)
    attack_edges: list[AttackPathEdge] = field(default_factory=list)
    attack_path_findings: list[AttackPathFinding] = field(default_factory=list)
    metrics: list[ScanMetric] = field(default_factory=list)
    owasp_coverage: list[dict[str, Any]] = field(default_factory=coverage_matrix)


def load_report_data(session: Session, assessment_id: str) -> ReportData:
    assessment = session.get(Assessment, assessment_id)
    if not assessment:
        raise ValueError(f"assessment not found: {assessment_id}")
    application = session.get(Application, assessment.application_id)
    if not application:
        raise ValueError("assessment application is missing")
    paths = list(
        session.scalars(
            select(AttackPath)
            .where(AttackPath.assessment_id == assessment_id)
            .order_by(AttackPath.score.desc())
        )
    )
    path_ids = [path.id for path in paths]
    return ReportData(
        assessment_id=assessment_id,
        application_name=application.name,
        target=application.seed_url,
        status=assessment.status,
        profile=assessment.profile,
        started_at=assessment.started_at,
        completed_at=assessment.completed_at,
        findings=list(
            session.scalars(
                select(Finding)
                .where(Finding.assessment_id == assessment_id)
                .order_by(Finding.priority_score.desc(), Finding.severity)
            )
        ),
        evidence=list(
            session.scalars(
                select(Evidence)
                .where(Evidence.assessment_id == assessment_id, Evidence.finding_id.is_not(None))
                .order_by(Evidence.observed_at)
            )
        ),
        endpoints=list(
            session.scalars(
                select(Endpoint)
                .where(Endpoint.assessment_id == assessment_id)
                .order_by(Endpoint.origin, Endpoint.path)
            )
        ),
        technologies=list(
            session.scalars(
                select(Technology)
                .where(Technology.assessment_id == assessment_id)
                .order_by(Technology.product)
            )
        ),
        plugin_executions=list(
            session.scalars(
                select(PluginExecution)
                .where(PluginExecution.assessment_id == assessment_id)
                .order_by(PluginExecution.plugin_name)
            )
        ),
        manual_reviews=list(
            session.scalars(
                select(ManualReviewItem)
                .where(ManualReviewItem.assessment_id == assessment_id)
                .order_by(ManualReviewItem.priority, ManualReviewItem.created_at)
            )
        ),
        attack_paths=paths,
        attack_nodes=list(
            session.scalars(select(AttackPathNode).where(AttackPathNode.attack_path_id.in_(path_ids)))
        )
        if path_ids
        else [],
        attack_edges=list(
            session.scalars(select(AttackPathEdge).where(AttackPathEdge.attack_path_id.in_(path_ids)))
        )
        if path_ids
        else [],
        attack_path_findings=list(
            session.scalars(
                select(AttackPathFinding).where(AttackPathFinding.attack_path_id.in_(path_ids))
            )
        )
        if path_ids
        else [],
        metrics=list(
            session.scalars(
                select(ScanMetric)
                .where(ScanMetric.assessment_id == assessment_id)
                .order_by(ScanMetric.metric_name)
            )
        ),
    )
