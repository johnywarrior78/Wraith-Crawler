from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def new_id() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(UTC)


JSON_VALUE = JSON().with_variant(JSONB(none_as_null=True), "postgresql")


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now, onupdate=now, nullable=False
    )


user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", String(36), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    roles: Mapped[list[Role]] = relationship(secondary=user_roles, lazy="selectin")


class AuthSession(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True, nullable=False)
    csrf_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)
    user: Mapped[User] = relationship(lazy="joined")


class Application(Base, TimestampMixin):
    __tablename__ = "applications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    seed_url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_origin: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    business_metadata: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    scope: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)

    __table_args__ = (UniqueConstraint("normalized_origin", name="uq_application_origin"),)


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    application_id: Mapped[str] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), index=True
    )
    requested_by_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False, index=True)
    profile: Mapped[str] = mapped_column(String(32), default="standard", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_summary: Mapped[str | None] = mapped_column(Text)
    tool_versions: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    configuration_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)
    application: Mapped[Application] = relationship(lazy="joined")

    __table_args__ = (
        Index("ix_assessment_application_status_started", "application_id", "status", "started_at"),
    )


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    application_id: Mapped[str] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), index=True
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    origin: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    scheme: Mapped[str] = mapped_column(String(16), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    resolved_ips: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    cname: Mapped[str | None] = mapped_column(String(255))
    http_status: Mapped[int | None] = mapped_column(Integer)
    redirect_chain: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    title: Mapped[str | None] = mapped_column(Text)
    server: Mapped[str | None] = mapped_column(String(255))
    cdn_waf: Mapped[str | None] = mapped_column(String(255))
    tls_details: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    discovery_sources: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)

    __table_args__ = (UniqueConstraint("assessment_id", "url", name="uq_asset_assessment_url"),)


class Endpoint(Base, TimestampMixin):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    application_id: Mapped[str] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    url: Mapped[str] = mapped_column(Text, nullable=False)
    origin: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(String(16), default="GET", nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(255))
    response_metadata: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    source_plugins: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    authentication_required: Mapped[bool | None] = mapped_column(Boolean)
    api_classification: Mapped[str | None] = mapped_column(String(128))
    javascript_source: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)

    __table_args__ = (
        UniqueConstraint("assessment_id", "method", "url", name="uq_endpoint_assessment_method_url"),
        Index("ix_endpoint_application_path", "application_id", "path"),
    )


class Parameter(Base, TimestampMixin):
    __tablename__ = "parameters"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    location: Mapped[str] = mapped_column(String(32), nullable=False)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    required: Mapped[bool | None] = mapped_column(Boolean)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    sample_metadata: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    risk_categories: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "endpoint_id", "normalized_name", "location", name="uq_parameter_endpoint_name_location"
        ),
    )


class Technology(Base, TimestampMixin):
    __tablename__ = "technologies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    application_id: Mapped[str] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), index=True
    )
    product: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[str | None] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    source_plugin: Mapped[str] = mapped_column(String(128), nullable=False)
    eol_state: Mapped[str | None] = mapped_column(String(64), index=True)
    vulnerability_references: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class PluginExecution(Base):
    __tablename__ = "plugin_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    plugin_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    failure_reason: Mapped[str | None] = mapped_column(String(64), index=True)
    message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    tool_path: Mapped[str | None] = mapped_column(Text)
    tool_version: Mapped[str | None] = mapped_column(String(255))
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)

    __table_args__ = (
        Index("ix_plugin_health_dashboard", "plugin_name", "state", "started_at"),
    )


class RawObservationDB(Base):
    __tablename__ = "raw_observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    plugin_execution_id: Mapped[str | None] = mapped_column(
        ForeignKey("plugin_executions.id", ondelete="SET NULL"), index=True
    )
    observation_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    raw_observation_id: Mapped[str | None] = mapped_column(
        ForeignKey("raw_observations.id", ondelete="SET NULL"), index=True
    )
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(128), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    location: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    fingerprint: Mapped[str | None] = mapped_column(String(64), index=True)
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class FindingCandidateDB(Base):
    __tablename__ = "finding_candidates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    finding_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    asset: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    policy_decision: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    application_id: Mapped[str] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    finding_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    family: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    asset: Mapped[str] = mapped_column(Text, nullable=False)
    affected_endpoints: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    method: Mapped[str | None] = mapped_column(String(16))
    parameters: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    validation_status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_plugins: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    cwe: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    cve: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    owasp: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    capec: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    mitre_attack: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    cvss: Mapped[float | None] = mapped_column(Float)
    epss: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    references: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="new", nullable=False, index=True)
    manual_review: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    priority_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    priority_level: Mapped[str] = mapped_column(String(32), default="informational", nullable=False)
    priority_rationale: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    attack_path_participation: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON_VALUE, default=dict, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)

    __table_args__ = (
        UniqueConstraint("assessment_id", "fingerprint", name="uq_finding_assessment_fingerprint"),
        Index("ix_finding_dashboard", "application_id", "status", "severity", "last_seen"),
    )


class FindingHistory(Base):
    __tablename__ = "finding_history"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    application_id: Mapped[str] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    previous_status: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    rationale: Mapped[str | None] = mapped_column(Text)


class Priority(Base):
    __tablename__ = "priorities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), unique=True, index=True
    )
    score: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    level: Mapped[str] = mapped_column(String(32), nullable=False)
    rationale: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    engine_version: Mapped[str] = mapped_column(String(32), nullable=False)


class KnowledgeReference(Base):
    __tablename__ = "knowledge_references"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    reference_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance: Mapped[str] = mapped_column(Text, nullable=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    __table_args__ = (
        UniqueConstraint("reference_type", "external_id", "version", name="uq_knowledge_version"),
    )


class LLMTriage(Base):
    __tablename__ = "llm_triage"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(255), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    output: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ScanMetric(Base):
    __tablename__ = "scan_metrics"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    metric_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    metric_value: Mapped[float | None] = mapped_column(Float)
    dimensions: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    application_id: Mapped[str] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    classification: Mapped[str] = mapped_column(String(32), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    priority: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="new", nullable=False, index=True)
    attack_scenario: Mapped[str] = mapped_column(Text, nullable=False)
    attacker_gain: Mapped[str] = mapped_column(Text, nullable=False)
    next_step: Mapped[str] = mapped_column(Text, nullable=False)
    technical_impact: Mapped[str] = mapped_column(Text, nullable=False)
    business_impact: Mapped[str] = mapped_column(Text, nullable=False)
    blast_radius: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_boundary: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_break_point: Mapped[str] = mapped_column(Text, nullable=False)
    critical_path_labels: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)

    __table_args__ = (
        UniqueConstraint("assessment_id", "fingerprint", name="uq_attack_path_assessment_fingerprint"),
        Index("ix_attack_path_dashboard", "application_id", "status", "priority", "last_seen"),
    )


class AttackPathNode(Base):
    __tablename__ = "attack_path_nodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    attack_path_id: Mapped[str] = mapped_column(
        ForeignKey("attack_paths.id", ondelete="CASCADE"), index=True
    )
    node_key: Mapped[str] = mapped_column(String(255), nullable=False)
    node_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    label: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_reference: Mapped[str | None] = mapped_column(String(64))
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    classification: Mapped[str] = mapped_column(String(32), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON_VALUE, default=dict, nullable=False)

    __table_args__ = (
        UniqueConstraint("attack_path_id", "node_key", name="uq_attack_path_node_key"),
    )


class AttackPathEdge(Base):
    __tablename__ = "attack_path_edges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    attack_path_id: Mapped[str] = mapped_column(
        ForeignKey("attack_paths.id", ondelete="CASCADE"), index=True
    )
    source_node_id: Mapped[str] = mapped_column(
        ForeignKey("attack_path_nodes.id", ondelete="CASCADE"), index=True
    )
    destination_node_id: Mapped[str] = mapped_column(
        ForeignKey("attack_path_nodes.id", ondelete="CASCADE"), index=True
    )
    relationship: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_reference: Mapped[str | None] = mapped_column(String(64))
    source_plugin: Mapped[str | None] = mapped_column(String(128))
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    classification: Mapped[str] = mapped_column(String(32), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    mitre_attack: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)


class AttackPathFinding(Base):
    __tablename__ = "attack_path_findings"

    attack_path_id: Mapped[str] = mapped_column(
        ForeignKey("attack_paths.id", ondelete="CASCADE"), primary_key=True
    )
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(64), nullable=False)


class AttackPathCapability(Base):
    __tablename__ = "attack_path_capabilities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    attack_path_id: Mapped[str] = mapped_column(
        ForeignKey("attack_paths.id", ondelete="CASCADE"), index=True
    )
    capability: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)


class AttackPathImpact(Base):
    __tablename__ = "attack_path_impacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    attack_path_id: Mapped[str] = mapped_column(
        ForeignKey("attack_paths.id", ondelete="CASCADE"), index=True
    )
    impact_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)


class ManualReviewItem(Base, TimestampMixin):
    __tablename__ = "manual_review_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    application_id: Mapped[str] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    parameter: Mapped[str | None] = mapped_column(String(255))
    candidate_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False)
    source_plugin: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    priority: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    suggested_steps: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    attack_path_relevance: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)
    assigned_to_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    resolution: Mapped[str | None] = mapped_column(Text)
