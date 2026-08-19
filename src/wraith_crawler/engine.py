from __future__ import annotations

import asyncio
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select

from .attack_paths import AttackPathEngine, PathFinding
from .config import AppConfig
from .coverage import assessment_coverage
from .domain import TargetInput, redact_text
from .enums import AssessmentStatus, PentestPhase, PluginState
from .inventory import SharedInventory
from .persistence.database import Database
from .persistence.models import (
    Application,
    Assessment,
    AssessmentCoverage,
    Asset,
    AttackPath,
    AttackPathCapability,
    AttackPathEdge,
    AttackPathFinding,
    AttackPathImpact,
    AttackPathNode,
    Endpoint,
    Evidence,
    Finding,
    LLMTriage,
    Parameter,
    PentestPhaseProgress,
    PluginExecution,
    PostExploitationStep,
    Priority,
    RawObservationDB,
    ScanMetric,
    Technology,
)
from .plugins import PluginContext, PluginRegistry, PluginRuntime, build_default_registry
from .scope import ScopeManager
from .services.findings import FindingPersistenceService
from .services.knowledge import KnowledgeService
from .services.llm import LLMEnrichmentService, OllamaProvider


class ScanEngine:
    def __init__(
        self,
        database: Database,
        config: AppConfig,
        registry: PluginRegistry | None = None,
    ) -> None:
        self.database = database
        self.config = config
        self.registry = registry or build_default_registry()
        self.finding_service = FindingPersistenceService()
        self.knowledge = KnowledgeService()
        self.attack_paths = AttackPathEngine()

    async def scan(
        self,
        target: TargetInput,
        *,
        include_plugins: list[str] | None = None,
        exclude_plugins: list[str] | None = None,
        requested_by_id: str | None = None,
        scratch_dir: Path | None = None,
    ) -> str:
        application_id, assessment_id = self._create_assessment(target, requested_by_id)
        inventory = SharedInventory()
        context = PluginContext(
            assessment_id=assessment_id,
            target=target,
            config=self.config,
            scope=ScopeManager(target),
            inventory=inventory,
            scratch_dir=scratch_dir,
        )
        try:
            plugins = self.registry.select(include_plugins, exclude_plugins)
            runtime = PluginRuntime(plugins, self.config.rate.plugin_concurrency)
            timed_results = await runtime.run(context)
            llm_records = await self._optional_llm_enrichment(timed_results)
            self._persist_results(
                application_id,
                assessment_id,
                context,
                timed_results,
                plugins=plugins,
                llm_records=llm_records,
            )
        except Exception as exc:
            with self.database.session() as session:
                assessment = session.get(Assessment, assessment_id)
                if assessment:
                    assessment.status = AssessmentStatus.FAILED.value
                    assessment.completed_at = datetime.now(UTC)
                    assessment.failure_summary = f"{type(exc).__name__}: {exc}"
            raise
        return assessment_id

    async def scan_batch(
        self,
        targets: list[TargetInput],
        *,
        include_plugins: list[str] | None = None,
        exclude_plugins: list[str] | None = None,
        requested_by_id: str | None = None,
    ) -> dict[str, str | Exception]:
        semaphore = asyncio.Semaphore(self.config.rate.target_concurrency)

        async def one(target: TargetInput) -> tuple[str, str | Exception]:
            async with semaphore:
                try:
                    assessment_id = await self.scan(
                        target,
                        include_plugins=include_plugins,
                        exclude_plugins=exclude_plugins,
                        requested_by_id=requested_by_id,
                    )
                    return target.url, assessment_id
                except Exception as exc:
                    return target.url, exc

        results = await asyncio.gather(*(one(target) for target in targets))
        return dict(results)

    def _create_assessment(self, target: TargetInput, requested_by_id: str | None) -> tuple[str, str]:
        parts = urlsplit(target.url)
        port = parts.port
        default = (parts.scheme == "http" and port in {None, 80}) or (
            parts.scheme == "https" and port in {None, 443}
        )
        origin = f"{parts.scheme}://{parts.hostname}" + ("" if default else f":{port}")
        with self.database.session() as session:
            application = session.scalar(
                select(Application).where(Application.normalized_origin == origin)
            )
            if not application:
                application = Application(
                    name=parts.hostname or origin,
                    seed_url=target.url,
                    normalized_origin=origin,
                    scope=target.model_dump(mode="json", exclude={"url"}),
                )
                session.add(application)
                session.flush()
            assessment = Assessment(
                application_id=application.id,
                requested_by_id=requested_by_id,
                status=AssessmentStatus.RUNNING.value,
                profile=self.config.profile.value,
                started_at=datetime.now(UTC),
                configuration_snapshot=self._safe_config_snapshot(),
                tool_versions={},
            )
            session.add(assessment)
            session.flush()
            return application.id, assessment.id

    def _persist_results(
        self,
        application_id: str,
        assessment_id: str,
        context: PluginContext,
        timed_results: list[Any],
        plugins: list[Any],
        llm_records: list[dict[str, Any]] | None = None,
    ) -> None:
        with self.database.session() as session:
            execution_ids: dict[str, str] = {}
            candidates = []
            for timed in timed_results:
                result = timed.result
                plugin_definition = self.registry.get(result.plugin)
                tool_path = None
                tool_version = None
                if plugin_definition.external_tool:
                    configured_tool = getattr(
                        self.config.tools, plugin_definition.external_tool, plugin_definition.external_tool
                    )
                    tool_path = shutil.which(configured_tool)
                    tool_version = self._tool_version(tool_path) if tool_path else None
                execution = PluginExecution(
                    assessment_id=assessment_id,
                    plugin_name=result.plugin,
                    phase=plugin_definition.phase.value,
                    security_question=result.security_question,
                    state=result.state.value,
                    failure_reason=result.failure_reason.value if result.failure_reason else None,
                    message=redact_text(result.message) if result.message else None,
                    started_at=timed.started_at,
                    completed_at=timed.completed_at,
                    duration_ms=timed.duration_ms,
                    tool_path=tool_path,
                    tool_version=tool_version,
                    tests_attempted=result.tests_attempted,
                    tests_completed=result.tests_completed,
                    targets_tested=len(result.targets_tested),
                    findings_count=len(result.findings),
                    skip_reason=(
                        result.message
                        if result.state in {PluginState.NOT_APPLICABLE, PluginState.BLOCKED}
                        else None
                    ),
                    metrics={
                        **result.metrics,
                        "next_tests": result.next_tests,
                        "attacker_capabilities": result.attacker_capabilities,
                    },
                )
                session.add(execution)
                session.flush()
                execution_ids[result.plugin] = execution.id
                for observation in result.observations:
                    row = RawObservationDB(
                        assessment_id=assessment_id,
                        plugin_execution_id=execution.id,
                        observation_type=observation.observation_type,
                        target=observation.target,
                        confidence=observation.confidence.value,
                        data=self._redact(observation.data),
                        observed_at=observation.observed_at,
                    )
                    session.add(row)
                    session.flush()
                    for evidence in observation.evidence:
                        session.add(
                            Evidence(
                                assessment_id=assessment_id,
                                raw_observation_id=row.id,
                                kind=evidence.kind,
                                summary=evidence.safe_payload()["summary"],
                                location=evidence.location,
                                payload=evidence.safe_payload(),
                                fingerprint=evidence.fingerprint,
                                sensitive=evidence.sensitive,
                                observed_at=evidence.observed_at,
                            )
                        )
                candidates.extend(self.knowledge.enrich(candidate) for candidate in result.findings)
            endpoint_ids = self._persist_inventory(
                session, application_id, assessment_id, context.inventory
            )
            findings = self.finding_service.persist(
                session,
                assessment_id=assessment_id,
                application_id=application_id,
                candidates=candidates,
            )
            findings_by_fingerprint = {finding.fingerprint: finding for finding in findings}
            for record in llm_records or []:
                finding = findings_by_fingerprint.get(record["fingerprint"])
                session.add(
                    LLMTriage(
                        assessment_id=assessment_id,
                        finding_id=finding.id if finding else None,
                        provider=self.config.llm.provider,
                        model=self.config.llm.model,
                        schema_version="1",
                        status=record["status"],
                        output=record.get("output") or {},
                        error=record.get("error"),
                    )
                )
            self._attach_finding_evidence(session, assessment_id, findings, candidates)
            completed_plugins = {
                item.result.plugin
                for item in timed_results
                if item.result.state is PluginState.COMPLETED
            }
            history = self.finding_service.correlate_history(
                session,
                application_id,
                assessment_id,
                completed_plugins=completed_plugins,
            )
            paths = self._persist_attack_paths(
                session, application_id, assessment_id, findings
            )
            self._persist_coverage(
                session,
                assessment_id,
                assessment_coverage(plugins, timed_results, findings),
            )
            self._persist_phases(
                session,
                assessment_id,
                timed_results,
                findings_count=len(findings),
                attack_paths_count=len(paths),
            )
            for name, value in {
                "assets_discovered": len(context.inventory.assets),
                "endpoints_discovered": len(endpoint_ids),
                "technologies_discovered": len(context.inventory.technologies),
                "findings_total": len(findings),
                "attack_paths_total": len(paths),
                **{f"findings_{key}": value for key, value in history.items()},
            }.items():
                session.add(
                    ScanMetric(
                        assessment_id=assessment_id,
                        metric_name=name,
                        metric_value=float(value),
                        dimensions={},
                    )
                )
            assessment = session.get(Assessment, assessment_id)
            if assessment:
                degraded = sum(
                    1
                    for item in timed_results
                    if item.result.state
                    in {PluginState.FAILED, PluginState.TIMED_OUT, PluginState.PARTIAL}
                )
                completed = sum(
                    1
                    for item in timed_results
                    if item.result.state in {PluginState.COMPLETED, PluginState.PARTIAL}
                )
                assessment.status = (
                    AssessmentStatus.COMPLETED.value
                    if degraded == 0
                    else AssessmentStatus.PARTIAL.value
                    if completed
                    else AssessmentStatus.FAILED.value
                )
                assessment.completed_at = datetime.now(UTC)
                assessment.tool_versions = {
                    plugin_name: {
                        "path": session.get(PluginExecution, execution_id).tool_path,
                        "version": session.get(PluginExecution, execution_id).tool_version,
                    }
                    for plugin_name, execution_id in execution_ids.items()
                    if session.get(PluginExecution, execution_id).tool_path
                }

    def _persist_inventory(
        self,
        session: Any,
        application_id: str,
        assessment_id: str,
        inventory: SharedInventory,
    ) -> dict[tuple[str, str], str]:
        asset_by_origin: dict[str, str] = {}
        for item in inventory.assets.values():
            row = Asset(
                assessment_id=assessment_id,
                application_id=application_id,
                url=item.url,
                origin=item.origin,
                scheme=item.scheme,
                hostname=item.hostname,
                port=item.port,
                resolved_ips=item.resolved_ips,
                cname=item.cname,
                http_status=item.status_code,
                redirect_chain=item.redirect_chain,
                title=item.title,
                server=item.server,
                cdn_waf=item.cdn_waf,
                tls_details=item.tls,
                discovery_sources=item.discovery_sources,
            )
            session.add(row)
            session.flush()
            asset_by_origin[item.origin] = row.id
        endpoint_ids: dict[tuple[str, str], str] = {}
        for key, item in inventory.endpoints.items():
            row = Endpoint(
                assessment_id=assessment_id,
                application_id=application_id,
                asset_id=asset_by_origin.get(item.origin),
                url=item.url,
                origin=item.origin,
                path=item.path,
                method=item.method,
                status_code=item.status_code,
                content_type=item.content_type,
                response_metadata=self._redact(item.response_metadata),
                source_plugins=item.sources,
                authentication_required=item.authentication_required,
                api_classification=item.api_classification,
                javascript_source=item.javascript_source,
                confidence=item.confidence.value,
            )
            session.add(row)
            session.flush()
            endpoint_ids[key] = row.id
            for item_parameter in item.parameters:
                session.add(
                    Parameter(
                        assessment_id=assessment_id,
                        endpoint_id=row.id,
                        name=item_parameter.name,
                        normalized_name=item_parameter.normalized_name,
                        location=item_parameter.location,
                        method=item_parameter.method,
                        required=item_parameter.required,
                        source=item_parameter.source,
                        sample_metadata=self._redact(item_parameter.sample_metadata),
                        risk_categories=item_parameter.risk_categories,
                        risk_score=item_parameter.risk_score,
                    )
                )
        for item in inventory.technologies.values():
            item = self.knowledge.enrich_technology(item)
            session.add(
                Technology(
                    assessment_id=assessment_id,
                    application_id=application_id,
                    product=item.product,
                    version=item.version,
                    category=item.category,
                    confidence=item.confidence.value,
                    evidence=item.evidence,
                    source_plugin=item.source_plugin,
                    eol_state=item.eol_state,
                    eol_date=item.eol_date,
                    supported=item.supported,
                    lifecycle_source=item.lifecycle_source,
                    lifecycle_evidence=item.lifecycle_evidence,
                    vulnerability_references=item.vulnerability_references,
                    vulnerability_data=item.vulnerability_data,
                )
            )
        return endpoint_ids

    @staticmethod
    def _attach_finding_evidence(
        session: Any,
        assessment_id: str,
        findings: list[Finding],
        candidates: list[Any],
    ) -> None:
        by_fingerprint = {candidate.fingerprint: candidate for candidate in candidates}
        for finding in findings:
            candidate = by_fingerprint.get(finding.fingerprint)
            if not candidate:
                continue
            for record in candidate.evidence:
                session.add(
                    Evidence(
                        assessment_id=assessment_id,
                        finding_id=finding.id,
                        kind=record.kind,
                        summary=record.safe_payload()["summary"],
                        location=record.location,
                        payload=record.safe_payload(),
                        fingerprint=record.fingerprint,
                        sensitive=record.sensitive,
                        observed_at=record.observed_at,
                    )
                )

    def _persist_attack_paths(
        self,
        session: Any,
        application_id: str,
        assessment_id: str,
        findings: list[Finding],
    ) -> list[AttackPath]:
        application = session.get(Application, application_id)
        path_findings = [
            PathFinding(
                id=finding.id,
                finding_type=finding.finding_type,
                title=finding.title,
                asset=finding.asset,
                endpoints=finding.affected_endpoints,
                parameters=finding.parameters,
                severity=finding.severity,
                confidence=finding.confidence,
                validation_status=finding.validation_status,
                remediation=finding.remediation,
                metadata=finding.metadata_json,
                fingerprint=finding.fingerprint,
                source_plugins=finding.source_plugins,
            )
            for finding in findings
        ]
        generated = self.attack_paths.build(
            application.normalized_origin if application else application_id,
            path_findings,
        )
        previous_paths = list(
            session.scalars(
                select(AttackPath).where(
                    AttackPath.application_id == application_id,
                    AttackPath.assessment_id != assessment_id,
                ).order_by(AttackPath.last_seen.desc())
            )
        )
        previous_by_fingerprint: dict[str, AttackPath] = {}
        previous_by_title: dict[str, AttackPath] = {}
        for previous in previous_paths:
            previous_by_fingerprint.setdefault(previous.fingerprint, previous)
            previous_by_title.setdefault(previous.title, previous)
        current_fingerprints = {item.fingerprint for item in generated}
        current_titles = {item.title for item in generated}
        for previous in previous_paths:
            if previous.status == "broken" and previous.title not in current_titles:
                previous.status = "resolved"
            elif previous.fingerprint not in current_fingerprints and previous.status not in {"broken", "resolved"}:
                previous.status = "broken"
        persisted: list[AttackPath] = []
        for item in generated:
            status = "unchanged"
            if item.fingerprint not in previous_by_fingerprint:
                prior = previous_by_title.get(item.title)
                if prior is None:
                    status = "new"
                else:
                    prior_finding_count = len(
                        list(
                            session.scalars(
                                select(AttackPathFinding.finding_id).where(
                                    AttackPathFinding.attack_path_id == prior.id
                                )
                            )
                        )
                    )
                    if len(item.finding_ids) > prior_finding_count:
                        status = "expanded"
                    elif len(item.finding_ids) < prior_finding_count:
                        status = "reduced"
            path = AttackPath(
                assessment_id=assessment_id,
                application_id=application_id,
                fingerprint=item.fingerprint,
                title=item.title,
                summary=item.summary,
                confidence=item.confidence,
                classification=item.classification,
                score=item.score,
                priority=item.priority,
                status=status,
                attack_scenario=item.attack_scenario,
                attacker_gain=item.attacker_gain,
                next_step=item.next_step,
                technical_impact=item.technical_impact,
                business_impact=item.business_impact,
                blast_radius=item.blast_radius,
                evidence_boundary=item.evidence_boundary,
                recommended_break_point=item.recommended_break_point,
                critical_path_labels=item.critical_path_labels,
            )
            session.add(path)
            session.flush()
            node_ids: dict[str, str] = {}
            for node in item.nodes:
                row = AttackPathNode(
                    attack_path_id=path.id,
                    node_key=node.key,
                    node_type=node.node_type,
                    label=node.label,
                    evidence_reference=node.evidence_reference,
                    confidence=node.confidence,
                    classification=node.classification,
                    metadata_json={},
                )
                session.add(row)
                session.flush()
                node_ids[node.key] = row.id
            for edge in item.edges:
                session.add(
                    AttackPathEdge(
                        attack_path_id=path.id,
                        source_node_id=node_ids[edge.source],
                        destination_node_id=node_ids[edge.destination],
                        relationship=edge.relationship,
                        evidence_reference=edge.evidence_reference,
                        source_plugin=edge.source_plugin,
                        confidence=edge.confidence,
                        classification=edge.classification,
                        rationale=edge.rationale,
                        mitre_attack=edge.mitre_attack,
                    )
                )
            for finding_id in item.finding_ids:
                session.add(
                    AttackPathFinding(
                        attack_path_id=path.id, finding_id=finding_id, role="chain_step"
                    )
                )
                finding = session.get(Finding, finding_id)
                if finding:
                    finding.attack_path_participation = True
                    finding.priority_score = min(100.0, finding.priority_score + 8.0)
                    finding.priority_rationale = {
                        **finding.priority_rationale,
                        "attack_path_participation": 8.0,
                        "attack_path_score": item.score,
                    }
                    if finding.priority_score >= 85:
                        finding.priority_level = "critical"
                    elif finding.priority_score >= 65:
                        finding.priority_level = "high"
                    elif finding.priority_score >= 40:
                        finding.priority_level = "medium"
                    elif finding.priority_score >= 15:
                        finding.priority_level = "low"
                    else:
                        finding.priority_level = "informational"
                    priority = session.scalar(
                        select(Priority).where(Priority.finding_id == finding.id)
                    )
                    if priority:
                        priority.score = finding.priority_score
                        priority.level = finding.priority_level
                        priority.rationale = finding.priority_rationale
            for capability in item.capabilities:
                session.add(
                    AttackPathCapability(
                        attack_path_id=path.id,
                        capability=capability,
                        confidence=item.confidence,
                        rationale="Derived from the correlated finding chain",
                    )
                )
            session.add(
                AttackPathImpact(
                    attack_path_id=path.id,
                    impact_type="technical",
                    description=item.technical_impact,
                    severity=item.priority,
                    confidence="medium" if item.classification != "confirmed" else item.confidence,
                )
            )
            session.add(
                AttackPathImpact(
                    attack_path_id=path.id,
                    impact_type="business",
                    description=item.business_impact,
                    severity=item.priority,
                    confidence="low",
                )
            )
            primary_finding_id = item.finding_ids[0] if item.finding_ids else None
            for sequence, (action, capability, classification, confidence, rationale) in enumerate(
                (
                    (
                        item.next_step,
                        item.capabilities[0] if item.capabilities else "follow_on_access",
                        "inferred",
                        item.confidence,
                        "This is the next realistic attacker action derived from the bounded capability; it was not executed.",
                    ),
                    (
                        item.technical_impact,
                        "technical_impact_realization",
                        "speculative",
                        "low",
                        "Impact depends on data, privileges, controls, and business context not fully observable externally.",
                    ),
                ),
                1,
            ):
                session.add(
                    PostExploitationStep(
                        assessment_id=assessment_id,
                        attack_path_id=path.id,
                        source_finding_id=primary_finding_id,
                        sequence=sequence,
                        action=action,
                        capability=capability,
                        classification=classification,
                        confidence=confidence,
                        rationale=rationale,
                        technical_impact=item.technical_impact if sequence == 2 else None,
                        business_impact=item.business_impact if sequence == 2 else None,
                    )
                )
            persisted.append(path)
        return persisted

    @staticmethod
    def _persist_coverage(
        session: Any, assessment_id: str, rows: list[dict[str, object]]
    ) -> None:
        for row in rows:
            session.add(
                AssessmentCoverage(
                    assessment_id=assessment_id,
                    category=str(row["category"]),
                    name=str(row["name"]),
                    status=str(row["status"]),
                    automated_checks=list(row["automated_checks"]),
                    plugins=list(row["plugins"]),
                    tests_attempted=int(row["tests_attempted"]),
                    tests_completed=int(row["tests_completed"]),
                    findings_count=int(row["findings"]),
                    limitations=list(row["limitations"]),
                    manual_review_needs=list(row["manual_review_needs"]),
                )
            )

    def _persist_phases(
        self,
        session: Any,
        assessment_id: str,
        timed_results: list[Any],
        *,
        findings_count: int,
        attack_paths_count: int,
    ) -> None:
        by_phase: dict[PentestPhase, list[Any]] = {phase: [] for phase in PentestPhase}
        for item in timed_results:
            by_phase[self.registry.get(item.result.plugin).phase].append(item)
        core_phases = (
            PentestPhase.RECONNAISSANCE,
            PentestPhase.SCANNING,
            PentestPhase.ENUMERATION,
            PentestPhase.EXPLOITATION_VALIDATION,
        )
        for phase in core_phases:
            items = by_phase[phase]
            states = [item.result.state for item in items]
            if not items:
                status = "not_applicable"
            elif all(state is PluginState.NOT_APPLICABLE for state in states):
                status = "not_applicable"
            elif all(state in {PluginState.COMPLETED, PluginState.NOT_APPLICABLE} for state in states):
                status = "completed"
            elif any(state in {PluginState.COMPLETED, PluginState.PARTIAL} for state in states):
                status = "partial"
            else:
                status = "blocked"
            limitations = sorted(
                {
                    f"{item.result.plugin}: {item.result.message or item.result.failure_reason.value}"
                    for item in items
                    if item.result.failure_reason
                }
            )
            limitations.extend(
                sorted(
                    {
                        f"{item.result.plugin}: {item.result.message}"
                        for item in items
                        if item.result.state is PluginState.NOT_APPLICABLE
                        and item.result.message
                    }
                )
            )
            session.add(
                PentestPhaseProgress(
                    assessment_id=assessment_id,
                    phase=phase.value,
                    sequence=phase.order,
                    status=status,
                    started_at=min((item.started_at for item in items), default=None),
                    completed_at=max((item.completed_at for item in items), default=None),
                    plugins=[item.result.plugin for item in items],
                    tests_attempted=sum(item.result.tests_attempted for item in items),
                    tests_completed=sum(item.result.tests_completed for item in items),
                    findings_count=sum(len(item.result.findings) for item in items),
                    limitations=limitations,
                    summary=f"{len(items)} plugin(s) contributed to {phase.value.replace('_', ' ')}.",
                )
            )
        now = datetime.now(UTC)
        for phase, count, summary in (
            (
                PentestPhase.ANALYSIS,
                findings_count,
                f"Normalized and aggregated {findings_count} canonical finding(s).",
            ),
            (
                PentestPhase.ATTACK_PATH,
                attack_paths_count,
                f"Generated {attack_paths_count} evidence-bounded attack path(s).",
            ),
            (
                PentestPhase.POST_EXPLOITATION_REASONING,
                attack_paths_count,
                "Generated bounded next-action and impact reasoning without executing post-exploitation.",
            ),
        ):
            session.add(
                PentestPhaseProgress(
                    assessment_id=assessment_id,
                    phase=phase.value,
                    sequence=phase.order,
                    status="completed",
                    started_at=now,
                    completed_at=now,
                    plugins=[],
                    tests_attempted=count,
                    tests_completed=count,
                    findings_count=findings_count if phase is PentestPhase.ANALYSIS else 0,
                    limitations=(
                        ["No attack path was generated because no deterministic chain rule matched."]
                        if phase in {
                            PentestPhase.ATTACK_PATH,
                            PentestPhase.POST_EXPLOITATION_REASONING,
                        }
                        and attack_paths_count == 0
                        else []
                    ),
                    summary=summary,
                )
            )

    def _safe_config_snapshot(self) -> dict[str, Any]:
        payload = self.config.model_dump(mode="json")
        database = payload.get("database", {})
        database.pop("password", None)
        database.pop("url", None)
        return payload

    async def _optional_llm_enrichment(self, timed_results: list[Any]) -> list[dict[str, Any]]:
        if not self.config.llm.enabled:
            return []
        candidates = [candidate for item in timed_results for candidate in item.result.findings]
        if not candidates:
            return []
        if self.config.llm.provider != "ollama":
            return [
                {
                    "fingerprint": candidate.fingerprint,
                    "status": "failed",
                    "error": f"Unsupported LLM provider: {self.config.llm.provider}",
                }
                for candidate in candidates
            ]
        provider = OllamaProvider(
            self.config.llm.endpoint,
            self.config.llm.model,
            self.config.llm.timeout_seconds,
        )
        service = LLMEnrichmentService(
            provider,
            timeout=self.config.llm.timeout_seconds,
            retries=self.config.llm.retries,
        )

        async def enrich(candidate: Any) -> dict[str, Any]:
            output, error = await service.enrich(candidate)
            if output:
                candidate.metadata["llm_enrichment"] = output.model_dump(mode="json")
            return {
                "fingerprint": candidate.fingerprint,
                "status": "completed" if output else "failed",
                "output": output.model_dump(mode="json") if output else {},
                "error": error,
            }

        # Limit parallel model requests to avoid exhausting local Ollama memory.
        semaphore = asyncio.Semaphore(1)

        async def guarded(candidate: Any) -> dict[str, Any]:
            async with semaphore:
                return await enrich(candidate)

        return await asyncio.gather(*(guarded(candidate) for candidate in candidates))

    @classmethod
    def _redact(cls, value: Any) -> Any:
        sensitive_terms = ("password", "authorization", "api_key", "apikey", "token", "secret", "cookie")
        if isinstance(value, dict):
            return {
                key: "[REDACTED]" if any(term in key.lower() for term in sensitive_terms) else cls._redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._redact(item) for item in value]
        return value

    @staticmethod
    def _tool_version(path: str | None) -> str | None:
        if not path:
            return None
        for argument in ("-version", "--version", "-h"):
            try:
                # The executable is resolved with shutil.which and no shell is involved.
                completed = subprocess.run(  # noqa: S603
                    [path, argument], capture_output=True, text=True, timeout=10, check=False
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            output = (completed.stdout + completed.stderr).strip()
            if output:
                return output.splitlines()[0][:255]
        return "executable"
