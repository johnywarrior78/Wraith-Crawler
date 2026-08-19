from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..domain import EvidenceRecord, FindingCandidate
from ..enums import Confidence, FindingStatus, Severity, ValidationStatus
from ..persistence.models import (
    Finding,
    FindingCandidateDB,
    FindingHistory,
    ManualReviewItem,
    Priority,
)

CONFIDENCE_ORDER = {
    Confidence.SPECULATIVE: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
    Confidence.CONFIRMED: 4,
}
VALIDATION_ORDER = {
    ValidationStatus.CANDIDATE: 0,
    ValidationStatus.MANUAL_REVIEW: 1,
    ValidationStatus.SUSPECTED: 2,
    ValidationStatus.CONFIRMED: 3,
    ValidationStatus.FALSE_POSITIVE: -1,
}
SEVERITY_BASE = {
    Severity.CRITICAL: 65.0,
    Severity.HIGH: 50.0,
    Severity.MEDIUM: 32.0,
    Severity.LOW: 15.0,
    Severity.INFORMATIONAL: 2.0,
}


class FindingAggregator:
    """Aggregate by stable identity while retaining evidence and provenance."""

    def aggregate(self, candidates: list[FindingCandidate]) -> list[FindingCandidate]:
        groups: dict[str, list[FindingCandidate]] = defaultdict(list)
        for candidate in candidates:
            if candidate.validation_status is not ValidationStatus.FALSE_POSITIVE:
                groups[candidate.fingerprint].append(candidate)
        return [self._merge(group) for group in groups.values()]

    def _merge(self, group: list[FindingCandidate]) -> FindingCandidate:
        strongest = max(
            group,
            key=lambda item: (
                VALIDATION_ORDER[item.validation_status],
                CONFIDENCE_ORDER[item.confidence],
            ),
        )
        evidence: dict[str, EvidenceRecord] = {}
        for item in group:
            for record in item.evidence:
                key = record.fingerprint or f"{record.kind}:{record.location}:{record.summary}"
                evidence[key] = record
        merged = strongest.model_copy(deep=True)
        merged.affected_endpoints = sorted({x for item in group for x in item.affected_endpoints})
        merged.parameters = sorted({x for item in group for x in item.parameters})
        merged.source_plugins = sorted({x for item in group for x in item.source_plugins})
        merged.evidence = list(evidence.values())
        merged.cwe = sorted({x for item in group for x in item.cwe})
        merged.cve = sorted({x for item in group for x in item.cve})
        merged.owasp = sorted({x for item in group for x in item.owasp})
        merged.capec = sorted({x for item in group for x in item.capec})
        merged.mitre_attack = sorted({x for item in group for x in item.mitre_attack})
        merged.references = sorted({x for item in group for x in item.references})
        merged.kev = any(item.kev for item in group)
        epss_values = [item.epss for item in group if item.epss is not None]
        merged.epss = max(epss_values, default=None)
        cvss_values = [item.cvss for item in group if item.cvss is not None]
        merged.cvss = max(cvss_values, default=None)
        merged.manual_review = all(item.manual_review for item in group)
        merged.metadata["corroborating_plugins"] = merged.source_plugins
        merged.metadata["observation_count"] = len(group)
        if len(merged.source_plugins) > 1 and CONFIDENCE_ORDER[merged.confidence] < 3:
            merged.confidence = Confidence.HIGH
        return merged


@dataclass(frozen=True, slots=True)
class PriorityDecision:
    score: float
    level: Severity
    rationale: dict[str, Any]


class PrioritizationEngine:
    VERSION = "1.0"

    def score(
        self,
        finding: FindingCandidate,
        *,
        external_exposure: bool = True,
        authentication_required: bool = False,
        sensitive_context: bool = False,
        attack_path_participation: bool = False,
        blast_radius: float = 0.0,
        business_criticality: float = 0.0,
    ) -> PriorityDecision:
        score = SEVERITY_BASE[finding.severity]
        factors: dict[str, float | bool | str] = {"base_severity": score}
        if finding.cvss is not None:
            adjustment = max(0.0, min(10.0, finding.cvss)) * 1.2
            score += adjustment
            factors["cvss"] = adjustment
        if finding.epss is not None:
            adjustment = max(0.0, min(1.0, finding.epss)) * 10.0
            score += adjustment
            factors["epss"] = adjustment
        if finding.kev:
            score += 12.0
            factors["cisa_kev"] = 12.0
        if finding.validation_status is ValidationStatus.CONFIRMED:
            score += 10.0
            factors["confirmed"] = 10.0
        elif finding.validation_status in {ValidationStatus.CANDIDATE, ValidationStatus.MANUAL_REVIEW}:
            score -= 8.0
            factors["unconfirmed"] = -8.0
        if external_exposure:
            score += 5.0
            factors["external_exposure"] = 5.0
        if authentication_required:
            score -= 4.0
            factors["authentication_required"] = -4.0
        if sensitive_context:
            score += 8.0
            factors["sensitive_context"] = 8.0
        if finding.family in {"secrets", "credential_exposure"}:
            score += 12.0
            factors["secret_exposure"] = 12.0
        if finding.metadata.get("eol"):
            score += 5.0
            factors["eol_component"] = 5.0
        if attack_path_participation:
            score += 8.0
            factors["attack_path_participation"] = 8.0
        blast = max(0.0, min(10.0, blast_radius))
        business = max(0.0, min(10.0, business_criticality))
        score += blast + business
        if blast:
            factors["blast_radius"] = blast
        if business:
            factors["business_criticality"] = business
        score = round(max(0.0, min(100.0, score)), 1)
        level = self._level(score)
        return PriorityDecision(score, level, factors)

    @staticmethod
    def _level(score: float) -> Severity:
        if score >= 85:
            return Severity.CRITICAL
        if score >= 65:
            return Severity.HIGH
        if score >= 40:
            return Severity.MEDIUM
        if score >= 15:
            return Severity.LOW
        return Severity.INFORMATIONAL


class FindingPersistenceService:
    def __init__(self) -> None:
        self.aggregator = FindingAggregator()
        self.prioritizer = PrioritizationEngine()

    def persist(
        self,
        session: Session,
        *,
        assessment_id: str,
        application_id: str,
        candidates: list[FindingCandidate],
    ) -> list[Finding]:
        now = datetime.now(UTC)
        final_findings: list[Finding] = []
        for candidate in self.aggregator.aggregate(candidates):
            decision = self.prioritizer.score(
                candidate,
                sensitive_context=bool(candidate.metadata.get("sensitive_context")),
                business_criticality=float(candidate.metadata.get("business_criticality", 0)),
            )
            session.add(
                FindingCandidateDB(
                    assessment_id=assessment_id,
                    fingerprint=candidate.fingerprint,
                    finding_type=candidate.finding_type,
                    asset=candidate.asset,
                    payload=candidate.model_dump(mode="json"),
                    policy_decision="manual_review" if candidate.manual_review else "accepted",
                )
            )
            finding = Finding(
                assessment_id=assessment_id,
                application_id=application_id,
                fingerprint=candidate.fingerprint,
                finding_type=candidate.finding_type,
                family=candidate.family,
                title=candidate.title,
                description=candidate.description,
                asset=candidate.asset,
                affected_endpoints=candidate.affected_endpoints,
                method=candidate.method,
                parameters=candidate.parameters,
                severity=candidate.severity.value,
                confidence=candidate.confidence.value,
                validation_status=candidate.validation_status.value,
                source_plugins=candidate.source_plugins,
                cwe=candidate.cwe,
                cve=candidate.cve,
                owasp=candidate.owasp,
                capec=candidate.capec,
                mitre_attack=candidate.mitre_attack,
                cvss=candidate.cvss,
                epss=candidate.epss,
                kev=candidate.kev,
                remediation=candidate.remediation,
                references=candidate.references,
                manual_review=candidate.manual_review,
                priority_score=decision.score,
                priority_level=decision.level.value,
                priority_rationale=decision.rationale,
                attacker_narrative=candidate.attacker_narrative.model_dump(mode="json"),
                metadata_json=candidate.metadata,
                status=FindingStatus.NEW.value,
                first_seen=now,
                last_seen=now,
            )
            session.add(finding)
            session.flush()
            session.add(
                Priority(
                    finding_id=finding.id,
                    score=decision.score,
                    level=decision.level.value,
                    rationale=decision.rationale,
                    engine_version=self.prioritizer.VERSION,
                )
            )
            session.add(
                FindingHistory(
                    finding_id=finding.id,
                    application_id=application_id,
                    assessment_id=assessment_id,
                    status=FindingStatus.NEW.value,
                    rationale="First observed in this assessment",
                )
            )
            if candidate.manual_review:
                session.add(
                    ManualReviewItem(
                        assessment_id=assessment_id,
                        application_id=application_id,
                        finding_id=finding.id,
                        endpoint=candidate.affected_endpoints[0]
                        if candidate.affected_endpoints
                        else candidate.asset,
                        parameter=candidate.parameters[0] if candidate.parameters else None,
                        candidate_type=candidate.finding_type,
                        reason=candidate.metadata.get(
                            "review_reason", "Automatic confirmation was not safely possible"
                        ),
                        evidence_summary="; ".join(e.summary for e in candidate.evidence[:3])
                        or "Candidate evidence is recorded with the finding",
                        source_plugin=",".join(candidate.source_plugins),
                        confidence=candidate.confidence.value,
                        priority=decision.level.value,
                        suggested_steps=candidate.metadata.get(
                            "suggested_steps",
                            ["Review the recorded request and response", "Validate only within scope"],
                        ),
                        attack_path_relevance=candidate.metadata.get("attack_path_relevance"),
                    )
                )
            final_findings.append(finding)
        session.flush()
        return final_findings

    def correlate_history(
        self,
        session: Session,
        application_id: str,
        assessment_id: str,
        *,
        completed_plugins: set[str] | None = None,
    ) -> dict[str, int]:
        current = list(
            session.scalars(
                select(Finding).where(
                    Finding.application_id == application_id, Finding.assessment_id == assessment_id
                )
            )
        )
        previous_assessment_id = session.scalar(
            select(Finding.assessment_id)
            .where(
                Finding.application_id == application_id,
                Finding.assessment_id != assessment_id,
            )
            .order_by(Finding.last_seen.desc())
            .limit(1)
        )
        if not previous_assessment_id:
            return {"new": len(current), "open": 0, "reopened": 0, "resolved": 0}
        previous = list(
            session.scalars(select(Finding).where(Finding.assessment_id == previous_assessment_id))
        )
        current_by_fp = {finding.fingerprint: finding for finding in current}
        previous_by_fp = {finding.fingerprint: finding for finding in previous}
        counts = {"new": 0, "open": 0, "reopened": 0, "resolved": 0}
        for fp, finding in current_by_fp.items():
            old = previous_by_fp.get(fp)
            if not old:
                counts["new"] += 1
                continue
            if old.status == FindingStatus.RESOLVED.value:
                finding.status = FindingStatus.REOPENED.value
                counts["reopened"] += 1
            else:
                finding.status = FindingStatus.OPEN.value
                finding.first_seen = old.first_seen
                counts["open"] += 1
            session.add(
                FindingHistory(
                    finding_id=finding.id,
                    application_id=application_id,
                    assessment_id=assessment_id,
                    previous_status=old.status,
                    status=finding.status,
                    rationale="Deterministic fingerprint matched the previous assessment",
                )
            )
        for fp, old in previous_by_fp.items():
            if fp not in current_by_fp and old.status != FindingStatus.RESOLVED.value:
                if completed_plugins is not None and not set(old.source_plugins).issubset(
                    completed_plugins
                ):
                    continue
                old.status = FindingStatus.RESOLVED.value
                session.add(
                    FindingHistory(
                        finding_id=old.id,
                        application_id=application_id,
                        assessment_id=assessment_id,
                        previous_status=FindingStatus.OPEN.value,
                        status=FindingStatus.RESOLVED.value,
                        rationale="Not observed in the current completed assessment",
                    )
                )
                counts["resolved"] += 1
        return counts
