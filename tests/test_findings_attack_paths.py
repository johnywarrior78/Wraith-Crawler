from __future__ import annotations

from wraith_crawler.attack_paths import AttackPathEngine, PathFinding
from wraith_crawler.domain import EvidenceRecord, FindingCandidate
from wraith_crawler.enums import Confidence, Severity, ValidationStatus
from wraith_crawler.services.findings import FindingAggregator, PrioritizationEngine


def candidate(plugin: str, endpoint: str = "https://example.com/a") -> FindingCandidate:
    return FindingCandidate(
        finding_type="missing_security_headers",
        family="misconfiguration",
        title="Headers missing",
        description="Missing controls",
        asset="https://example.com",
        affected_endpoints=[endpoint],
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        validation_status=ValidationStatus.CONFIRMED,
        evidence=[EvidenceRecord(kind="headers", summary=f"Observed by {plugin}", location=endpoint)],
        source_plugins=[plugin],
        remediation="Set headers",
    )


def test_aggregation_keeps_endpoints_and_provenance() -> None:
    left = candidate("headers", "https://example.com/a")
    right = candidate("nuclei", "https://example.com/a")
    aggregated = FindingAggregator().aggregate([left, right])
    assert len(aggregated) == 1
    assert aggregated[0].source_plugins == ["headers", "nuclei"]
    assert len(aggregated[0].evidence) == 2
    assert aggregated[0].confidence == Confidence.HIGH


def test_aggregation_does_not_merge_different_endpoints() -> None:
    assert len(FindingAggregator().aggregate([candidate("a", "https://example.com/a"), candidate("b", "https://example.com/b")])) == 2


def test_priority_confirmed_kev_attack_path() -> None:
    item = candidate("headers")
    item.severity = Severity.HIGH
    item.kev = True
    item.epss = 0.9
    item.cvss = 9.8
    decision = PrioritizationEngine().score(item, sensitive_context=True, attack_path_participation=True, blast_radius=8)
    assert decision.score >= 85
    assert decision.level == Severity.CRITICAL
    assert decision.rationale["cisa_kev"] == 12


def test_priority_manual_review_penalty() -> None:
    item = candidate("headers")
    item.validation_status = ValidationStatus.MANUAL_REVIEW
    decision = PrioritizationEngine().score(item)
    assert decision.rationale["unconfirmed"] == -8


def path_finding(identifier: str, finding_type: str, validation: str = "confirmed") -> PathFinding:
    return PathFinding(
        id=identifier,
        finding_type=finding_type,
        title=finding_type,
        asset="https://example.com",
        endpoints=["https://example.com/api"],
        severity="high",
        confidence="confirmed" if validation == "confirmed" else "medium",
        validation_status=validation,
        remediation=f"Fix {finding_type}",
        metadata={"sensitive_context": True},
    )


def test_attack_path_chain_rule() -> None:
    findings = [
        path_finding("1", "source_map_exposure"),
        path_finding("2", "secret_exposure"),
        path_finding("3", "reachable_api"),
    ]
    paths = AttackPathEngine().build("https://example.com", findings)
    assert len(paths) == 1
    assert paths[0].classification == "confirmed"
    assert paths[0].finding_ids == ["1", "2", "3"]
    assert any(edge.classification == "speculative" for edge in paths[0].edges)
    assert "modeled" in paths[0].evidence_boundary.lower()


def test_attack_path_never_marks_inference_confirmed() -> None:
    paths = AttackPathEngine().build("https://example.com", [path_finding("1", "sql_injection", "suspected")])
    assert paths[0].classification == "inferred"
    assert paths[0].confidence == "medium"


def test_attack_path_breakpoint_uses_remediation() -> None:
    path = AttackPathEngine().build("https://example.com", [path_finding("1", "sql_injection")])[0]
    assert path.recommended_break_point == "Fix sql_injection"
    assert path.mitre_attack == ["T1190", "T1213.006"]
    assert any("T1190" in edge.mitre_attack for edge in path.edges)
