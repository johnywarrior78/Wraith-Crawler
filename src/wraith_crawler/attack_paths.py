from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PathFinding:
    id: str
    finding_type: str
    title: str
    asset: str
    endpoints: list[str]
    severity: str
    confidence: str
    validation_status: str
    remediation: str
    metadata: dict[str, Any] = field(default_factory=dict)
    fingerprint: str | None = None


@dataclass(slots=True)
class PathNode:
    key: str
    node_type: str
    label: str
    confidence: str
    classification: str
    evidence_reference: str | None = None


@dataclass(slots=True)
class PathEdge:
    source: str
    destination: str
    relationship: str
    confidence: str
    classification: str
    rationale: str
    evidence_reference: str | None = None
    source_plugin: str | None = None
    mitre_attack: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AttackPathResult:
    fingerprint: str
    title: str
    summary: str
    confidence: str
    classification: str
    score: float
    priority: str
    nodes: list[PathNode]
    edges: list[PathEdge]
    finding_ids: list[str]
    capabilities: list[str]
    attack_scenario: str
    attacker_gain: str
    next_step: str
    technical_impact: str
    business_impact: str
    blast_radius: str
    evidence_boundary: str
    recommended_break_point: str
    critical_path_labels: list[str] = field(default_factory=list)


CHAIN_RULES: tuple[tuple[frozenset[str], dict[str, str]], ...] = (
    (
        frozenset({"source_map_exposure", "secret_exposure", "reachable_api"}),
        {
            "title": "Client source disclosure to unauthorized API capability",
            "gain": "A credential or token usable against a reachable API",
            "next": "Attempt only authorized API operations associated with the exposed credential",
            "technical": "Unauthorized API actions or sensitive data access",
            "business": "Data disclosure, account abuse, or third-party service cost",
        },
    ),
    (
        frozenset({"directory_listing", "sensitive_file_exposure", "secret_exposure"}),
        {
            "title": "Browsable artifacts expose backend credentials",
            "gain": "Knowledge of deployment artifacts and a backend credential",
            "next": "Model access to the corresponding authorized backend service",
            "technical": "Backend service access and possible application compromise",
            "business": "Sensitive data exposure and operational disruption",
        },
    ),
    (
        frozenset({"openapi_exposure", "anonymous_sensitive_api", "idor_bola"}),
        {
            "title": "API documentation enables unauthorized object access",
            "gain": "A map of sensitive API objects and an access-control bypass candidate",
            "next": "Validate cross-object access with approved test identities",
            "technical": "Unauthorized object or record access",
            "business": "Customer data disclosure or fraudulent changes",
        },
    ),
    (
        frozenset({"cross_site_scripting", "insecure_cookie"}),
        {
            "title": "Client-side injection increases account abuse potential",
            "gain": "Script execution in the victim origin with access permitted by cookie controls",
            "next": "Model authorized user actions reachable from the injected context",
            "technical": "Account actions or session misuse within browser control boundaries",
            "business": "Account compromise, fraud, or unauthorized data access",
        },
    ),
)

SINGLE_RULES: dict[str, dict[str, str]] = {
    "sql_injection": {
        "gain": "Database query manipulation",
        "next": "Model exposure of application data and credential material without dumping data",
        "technical": "Data confidentiality and integrity loss; possible application compromise",
        "business": "Sensitive data breach, fraud, and service disruption",
    },
    "secret_exposure": {
        "gain": "Possession of a disclosed credential or token",
        "next": "Identify the in-scope service and permissions associated with the secret",
        "technical": "Unauthorized service capability, bounded by the secret's privileges",
        "business": "Data exposure, fraudulent activity, or unexpected third-party charges",
    },
    "cross_site_scripting": {
        "gain": "Script execution in a user's browser within the affected origin",
        "next": "Model user actions and data reachable from that browser context",
        "technical": "User-context data access and actions; HttpOnly cookies remain unreadable",
        "business": "Account abuse, phishing, and loss of user trust",
    },
}


class AttackPathEngine:
    """Builds evidence-bounded path graphs without performing post-exploitation."""

    def build(self, application: str, findings: list[PathFinding]) -> list[AttackPathResult]:
        by_type: dict[str, list[PathFinding]] = defaultdict(list)
        for finding in findings:
            by_type[finding.finding_type].append(finding)
        paths: list[AttackPathResult] = []
        consumed: set[str] = set()
        present = set(by_type)
        for required, narrative in CHAIN_RULES:
            if not required.issubset(present):
                continue
            selected = [by_type[k][0] for k in sorted(required)]
            consumed.update(f.id for f in selected)
            paths.append(self._make_path(application, selected, narrative["title"], narrative))
        for finding in findings:
            narrative = SINGLE_RULES.get(finding.finding_type)
            if narrative and finding.id not in consumed:
                paths.append(self._make_path(application, [finding], finding.title, narrative))
        paths = sorted(paths, key=lambda path: path.score, reverse=True)
        if paths:
            paths[0].critical_path_labels.extend(["highest_impact", "most_likely"])
            shortest = min(paths, key=lambda path: (len(path.finding_ids), -path.score))
            shortest.critical_path_labels.append("shortest_to_sensitive_impact")
            for path in paths:
                path.critical_path_labels.append(
                    "confirmed_path" if path.classification == "confirmed" else "potential_path"
                )
                path.critical_path_labels = sorted(set(path.critical_path_labels))
        return paths

    def _make_path(
        self,
        application: str,
        findings: list[PathFinding],
        title: str,
        narrative: dict[str, str],
    ) -> AttackPathResult:
        confirmed = all(f.validation_status == "confirmed" for f in findings)
        confidence = self._confidence(findings)
        classification = "confirmed" if confirmed else "inferred"
        finding_keys = sorted(f.id for f in findings)
        stable_finding_keys = sorted(f.fingerprint or f.finding_type for f in findings)
        fingerprint = hashlib.sha256(
            json.dumps(
                {"application": application, "findings": stable_finding_keys}, sort_keys=True
            ).encode()
        ).hexdigest()
        nodes = [
            PathNode("attacker", "attacker", "Unauthenticated external attacker", "confirmed", "confirmed"),
            PathNode("application", "domain_application", application, "confirmed", "confirmed"),
        ]
        edges = [
            PathEdge(
                "attacker",
                "application",
                "can reach",
                "confirmed",
                "confirmed",
                "The operator supplied this public target and HTTP reachability was observed.",
            )
        ]
        previous = "application"
        for index, finding in enumerate(findings):
            key = f"finding:{finding.id}"
            nodes.append(
                PathNode(
                    key,
                    "vulnerability",
                    finding.title,
                    finding.confidence,
                    "confirmed" if finding.validation_status == "confirmed" else "inferred",
                    finding.id,
                )
            )
            edges.append(
                PathEdge(
                    previous,
                    key,
                    "enables exploitation of" if index == 0 else "can be chained with",
                    finding.confidence,
                    "confirmed" if finding.validation_status == "confirmed" else "inferred",
                    f"Finding {finding.id} supplies the recorded evidence for this step.",
                    finding.id,
                )
            )
            previous = key
        capability_key = "capability:gain"
        impact_key = "impact:technical"
        nodes.extend(
            [
                PathNode(capability_key, "attacker_capability", narrative["gain"], confidence, "inferred"),
                PathNode(impact_key, "sensitive_data", narrative["technical"], confidence, "speculative"),
            ]
        )
        edges.extend(
            [
                PathEdge(
                    previous,
                    capability_key,
                    "could provide",
                    confidence,
                    "inferred",
                    "Capability is a bounded inference from the validated weakness; it was not exercised.",
                ),
                PathEdge(
                    capability_key,
                    impact_key,
                    "could progress to",
                    "medium",
                    "speculative",
                    "Impact depends on privileges, data, and controls not fully observable externally.",
                ),
            ]
        )
        score = self._score(findings, confirmed, len(findings))
        break_finding = max(findings, key=lambda finding: self._severity_value(finding.severity))
        boundary = (
            "Confirmed evidence covers all vulnerability steps; capability and impact remain modeled."
            if confirmed
            else "Evidence confirms target exposure, while one or more vulnerability and impact steps require review."
        )
        return AttackPathResult(
            fingerprint=fingerprint,
            title=title,
            summary=f"External reachability through {len(findings)} correlated weakness(es) could lead to {narrative['technical']}",
            confidence=confidence,
            classification=classification,
            score=score,
            priority=self._priority(score),
            nodes=nodes,
            edges=edges,
            finding_ids=finding_keys,
            capabilities=[narrative["gain"]],
            attack_scenario=" -> ".join(["External attacker", application, *[f.title for f in findings]]),
            attacker_gain=narrative["gain"],
            next_step=narrative["next"],
            technical_impact=narrative["technical"],
            business_impact=narrative["business"],
            blast_radius="Bounded to the affected application and any service privileges evidenced by the findings.",
            evidence_boundary=boundary,
            recommended_break_point=break_finding.remediation,
        )

    @staticmethod
    def _confidence(findings: list[PathFinding]) -> str:
        rank = {"confirmed": 4, "high": 3, "medium": 2, "low": 1, "speculative": 0}
        minimum = min((rank.get(f.confidence, 1) for f in findings), default=1)
        return {4: "confirmed", 3: "high", 2: "medium", 1: "low", 0: "speculative"}[minimum]

    @staticmethod
    def _severity_value(severity: str) -> float:
        return {"critical": 10, "high": 8, "medium": 5, "low": 2, "informational": 0}.get(
            severity, 0
        )

    def _score(self, findings: list[PathFinding], confirmed: bool, chain_length: int) -> float:
        severity = max((self._severity_value(f.severity) for f in findings), default=0) * 6
        exposure = 10
        validation = 15 if confirmed else 6
        chain = min(chain_length * 5, 15)
        sensitive = 8 if any(f.metadata.get("sensitive_context") for f in findings) else 0
        prerequisites = max(0, 5 - (chain_length - 1) * 2)
        return round(min(100.0, severity + exposure + validation + chain + sensitive + prerequisites), 1)

    @staticmethod
    def _priority(score: float) -> str:
        if score >= 85:
            return "critical"
        if score >= 65:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 15:
            return "low"
        return "informational"
