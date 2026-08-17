from __future__ import annotations

from dataclasses import dataclass

from ..domain import FindingCandidate


@dataclass(frozen=True, slots=True)
class KnowledgeMapping:
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    capec: tuple[str, ...]
    remediation: str


MAPPINGS: dict[str, KnowledgeMapping] = {
    "missing_security_headers": KnowledgeMapping(
        ("CWE-693",),
        ("A05:2021",),
        ("CAPEC-126",),
        "Deploy the missing response headers at the application or reverse-proxy layer and test all routes.",
    ),
    "insecure_cors": KnowledgeMapping(
        ("CWE-942",),
        ("A05:2021",),
        ("CAPEC-180",),
        "Use a strict allowlist, never reflect arbitrary origins, and do not combine wildcard access with credentials.",
    ),
    "secret_exposure": KnowledgeMapping(
        ("CWE-798", "CWE-200"),
        ("A02:2021",),
        ("CAPEC-545",),
        "Revoke the exposed credential, remove it from client-accessible content and history, and use a secret manager.",
    ),
    "sql_injection": KnowledgeMapping(
        ("CWE-89",),
        ("A03:2021",),
        ("CAPEC-66",),
        "Use parameterized queries, least-privileged database roles, and server-side input validation.",
    ),
    "cross_site_scripting": KnowledgeMapping(
        ("CWE-79",),
        ("A03:2021",),
        ("CAPEC-63",),
        "Apply context-aware output encoding and sanitization, and enforce a restrictive Content Security Policy.",
    ),
}


class KnowledgeService:
    VERSION = "2026.1"

    def enrich(self, candidate: FindingCandidate) -> FindingCandidate:
        mapping = MAPPINGS.get(candidate.finding_type)
        if not mapping:
            candidate.metadata.setdefault("knowledge_version", self.VERSION)
            candidate.metadata.setdefault("knowledge_provenance", "wraith_builtin")
            return candidate
        candidate.cwe = sorted(set(candidate.cwe).union(mapping.cwe))
        candidate.owasp = sorted(set(candidate.owasp).union(mapping.owasp))
        candidate.capec = sorted(set(candidate.capec).union(mapping.capec))
        if not candidate.remediation:
            candidate.remediation = mapping.remediation
        candidate.metadata["knowledge_version"] = self.VERSION
        candidate.metadata["knowledge_provenance"] = "wraith_builtin"
        return candidate
