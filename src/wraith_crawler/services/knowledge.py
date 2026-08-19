from __future__ import annotations

import re
from dataclasses import dataclass

from ..domain import AttackerNarrative, FindingCandidate, TechnologyRecord


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


ATTACKER_OUTCOMES: dict[str, tuple[str, str, str, tuple[str, ...]]] = {
    "sql_injection": (
        "sql_query_manipulation",
        "Database confidentiality or integrity loss and possible application compromise.",
        "Data breach, fraud, regulatory exposure, and service disruption.",
        ("database_read", "secret_acquisition", "account_access"),
    ),
    "cross_site_scripting": (
        "arbitrary_javascript_execution",
        "Execution of attacker-controlled JavaScript in the affected browser origin.",
        "Unauthorized user actions, phishing, and loss of customer trust.",
        ("session_abuse", "account_access"),
    ),
    "secret_exposure": (
        "secret_acquisition",
        "Potential use of the disclosed credential within its actual privilege boundary.",
        "Data exposure, service abuse, fraudulent activity, or third-party cost.",
        ("api_access", "cloud_access", "account_access"),
    ),
    "source_map_exposure": (
        "sensitive_information_disclosure",
        "Original source, hidden endpoints, and build metadata may become visible.",
        "Reduced attacker effort and possible disclosure of proprietary logic or credentials.",
        ("endpoint_discovery", "secret_acquisition", "api_access"),
    ),
    "directory_listing": (
        "file_discovery",
        "Browsable files can reveal backups, configuration, source, or deployment artifacts.",
        "Sensitive-data exposure and an increased chance of backend compromise.",
        ("file_disclosure", "secret_acquisition", "backend_access"),
    ),
    "sensitive_file_exposure": (
        "file_disclosure",
        "Direct retrieval of the exposed artifact and any security-relevant contents.",
        "Credential exposure, data breach, or application compromise.",
        ("secret_acquisition", "database_access", "cloud_access"),
    ),
    "idor_bola": (
        "authorization_bypass",
        "If confirmed with approved identities, object references may permit unauthorized record access.",
        "Cross-customer data exposure or unauthorized changes at enumeration scale.",
        ("identifier_enumeration", "mass_record_exposure"),
    ),
    "ssrf": (
        "internal_service_interaction",
        "If safely confirmed, the server may make attacker-influenced outbound requests.",
        "Access to otherwise unreachable services or data, bounded by egress controls.",
        ("internal_service_discovery", "cloud_access"),
    ),
    "open_redirect": (
        "trusted_origin_redirect",
        "The trusted application URL can redirect a victim to an attacker-selected destination.",
        "Phishing effectiveness, token leakage in some flows, and brand abuse.",
        ("phishing", "authentication_flow_abuse"),
    ),
    "insecure_cookie": (
        "session_abuse",
        "The observed cookie controls may make session material easier to expose or misuse.",
        "Account compromise risk where the cookie carries authenticated state.",
        ("cross_site_scripting", "transport_interception"),
    ),
    "debug_interface_exposure": (
        "debug_surface_access",
        "A public diagnostic console may disclose internals or expose debug-only operations.",
        "Application compromise or sensitive-data exposure if dangerous debug functions are reachable.",
        ("endpoint_discovery", "secret_acquisition", "application_access"),
    ),
    "management_metrics_exposure": (
        "operational_information_disclosure",
        "Runtime, process, and dependency details may be available without authentication.",
        "Reduced attacker effort and disclosure of infrastructure or service behavior.",
        ("service_discovery", "targeted_component_analysis"),
    ),
    "detailed_health_exposure": (
        "service_topology_disclosure",
        "Detailed health data can reveal backend services, dependencies, and failure state.",
        "Reduced attacker effort and possible disclosure of sensitive infrastructure relationships.",
        ("service_discovery", "targeted_component_analysis"),
    ),
}


LIFECYCLE_RULES: dict[str, tuple[re.Pattern[str], str, str, str]] = {
    "jquery": (
        re.compile(r"^(?:0|1|2)\."),
        "eol",
        "https://jquery.com/support/",
        "jQuery 0.x, 1.x, and 2.x are outside the actively supported release line.",
    ),
    "jquery migrate": (
        re.compile(r"^(?:0|1)\."),
        "eol",
        "https://github.com/jquery/jquery-migrate",
        "The detected jQuery Migrate release is from an obsolete major line.",
    ),
    "angularjs": (
        re.compile(r"^1\."),
        "eol",
        "https://docs.angularjs.org/misc/version-support-status",
        "Official long-term support for AngularJS ended on 2021-12-31.",
    ),
    "moment.js": (
        re.compile(r"^\d+\."),
        "maintenance",
        "https://momentjs.com/docs/#/-project-status/",
        "Moment.js is a legacy project in maintenance mode.",
    ),
    "php": (
        re.compile(r"^(?:[0-7]\.|8\.[01](?:\.|$))"),
        "eol",
        "https://www.php.net/supported-versions.php",
        "The advertised PHP branch is outside current security support.",
    ),
    "node.js": (
        re.compile(r"^(?:0|[1-9]|1\d|20)(?:\.|$)"),
        "eol",
        "https://github.com/nodejs/Release",
        "The advertised Node.js major is outside its maintenance window.",
    ),
}


class KnowledgeService:
    VERSION = "2026.1"

    def enrich(self, candidate: FindingCandidate) -> FindingCandidate:
        mapping = MAPPINGS.get(candidate.finding_type)
        if mapping:
            candidate.cwe = sorted(set(candidate.cwe).union(mapping.cwe))
            candidate.owasp = sorted(set(candidate.owasp).union(mapping.owasp))
            candidate.capec = sorted(set(candidate.capec).union(mapping.capec))
            if not candidate.remediation:
                candidate.remediation = mapping.remediation
        candidate.metadata["knowledge_version"] = self.VERSION
        candidate.metadata["knowledge_provenance"] = "wraith_builtin"
        self._attacker_narrative(candidate)
        return candidate

    def enrich_technology(self, technology: TechnologyRecord) -> TechnologyRecord:
        """Apply only lifecycle rules supported by an observed version."""
        if not technology.version:
            return technology
        normalized = technology.product.strip().lower()
        rule = LIFECYCLE_RULES.get(normalized)
        if not rule:
            return technology
        pattern, state, source, evidence = rule
        if not pattern.search(technology.version.strip().lstrip("v")):
            return technology
        technology.eol_state = technology.eol_state or state
        technology.supported = False if state == "eol" else None
        technology.lifecycle_source = technology.lifecycle_source or source
        technology.lifecycle_evidence = sorted(
            set([*technology.lifecycle_evidence, evidence, f"Observed version: {technology.version}"])
        )
        return technology

    @staticmethod
    def _attacker_narrative(candidate: FindingCandidate) -> None:
        if candidate.attacker_narrative.what_was_found:
            return
        outcome = ATTACKER_OUTCOMES.get(candidate.finding_type)
        if outcome is None and candidate.finding_type.startswith("nuclei:"):
            outcome = (
                "validated_security_weakness",
                "The matched condition may provide the capability described by the validated template.",
                "Impact depends on the affected component, exposure, and reachable data or functions.",
                ("manual_chain_review",),
            )
        capability, technical, business, chains = outcome or (
            "security_control_bypass",
            "The weakness may reduce a security control at the affected endpoint.",
            "Business impact depends on reachable functions, identities, and sensitive data.",
            ("manual_chain_review",),
        )
        confirmed = candidate.validation_status.value == "confirmed"
        location = ", ".join(candidate.affected_endpoints) or candidate.asset
        evidence = "; ".join(item.summary for item in candidate.evidence[:3])
        candidate.attacker_narrative = AttackerNarrative(
            what_was_found=candidate.description,
            where=location,
            validation=evidence or "No independent validation evidence was supplied.",
            exploitation=(
                f"An attacker could use the observed condition to pursue {capability.replace('_', ' ')}."
                if confirmed
                else f"An analyst should safely validate whether this candidate permits {capability.replace('_', ' ')}."
            ),
            capability_gained=capability,
            next_realistic_step=(
                f"Evaluate the in-scope permissions and resources reachable through {capability.replace('_', ' ')}."
            ),
            chain_opportunities=list(chains),
            confirmed=["The recorded externally observable condition and its evidence"] if confirmed else [],
            inferred=(
                ["Exploitability and downstream attacker capability require additional validation"]
                if not confirmed
                else ["Downstream capability and impact were not exercised"]
            ),
            technical_impact=technical,
            business_impact=business,
            remediation_break_point=candidate.remediation,
        )
        candidate.metadata.setdefault("attacker_capability", capability)
