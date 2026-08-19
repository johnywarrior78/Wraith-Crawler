from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

ATTACK_CATALOG_VERSION = "enterprise-v19.1"


@dataclass(frozen=True, slots=True)
class AttackTechnique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    url: str


@dataclass(frozen=True, slots=True)
class FindingTechniqueRule:
    technique_id: str
    relationship: str
    rationale: str


ATTACK_TECHNIQUES: dict[str, AttackTechnique] = {
    "T1005": AttackTechnique(
        "T1005",
        "Data from Local System",
        ("collection",),
        "https://attack.mitre.org/techniques/T1005/",
    ),
    "T1046": AttackTechnique(
        "T1046",
        "Network Service Discovery",
        ("discovery",),
        "https://attack.mitre.org/techniques/T1046/",
    ),
    "T1078": AttackTechnique(
        "T1078",
        "Valid Accounts",
        ("initial-access", "persistence", "privilege-escalation", "stealth"),
        "https://attack.mitre.org/techniques/T1078/",
    ),
    "T1133": AttackTechnique(
        "T1133",
        "External Remote Services",
        ("initial-access", "persistence"),
        "https://attack.mitre.org/techniques/T1133/",
    ),
    "T1189": AttackTechnique(
        "T1189",
        "Drive-by Compromise",
        ("initial-access",),
        "https://attack.mitre.org/techniques/T1189/",
    ),
    "T1190": AttackTechnique(
        "T1190",
        "Exploit Public-Facing Application",
        ("initial-access",),
        "https://attack.mitre.org/techniques/T1190/",
    ),
    "T1204.001": AttackTechnique(
        "T1204.001",
        "User Execution: Malicious Link",
        ("execution",),
        "https://attack.mitre.org/techniques/T1204/001/",
    ),
    "T1213.006": AttackTechnique(
        "T1213.006",
        "Data from Information Repositories: Databases",
        ("collection",),
        "https://attack.mitre.org/techniques/T1213/006/",
    ),
    "T1528": AttackTechnique(
        "T1528",
        "Steal Application Access Token",
        ("credential-access",),
        "https://attack.mitre.org/techniques/T1528/",
    ),
    "T1539": AttackTechnique(
        "T1539",
        "Steal Web Session Cookie",
        ("credential-access",),
        "https://attack.mitre.org/techniques/T1539/",
    ),
    "T1550.004": AttackTechnique(
        "T1550.004",
        "Use Alternate Authentication Material: Web Session Cookie",
        ("lateral-movement",),
        "https://attack.mitre.org/techniques/T1550/004/",
    ),
    "T1552.001": AttackTechnique(
        "T1552.001",
        "Unsecured Credentials: Credentials In Files",
        ("credential-access",),
        "https://attack.mitre.org/techniques/T1552/001/",
    ),
    "T1552.004": AttackTechnique(
        "T1552.004",
        "Unsecured Credentials: Private Keys",
        ("credential-access",),
        "https://attack.mitre.org/techniques/T1552/004/",
    ),
    "T1566.002": AttackTechnique(
        "T1566.002",
        "Phishing: Spearphishing Link",
        ("initial-access",),
        "https://attack.mitre.org/techniques/T1566/002/",
    ),
    "T1590.004": AttackTechnique(
        "T1590.004",
        "Gather Victim Network Information: Network Topology",
        ("reconnaissance",),
        "https://attack.mitre.org/techniques/T1590/004/",
    ),
    "T1592.002": AttackTechnique(
        "T1592.002",
        "Gather Victim Host Information: Software",
        ("reconnaissance",),
        "https://attack.mitre.org/techniques/T1592/002/",
    ),
}


FINDING_TECHNIQUE_RULES: dict[str, tuple[FindingTechniqueRule, ...]] = {
    "sql_injection": (
        FindingTechniqueRule(
            "T1190",
            "observed_precondition",
            "A public-facing application weakness can be exploited through crafted SQL input.",
        ),
    ),
    "cross_site_scripting": (
        FindingTechniqueRule(
            "T1189",
            "observed_precondition",
            "MITRE explicitly includes XSS as a way adversaries can insert scripts into a website.",
        ),
    ),
    "xss_reflection_candidate": (
        FindingTechniqueRule(
            "T1189",
            "candidate_for",
            "A reflected input is only a candidate precondition for browser-side compromise.",
        ),
    ),
    "idor_bola": (
        FindingTechniqueRule(
            "T1190",
            "candidate_for",
            "An object-authorization weakness may be exploited through the public application.",
        ),
    ),
    "anonymous_sensitive_api": (
        FindingTechniqueRule(
            "T1190",
            "observed_precondition",
            "A public API access-control weakness can provide unauthorized application access.",
        ),
    ),
    "insecure_cors": (
        FindingTechniqueRule(
            "T1190",
            "candidate_for",
            "An exploitable cross-origin policy may expose public application data or actions.",
        ),
    ),
    "ssrf": (
        FindingTechniqueRule(
            "T1190",
            "candidate_for",
            "An SSRF weakness may provide initial access through an Internet-facing application.",
        ),
    ),
    "path_traversal_candidate": (
        FindingTechniqueRule(
            "T1190",
            "candidate_for",
            "A traversal or file-inclusion weakness may be exploited through the public application.",
        ),
        FindingTechniqueRule(
            "T1005",
            "could_enable",
            "Successful traversal may enable collection of files from the application host.",
        ),
    ),
    "secret_exposure": (
        FindingTechniqueRule(
            "T1552.001",
            "credential_source",
            "The public artifact contains a credential-like value stored in a file or client resource.",
        ),
        FindingTechniqueRule(
            "T1078",
            "could_enable",
            "A valid exposed credential could be used to access its associated account or service.",
        ),
    ),
    "sensitive_file_exposure": (
        FindingTechniqueRule(
            "T1005",
            "could_enable",
            "A public server-side artifact may enable collection of locally stored data.",
        ),
    ),
    "directory_listing": (
        FindingTechniqueRule(
            "T1005",
            "could_enable",
            "A browsable server directory may expose files that an adversary could collect.",
        ),
    ),
    "source_map_exposure": (
        FindingTechniqueRule(
            "T1592.002",
            "reconnaissance_exposure",
            "Source maps disclose software structure that can inform adversary targeting.",
        ),
    ),
    "version_disclosure": (
        FindingTechniqueRule(
            "T1592.002",
            "reconnaissance_exposure",
            "Advertised software and version details can inform adversary targeting.",
        ),
    ),
    "default_server_page": (
        FindingTechniqueRule(
            "T1592.002",
            "reconnaissance_exposure",
            "A default page can disclose server software and deployment characteristics.",
        ),
    ),
    "verbose_error": (
        FindingTechniqueRule(
            "T1592.002",
            "reconnaissance_exposure",
            "Public error details can disclose software, runtime, and deployment characteristics.",
        ),
    ),
    "openapi_exposure": (
        FindingTechniqueRule(
            "T1592.002",
            "reconnaissance_exposure",
            "A public API schema exposes application software structure and reachable operations.",
        ),
    ),
    "graphql_introspection": (
        FindingTechniqueRule(
            "T1592.002",
            "reconnaissance_exposure",
            "GraphQL introspection exposes application software types and reachable operations.",
        ),
    ),
    "vulnerable_javascript_component": (
        FindingTechniqueRule(
            "T1592.002",
            "reconnaissance_exposure",
            "An exact client component version can inform adversary targeting.",
        ),
        FindingTechniqueRule(
            "T1189",
            "could_enable",
            "A vulnerable client component may support browser-side compromise if exploitable.",
        ),
    ),
    "open_redirect": (
        FindingTechniqueRule(
            "T1566.002",
            "could_enable",
            "A trusted-origin redirect can support a malicious link in a phishing flow.",
        ),
        FindingTechniqueRule(
            "T1204.001",
            "could_enable",
            "Abuse depends on a user following the crafted redirect link.",
        ),
    ),
    "insecure_cookie": (
        FindingTechniqueRule(
            "T1539",
            "could_enable",
            "Weak cookie controls can increase the opportunity for session-cookie theft.",
        ),
        FindingTechniqueRule(
            "T1550.004",
            "could_enable",
            "A stolen authentication cookie could be reused as alternate authentication material.",
        ),
    ),
    "session_token_in_url": (
        FindingTechniqueRule(
            "T1528",
            "credential_source",
            "A token in a URL can leak through browser history, referrers, logs, or intermediaries.",
        ),
    ),
    "broad_session_cookie_scope": (
        FindingTechniqueRule(
            "T1539",
            "could_enable",
            "Broad cookie scope increases the number of origins that may expose session material.",
        ),
        FindingTechniqueRule(
            "T1550.004",
            "could_enable",
            "Compromised session material may be reused to authenticate to the web application.",
        ),
    ),
    "conflicting_session_cookies": (
        FindingTechniqueRule(
            "T1550.004",
            "could_enable",
            "Ambiguous cookie scope can contribute to session confusion or reuse scenarios.",
        ),
    ),
    "debug_interface_exposure": (
        FindingTechniqueRule(
            "T1133",
            "observed_precondition",
            "MITRE includes exposed unauthenticated application interfaces as external remote services.",
        ),
        FindingTechniqueRule(
            "T1190",
            "could_enable",
            "Dangerous debug functions may provide an exploitable public-facing application weakness.",
        ),
    ),
    "management_interface_exposure": (
        FindingTechniqueRule(
            "T1133",
            "observed_precondition",
            "A public management interface is an externally reachable service boundary.",
        ),
    ),
    "management_metrics_exposure": (
        FindingTechniqueRule(
            "T1592.002",
            "reconnaissance_exposure",
            "Public metrics can disclose runtime software and dependency characteristics.",
        ),
    ),
    "detailed_health_exposure": (
        FindingTechniqueRule(
            "T1590.004",
            "reconnaissance_exposure",
            "Disclosed backend dependencies expose part of the victim's logical network topology.",
        ),
    ),
}


CAPABILITY_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "sql_query_manipulation": ("T1190", "T1213.006"),
    "arbitrary_javascript_execution": ("T1189", "T1539"),
    "secret_acquisition": ("T1552.001", "T1078"),
    "file_disclosure": ("T1005",),
    "authorization_bypass": ("T1190",),
    "api_access": ("T1133",),
    "internal_service_interaction": ("T1190", "T1046"),
    "trusted_origin_redirect": ("T1566.002", "T1204.001"),
    "session_abuse": ("T1539", "T1550.004"),
    "debug_surface_access": ("T1133", "T1190"),
    "operational_information_disclosure": ("T1592.002",),
    "service_topology_disclosure": ("T1046",),
}


def attack_catalog() -> list[dict[str, object]]:
    return [
        {**asdict(technique), "catalog_version": ATTACK_CATALOG_VERSION}
        for technique in sorted(ATTACK_TECHNIQUES.values(), key=lambda item: item.technique_id)
    ]


def technique_label(technique_id: str) -> str:
    technique = ATTACK_TECHNIQUES.get(technique_id)
    return f"{technique_id} — {technique.name}" if technique else technique_id


def technique_ids_for_finding_type(finding_type: str) -> tuple[str, ...]:
    return tuple(rule.technique_id for rule in FINDING_TECHNIQUE_RULES.get(finding_type, ()))


def finding_attack_mappings(
    finding_type: str,
    *,
    metadata: dict[str, Any] | None = None,
    confidence: str,
    validation_status: str,
    has_cve: bool = False,
) -> list[dict[str, object]]:
    rules = list(FINDING_TECHNIQUE_RULES.get(finding_type, ()))
    metadata = metadata or {}
    if finding_type == "secret_exposure":
        secret_type = str(metadata.get("secret_type") or "")
        if secret_type == "private_key":  # noqa: S105 - this is a secret classification
            rules.append(
                FindingTechniqueRule(
                    "T1552.004",
                    "credential_source",
                    "The exposed credential is a private cryptographic key.",
                )
            )
        if secret_type in {"github_token", "jwt"}:
            rules.append(
                FindingTechniqueRule(
                    "T1528",
                    "credential_source",
                    "The exposed value is an application, API, cloud, or service access token.",
                )
            )
    if finding_type.startswith("nuclei:") and has_cve:
        rules.append(
            FindingTechniqueRule(
                "T1190",
                "candidate_for",
                "A matched public-facing CVE may support exploitation of the exposed application.",
            )
        )
    deduplicated: dict[str, FindingTechniqueRule] = {}
    for rule in rules:
        deduplicated.setdefault(rule.technique_id, rule)
    classification = (
        "confirmed"
        if validation_status == "confirmed"
        else "inferred"
    )
    return [
        {
            "technique_id": rule.technique_id,
            "name": ATTACK_TECHNIQUES[rule.technique_id].name,
            "tactics": list(ATTACK_TECHNIQUES[rule.technique_id].tactics),
            "relationship": rule.relationship,
            "confidence": confidence,
            "classification": classification,
            "rationale": rule.rationale,
            "url": ATTACK_TECHNIQUES[rule.technique_id].url,
            "catalog_version": ATTACK_CATALOG_VERSION,
        }
        for rule in deduplicated.values()
    ]


def technique_ids_for_capability(capability: str) -> tuple[str, ...]:
    return CAPABILITY_TECHNIQUES.get(capability, ())
