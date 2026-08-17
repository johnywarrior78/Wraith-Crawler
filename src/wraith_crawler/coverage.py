from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class CoverageEntry:
    category: str
    name: str
    capabilities: tuple[str, ...]
    cwe: tuple[str, ...]
    automation_level: str
    validation_strength: str
    limitation: str


OWASP_COVERAGE: tuple[CoverageEntry, ...] = (
    CoverageEntry(
        "A01:2021",
        "Broken Access Control",
        ("idor_bola_analysis", "auth_discovery", "management_interfaces"),
        ("CWE-200", "CWE-284", "CWE-639"),
        "partial",
        "candidate_to_confirmed",
        "Authorization differences often require authenticated multi-user testing.",
    ),
    CoverageEntry(
        "A02:2021",
        "Cryptographic Failures",
        ("tls", "cookie_security", "secret_exposure"),
        ("CWE-295", "CWE-319", "CWE-614"),
        "high",
        "deterministic",
        "Data-at-rest cryptography is not externally observable.",
    ),
    CoverageEntry(
        "A03:2021",
        "Injection",
        ("sqlmap", "dalfox", "parameter_analysis", "path_traversal"),
        ("CWE-79", "CWE-89", "CWE-22"),
        "partial",
        "safe_active_validation",
        "Only bounded, non-destructive payloads are used.",
    ),
    CoverageEntry(
        "A04:2021",
        "Insecure Design",
        ("manual_review",),
        ("CWE-840",),
        "manual",
        "observable_evidence_only",
        "Design defects generally require business and authenticated context.",
    ),
    CoverageEntry(
        "A05:2021",
        "Security Misconfiguration",
        ("security_headers", "cors", "directory_listing", "http_methods", "debug_interfaces"),
        ("CWE-16", "CWE-942", "CWE-548"),
        "high",
        "deterministic",
        "Internal configuration not reflected in responses is out of scope.",
    ),
    CoverageEntry(
        "A06:2021",
        "Vulnerable and Outdated Components",
        ("retirejs", "technology_fingerprinting", "nuclei"),
        ("CWE-1104",),
        "high",
        "version_and_signature",
        "Versions hidden by the target may not be identifiable.",
    ),
    CoverageEntry(
        "A07:2021",
        "Identification and Authentication Failures",
        ("auth_discovery", "cookie_security"),
        ("CWE-287", "CWE-384"),
        "partial",
        "behavioral_observation",
        "No credential guessing, stuffing, or brute force is performed.",
    ),
    CoverageEntry(
        "A08:2021",
        "Software and Data Integrity Failures",
        ("sensitive_files", "source_maps", "component_analysis"),
        ("CWE-494", "CWE-502"),
        "partial",
        "external_artifact_evidence",
        "Build and deployment trust boundaries are usually internal.",
    ),
    CoverageEntry(
        "A09:2021",
        "Security Logging and Monitoring Failures",
        ("manual_review",),
        ("CWE-778",),
        "manual",
        "not_externally_verifiable",
        "Logging and monitoring controls are not normally visible externally.",
    ),
    CoverageEntry(
        "A10:2021",
        "Server-Side Request Forgery",
        ("ssrf_candidate_analysis",),
        ("CWE-918",),
        "partial",
        "safe_external_validation",
        "Private/internal network probes require separate explicit authorization.",
    ),
)


def coverage_matrix() -> list[dict[str, object]]:
    return [asdict(entry) for entry in OWASP_COVERAGE]
