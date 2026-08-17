from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .enums import Confidence, FailureReason, PluginState, Severity, ValidationStatus


def utcnow() -> datetime:
    return datetime.now(UTC)


def canonical_url(value: str) -> str:
    """Normalize a URL without broadening its scope or altering meaningful query data."""
    parts = urlsplit(value.strip())
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("target must be an absolute http:// or https:// URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError("credentials must not be embedded in target URLs")
    host = parts.hostname.encode("idna").decode("ascii").lower()
    port = parts.port
    if (parts.scheme.lower(), port) in {("http", 80), ("https", 443)}:
        port = None
    netloc = host if port is None else f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


SENSITIVE_PARAMETER = re.compile(
    r"(?:pass(?:word)?|secret|token|api[_-]?key|authorization|auth|cookie|session|jwt)",
    re.IGNORECASE,
)


def redact_url(value: str) -> str:
    """Mask secret-like query values while retaining endpoint structure for evidence."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return value
    query = urlencode(
        [
            (name, "[REDACTED]" if SENSITIVE_PARAMETER.search(name) else item)
            for name, item in parse_qsl(parts.query, keep_blank_values=True)
        ],
        doseq=True,
    )
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def redact_text(value: str) -> str:
    text = re.sub(
        r"(?i)\b(password|secret|token|api[_-]?key|authorization|cookie|session|jwt)(\s*[:=]\s*)([^\s,;&]+)",
        r"\1\2[REDACTED]",
        value,
    )

    def mask_url(match: re.Match[str]) -> str:
        token = match.group(0)
        trailing = token[-1] if token[-1] in ".),]" else ""
        core = token[:-1] if trailing else token
        return redact_url(core) + trailing

    return re.sub(r"https?://[^\s<>\"']+", mask_url, text)


class TargetInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    url: str
    include_hosts: list[str] = Field(default_factory=list)
    exclude_hosts: list[str] = Field(default_factory=list)
    include_paths: list[str] = Field(default_factory=list)
    exclude_paths: list[str] = Field(default_factory=list)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return canonical_url(value)


class EvidenceRecord(BaseModel):
    kind: str
    summary: str
    location: str | None = None
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    observed_at: datetime = Field(default_factory=utcnow)
    fingerprint: str | None = None
    sensitive: bool = False

    def safe_payload(self) -> dict[str, Any]:
        data = self.model_dump(mode="json", exclude_none=True)
        if self.sensitive:
            data.pop("request", None)
            data.pop("response", None)
            data["summary"] = "Sensitive evidence retained in redacted form"
        return data


class RawObservation(BaseModel):
    plugin: str
    observation_type: str
    target: str
    data: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM
    observed_at: datetime = Field(default_factory=utcnow)


class AssetRecord(BaseModel):
    url: str
    origin: str
    scheme: str
    hostname: str
    port: int
    resolved_ips: list[str] = Field(default_factory=list)
    cname: str | None = None
    status_code: int | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    title: str | None = None
    server: str | None = None
    cdn_waf: str | None = None
    tls: dict[str, Any] = Field(default_factory=dict)
    discovery_sources: list[str] = Field(default_factory=list)


class ParameterRecord(BaseModel):
    name: str
    normalized_name: str
    location: str
    method: str = "GET"
    required: bool | None = None
    source: str
    sample_metadata: dict[str, Any] = Field(default_factory=dict)
    risk_categories: list[str] = Field(default_factory=list)
    risk_score: float = 0.0


class EndpointRecord(BaseModel):
    url: str
    origin: str
    path: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str | None = None
    response_metadata: dict[str, Any] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)
    parameters: list[ParameterRecord] = Field(default_factory=list)
    authentication_required: bool | None = None
    api_classification: str | None = None
    javascript_source: str | None = None
    confidence: Confidence = Confidence.MEDIUM


class TechnologyRecord(BaseModel):
    product: str
    version: str | None = None
    category: str
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[str] = Field(default_factory=list)
    source_plugin: str
    eol_state: str | None = None
    vulnerability_references: list[str] = Field(default_factory=list)


class FindingCandidate(BaseModel):
    finding_type: str
    family: str
    title: str
    description: str
    asset: str
    affected_endpoints: list[str] = Field(default_factory=list)
    method: str | None = None
    parameters: list[str] = Field(default_factory=list)
    severity: Severity
    confidence: Confidence
    validation_status: ValidationStatus
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    source_plugins: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    capec: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    remediation: str
    references: list[str] = Field(default_factory=list)
    manual_review: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        material = {
            "type": self.finding_type,
            "asset": self.asset.lower(),
            "endpoints": sorted(self.affected_endpoints),
            "method": self.method,
            "parameters": sorted(self.parameters),
            "component": self.metadata.get("component"),
        }
        return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


class PluginResult(BaseModel):
    plugin: str
    state: PluginState
    failure_reason: FailureReason | None = None
    message: str | None = None
    capabilities_produced: set[str] = Field(default_factory=set)
    assets: list[AssetRecord] = Field(default_factory=list)
    endpoints: list[EndpointRecord] = Field(default_factory=list)
    technologies: list[TechnologyRecord] = Field(default_factory=list)
    observations: list[RawObservation] = Field(default_factory=list)
    findings: list[FindingCandidate] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    partial_output_trustworthy: bool = False
