from __future__ import annotations

import asyncio
import hashlib
import html
import re
import socket
import ssl
import time
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urljoin, urlsplit

import httpx

from ..domain import (
    AssetRecord,
    EndpointRecord,
    EvidenceRecord,
    FindingCandidate,
    PluginResult,
    RawObservation,
    TechnologyRecord,
    canonical_url,
)
from ..enums import Confidence, FailureReason, PluginState, ScanProfile, Severity, ValidationStatus
from .base import AssessmentPlugin, HTTPResponseSnapshot, PluginContext


def _origin(url: str) -> str:
    parts = urlsplit(url)
    port = parts.port
    default = (parts.scheme == "http" and port in {None, 80}) or (
        parts.scheme == "https" and port in {None, 443}
    )
    return f"{parts.scheme}://{parts.hostname}" + ("" if default else f":{port}")


def _endpoint(url: str, source: str, **kwargs: object) -> EndpointRecord:
    parts = urlsplit(url)
    return EndpointRecord(
        url=canonical_url(url),
        origin=_origin(url),
        path=parts.path or "/",
        sources=[source],
        **kwargs,
    )


def _safe_response_headers(headers: dict[str, str]) -> dict[str, str]:
    """Retain response metadata without persisting authentication material."""
    sensitive = {"set-cookie", "authorization", "proxy-authorization"}
    return {
        key: "[REDACTED]" if key.lower() in sensitive else value
        for key, value in headers.items()
    }


def _parse_set_cookie_header(raw: str) -> list[tuple[str, dict[str, str | None]]]:
    """Parse combined Set-Cookie headers while discarding every cookie value."""
    cookies: list[tuple[str, dict[str, str | None]]] = []
    for item in re.split(r",(?=\s*[^;,\s]+=)", raw):
        segments = [segment.strip() for segment in item.split(";") if segment.strip()]
        if not segments or "=" not in segments[0]:
            continue
        name = segments[0].split("=", 1)[0].strip()
        if not name:
            continue
        attributes: dict[str, str | None] = {}
        for segment in segments[1:]:
            key, separator, value = segment.partition("=")
            attributes[key.strip().lower()] = value.strip() if separator else None
        cookies.append((name, attributes))
    return cookies


def _is_authentication_cookie(name: str) -> bool:
    lowered = name.lower()
    common_names = {
        "asp.net_sessionid",
        "auth_token",
        "connect.sid",
        "jsessionid",
        "jwt",
        "phpsessid",
        "session",
        "session_id",
        "sessionid",
        "sid",
    }
    if lowered in common_names:
        return True
    normalized = re.sub(r"[^a-z0-9]+", "_", lowered).strip("_")
    return bool(
        re.search(
            r"(?:^|_)(?:auth(?:entication)?|access_token|jwt|sess(?:ion)?(?:id)?|sid)(?:$|_)",
            normalized,
        )
    )


class SeedHTTPPlugin(AssessmentPlugin):
    name = "seed_http"
    description = "Independent seed URL validation and HTTP metadata"
    requires = frozenset({"seed_url"})
    produces = frozenset({"http_metadata", "validated_origin", "endpoints"})
    timeout_seconds = 60
    RETRYABLE_NON_FINAL_STATUSES = frozenset({202, 429, 502, 503, 504})

    async def run(self, context: PluginContext) -> PluginResult:
        started = time.monotonic()
        requests = 0
        try:
            async with httpx.AsyncClient(
                timeout=context.config.rate.request_timeout_seconds,
                follow_redirects=False,
                verify=True,
                headers={"User-Agent": "Wraith-Crawler/0.1 authorized-security-assessment"},
            ) as client:
                for attempt in range(max(0, context.config.rate.retries) + 1):
                    response = await client.get(context.target.url)
                    requests += 1
                    if response.status_code not in self.RETRYABLE_NON_FINAL_STATUSES:
                        break
                    if attempt < max(0, context.config.rate.retries):
                        await asyncio.sleep(self._retry_delay(response, attempt))
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
            return PluginResult(
                plugin=self.name,
                state=PluginState.FAILED,
                failure_reason=FailureReason.TARGET_UNREACHABLE,
                message=f"{type(exc).__name__}: target could not be reached",
            )
        except httpx.HTTPError as exc:
            return PluginResult(
                plugin=self.name,
                state=PluginState.FAILED,
                failure_reason=FailureReason.TOOL_EXECUTION_FAILED,
                message=f"HTTP validation failed: {type(exc).__name__}",
            )
        body_bytes = response.content[:1_048_576]
        encoding = response.encoding or "utf-8"
        body = body_bytes.decode(encoding, errors="replace")
        headers = {key.lower(): value for key, value in response.headers.items()}
        safe_headers = _safe_response_headers(headers)
        redirect_chain: list[str] = []
        if response.is_redirect and response.headers.get("location"):
            location = urljoin(str(response.url), response.headers["location"])
            redirect_chain.append(location)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        snapshot = HTTPResponseSnapshot(
            url=str(response.url),
            status_code=response.status_code,
            headers=headers,
            body=body,
            elapsed_ms=elapsed_ms,
            redirect_chain=redirect_chain,
        )
        context.http_snapshots[context.target.url] = snapshot
        parts = urlsplit(context.target.url)
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        title = html.unescape(re.sub(r"\s+", " ", title_match.group(1))).strip() if title_match else None
        port = parts.port or (443 if parts.scheme == "https" else 80)
        asset = AssetRecord(
            url=context.target.url,
            origin=_origin(context.target.url),
            scheme=parts.scheme,
            hostname=parts.hostname or "",
            port=port,
            status_code=response.status_code,
            redirect_chain=redirect_chain,
            title=title,
            server=headers.get("server"),
            discovery_sources=[self.name],
        )
        observations = [
            RawObservation(
                plugin=self.name,
                observation_type="http_response",
                target=context.target.url,
                data={
                    "status_code": response.status_code,
                    "headers": safe_headers,
                    "content_length_observed": len(body_bytes),
                    "body_truncated": len(response.content) > len(body_bytes),
                    "elapsed_ms": elapsed_ms,
                    "redirect_chain": redirect_chain,
                    "request_attempts": requests,
                },
                evidence=[
                    EvidenceRecord(
                        kind="http_response",
                        summary=f"GET returned HTTP {response.status_code}",
                        location=context.target.url,
                        response={"status": response.status_code, "headers": safe_headers},
                    )
                ],
                confidence=Confidence.CONFIRMED,
            )
        ]
        metrics = {
            "requests": requests,
            "bytes_sampled": len(body_bytes),
            "status_code": response.status_code,
        }
        if response.status_code in self.RETRYABLE_NON_FINAL_STATUSES:
            return PluginResult(
                plugin=self.name,
                state=PluginState.PARTIAL,
                failure_reason=FailureReason.INCOMPLETE_RESPONSE,
                message=(
                    f"Seed URL returned non-final HTTP {response.status_code} after "
                    f"{requests} attempt(s); discovery capabilities were withheld"
                ),
                assets=[asset],
                observations=observations,
                metrics=metrics,
                partial_output_trustworthy=True,
            )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            assets=[asset],
            endpoints=[
                _endpoint(
                    context.target.url,
                    self.name,
                    status_code=response.status_code,
                    content_type=headers.get("content-type"),
                    response_metadata={"elapsed_ms": elapsed_ms, "headers": safe_headers},
                    confidence=Confidence.CONFIRMED,
                )
            ],
            observations=observations,
            metrics=metrics,
        )

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("retry-after", "").strip()
        try:
            return min(5.0, max(0.0, float(retry_after)))
        except ValueError:
            return min(5.0, float(2**attempt))


class TLSPlugin(AssessmentPlugin):
    name = "tls"
    description = "TLS certificate, trust, version, and transport checks"
    requires = frozenset({"seed_url"})
    produces = frozenset({"tls_metadata"})
    owasp = ("A02:2021",)
    cwe = ("CWE-295", "CWE-319")
    timeout_seconds = 30

    async def run(self, context: PluginContext) -> PluginResult:
        parts = urlsplit(context.target.url)
        if parts.scheme != "https":
            finding = FindingCandidate(
                finding_type="insecure_http_transport",
                family="transport_security",
                title="Application is served over unencrypted HTTP",
                description="The supplied entry point uses HTTP, allowing network observers to read or modify traffic.",
                asset=_origin(context.target.url),
                affected_endpoints=[context.target.url],
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                validation_status=ValidationStatus.CONFIRMED,
                evidence=[
                    EvidenceRecord(
                        kind="target_url", summary="Seed URL uses the http scheme", location=context.target.url
                    )
                ],
                source_plugins=[self.name],
                cwe=["CWE-319"],
                owasp=["A02:2021"],
                remediation="Redirect HTTP to HTTPS and enforce HTTPS with HSTS after validating all subdomains.",
            )
            return self.success(
                self.name,
                capabilities_produced=set(self.produces),
                findings=[finding],
                message="TLS not applicable to the HTTP seed; transport finding recorded",
            )
        host = parts.hostname or ""
        port = parts.port or 443
        try:
            details = await asyncio.wait_for(
                asyncio.to_thread(self._inspect, host, port),
                timeout=context.config.rate.request_timeout_seconds,
            )
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            return PluginResult(
                plugin=self.name,
                state=PluginState.PARTIAL,
                failure_reason=FailureReason.TARGET_UNREACHABLE,
                message=f"TLS handshake failed: {type(exc).__name__}",
                partial_output_trustworthy=True,
                capabilities_produced=set(self.produces),
                findings=[
                    FindingCandidate(
                        finding_type="tls_handshake_failure",
                        family="transport_security",
                        title="TLS connection could not be validated",
                        description="The external TLS handshake failed and requires review.",
                        asset=_origin(context.target.url),
                        affected_endpoints=[context.target.url],
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        validation_status=ValidationStatus.MANUAL_REVIEW,
                        evidence=[
                            EvidenceRecord(
                                kind="tls_error",
                                summary=f"TLS handshake raised {type(exc).__name__}",
                                location=context.target.url,
                            )
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-295"],
                        owasp=["A02:2021"],
                        remediation="Review certificate trust, hostname, protocol support and the complete chain.",
                        manual_review=True,
                    )
                ],
            )
        findings: list[FindingCandidate] = []
        if not details["trusted"]:
            findings.append(
                FindingCandidate(
                    finding_type="untrusted_tls_certificate",
                    family="transport_security",
                    title="TLS certificate is not trusted",
                    description="A default system trust validation could not establish a trusted certificate chain.",
                    asset=_origin(context.target.url),
                    affected_endpoints=[context.target.url],
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    validation_status=ValidationStatus.CONFIRMED,
                    evidence=[
                        EvidenceRecord(
                            kind="tls_validation",
                            summary=details.get("validation_error", "Certificate validation failed"),
                            location=context.target.url,
                        )
                    ],
                    source_plugins=[self.name],
                    cwe=["CWE-295"],
                    owasp=["A02:2021"],
                    remediation="Install a certificate with a valid hostname and complete chain from a trusted CA.",
                )
            )
        days = details.get("days_until_expiry")
        if isinstance(days, int) and days < 30:
            severity = Severity.HIGH if days < 0 else Severity.LOW
            findings.append(
                FindingCandidate(
                    finding_type="tls_certificate_expiry",
                    family="transport_security",
                    title="TLS certificate is expired" if days < 0 else "TLS certificate expires soon",
                    description=f"The observed certificate has {days} days remaining.",
                    asset=_origin(context.target.url),
                    affected_endpoints=[context.target.url],
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    validation_status=ValidationStatus.CONFIRMED,
                    evidence=[
                        EvidenceRecord(
                            kind="certificate",
                            summary=f"Certificate expiration is {details.get('not_after')}",
                            location=context.target.url,
                        )
                    ],
                    source_plugins=[self.name],
                    cwe=["CWE-298"],
                    owasp=["A02:2021"],
                    remediation="Renew and deploy the certificate before expiry and automate renewal monitoring.",
                )
            )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            observations=[
                RawObservation(
                    plugin=self.name,
                    observation_type="tls_certificate",
                    target=context.target.url,
                    data=details,
                    evidence=[
                        EvidenceRecord(
                            kind="tls_handshake",
                            summary=f"Negotiated {details.get('protocol')} with {details.get('cipher')}",
                            location=context.target.url,
                        )
                    ],
                    confidence=Confidence.CONFIRMED,
                )
            ],
            findings=findings,
        )

    @staticmethod
    def _inspect(host: str, port: int) -> dict[str, object]:
        validation_error: str | None = None
        trusted = True
        try:
            trusted_context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as raw:
                with trusted_context.wrap_socket(raw, server_hostname=host):
                    pass
        except ssl.SSLCertVerificationError as exc:
            trusted = False
            validation_error = str(exc.verify_message)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secure:
                cert = secure.getpeercert(binary_form=False)
                binary = secure.getpeercert(binary_form=True)
                protocol = secure.version()
                cipher = secure.cipher()[0] if secure.cipher() else None
        result: dict[str, object] = {
            "trusted": trusted,
            "validation_error": validation_error,
            "protocol": protocol,
            "cipher": cipher,
            "certificate_sha256": hashlib.sha256(binary).hexdigest() if binary else None,
        }
        # getpeercert() can be empty under CERT_NONE; decode via a temporary PEM only when fields exist.
        if cert:
            not_after = cert.get("notAfter")
            result.update({"subject": cert.get("subject"), "issuer": cert.get("issuer"), "not_after": not_after})
            if isinstance(not_after, str):
                expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC)
                result["days_until_expiry"] = (expiry - datetime.now(UTC)).days
        return result


class HTMLDiscoveryPlugin(AssessmentPlugin):
    name = "html_discovery"
    description = "In-scope endpoint, form, JavaScript, API and authentication discovery"
    requires = frozenset({"http_metadata"})
    produces = frozenset(
        {
            "endpoints",
            "javascript_urls",
            "api_candidates",
            "auth_surfaces",
            "html_discovery_complete",
        }
    )

    LINK_RE = re.compile(r"(?:href|src|action)\s*=\s*['\"]([^'\"#]+)", re.I)
    JS_ENDPOINT_RE = re.compile(r"['\"]((?:/|https?://)[A-Za-z0-9_./?=&%:-]{2,})['\"]")

    async def run(self, context: PluginContext) -> PluginResult:
        snapshot = context.http_snapshots[context.target.url]
        endpoints = [_endpoint(context.target.url, self.name, status_code=snapshot.status_code)]
        scripts: set[str] = set()
        api_candidates: set[str] = set()
        for raw in self.LINK_RE.findall(snapshot.body):
            try:
                url = context.scope.resolve(html.unescape(raw), snapshot.url)
            except ValueError:
                continue
            if not context.scope.check(url).allowed:
                continue
            endpoints.append(_endpoint(url, self.name))
            if urlsplit(url).path.lower().endswith(".js"):
                scripts.add(url)
            if re.search(r"/(api|graphql|v[0-9]+)(/|$)", urlsplit(url).path, re.I):
                api_candidates.add(url)
        for raw in self.JS_ENDPOINT_RE.findall(snapshot.body):
            try:
                url = context.scope.resolve(raw, snapshot.url)
            except ValueError:
                continue
            if context.scope.check(url).allowed:
                endpoints.append(_endpoint(url, self.name, javascript_source=snapshot.url))
                if "/api" in urlsplit(url).path.lower():
                    api_candidates.add(url)
        for endpoint in endpoints:
            path_lower = endpoint.path.lower()
            if any(term in path_lower for term in ("login", "signin", "oauth", "saml", "reset")):
                endpoint.authentication_required = False
                endpoint.response_metadata["auth_surface"] = True
            if endpoint.url in api_candidates:
                endpoint.api_classification = "api_candidate"
        observations = [
            RawObservation(
                plugin=self.name,
                observation_type="html_discovery",
                target=snapshot.url,
                data={"endpoint_count": len(endpoints), "javascript": sorted(scripts), "api": sorted(api_candidates)},
                confidence=Confidence.HIGH,
            )
        ]
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            endpoints=endpoints,
            observations=observations,
            metrics={"endpoints_discovered": len(endpoints), "javascript_discovered": len(scripts)},
        )


class SecurityHeadersPlugin(AssessmentPlugin):
    name = "security_headers"
    requires = frozenset({"http_metadata"})
    produces = frozenset({"header_assessment"})
    owasp = ("A05:2021",)
    cwe = ("CWE-693",)

    EXPECTED = {
        "content-security-policy": "Content-Security-Policy",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
        "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
        "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
    }

    async def run(self, context: PluginContext) -> PluginResult:
        snapshot = context.http_snapshots[context.target.url]
        expected = dict(self.EXPECTED)
        if context.target.url.startswith("https://"):
            expected["strict-transport-security"] = "Strict-Transport-Security"
        missing = [label for key, label in expected.items() if key not in snapshot.headers]
        # X-Frame-Options is optional when CSP frame-ancestors is present.
        csp = snapshot.headers.get("content-security-policy", "")
        if "x-frame-options" not in snapshot.headers and "frame-ancestors" not in csp.lower():
            missing.append("X-Frame-Options or CSP frame-ancestors")
        findings: list[FindingCandidate] = []
        if missing:
            findings.append(
                FindingCandidate(
                    finding_type="missing_security_headers",
                    family="security_misconfiguration",
                    title="Recommended browser security headers are missing",
                    description="One or more response controls that reduce browser-side attack impact were not observed.",
                    asset=_origin(context.target.url),
                    affected_endpoints=[snapshot.url],
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    validation_status=ValidationStatus.CONFIRMED,
                    evidence=[
                        EvidenceRecord(
                            kind="http_headers",
                            summary=f"Missing: {', '.join(missing)}",
                            location=snapshot.url,
                            response={
                                "status": snapshot.status_code,
                                "headers": _safe_response_headers(snapshot.headers),
                            },
                        )
                    ],
                    source_plugins=[self.name],
                    cwe=["CWE-693"],
                    owasp=["A05:2021"],
                    remediation="Define a tested site-wide header policy at the application or edge layer.",
                    metadata={"missing_headers": missing, "aggregate_scope": _origin(context.target.url)},
                )
            )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            findings=findings,
            observations=[
                RawObservation(
                    plugin=self.name,
                    observation_type="security_headers",
                    target=snapshot.url,
                    data={"missing": missing, "present": sorted(snapshot.headers)},
                    confidence=Confidence.CONFIRMED,
                )
            ],
        )


class CookieSecurityPlugin(AssessmentPlugin):
    name = "cookie_security"
    description = "Session-cookie discovery and browser security attribute assessment"
    requires = frozenset({"http_metadata"})
    produces = frozenset({"cookie_assessment", "session_cookie_analysis"})
    owasp = ("A02:2021", "A07:2021")
    cwe = ("CWE-614", "CWE-1004", "CWE-1275")

    async def run(self, context: PluginContext) -> PluginResult:
        snapshot = context.http_snapshots[context.target.url]
        raw = snapshot.headers.get("set-cookie")
        if not raw:
            return self.success(self.name, capabilities_produced=set(self.produces), message="No cookies observed")
        findings: list[FindingCandidate] = []
        observations: list[dict[str, object]] = []
        session_cookie_count = 0
        for name, attributes in _parse_set_cookie_header(raw):
            attribute_names = sorted(attributes)
            authentication_cookie = _is_authentication_cookie(name)
            session_lifetime = "expires" not in attributes and "max-age" not in attributes
            if authentication_cookie:
                session_cookie_count += 1
            missing: list[str] = []
            if context.target.url.startswith("https://") and "secure" not in attributes:
                missing.append("Secure")
            if authentication_cookie:
                if "httponly" not in attributes:
                    missing.append("HttpOnly")
                if "samesite" not in attributes:
                    missing.append("SameSite")
            prefix_violations: list[str] = []
            lowered_name = name.lower()
            if lowered_name.startswith("__secure-") and "secure" not in attributes:
                prefix_violations.append("__Secure- prefix requires Secure")
            if lowered_name.startswith("__host-"):
                if "secure" not in attributes:
                    prefix_violations.append("__Host- prefix requires Secure")
                if "domain" in attributes:
                    prefix_violations.append("__Host- prefix forbids Domain")
                if attributes.get("path") != "/":
                    prefix_violations.append("__Host- prefix requires Path=/")
            observations.append(
                {
                    "cookie_name": name,
                    "attributes": attribute_names,
                    "authentication_cookie": authentication_cookie,
                    "session_lifetime": session_lifetime,
                    "prefix_valid": not prefix_violations,
                }
            )
            issues = [*missing, *prefix_violations]
            if not issues:
                continue
            findings.append(
                FindingCandidate(
                    finding_type="insecure_cookie",
                    family="session_security",
                    title=(
                        f"Session cookie {name} lacks recommended security controls"
                        if authentication_cookie
                        else f"Cookie {name} lacks recommended security controls"
                    ),
                    description=(
                        "A likely authentication or session cookie was set without one or more controls "
                        "that constrain transport, script access, cross-site use, or cookie scope."
                        if authentication_cookie
                        else "The cookie violates a transport or cookie-prefix security requirement."
                    ),
                    asset=_origin(snapshot.url),
                    affected_endpoints=[snapshot.url],
                    severity=(
                        Severity.MEDIUM
                        if authentication_cookie and ({"Secure", "HttpOnly"} & set(missing))
                        else Severity.LOW
                    ),
                    confidence=Confidence.CONFIRMED,
                    validation_status=ValidationStatus.CONFIRMED,
                    evidence=[
                        EvidenceRecord(
                            kind="set_cookie",
                            summary=f"Cookie {name} has control issues: {', '.join(issues)}",
                            location=snapshot.url,
                            response={
                                "cookie_name": name,
                                "observed_attributes": attribute_names,
                                "missing_attributes": missing,
                                "prefix_violations": prefix_violations,
                                "authentication_cookie": authentication_cookie,
                                "session_lifetime": session_lifetime,
                            },
                        )
                    ],
                    source_plugins=[self.name],
                    cwe=["CWE-614", "CWE-1004", "CWE-1275"],
                    owasp=["A02:2021", "A07:2021"],
                    remediation=(
                        "Set Secure, HttpOnly and an appropriate SameSite policy on authentication cookies; "
                        "honor __Secure- and __Host- prefix rules and minimize Domain and Path scope."
                    ),
                    metadata={
                        "cookie_name": name,
                        "cookie_class": "authentication_session" if authentication_cookie else "other",
                        "session_lifetime": session_lifetime,
                        "missing_attributes": missing,
                        "prefix_violations": prefix_violations,
                    },
                )
            )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            findings=findings,
            observations=[
                RawObservation(
                    plugin=self.name,
                    observation_type="session_cookie_inventory",
                    target=snapshot.url,
                    data={"cookies": observations},
                    confidence=Confidence.CONFIRMED,
                )
            ],
            metrics={
                "cookies_observed": len(observations),
                "authentication_cookies": session_cookie_count,
                "cookies_with_issues": len(findings),
            },
        )


class CORSPlugin(AssessmentPlugin):
    name = "cors"
    requires = frozenset({"http_metadata"})
    produces = frozenset({"cors_assessment"})
    owasp = ("A05:2021",)
    cwe = ("CWE-942",)

    async def run(self, context: PluginContext) -> PluginResult:
        probe_origin = "https://wraith.invalid"
        try:
            async with httpx.AsyncClient(
                timeout=context.config.rate.request_timeout_seconds,
                follow_redirects=False,
                headers={"Origin": probe_origin, "User-Agent": "Wraith-Crawler/0.1"},
            ) as client:
                response = await client.get(context.target.url)
        except httpx.HTTPError as exc:
            return PluginResult(
                plugin=self.name,
                state=PluginState.PARTIAL,
                failure_reason=FailureReason.TARGET_UNREACHABLE,
                message=f"CORS behavior probe failed: {type(exc).__name__}",
                partial_output_trustworthy=True,
                capabilities_produced=set(self.produces),
            )
        allow_origin = response.headers.get("access-control-allow-origin")
        credentials = response.headers.get("access-control-allow-credentials", "").lower() == "true"
        unsafe = allow_origin == probe_origin or (allow_origin == "*" and credentials)
        findings = []
        if unsafe:
            findings.append(
                FindingCandidate(
                    finding_type="insecure_cors",
                    family="security_misconfiguration",
                    title="CORS policy permits an untrusted origin",
                    description="The server accepted a synthetic untrusted Origin value in its access-control response.",
                    asset=_origin(context.target.url),
                    affected_endpoints=[context.target.url],
                    severity=Severity.HIGH if credentials else Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    validation_status=ValidationStatus.CONFIRMED,
                    evidence=[
                        EvidenceRecord(
                            kind="cors_probe",
                            summary=f"Origin {probe_origin} received ACAO {allow_origin!r}; credentials={credentials}",
                            location=context.target.url,
                            request={"headers": {"Origin": probe_origin}},
                            response={
                                "status": response.status_code,
                                "headers": {
                                    "access-control-allow-origin": allow_origin,
                                    "access-control-allow-credentials": str(credentials),
                                },
                            },
                        )
                    ],
                    source_plugins=[self.name],
                    cwe=["CWE-942"],
                    owasp=["A05:2021"],
                    remediation="Use an exact trusted-origin allowlist and disable credentialed CORS where unnecessary.",
                )
            )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            findings=findings,
            observations=[
                RawObservation(
                    plugin=self.name,
                    observation_type="cors_behavior",
                    target=context.target.url,
                    data={"probe_origin": probe_origin, "allow_origin": allow_origin, "credentials": credentials},
                    confidence=Confidence.CONFIRMED,
                )
            ],
            metrics={"requests": 1},
        )


class HTTPMethodsPlugin(AssessmentPlugin):
    name = "http_methods"
    requires = frozenset({"http_metadata"})
    produces = frozenset({"method_assessment"})
    owasp = ("A05:2021",)

    async def run(self, context: PluginContext) -> PluginResult:
        try:
            async with httpx.AsyncClient(timeout=context.config.rate.request_timeout_seconds) as client:
                response = await client.options(context.target.url)
        except httpx.HTTPError as exc:
            return PluginResult(
                plugin=self.name,
                state=PluginState.PARTIAL,
                failure_reason=FailureReason.TARGET_UNREACHABLE,
                message=f"OPTIONS probe failed: {type(exc).__name__}",
                capabilities_produced=set(self.produces),
                partial_output_trustworthy=True,
            )
        allow = {item.strip().upper() for item in response.headers.get("allow", "").split(",") if item.strip()}
        unusual = sorted(allow.intersection({"TRACE", "CONNECT", "PUT", "DELETE", "PATCH"}))
        findings = []
        if unusual:
            findings.append(
                FindingCandidate(
                    finding_type="unusual_http_methods",
                    family="security_misconfiguration",
                    title="Potentially dangerous HTTP methods are advertised",
                    description="OPTIONS advertised methods that may expand the exposed write or diagnostic surface.",
                    asset=_origin(context.target.url),
                    affected_endpoints=[context.target.url],
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    validation_status=ValidationStatus.MANUAL_REVIEW,
                    evidence=[
                        EvidenceRecord(
                            kind="options_response",
                            summary=f"Allow header advertised: {', '.join(sorted(allow))}",
                            location=context.target.url,
                        )
                    ],
                    source_plugins=[self.name],
                    cwe=["CWE-749"],
                    owasp=["A05:2021"],
                    remediation="Disable methods the application does not require and enforce authorization on state-changing methods.",
                    manual_review=True,
                    metadata={"advertised_methods": sorted(allow)},
                )
            )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            findings=findings,
            metrics={"requests": 1},
        )


class ParameterAnalysisPlugin(AssessmentPlugin):
    name = "parameter_analysis"
    # Wait until seed-page HTML discovery has been merged into the shared
    # inventory. The generic ``endpoints`` capability is produced by the seed
    # request itself, so using it alone lets this plugin race ahead and miss
    # query parameters on links and forms discovered in the response body.
    requires = frozenset({"endpoints", "html_discovery_complete"})
    produces = frozenset({"parameter_candidates"})
    owasp = ("A01:2021", "A03:2021", "A10:2021")

    CATEGORIES = {
        "sqli": re.compile(r"(^|_)(id|query|search|filter|sort|where|user|account)(_|$)", re.I),
        "xss": re.compile(r"(^|_)(q|query|search|name|message|comment|return)(_|$)", re.I),
        "redirect": re.compile(r"(^|_)(url|uri|redirect|return|next|continue|dest)(_|$)", re.I),
        "path": re.compile(r"(^|_)(file|path|folder|template|page|document|include)(_|$)", re.I),
        "ssrf": re.compile(r"(^|_)(url|uri|webhook|callback|proxy|fetch|image|import)(_|$)", re.I),
        "idor": re.compile(r"(^|_)(id|user_id|account_id|order_id|object_id|uuid)(_|$)", re.I),
    }

    async def run(self, context: PluginContext) -> PluginResult:
        observations: list[RawObservation] = []
        endpoints = list(context.inventory.endpoints.values())
        # The runtime merges this plugin's input capability before plugins run; include seed query directly.
        if not endpoints:
            endpoints = [_endpoint(context.target.url, self.name)]
        for endpoint in endpoints:
            for parameter in endpoint.parameters:
                categories = [name for name, regex in self.CATEGORIES.items() if regex.search(parameter.normalized_name)]
                parameter.risk_categories = sorted(set(parameter.risk_categories + categories))
                parameter.risk_score = min(10.0, 1.5 * len(categories) + (1 if parameter.location == "query" else 0))
                for category in categories:
                    if category == "xss":
                        context.queues.xss.append((endpoint.url, parameter.name))
                    elif category == "sqli":
                        context.queues.sqli.append((endpoint.url, parameter.name))
                    elif category == "ssrf":
                        context.queues.ssrf.append((endpoint.url, parameter.name))
                    elif category == "idor":
                        context.queues.idor.append((endpoint.url, parameter.name))
                    elif category == "path":
                        context.queues.path.append((endpoint.url, parameter.name))
                    elif category == "redirect":
                        context.queues.redirect.append((endpoint.url, parameter.name))
                if categories:
                    observations.append(
                        RawObservation(
                            plugin=self.name,
                            observation_type="parameter_risk_classification",
                            target=endpoint.url,
                            data={"parameter": parameter.name, "location": parameter.location, "categories": categories},
                            confidence=Confidence.MEDIUM,
                        )
                    )
        findings: list[FindingCandidate] = []
        for queue_name, queue in (("ssrf", context.queues.ssrf), ("idor_bola", context.queues.idor)):
            for endpoint, parameter in queue[: context.config.rate.max_candidates]:
                findings.append(
                    FindingCandidate(
                        finding_type=queue_name,
                        family="access_control" if queue_name == "idor_bola" else "ssrf",
                        title=("Potential IDOR/BOLA parameter" if queue_name == "idor_bola" else "Potential SSRF parameter"),
                        description="The parameter name and context indicate a candidate, but exploitability was not automatically asserted.",
                        asset=_origin(endpoint),
                        affected_endpoints=[endpoint],
                        parameters=[parameter],
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        validation_status=ValidationStatus.MANUAL_REVIEW,
                        evidence=[
                            EvidenceRecord(
                                kind="parameter_classification",
                                summary=f"Parameter {parameter} classified as {queue_name} candidate",
                                location=endpoint,
                            )
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-639" if queue_name == "idor_bola" else "CWE-918"],
                        owasp=["A01:2021" if queue_name == "idor_bola" else "A10:2021"],
                        remediation="Validate server-side authorization and strictly constrain user-controlled destinations.",
                        manual_review=True,
                        metadata={
                            "review_reason": "External unauthenticated evidence cannot prove authorization semantics safely",
                            "suggested_steps": [
                                "Use operator-approved test identities for differential authorization checks",
                                "Do not probe internal address space without separate authorization",
                            ],
                            "attack_path_relevance": "May become chainable if sensitive anonymous behavior is confirmed",
                        },
                    )
                )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            observations=observations,
            findings=findings,
            metrics={
                "xss_candidates": len(context.queues.xss),
                "sqli_candidates": len(context.queues.sqli),
                "ssrf_candidates": len(context.queues.ssrf),
                "idor_candidates": len(context.queues.idor),
                "redirect_candidates": len(context.queues.redirect),
                "path_candidates": len(context.queues.path),
            },
        )


class JavaScriptAnalysisPlugin(AssessmentPlugin):
    name = "javascript_analysis"
    requires = frozenset({"javascript_urls"})
    produces = frozenset({"javascript_content", "javascript_endpoints", "source_map_candidates"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP, ScanProfile.DISCOVERY_ONLY})
    owasp = ("A06:2021", "A08:2021")

    ENDPOINT_RE = re.compile(r"['\"]((?:/|https?://)[A-Za-z0-9_./?=&%:-]{2,})['\"]")
    MAP_RE = re.compile(r"(?im)[#@]\s*sourceMappingURL\s*=\s*(\S+)")
    WS_RE = re.compile(r"['\"](wss?://[^'\"\s]+)['\"]", re.I)

    async def run(self, context: PluginContext) -> PluginResult:
        javascript_urls = sorted(
            {
                endpoint.url
                for endpoint in context.inventory.endpoints.values()
                if urlsplit(endpoint.url).path.lower().endswith((".js", ".mjs"))
            }
        )[: min(context.config.rate.max_endpoints, 100)]
        if not javascript_urls:
            return PluginResult(
                plugin=self.name,
                state=PluginState.NOT_APPLICABLE,
                message="No in-scope JavaScript URLs were discovered",
            )
        endpoints: list[EndpointRecord] = []
        findings: list[FindingCandidate] = []
        observations: list[RawObservation] = []
        semaphore = asyncio.Semaphore(min(context.config.rate.plugin_concurrency, 6))

        async with httpx.AsyncClient(
            timeout=context.config.rate.request_timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "Wraith-Crawler/0.1"},
        ) as client:
            async def fetch(url: str) -> tuple[str, httpx.Response | None]:
                async with semaphore:
                    try:
                        response = await client.get(url)
                    except httpx.HTTPError:
                        return url, None
                    return url, response

            responses = await asyncio.gather(*(fetch(url) for url in javascript_urls))
        for url, response in responses:
            if response is None or response.status_code != 200 or len(response.content) > 2_000_000:
                continue
            content_type = response.headers.get("content-type", "").lower()
            if "javascript" not in content_type and not urlsplit(url).path.lower().endswith((".js", ".mjs")):
                continue
            content = response.text
            context.javascript_content[url] = content
            endpoints.append(_endpoint(url, self.name, status_code=200, content_type=content_type))
            discovered: list[str] = []
            for raw in self.ENDPOINT_RE.findall(content):
                try:
                    candidate = context.scope.resolve(raw, url)
                except ValueError:
                    continue
                if context.scope.check(candidate).allowed:
                    endpoints.append(_endpoint(candidate, self.name, javascript_source=url))
                    discovered.append(candidate)
            for raw in self.MAP_RE.findall(content):
                try:
                    map_url = context.scope.resolve(raw, url)
                except ValueError:
                    continue
                if context.scope.check(map_url).allowed:
                    endpoints.append(_endpoint(map_url, self.name, javascript_source=url))
                    findings.append(
                        FindingCandidate(
                            finding_type="source_map_exposure",
                            family="client_side_exposure",
                            title="JavaScript source map reference discovered",
                            description="A downloaded JavaScript asset references a potentially public source map.",
                            asset=_origin(url),
                            affected_endpoints=[map_url],
                            severity=Severity.LOW,
                            confidence=Confidence.MEDIUM,
                            validation_status=ValidationStatus.SUSPECTED,
                            evidence=[
                                EvidenceRecord(
                                    kind="source_map_reference",
                                    summary=f"sourceMappingURL in {url}",
                                    location=map_url,
                                )
                            ],
                            source_plugins=[self.name],
                            cwe=["CWE-200"],
                            owasp=["A08:2021"],
                            remediation="Remove production source maps when unnecessary and ensure builds contain no secrets or internal-only source.",
                            manual_review=True,
                        )
                    )
            for ws_url in self.WS_RE.findall(content):
                findings.append(
                    FindingCandidate(
                        finding_type="websocket_endpoint",
                        family="realtime_surface",
                        title="WebSocket endpoint discovered",
                        description="Client JavaScript references a WebSocket endpoint. It is queued for safe handshake and authorization review.",
                        asset=_origin(url),
                        affected_endpoints=[ws_url],
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.HIGH,
                        validation_status=ValidationStatus.MANUAL_REVIEW,
                        evidence=[
                            EvidenceRecord(
                                kind="javascript_reference",
                                summary=f"WebSocket URL referenced by {url}",
                                location=ws_url,
                            )
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-284"],
                        owasp=["A01:2021"],
                        remediation="Enforce origin, authentication and per-message authorization controls on the WebSocket handshake and channel.",
                        manual_review=True,
                    )
                )
            observations.append(
                RawObservation(
                    plugin=self.name,
                    observation_type="javascript_analysis",
                    target=url,
                    data={"bytes": len(response.content), "endpoints": discovered},
                    confidence=Confidence.HIGH,
                )
            )
        state = PluginState.COMPLETED if context.javascript_content else PluginState.PARTIAL
        return PluginResult(
            plugin=self.name,
            state=state,
            failure_reason=None if context.javascript_content else FailureReason.TARGET_UNREACHABLE,
            capabilities_produced=set(self.produces) if context.javascript_content else set(),
            endpoints=endpoints,
            observations=observations,
            findings=findings,
            metrics={"requested": len(javascript_urls), "downloaded": len(context.javascript_content)},
            partial_output_trustworthy=bool(context.javascript_content),
        )


class GraphQLDiscoveryPlugin(AssessmentPlugin):
    name = "graphql_discovery"
    requires = frozenset({"api_candidates"})
    produces = frozenset({"graphql_assessment"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP, ScanProfile.DISCOVERY_ONLY})
    owasp = ("A01:2021", "A05:2021")

    async def run(self, context: PluginContext) -> PluginResult:
        urls = {
            endpoint.url
            for endpoint in context.inventory.endpoints.values()
            if "graphql" in endpoint.path.lower()
        }
        urls.add(urljoin(_origin(context.target.url), "/graphql"))
        endpoints: list[EndpointRecord] = []
        findings: list[FindingCandidate] = []
        async with httpx.AsyncClient(timeout=context.config.rate.request_timeout_seconds, follow_redirects=False) as client:
            for url in sorted(urls)[:10]:
                if not context.scope.check(url).allowed:
                    continue
                try:
                    response = await client.post(
                        url,
                        json={"query": "query WraithSchemaCheck { __schema { queryType { name } } }"},
                        headers={"User-Agent": "Wraith-Crawler/0.1"},
                    )
                except httpx.HTTPError:
                    continue
                endpoints.append(
                    _endpoint(
                        url,
                        self.name,
                        method="POST",
                        status_code=response.status_code,
                        content_type=response.headers.get("content-type"),
                        api_classification="graphql",
                    )
                )
                try:
                    payload = response.json()
                except ValueError:
                    continue
                introspection = response.status_code == 200 and isinstance(payload, dict) and isinstance(payload.get("data"), dict) and payload["data"].get("__schema")
                if introspection:
                    findings.append(
                        FindingCandidate(
                            finding_type="graphql_introspection",
                            family="api_security",
                            title="GraphQL introspection is available anonymously",
                            description="A safe schema query returned GraphQL schema metadata without credentials.",
                            asset=_origin(url),
                            affected_endpoints=[url],
                            method="POST",
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            validation_status=ValidationStatus.CONFIRMED,
                            evidence=[
                                EvidenceRecord(
                                    kind="graphql_response",
                                    summary="Anonymous __schema query returned a query type",
                                    location=url,
                                    response={"status": response.status_code, "schema_present": True},
                                )
                            ],
                            source_plugins=[self.name],
                            cwe=["CWE-200"],
                            owasp=["A05:2021"],
                            remediation="Disable production introspection when not required, while prioritizing field-level authorization and query controls.",
                        )
                    )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            endpoints=endpoints,
            findings=findings,
            metrics={"candidates": len(urls)},
        )


class RedirectTraversalAnalysisPlugin(AssessmentPlugin):
    name = "redirect_traversal_analysis"
    requires = frozenset({"parameter_candidates"})
    produces = frozenset({"redirect_traversal_assessment"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP})
    owasp = ("A01:2021", "A03:2021")

    async def run(self, context: PluginContext) -> PluginResult:
        findings: list[FindingCandidate] = []
        for endpoint, parameter in context.queues.path[: context.config.rate.max_candidates]:
            findings.append(
                FindingCandidate(
                    finding_type="path_traversal_candidate",
                    family="injection",
                    title="Potential path traversal or file inclusion parameter",
                    description="The parameter context is path-like. No server file was requested automatically.",
                    asset=_origin(endpoint),
                    affected_endpoints=[endpoint],
                    parameters=[parameter],
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    validation_status=ValidationStatus.MANUAL_REVIEW,
                    evidence=[
                        EvidenceRecord(
                            kind="parameter_classification",
                            summary=f"Parameter {parameter} classified as file/path input",
                            location=endpoint,
                        )
                    ],
                    source_plugins=[self.name],
                    cwe=["CWE-22"],
                    owasp=["A03:2021"],
                    remediation="Canonicalize and allowlist server-side file identifiers; never concatenate user input into filesystem paths.",
                    manual_review=True,
                    metadata={
                        "review_reason": "Automated file probes were avoided to preserve a non-destructive evidence boundary",
                        "suggested_steps": ["Use an operator-approved benign fixture file for differential validation"],
                    },
                )
            )
        # Redirect validation uses an invalid, non-resolving public domain and never follows the response.
        async with httpx.AsyncClient(timeout=context.config.rate.request_timeout_seconds, follow_redirects=False) as client:
            for endpoint, parameter in context.queues.redirect[:25]:
                parts = urlsplit(endpoint)
                query = dict(parse_qsl(parts.query, keep_blank_values=True))
                query[parameter] = "https://wraith.invalid/redirect-check"
                from urllib.parse import urlencode, urlunsplit

                probe = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
                try:
                    response = await client.get(probe, headers={"User-Agent": "Wraith-Crawler/0.1"})
                except httpx.HTTPError:
                    continue
                location = response.headers.get("location", "")
                if response.status_code in {301, 302, 303, 307, 308} and location.startswith("https://wraith.invalid"):
                    findings.append(
                        FindingCandidate(
                            finding_type="open_redirect",
                            family="access_control",
                            title="Open redirect validated",
                            description="A synthetic external URL was reflected into a redirect Location without following it.",
                            asset=_origin(endpoint),
                            affected_endpoints=[endpoint],
                            parameters=[parameter],
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            validation_status=ValidationStatus.CONFIRMED,
                            evidence=[
                                EvidenceRecord(
                                    kind="redirect_response",
                                    summary=f"HTTP {response.status_code} Location points to wraith.invalid",
                                    location=endpoint,
                                    response={"status": response.status_code, "location": location},
                                )
                            ],
                            source_plugins=[self.name],
                            cwe=["CWE-601"],
                            owasp=["A01:2021"],
                            remediation="Allowlist relative paths or trusted destinations and reject scheme-relative and external URLs.",
                        )
                    )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            findings=findings,
            metrics={"redirect_candidates": len(context.queues.redirect), "path_candidates": len(context.queues.path)},
        )


class SecretsPlugin(AssessmentPlugin):
    name = "secret_exposure"
    requires = frozenset({"http_metadata"})
    produces = frozenset({"secret_assessment"})
    owasp = ("A02:2021", "A08:2021")
    cwe = ("CWE-798", "CWE-200")

    PATTERNS = {
        "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,255}\b"),
        "stripe_secret": re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "connection_string": re.compile(r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s'\"]+"),
    }

    async def run(self, context: PluginContext) -> PluginResult:
        snapshot = context.http_snapshots[context.target.url]
        findings: list[FindingCandidate] = []
        for secret_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(snapshot.body):
                value = match.group(0)
                digest = hashlib.sha256(value.encode()).hexdigest()
                findings.append(
                    FindingCandidate(
                        finding_type="secret_exposure",
                        family="secrets",
                        title=f"Potential {secret_type.replace('_', ' ')} exposed in client content",
                        description="A known-format credential pattern was present in a publicly reachable response. The value is never used automatically.",
                        asset=_origin(snapshot.url),
                        affected_endpoints=[snapshot.url],
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        validation_status=ValidationStatus.SUSPECTED,
                        evidence=[
                            EvidenceRecord(
                                kind="redacted_secret_match",
                                summary=f"{secret_type} pattern at offset {match.start()}, fingerprint {digest[:12]}",
                                location=snapshot.url,
                                fingerprint=digest,
                                sensitive=True,
                            )
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-798", "CWE-200"],
                        owasp=["A02:2021", "A08:2021"],
                        remediation="Revoke the value, remove it from public artifacts and history, and move secrets to a server-side secret manager.",
                        manual_review=True,
                        metadata={
                            "secret_type": secret_type,
                            "secret_fingerprint": digest,
                            "sensitive_context": True,
                            "review_reason": "Validity is intentionally not tested against a third-party service",
                        },
                    )
                )
        return self.success(self.name, capabilities_produced=set(self.produces), findings=findings)


class FingerprintingPlugin(AssessmentPlugin):
    name = "technology_fingerprinting"
    description = "Passive web-server and client-framework fingerprinting"
    requires = frozenset({"http_metadata"})
    produces = frozenset({"technologies"})
    owasp = ("A06:2021",)

    async def run(self, context: PluginContext) -> PluginResult:
        snapshot = context.http_snapshots[context.target.url]
        technologies: list[TechnologyRecord] = []
        server = snapshot.headers.get("server")
        if server:
            product, _, version = server.partition("/")
            technologies.append(
                TechnologyRecord(
                    product=product.strip(),
                    version=version.strip() or None,
                    category="web_server",
                    confidence=Confidence.HIGH,
                    evidence=[f"Server header: {server}"],
                    source_plugin=self.name,
                )
            )
        powered = snapshot.headers.get("x-powered-by")
        if powered:
            product, _, version = powered.partition("/")
            technologies.append(
                TechnologyRecord(
                    product=product.strip(),
                    version=version.strip() or None,
                    category="framework",
                    confidence=Confidence.HIGH,
                    evidence=[f"X-Powered-By header: {powered}"],
                    source_plugin=self.name,
                )
            )
        signatures = {
            "React": (r"__REACT_DEVTOOLS_GLOBAL_HOOK__|data-reactroot", "javascript_framework"),
            "Angular": (r"ng-version=|app-root", "javascript_framework"),
        }
        for product, (pattern, category) in signatures.items():
            if re.search(pattern, snapshot.body, re.I):
                technologies.append(
                    TechnologyRecord(
                        product=product,
                        category=category,
                        confidence=Confidence.MEDIUM,
                        evidence=[f"HTML signature matched {pattern}"],
                        source_plugin=self.name,
                    )
                )
        return self.success(
            self.name, capabilities_produced=set(self.produces), technologies=technologies
        )


class CMSDetectionPlugin(AssessmentPlugin):
    name = "cms_detection"
    description = "Passive multi-signal CMS and hosted-site-platform detection"
    requires = frozenset({"http_metadata"})
    produces = frozenset({"cms_detection", "technologies"})
    owasp = ("A06:2021",)

    GENERATOR_PATTERNS = {
        "WordPress": re.compile(r"\bWordPress(?:\s+([0-9][0-9A-Za-z._-]*))?", re.I),
        "Drupal": re.compile(r"\bDrupal(?:\s+([0-9][0-9A-Za-z._-]*))?", re.I),
        "Joomla": re.compile(r"\bJoomla!?(?:\s+([0-9][0-9A-Za-z._-]*))?", re.I),
        "Magento": re.compile(r"\bMagento(?:\s+([0-9][0-9A-Za-z._-]*))?", re.I),
        "Ghost": re.compile(r"\bGhost(?:\s+([0-9][0-9A-Za-z._-]*))?", re.I),
        "TYPO3": re.compile(r"\bTYPO3(?:\s+CMS)?(?:\s+([0-9][0-9A-Za-z._-]*))?", re.I),
        "Umbraco": re.compile(r"\bUmbraco(?:\s+([0-9][0-9A-Za-z._-]*))?", re.I),
    }
    BODY_SIGNATURES = {
        "WordPress": (
            ("wp-content or wp-includes asset path", re.compile(r"/wp-(?:content|includes)/", re.I), 2),
            ("WordPress REST API reference", re.compile(r"api\.w\.org|/wp-json(?:/|[\"'])", re.I), 2),
        ),
        "Drupal": (
            ("Drupal settings or public asset path", re.compile(r"drupalSettings|/sites/(?:default|all)/(?:files|modules|themes)/", re.I), 2),
        ),
        "Joomla": (
            ("Joomla component or system-media path", re.compile(r"/media/system/(?:js|css)/|/components/com_|[?&]option=com_", re.I), 2),
        ),
        "Magento": (
            ("Magento client or versioned static asset", re.compile(r"Magento_[A-Za-z]|mage/cookies|/static/version[0-9]+/", re.I), 2),
        ),
        "Shopify": (
            ("Shopify CDN or theme marker", re.compile(r"cdn\.shopify\.com|Shopify\.theme|shopify-section", re.I), 3),
        ),
        "Ghost": (
            ("Ghost content or client marker", re.compile(r"/ghost/|ghost\.io|data-ghost", re.I), 2),
        ),
        "TYPO3": (
            ("TYPO3 public asset path", re.compile(r"/typo3conf/|/typo3temp/|/typo3/sysext/", re.I), 2),
        ),
        "Umbraco": (
            ("Umbraco public path or marker", re.compile(r"/umbraco/|data-umbraco", re.I), 2),
        ),
        "Wix": (
            ("Wix static asset or SDK marker", re.compile(r"static\.wixstatic\.com|wix-code-sdk", re.I), 3),
        ),
        "Squarespace": (
            ("Squarespace static asset or runtime marker", re.compile(r"static[0-9]*\.squarespace\.com|Squarespace\.context|squarespace-cdn\.com", re.I), 3),
        ),
    }
    HEADER_SIGNATURES = {
        "WordPress": (("WordPress REST API Link header", re.compile(r"api\.w\.org", re.I), 2),),
        "Drupal": (("Drupal cache header", re.compile(r"^x-drupal-(?:cache|dynamic-cache):", re.I | re.M), 3),),
        "Magento": (("Magento variation header", re.compile(r"^x-magento-vary:", re.I | re.M), 3),),
        "Shopify": (("Shopify response header", re.compile(r"^x-(?:shopid|shopify)[^:]*:", re.I | re.M), 3),),
        "Wix": (("Wix response header", re.compile(r"^x-wix-", re.I | re.M), 3),),
    }
    COOKIE_NAME_PATTERNS = {
        "WordPress": re.compile(r"^(?:wordpress_|wordpress_logged_in_|wp-settings-)", re.I),
        "Drupal": re.compile(r"^(?:S?SESS)[A-Za-z0-9_-]+$"),
        "Magento": re.compile(r"^(?:private_content_version|section_data_ids)$", re.I),
        "Shopify": re.compile(r"^_shopify_", re.I),
    }
    CATEGORIES = {
        "Magento": "ecommerce_cms",
        "Shopify": "hosted_ecommerce_cms",
        "Wix": "hosted_cms",
        "Squarespace": "hosted_cms",
    }

    @staticmethod
    def _generator_values(body: str) -> list[str]:
        values: list[str] = []
        for tag in re.findall(r"<meta\b[^>]*>", body, re.I):
            name = re.search(r"\bname\s*=\s*(['\"])generator\1", tag, re.I)
            content = re.search(r"\bcontent\s*=\s*(['\"])(.*?)\1", tag, re.I | re.S)
            if name and content:
                values.append(html.unescape(content.group(2)).strip())
        return values

    @classmethod
    def detect(cls, snapshot: HTTPResponseSnapshot) -> list[TechnologyRecord]:
        products = set(cls.BODY_SIGNATURES) | set(cls.HEADER_SIGNATURES) | set(cls.GENERATOR_PATTERNS)
        scores = {product: 0 for product in products}
        evidence: dict[str, list[str]] = {product: [] for product in products}
        versions: dict[str, str | None] = {product: None for product in products}

        for generator in cls._generator_values(snapshot.body):
            for product, pattern in cls.GENERATOR_PATTERNS.items():
                match = pattern.search(generator)
                if not match:
                    continue
                scores[product] += 4
                evidence[product].append(f"Generator meta tag identifies {product}")
                if match.lastindex and match.group(1):
                    versions[product] = match.group(1).rstrip(".,;")

        for product, signatures in cls.BODY_SIGNATURES.items():
            for label, pattern, weight in signatures:
                if pattern.search(snapshot.body):
                    scores[product] += weight
                    evidence[product].append(label)

        header_text = "\n".join(
            f"{key}: {value}"
            for key, value in snapshot.headers.items()
            if key.lower() != "set-cookie"
        )
        for product, signatures in cls.HEADER_SIGNATURES.items():
            for label, pattern, weight in signatures:
                if pattern.search(header_text):
                    scores[product] += weight
                    evidence[product].append(label)

        cookie_names = [
            name for name, _attributes in _parse_set_cookie_header(snapshot.headers.get("set-cookie", ""))
        ]
        for product, pattern in cls.COOKIE_NAME_PATTERNS.items():
            if any(pattern.search(name) for name in cookie_names):
                scores[product] += 2
                evidence[product].append(f"{product}-specific cookie name")

        technologies: list[TechnologyRecord] = []
        for product in sorted(products):
            if scores[product] < 2:
                continue
            technologies.append(
                TechnologyRecord(
                    product=product,
                    version=versions[product],
                    category=cls.CATEGORIES.get(product, "cms"),
                    confidence=Confidence.HIGH if scores[product] >= 4 else Confidence.MEDIUM,
                    evidence=sorted(set(evidence[product])),
                    source_plugin=cls.name,
                )
            )
        return technologies

    async def run(self, context: PluginContext) -> PluginResult:
        technologies = self.detect(context.http_snapshots[context.target.url])
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            technologies=technologies,
            observations=[
                RawObservation(
                    plugin=self.name,
                    observation_type="cms_fingerprints",
                    target=context.target.url,
                    data={
                        "detected": [
                            {
                                "product": technology.product,
                                "version": technology.version,
                                "category": technology.category,
                                "confidence": technology.confidence.value,
                                "signal_count": len(technology.evidence),
                            }
                            for technology in technologies
                        ]
                    },
                    confidence=Confidence.HIGH if technologies else Confidence.MEDIUM,
                )
            ],
            metrics={"cms_detected": len(technologies)},
        )


class DirectoryListingPlugin(AssessmentPlugin):
    name = "directory_listing"
    description = "Bounded verification of directory indexes derived from discovered in-scope paths"
    requires = frozenset({"http_metadata", "html_discovery_complete"})
    produces = frozenset({"directory_listing_assessment"})
    owasp = ("A05:2021",)
    cwe = ("CWE-548",)
    timeout_seconds = 60

    MAX_CANDIDATES = 10
    BODY_LIMIT = 1_048_576
    SIGNATURES = {
        "index_title": re.compile(r"<title[^>]*>\s*(?:index of|directory listing for)\b", re.I),
        "index_heading": re.compile(r"<h1[^>]*>\s*(?:index of|directory listing for)\b", re.I),
        "parent_directory": re.compile(r"(?:href\s*=\s*['\"]\.\./['\"]|parent directory|\[to parent directory\])", re.I),
        "listing_columns": re.compile(r"(?:last modified|last modification|\bname\b.{0,80}\bsize\b)", re.I | re.S),
        "iis_listing": re.compile(r"directory listing\s*--\s*/", re.I),
    }

    @classmethod
    def detect_signatures(cls, body: str) -> list[str]:
        matches = [name for name, pattern in cls.SIGNATURES.items() if pattern.search(body)]
        index_marker = any(name in matches for name in ("index_title", "index_heading", "iis_listing"))
        structure_marker = any(name in matches for name in ("parent_directory", "listing_columns"))
        return matches if index_marker and structure_marker else []

    @staticmethod
    def candidate_urls(context: PluginContext) -> list[str]:
        origin = _origin(context.target.url)
        paths = {"/"}
        for endpoint in context.inventory.endpoints.values():
            path = urlsplit(endpoint.url).path or "/"
            if path.endswith("/"):
                directory = path
            else:
                parent = path.rsplit("/", 1)[0]
                directory = f"{parent}/" if parent else "/"
            paths.add(directory)
        urls = {
            canonical_url(urljoin(f"{origin}/", path.lstrip("/")))
            for path in paths
        }
        return sorted(
            (url for url in urls if context.scope.check(url).allowed),
            key=lambda value: (urlsplit(value).path.count("/"), value),
        )

    async def run(self, context: PluginContext) -> PluginResult:
        candidates = self.candidate_urls(context)[
            : min(self.MAX_CANDIDATES, context.config.rate.max_candidates)
        ]
        seed = context.http_snapshots[context.target.url]
        cached = {canonical_url(seed.url): seed}
        endpoints: list[EndpointRecord] = []
        findings: list[FindingCandidate] = []
        matches: list[dict[str, object]] = []
        failed_requests = 0
        network_requests = 0
        request_interval = 1.0 / max(context.config.rate.global_requests_per_second, 0.1)

        async with httpx.AsyncClient(
            timeout=min(context.config.rate.request_timeout_seconds, 5.0),
            follow_redirects=False,
            headers={"User-Agent": "Wraith-Crawler/0.1 authorized-security-assessment"},
        ) as client:
            for url in candidates:
                snapshot = cached.get(url)
                truncated = False
                if snapshot is None:
                    if network_requests:
                        await asyncio.sleep(request_interval)
                    started = time.monotonic()
                    try:
                        async with client.stream("GET", url) as response:
                            body_bytes = bytearray()
                            async for chunk in response.aiter_bytes():
                                remaining = self.BODY_LIMIT - len(body_bytes)
                                if remaining <= 0:
                                    truncated = True
                                    break
                                body_bytes.extend(chunk[:remaining])
                                if len(chunk) > remaining:
                                    truncated = True
                                    break
                            encoding = response.encoding or "utf-8"
                            snapshot = HTTPResponseSnapshot(
                                url=str(response.url),
                                status_code=response.status_code,
                                headers={
                                    key.lower(): value for key, value in response.headers.items()
                                },
                                body=bytes(body_bytes).decode(encoding, errors="replace"),
                                elapsed_ms=int((time.monotonic() - started) * 1000),
                            )
                    except httpx.HTTPError:
                        failed_requests += 1
                        network_requests += 1
                        continue
                    network_requests += 1
                    context.http_snapshots[url] = snapshot

                endpoints.append(
                    _endpoint(
                        url,
                        self.name,
                        status_code=snapshot.status_code,
                        content_type=snapshot.headers.get("content-type"),
                        response_metadata={"body_truncated": truncated},
                        confidence=Confidence.CONFIRMED,
                    )
                )
                content_type = snapshot.headers.get("content-type", "").split(";", 1)[0].lower()
                if snapshot.status_code < 200 or snapshot.status_code >= 300:
                    continue
                if content_type and not (
                    content_type.startswith("text/") or content_type == "application/xhtml+xml"
                ):
                    continue
                signatures = self.detect_signatures(snapshot.body)
                if not signatures:
                    continue
                matches.append({"url": url, "signatures": signatures})
                findings.append(
                    FindingCandidate(
                        finding_type="directory_listing",
                        family="security_misconfiguration",
                        title="Directory indexing appears enabled",
                        description=(
                            "A bounded GET request returned multiple independent directory-index markers "
                            "at an evidence-derived in-scope path."
                        ),
                        asset=_origin(url),
                        affected_endpoints=[url],
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        validation_status=ValidationStatus.SUSPECTED,
                        evidence=[
                            EvidenceRecord(
                                kind="directory_index_response",
                                summary=f"Directory index markers: {', '.join(signatures)}",
                                location=url,
                                response={
                                    "status": snapshot.status_code,
                                    "content_type": content_type or None,
                                    "signatures": signatures,
                                    "body_truncated": truncated,
                                },
                            )
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-548"],
                        owasp=["A05:2021"],
                        remediation=(
                            "Disable directory indexing, remove unintended artifacts, and explicitly publish "
                            "only required files."
                        ),
                    )
                )

        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            endpoints=endpoints,
            findings=findings,
            observations=[
                RawObservation(
                    plugin=self.name,
                    observation_type="directory_listing_checks",
                    target=context.target.url,
                    data={
                        "candidate_count": len(candidates),
                        "matches": matches,
                        "failed_requests": failed_requests,
                    },
                    confidence=Confidence.HIGH,
                )
            ],
            metrics={
                "candidates": len(candidates),
                "network_requests": network_requests,
                "failed_requests": failed_requests,
                "directory_listings": len(findings),
            },
        )


class PassiveExposurePlugin(AssessmentPlugin):
    name = "passive_exposure"
    requires = frozenset({"http_metadata", "endpoints"})
    produces = frozenset({"passive_exposure_assessment"})
    owasp = ("A01:2021", "A05:2021", "A08:2021")

    async def run(self, context: PluginContext) -> PluginResult:
        snapshot = context.http_snapshots[context.target.url]
        findings: list[FindingCandidate] = []
        body = snapshot.body
        if re.search(r"(?i)(traceback \(most recent call last\)|stack trace:|exception in thread|debug=true)", body):
            findings.append(
                FindingCandidate(
                    finding_type="verbose_error",
                    family="security_misconfiguration",
                    title="Verbose error or stack trace exposed",
                    description="The public response includes a stack-trace or debug signature.",
                    asset=_origin(snapshot.url),
                    affected_endpoints=[snapshot.url],
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    validation_status=ValidationStatus.CONFIRMED,
                    evidence=[
                        EvidenceRecord(
                            kind="response_signature", summary="Verbose exception signature observed", location=snapshot.url
                        )
                    ],
                    source_plugins=[self.name],
                    cwe=["CWE-209"],
                    owasp=["A05:2021"],
                    remediation="Return generic production error pages and retain diagnostic details only in protected logs.",
                )
            )
        for endpoint in context.inventory.endpoints.values():
            path = endpoint.path.lower()
            if any(token in path for token in ("swagger", "openapi", "api-docs")):
                findings.append(
                    FindingCandidate(
                        finding_type="openapi_exposure",
                        family="api_security",
                        title="API documentation is publicly discoverable",
                        description="A Swagger or OpenAPI resource was linked from public application content.",
                        asset=_origin(endpoint.url),
                        affected_endpoints=[endpoint.url],
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.MEDIUM,
                        validation_status=ValidationStatus.SUSPECTED,
                        evidence=[
                            EvidenceRecord(kind="discovered_endpoint", summary="API documentation path discovered", location=endpoint.url)
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-200"],
                        owasp=["A05:2021"],
                        remediation="Restrict operational API documentation when it is not intended for public consumers.",
                    )
                )
            if "graphql" in path:
                findings.append(
                    FindingCandidate(
                        finding_type="graphql_endpoint",
                        family="api_security",
                        title="GraphQL endpoint discovered",
                        description="A likely GraphQL endpoint is reachable or referenced and should be reviewed for anonymous query access and introspection.",
                        asset=_origin(endpoint.url),
                        affected_endpoints=[endpoint.url],
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.MEDIUM,
                        validation_status=ValidationStatus.MANUAL_REVIEW,
                        evidence=[
                            EvidenceRecord(kind="discovered_endpoint", summary="GraphQL path discovered", location=endpoint.url)
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-200"],
                        owasp=["A01:2021"],
                        remediation="Disable production IDEs, limit introspection as appropriate, and enforce field-level authorization.",
                        manual_review=True,
                    )
                )
        return self.success(self.name, capabilities_produced=set(self.produces), findings=findings)


class RobotsSitemapPlugin(AssessmentPlugin):
    name = "robots_sitemap"
    requires = frozenset({"validated_origin"})
    produces = frozenset({"robots_sitemap_paths"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP, ScanProfile.DISCOVERY_ONLY})

    async def run(self, context: PluginContext) -> PluginResult:
        endpoints: list[EndpointRecord] = []
        observations: list[RawObservation] = []
        async with httpx.AsyncClient(timeout=context.config.rate.request_timeout_seconds) as client:
            for path in ("/robots.txt", "/sitemap.xml"):
                url = urljoin(_origin(context.target.url), path)
                try:
                    response = await client.get(url, headers={"User-Agent": "Wraith-Crawler/0.1"})
                except httpx.HTTPError:
                    continue
                if response.status_code >= 400 or len(response.content) > 2_000_000:
                    continue
                endpoints.append(_endpoint(url, self.name, status_code=response.status_code, content_type=response.headers.get("content-type")))
                candidates = re.findall(r"(?im)^(?:allow|disallow|sitemap):\s*(\S+)|<loc>\s*([^<]+)", response.text)
                discovered: list[str] = []
                for match in candidates:
                    raw = next((item for item in match if item), "")
                    try:
                        candidate = context.scope.resolve(raw, url)
                    except ValueError:
                        continue
                    if context.scope.check(candidate).allowed:
                        endpoints.append(_endpoint(candidate, self.name))
                        discovered.append(candidate)
                observations.append(
                    RawObservation(
                        plugin=self.name,
                        observation_type="robots_sitemap",
                        target=url,
                        data={"status": response.status_code, "paths": discovered},
                        confidence=Confidence.CONFIRMED,
                    )
                )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            endpoints=endpoints,
            observations=observations,
            metrics={"requests": 2},
        )


class SensitiveFilesPlugin(AssessmentPlugin):
    name = "sensitive_files"
    requires = frozenset({"validated_origin"})
    produces = frozenset({"sensitive_file_assessment"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP})
    owasp = ("A05:2021", "A08:2021")

    PATHS = {
        "/.env": ("environment file", re.compile(r"(?im)^(?:DB_|DATABASE_|API_|SECRET_|APP_KEY)")),
        "/.git/HEAD": ("Git metadata", re.compile(r"^ref: refs/heads/")),
        "/web.config": ("IIS configuration", re.compile(r"(?i)<configuration[\s>]")),
        "/appsettings.json": ("application settings", re.compile(r'(?i)"(?:ConnectionStrings|Logging)"\s*:')),
        "/package.json": ("Node package manifest", re.compile(r'"(?:name|dependencies)"\s*:')),
        "/docker-compose.yml": ("Compose manifest", re.compile(r"(?im)^(?:services|version):")),
        "/.well-known/../backup.sql": ("database dump", re.compile(r"(?i)(CREATE TABLE|INSERT INTO)")),
    }

    async def run(self, context: PluginContext) -> PluginResult:
        origin = _origin(context.target.url)
        baseline = context.http_snapshots.get(context.target.url)
        baseline_hash = hashlib.sha256((baseline.body if baseline else "").encode()).hexdigest()
        findings: list[FindingCandidate] = []
        endpoints: list[EndpointRecord] = []
        async with httpx.AsyncClient(timeout=context.config.rate.request_timeout_seconds, follow_redirects=False) as client:
            for path, (label, validator) in self.PATHS.items():
                if ".." in path:
                    continue
                url = urljoin(origin, path)
                try:
                    response = await client.get(url, headers={"User-Agent": "Wraith-Crawler/0.1"})
                except httpx.HTTPError:
                    continue
                body = response.text[:1_000_000]
                body_hash = hashlib.sha256(body.encode()).hexdigest()
                valid = response.status_code == 200 and validator.search(body) and body_hash != baseline_hash
                endpoints.append(_endpoint(url, self.name, status_code=response.status_code, content_type=response.headers.get("content-type")))
                if not valid:
                    continue
                findings.append(
                    FindingCandidate(
                        finding_type="sensitive_file_exposure",
                        family="information_exposure",
                        title=f"Publicly accessible {label}",
                        description=f"The curated path {path} returned content matching deterministic {label} markers.",
                        asset=origin,
                        affected_endpoints=[url],
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        validation_status=ValidationStatus.CONFIRMED,
                        evidence=[
                            EvidenceRecord(
                                kind="validated_file_signature",
                                summary=f"HTTP 200 and deterministic {label} signature; body hash {body_hash[:12]}",
                                location=url,
                                sensitive=True,
                            )
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-200", "CWE-538"],
                        owasp=["A05:2021", "A08:2021"],
                        remediation="Remove the artifact from the web root, rotate any contained credentials, and block sensitive paths at the edge.",
                        metadata={"sensitive_context": True, "artifact_type": label},
                    )
                )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            endpoints=endpoints,
            findings=findings,
            metrics={"requests": len(self.PATHS)},
        )


class SourceMapPlugin(AssessmentPlugin):
    name = "source_maps"
    requires = frozenset({"http_metadata"})
    produces = frozenset({"source_map_candidates"})
    owasp = ("A08:2021",)

    async def run(self, context: PluginContext) -> PluginResult:
        snapshot = context.http_snapshots[context.target.url]
        references = re.findall(r"(?im)[#@]\s*sourceMappingURL\s*=\s*(\S+\.map(?:\?\S*)?)", snapshot.body)
        endpoints: list[EndpointRecord] = []
        findings: list[FindingCandidate] = []
        for raw in references:
            try:
                url = context.scope.resolve(raw, snapshot.url)
            except ValueError:
                continue
            if context.scope.check(url).allowed:
                endpoints.append(_endpoint(url, self.name))
                findings.append(
                    FindingCandidate(
                        finding_type="source_map_exposure",
                        family="client_side_exposure",
                        title="Public source map reference discovered",
                        description="Client content references a source map that may disclose original sources or internal configuration.",
                        asset=_origin(url),
                        affected_endpoints=[url],
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        validation_status=ValidationStatus.SUSPECTED,
                        evidence=[EvidenceRecord(kind="source_map_reference", summary="sourceMappingURL reference found", location=url)],
                        source_plugins=[self.name],
                        cwe=["CWE-200"],
                        owasp=["A08:2021"],
                        remediation="Do not publish production source maps unless required; remove secrets and internal-only metadata from builds.",
                        manual_review=True,
                    )
                )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            endpoints=endpoints,
            findings=findings,
        )


BUILTIN_PLUGINS = (
    SeedHTTPPlugin,
    TLSPlugin,
    HTMLDiscoveryPlugin,
    JavaScriptAnalysisPlugin,
    SecurityHeadersPlugin,
    CookieSecurityPlugin,
    CORSPlugin,
    HTTPMethodsPlugin,
    FingerprintingPlugin,
    CMSDetectionPlugin,
    DirectoryListingPlugin,
    PassiveExposurePlugin,
    RobotsSitemapPlugin,
    SensitiveFilesPlugin,
    SourceMapPlugin,
    SecretsPlugin,
    ParameterAnalysisPlugin,
    GraphQLDiscoveryPlugin,
    RedirectTraversalAnalysisPlugin,
)
