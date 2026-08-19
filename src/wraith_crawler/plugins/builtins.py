from __future__ import annotations

import asyncio
import hashlib
import html
import re
import socket
import ssl
import time
from datetime import UTC, datetime
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit

import httpx

from ..domain import (
    SENSITIVE_PARAMETER,
    AssetRecord,
    EndpointRecord,
    EvidenceRecord,
    FindingCandidate,
    ParameterRecord,
    PluginResult,
    RawObservation,
    TechnologyRecord,
    canonical_url,
)
from ..enums import (
    Confidence,
    FailureReason,
    PentestPhase,
    PluginState,
    ScanProfile,
    Severity,
    ValidationStatus,
)
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


class _DiscoveryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []
        self.forms: list[dict[str, object]] = []
        self.inline_scripts: list[str] = []
        self._form: dict[str, object] | None = None
        self._script: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value for key, value in attrs}
        if tag in {"a", "link"} and values.get("href"):
            self.urls.append(str(values["href"]))
        if tag in {"script", "img", "iframe", "source"} and values.get("src"):
            self.urls.append(str(values["src"]))
        if tag == "form":
            self._form = {
                "action": values.get("action") or "",
                "method": str(values.get("method") or "GET").upper(),
                "parameters": [],
            }
        elif self._form is not None and tag in {"input", "select", "textarea", "button"}:
            if values.get("name"):
                parameters = self._form["parameters"]
                assert isinstance(parameters, list)
                parameters.append(
                    {
                        "name": str(values["name"]),
                        "type": str(values.get("type") or tag),
                        "required": "required" in values,
                    }
                )
        if tag == "script" and not values.get("src"):
            self._script = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        if tag == "script" and self._script is not None:
            content = "".join(self._script).strip()
            if content:
                self.inline_scripts.append(content)
            self._script = None

    def handle_data(self, data: str) -> None:
        if self._script is not None:
            self._script.append(data)


class SeedHTTPPlugin(AssessmentPlugin):
    name = "seed_http"
    description = "Independent seed URL validation and HTTP metadata"
    requires = frozenset({"seed_url"})
    produces = frozenset({"http_metadata", "validated_origin", "endpoints"})
    timeout_seconds = 60
    phase = PentestPhase.RECONNAISSANCE
    security_question = "Is the supplied URL reachable, what HTTP service answers, and what redirects occur?"
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
                redirect_chain: list[str] = []
                visited = {canonical_url(context.target.url)}
                for _hop in range(10):
                    if not response.is_redirect or not response.headers.get("location"):
                        break
                    location = urljoin(str(response.url), response.headers["location"])
                    try:
                        normalized_location = canonical_url(location)
                    except ValueError:
                        break
                    redirect_chain.append(normalized_location)
                    if normalized_location in visited or not context.scope.check(
                        normalized_location
                    ).allowed:
                        break
                    visited.add(normalized_location)
                    response = await client.get(normalized_location)
                    requests += 1
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
            "redirect_hops": len(redirect_chain),
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
        findings: list[FindingCandidate] = []
        if context.target.url.startswith("https://") and any(
            url.startswith("http://") for url in redirect_chain
        ):
            findings.append(
                FindingCandidate(
                    finding_type="https_downgrade_redirect",
                    family="transport_security",
                    title="HTTPS redirect chain downgrades to HTTP",
                    description="An HTTPS entry point redirects to an unencrypted HTTP destination.",
                    asset=_origin(context.target.url),
                    affected_endpoints=[context.target.url],
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    validation_status=ValidationStatus.CONFIRMED,
                    evidence=[
                        EvidenceRecord(
                            kind="redirect_chain",
                            summary="HTTPS redirect chain contains an HTTP destination",
                            location=context.target.url,
                            matched_indicator="http://",
                            response={"redirect_chain": redirect_chain},
                        )
                    ],
                    source_plugins=[self.name],
                    cwe=["CWE-319"],
                    owasp=["A02:2021"],
                    remediation="Keep every redirect hop on HTTPS and remove downgrade destinations.",
                )
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
            findings=findings,
            metrics=metrics,
        )

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("retry-after", "").strip()
        try:
            return min(5.0, max(0.0, float(retry_after)))
        except ValueError:
            return min(5.0, float(2**attempt))


class DNSReconPlugin(AssessmentPlugin):
    name = "dns_recon"
    description = "Hostname, address, alias, and origin reconnaissance"
    requires = frozenset({"seed_url"})
    produces = frozenset({"dns_metadata"})
    phase = PentestPhase.RECONNAISSANCE
    security_question = "What addresses and DNS aliases back the supplied application hostname?"
    timeout_seconds = 20

    async def run(self, context: PluginContext) -> PluginResult:
        parts = urlsplit(context.target.url)
        hostname = parts.hostname or ""
        try:
            aliases, addresses = await asyncio.to_thread(self._resolve, hostname)
        except OSError as exc:
            return PluginResult(
                plugin=self.name,
                state=PluginState.PARTIAL,
                failure_reason=FailureReason.TARGET_UNREACHABLE,
                message=f"DNS resolution failed: {type(exc).__name__}",
                capabilities_produced=set(self.produces),
                tests_attempted=1,
            )
        asset = AssetRecord(
            url=context.target.url,
            origin=_origin(context.target.url),
            scheme=parts.scheme,
            hostname=hostname,
            port=parts.port or (443 if parts.scheme == "https" else 80),
            resolved_ips=addresses,
            cname=aliases[0] if aliases else None,
            discovery_sources=[self.name],
        )
        evidence = EvidenceRecord(
            kind="dns_resolution",
            summary=f"Resolved {hostname} to {', '.join(addresses) or 'no address'}",
            location=hostname,
            matched_indicator=",".join(addresses),
        )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            assets=[asset],
            observations=[
                RawObservation(
                    plugin=self.name,
                    observation_type="dns_reconnaissance",
                    target=hostname,
                    data={"hostname": hostname, "addresses": addresses, "aliases": aliases},
                    evidence=[evidence],
                    confidence=Confidence.CONFIRMED,
                )
            ],
            tests_attempted=1,
            tests_completed=1,
            targets_tested=[hostname],
            metrics={"addresses": len(addresses), "aliases": len(aliases)},
        )

    @staticmethod
    def _resolve(hostname: str) -> tuple[list[str], list[str]]:
        canonical, aliases, legacy_addresses = socket.gethostbyname_ex(hostname)
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            if item[4]
        }
        addresses.update(legacy_addresses)
        names = {name.rstrip(".") for name in [canonical, *aliases] if name and name != hostname}
        return sorted(names), sorted(addresses)


class TLSPlugin(AssessmentPlugin):
    name = "tls"
    description = "TLS certificate, trust, version, and transport checks"
    requires = frozenset({"seed_url"})
    produces = frozenset({"tls_metadata"})
    owasp = ("A02:2021",)
    cwe = ("CWE-295", "CWE-319")
    timeout_seconds = 30
    phase = PentestPhase.RECONNAISSANCE
    stage = 1
    security_question = "Is HTTPS trusted, current, correctly named, and free of downgrade indicators?"

    async def run(self, context: PluginContext) -> PluginResult:
        parts = urlsplit(context.target.url)
        if parts.scheme != "https":
            snapshot = context.http_snapshots.get(context.target.url)
            upgraded = bool(
                snapshot
                and snapshot.redirect_chain
                and snapshot.redirect_chain[0].startswith("https://")
            )
            if upgraded:
                return self.success(
                    self.name,
                    capabilities_produced=set(self.produces),
                    observations=[
                        RawObservation(
                            plugin=self.name,
                            observation_type="http_to_https_redirect",
                            target=context.target.url,
                            data={"redirect_chain": snapshot.redirect_chain},
                            confidence=Confidence.CONFIRMED,
                        )
                    ],
                    message="HTTP entry point redirects to HTTPS",
                )
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
            assets=[
                AssetRecord(
                    url=context.target.url,
                    origin=_origin(context.target.url),
                    scheme=parts.scheme,
                    hostname=host,
                    port=port,
                    tls=details,
                    discovery_sources=[self.name],
                )
            ],
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
        trusted_cert: dict[str, object] = {}
        try:
            trusted_context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as raw:
                with trusted_context.wrap_socket(raw, server_hostname=host) as secure:
                    trusted_cert = secure.getpeercert()
        except ssl.SSLCertVerificationError as exc:
            trusted = False
            validation_error = str(exc.verify_message)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secure:
                cert = trusted_cert or secure.getpeercert(binary_form=False)
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
    phase = PentestPhase.ENUMERATION
    stage = 0
    security_question = "What links, forms, scripts, APIs, parameters, and authentication surfaces are exposed in HTML?"

    LINK_RE = re.compile(r"(?:href|src)\s*=\s*['\"]([^'\"#]+)", re.I)
    JS_ENDPOINT_RE = re.compile(r"['\"]((?:/|https?://)[A-Za-z0-9_./?=&%:-]{2,})['\"]")

    async def run(self, context: PluginContext) -> PluginResult:
        snapshot = context.http_snapshots[context.target.url]
        endpoints = [_endpoint(context.target.url, self.name, status_code=snapshot.status_code)]
        scripts: set[str] = set()
        api_candidates: set[str] = set()
        parser = _DiscoveryParser()
        try:
            parser.feed(snapshot.body)
        except Exception:
            parser = _DiscoveryParser()
        for raw in {*self.LINK_RE.findall(snapshot.body), *parser.urls}:
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
        for inline_script in parser.inline_scripts:
            for raw in self.JS_ENDPOINT_RE.findall(inline_script):
                try:
                    url = context.scope.resolve(raw, snapshot.url)
                except ValueError:
                    continue
                if context.scope.check(url).allowed:
                    endpoints.append(_endpoint(url, self.name, javascript_source=snapshot.url))
                    if "/api" in urlsplit(url).path.lower():
                        api_candidates.add(url)
        for index, form in enumerate(parser.forms):
            try:
                url = context.scope.resolve(str(form["action"]), snapshot.url)
            except ValueError:
                continue
            if not context.scope.check(url).allowed:
                continue
            method = str(form["method"]).upper()
            parameters = []
            for item in form["parameters"]:
                assert isinstance(item, dict)
                name = str(item["name"])
                parameters.append(
                    ParameterRecord(
                        name=name,
                        normalized_name=name.strip().lower().replace("-", "_"),
                        location="query" if method in {"GET", "HEAD"} else "body",
                        method=method,
                        required=bool(item["required"]),
                        source="html_form",
                        sample_metadata={"input_type": item["type"]},
                    )
                )
            endpoints.append(
                _endpoint(
                    url,
                    self.name,
                    method=method,
                    parameters=parameters,
                    response_metadata={"form_index": index},
                )
            )
        for index, content in enumerate(parser.inline_scripts):
            context.javascript_content[f"{snapshot.url}#inline-script-{index + 1}"] = content
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
                data={
                    "endpoint_count": len(endpoints),
                    "javascript": sorted(scripts),
                    "inline_javascript": len(parser.inline_scripts),
                    "forms": len(parser.forms),
                    "api": sorted(api_candidates),
                },
                confidence=Confidence.HIGH,
            )
        ]
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            endpoints=endpoints,
            observations=observations,
            metrics={
                "endpoints_discovered": len(endpoints),
                "javascript_discovered": len(scripts),
                "inline_javascript": len(parser.inline_scripts),
                "forms_discovered": len(parser.forms),
            },
        )


class SecurityHeadersPlugin(AssessmentPlugin):
    name = "security_headers"
    requires = frozenset({"http_metadata"})
    produces = frozenset({"header_assessment"})
    owasp = ("A05:2021",)
    cwe = ("CWE-693",)
    # Run after enumeration so one site-wide finding can aggregate the
    # discovered page sample instead of reporting only the seed response.
    phase = PentestPhase.EXPLOITATION_VALIDATION
    security_question = "Which browser security controls are absent or ineffective across sampled pages?"

    EXPECTED = {
        "content-security-policy": "Content-Security-Policy",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
        "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
        "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
    }

    async def run(self, context: PluginContext) -> PluginResult:
        sampled: dict[str, HTTPResponseSnapshot] = {
            url: snapshot
            for url, snapshot in context.http_snapshots.items()
            if context.scope.check(url.split("#", 1)[0]).allowed
        }
        cached_count = len(sampled)
        candidates = [
            endpoint.url
            for endpoint in context.inventory.endpoints.values()
            if endpoint.method.upper() == "GET"
            and endpoint.url not in sampled
            and not re.search(
                r"(?i)\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|woff2?|ttf|zip|pdf)(?:\?|$)",
                endpoint.url,
            )
        ][:30]
        completed = 0
        if candidates:
            async with httpx.AsyncClient(
                timeout=context.config.rate.request_timeout_seconds,
                follow_redirects=False,
                headers={"User-Agent": "Wraith-Crawler/0.1"},
            ) as client:
                for url in candidates:
                    try:
                        response = await client.get(url)
                    except httpx.HTTPError:
                        continue
                    completed += 1
                    sampled[url] = HTTPResponseSnapshot(
                        url=str(response.url),
                        status_code=response.status_code,
                        headers={key.lower(): value for key, value in response.headers.items()},
                        body="",
                        elapsed_ms=0,
                    )
        missing_by_url: dict[str, list[str]] = {}
        counts: dict[str, int] = {}
        for url, snapshot in sampled.items():
            expected = dict(self.EXPECTED)
            if url.startswith("https://"):
                expected["strict-transport-security"] = "Strict-Transport-Security"
            missing = [label for key, label in expected.items() if key not in snapshot.headers]
            csp = snapshot.headers.get("content-security-policy", "")
            if "x-frame-options" not in snapshot.headers and "frame-ancestors" not in csp.lower():
                missing.append("X-Frame-Options or CSP frame-ancestors")
            if missing:
                missing_by_url[url] = missing
                for header in missing:
                    counts[header] = counts.get(header, 0) + 1
        findings: list[FindingCandidate] = []
        if missing_by_url:
            affected = sorted(missing_by_url)
            findings.append(
                FindingCandidate(
                    finding_type="missing_security_headers",
                    family="security_misconfiguration",
                    title="Recommended browser security headers are missing",
                    description="One or more response controls that reduce browser-side attack impact were not observed.",
                    asset=_origin(context.target.url),
                    affected_endpoints=affected,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    validation_status=ValidationStatus.CONFIRMED,
                    evidence=[
                        EvidenceRecord(
                            kind="http_headers",
                            summary=f"Missing: {', '.join(headers)}",
                            location=url,
                            status_code=sampled[url].status_code,
                            matched_indicator=",".join(headers),
                            response={
                                "status": sampled[url].status_code,
                                "headers": _safe_response_headers(sampled[url].headers),
                            },
                        )
                        for url, headers in list(missing_by_url.items())[:20]
                    ],
                    source_plugins=[self.name],
                    cwe=["CWE-693"],
                    owasp=["A05:2021"],
                    remediation="Define a tested site-wide header policy at the application or edge layer.",
                    metadata={
                        "missing_headers": sorted(counts),
                        "affected_endpoint_count": len(affected),
                        "header_counts": counts,
                        "aggregate_scope": _origin(context.target.url),
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
                    observation_type="security_headers",
                    target=context.target.url,
                    data={
                        "responses_sampled": len(sampled),
                        "affected_endpoints": len(missing_by_url),
                        "header_counts": counts,
                    },
                    confidence=Confidence.CONFIRMED,
                )
            ],
            tests_attempted=cached_count + len(candidates),
            tests_completed=cached_count + completed,
            metrics={
                "responses_sampled": len(sampled),
                "network_requests": len(candidates),
                "completed_requests": completed,
                "affected_endpoints": len(missing_by_url),
            },
        )


class CookieSecurityPlugin(AssessmentPlugin):
    name = "cookie_security"
    description = "Session-cookie discovery and browser security attribute assessment"
    requires = frozenset({"http_metadata"})
    produces = frozenset({"cookie_assessment", "session_cookie_analysis"})
    owasp = ("A02:2021", "A07:2021")
    cwe = ("CWE-614", "CWE-1004", "CWE-1275")
    phase = PentestPhase.SCANNING
    security_question = "Do observed cookies safely constrain transport, script access, cross-site use, and scope?"

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
                if context.target.url.startswith("http://") and "secure" not in attributes:
                    missing.append("Secure (session cookie set over HTTP)")
                if "httponly" not in attributes:
                    missing.append("HttpOnly")
                if "samesite" not in attributes:
                    missing.append("SameSite")
                elif (
                    str(attributes.get("samesite") or "").lower() == "none"
                    and "secure" not in attributes
                ):
                    missing.append("Secure required with SameSite=None")
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
    phase = PentestPhase.SCANNING
    security_question = "Can an untrusted web origin read application responses, especially with credentials?"

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
            tests_attempted=1,
            tests_completed=1,
            metrics={"requests": 1},
        )


class HTTPMethodsPlugin(AssessmentPlugin):
    name = "http_methods"
    requires = frozenset({"http_metadata"})
    produces = frozenset({"method_assessment"})
    owasp = ("A05:2021",)
    phase = PentestPhase.SCANNING
    security_question = "Does the server expose unnecessary or diagnostic HTTP methods?"

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
        trace_status: int | None = None
        try:
            async with httpx.AsyncClient(
                timeout=context.config.rate.request_timeout_seconds,
                follow_redirects=False,
                headers={"User-Agent": "Wraith-Crawler/0.1"},
            ) as client:
                trace = await client.request("TRACE", context.target.url)
                trace_status = trace.status_code
        except httpx.HTTPError:
            trace = None
        if trace is not None and 200 <= trace.status_code < 300:
            findings.append(
                FindingCandidate(
                    finding_type="http_trace_enabled",
                    family="security_misconfiguration",
                    title="HTTP TRACE method is enabled",
                    description="A direct TRACE request was accepted by the public endpoint.",
                    asset=_origin(context.target.url),
                    affected_endpoints=[context.target.url],
                    method="TRACE",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    validation_status=ValidationStatus.CONFIRMED,
                    evidence=[
                        EvidenceRecord(
                            kind="trace_response",
                            summary=f"TRACE returned HTTP {trace.status_code}",
                            location=context.target.url,
                            method="TRACE",
                            status_code=trace.status_code,
                        )
                    ],
                    source_plugins=[self.name],
                    cwe=["CWE-749"],
                    owasp=["A05:2021"],
                    remediation="Disable TRACE unless it is explicitly required and protected.",
                )
            )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            findings=findings,
            tests_attempted=2,
            tests_completed=1 + (1 if trace_status is not None else 0),
            metrics={"requests": 2, "trace_status": trace_status},
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
    phase = PentestPhase.ENUMERATION
    stage = 3
    security_question = "Which discovered inputs are meaningful candidates for bounded vulnerability validation?"

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
            known_path_parameters = {
                parameter.name for parameter in endpoint.parameters if parameter.location == "path"
            }
            for index, segment in enumerate(filter(None, endpoint.path.split("/")), 1):
                identifier_type = None
                if re.fullmatch(r"[0-9]{1,20}", segment):
                    identifier_type = "integer"
                elif re.fullmatch(
                    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
                    segment,
                ):
                    identifier_type = "uuid"
                if identifier_type:
                    name = f"object_id_{index}"
                    if name not in known_path_parameters:
                        endpoint.parameters.append(
                            ParameterRecord(
                                name=name,
                                normalized_name=name,
                                location="path",
                                method=endpoint.method,
                                required=True,
                                source="path_identifier",
                                sample_metadata={
                                    "identifier_type": identifier_type,
                                    "length": len(segment),
                                },
                                risk_categories=["idor"],
                                risk_score=4.0,
                            )
                        )
            for parameter in endpoint.parameters:
                categories = (
                    ["idor"]
                    if parameter.location == "path"
                    else [
                        name
                        for name, regex in self.CATEGORIES.items()
                        if regex.search(parameter.normalized_name)
                    ]
                )
                parameter.risk_categories = sorted(set(parameter.risk_categories + categories))
                parameter.risk_score = min(10.0, 1.5 * len(categories) + (1 if parameter.location == "query" else 0))
                for category in categories:
                    if category == "xss" and parameter.location == "query":
                        context.queues.xss.append((endpoint.url, parameter.name))
                    elif category == "sqli" and parameter.location == "query":
                        context.queues.sqli.append((endpoint.url, parameter.name))
                    elif category == "ssrf":
                        context.queues.ssrf.append((endpoint.url, parameter.name))
                    elif category == "idor":
                        context.queues.idor.append((endpoint.url, parameter.name))
                    elif category == "path":
                        context.queues.path.append((endpoint.url, parameter.name))
                    elif category == "redirect" and parameter.location == "query":
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
    produces = frozenset(
        {
            "javascript_content",
            "javascript_endpoints",
            "source_map_candidates",
            "javascript_analysis_complete",
        }
    )
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP, ScanProfile.DISCOVERY_ONLY})
    owasp = ("A06:2021", "A08:2021")
    phase = PentestPhase.ENUMERATION
    stage = 1
    security_question = "What endpoints, source maps, WebSockets, libraries, and environment clues are exposed in JavaScript?"

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
        endpoints: list[EndpointRecord] = []
        findings: list[FindingCandidate] = []
        observations: list[RawObservation] = []
        semaphore = asyncio.Semaphore(min(context.config.rate.plugin_concurrency, 6))

        responses: list[tuple[str, httpx.Response | None]] = []
        if javascript_urls:
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
        downloaded_sources = {url for url, response in responses if response is not None}
        for source, content in list(context.javascript_content.items()):
            if source in downloaded_sources:
                continue
            discovered: list[str] = []
            for raw in self.ENDPOINT_RE.findall(content):
                try:
                    candidate = context.scope.resolve(raw, source.split("#", 1)[0])
                except ValueError:
                    continue
                if context.scope.check(candidate).allowed:
                    endpoints.append(_endpoint(candidate, self.name, javascript_source=source))
                    discovered.append(candidate)
            for raw in self.MAP_RE.findall(content):
                try:
                    map_url = context.scope.resolve(raw, source.split("#", 1)[0])
                except ValueError:
                    continue
                if context.scope.check(map_url).allowed:
                    endpoints.append(_endpoint(map_url, self.name, javascript_source=source))
            for ws_url in self.WS_RE.findall(content):
                findings.append(
                    FindingCandidate(
                        finding_type="websocket_endpoint",
                        family="realtime_surface",
                        title="WebSocket endpoint discovered",
                        description="Inline JavaScript references a WebSocket endpoint requiring handshake and authorization review.",
                        asset=_origin(context.target.url),
                        affected_endpoints=[ws_url],
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.HIGH,
                        validation_status=ValidationStatus.MANUAL_REVIEW,
                        evidence=[
                            EvidenceRecord(
                                kind="javascript_reference",
                                summary=f"WebSocket URL referenced by {source}",
                                location=ws_url,
                            )
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-284"],
                        owasp=["A01:2021"],
                        remediation="Enforce origin, authentication and per-message authorization controls.",
                        manual_review=True,
                    )
                )
            observations.append(
                RawObservation(
                    plugin=self.name,
                    observation_type="inline_javascript_analysis",
                    target=source,
                    data={"bytes": len(content.encode()), "endpoints": discovered},
                    confidence=Confidence.HIGH,
                )
            )
        downloaded = sum(1 for _url, response in responses if response is not None)
        return PluginResult(
            plugin=self.name,
            state=PluginState.COMPLETED,
            message=None if context.javascript_content else "No in-scope JavaScript content was discovered",
            capabilities_produced=set(self.produces),
            endpoints=endpoints,
            observations=observations,
            findings=findings,
            tests_attempted=len(javascript_urls),
            tests_completed=downloaded,
            metrics={
                "requested": len(javascript_urls),
                "downloaded": downloaded,
                "content_sources": len(context.javascript_content),
            },
        )


class OpenAPIDiscoveryPlugin(AssessmentPlugin):
    name = "openapi_discovery"
    description = "OpenAPI and Swagger schema discovery and endpoint enumeration"
    requires = frozenset({"validated_origin"})
    produces = frozenset({"api_candidates", "api_schema_analysis", "api_discovery_complete"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP, ScanProfile.DISCOVERY_ONLY})
    owasp = ("A01:2021", "A05:2021")
    phase = PentestPhase.ENUMERATION
    stage = 1
    security_question = "Do public API schemas disclose callable endpoints, parameters, and authentication requirements?"

    STANDARD_PATHS = (
        "/openapi.json",
        "/swagger.json",
        "/api/openapi.json",
        "/api/swagger.json",
        "/v3/api-docs",
        "/swagger/v1/swagger.json",
    )

    async def run(self, context: PluginContext) -> PluginResult:
        origin = _origin(context.target.url)
        candidates = {
            urljoin(f"{origin}/", path.lstrip("/")) for path in self.STANDARD_PATHS
        }
        candidates.update(
            endpoint.url
            for endpoint in context.inventory.endpoints.values()
            if re.search(r"(?i)(?:openapi|swagger|api-docs).*(?:json)?$", endpoint.path)
        )
        endpoints: list[EndpointRecord] = []
        findings: list[FindingCandidate] = []
        observations: list[RawObservation] = []
        completed = 0
        schemas = 0
        async with httpx.AsyncClient(
            timeout=context.config.rate.request_timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "Wraith-Crawler/0.1"},
        ) as client:
            for schema_url in sorted(candidates)[:20]:
                if not context.scope.check(schema_url).allowed:
                    continue
                try:
                    response = await client.get(schema_url)
                except httpx.HTTPError:
                    continue
                completed += 1
                endpoints.append(
                    _endpoint(
                        schema_url,
                        self.name,
                        status_code=response.status_code,
                        content_type=response.headers.get("content-type"),
                        api_classification="api_documentation",
                    )
                )
                if response.status_code != 200 or len(response.content) > 5_000_000:
                    continue
                try:
                    document = response.json()
                except ValueError:
                    continue
                if not isinstance(document, dict) or not (
                    document.get("openapi") or document.get("swagger")
                ) or not isinstance(document.get("paths"), dict):
                    continue
                schemas += 1
                context.http_snapshots[schema_url] = HTTPResponseSnapshot(
                    url=schema_url,
                    status_code=response.status_code,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body=response.text,
                    elapsed_ms=0,
                )
                security_schemes = (
                    document.get("components", {}).get("securitySchemes", {})
                    if isinstance(document.get("components"), dict)
                    else {}
                )
                operation_count = 0
                for path, path_item in document["paths"].items():
                    if not isinstance(path, str) or not isinstance(path_item, dict):
                        continue
                    for method, operation in path_item.items():
                        if method.lower() not in {
                            "get",
                            "post",
                            "put",
                            "patch",
                            "delete",
                            "head",
                            "options",
                        } or not isinstance(operation, dict):
                            continue
                        try:
                            endpoint_url = context.scope.resolve(path, f"{origin}/")
                        except ValueError:
                            continue
                        if not context.scope.check(endpoint_url).allowed:
                            continue
                        parameters = self._parameters(
                            [
                                *(
                                    path_item.get("parameters", [])
                                    if isinstance(path_item.get("parameters"), list)
                                    else []
                                ),
                                *(
                                    operation.get("parameters", [])
                                    if isinstance(operation.get("parameters"), list)
                                    else []
                                ),
                            ],
                            method.upper(),
                        )
                        parameters.extend(self._body_parameters(operation, method.upper()))
                        operation_security = operation.get("security", document.get("security"))
                        endpoints.append(
                            _endpoint(
                                endpoint_url,
                                self.name,
                                method=method.upper(),
                                parameters=parameters,
                                authentication_required=bool(operation_security),
                                api_classification="rest_api",
                                response_metadata={
                                    "operation_id": operation.get("operationId"),
                                    "schema_source": schema_url,
                                },
                                confidence=Confidence.HIGH,
                            )
                        )
                        operation_count += 1
                findings.append(
                    FindingCandidate(
                        finding_type="openapi_exposure",
                        family="api_security",
                        title="OpenAPI or Swagger schema is publicly accessible",
                        description="A valid public API schema disclosed operations, parameters, and authentication declarations.",
                        asset=origin,
                        affected_endpoints=[schema_url],
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.CONFIRMED,
                        validation_status=ValidationStatus.CONFIRMED,
                        evidence=[
                            EvidenceRecord(
                                kind="openapi_schema",
                                summary=f"Valid schema exposed {operation_count} operation(s)",
                                location=schema_url,
                                status_code=response.status_code,
                                matched_indicator="openapi" if document.get("openapi") else "swagger",
                                response={
                                    "status": response.status_code,
                                    "operations": operation_count,
                                    "security_schemes": sorted(security_schemes),
                                },
                            )
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-200"],
                        owasp=["A05:2021"],
                        remediation="Restrict API schemas when they are not intended for public consumers and enforce authorization independently of documentation visibility.",
                    )
                )
                observations.append(
                    RawObservation(
                        plugin=self.name,
                        observation_type="openapi_schema",
                        target=schema_url,
                        data={
                            "version": document.get("openapi") or document.get("swagger"),
                            "operations": operation_count,
                            "security_schemes": sorted(security_schemes),
                        },
                        confidence=Confidence.CONFIRMED,
                    )
                )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            endpoints=endpoints,
            findings=findings,
            observations=observations,
            tests_attempted=len(candidates),
            tests_completed=completed,
            metrics={"candidates": len(candidates), "schemas": schemas},
        )

    @staticmethod
    def _parameters(items: list[object], method: str) -> list[ParameterRecord]:
        parameters: list[ParameterRecord] = []
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                continue
            location = str(item.get("in") or "query").lower()
            parameters.append(
                ParameterRecord(
                    name=item["name"],
                    normalized_name=item["name"].strip().lower().replace("-", "_"),
                    location=location,
                    method=method,
                    required=bool(item.get("required")),
                    source="openapi",
                    sample_metadata={
                        "schema_type": (item.get("schema") or {}).get("type")
                        if isinstance(item.get("schema"), dict)
                        else None
                    },
                )
            )
        return parameters

    @staticmethod
    def _body_parameters(operation: dict[str, object], method: str) -> list[ParameterRecord]:
        body = operation.get("requestBody")
        if not isinstance(body, dict) or not isinstance(body.get("content"), dict):
            return []
        parameters: list[ParameterRecord] = []
        for media in body["content"].values():
            if not isinstance(media, dict) or not isinstance(media.get("schema"), dict):
                continue
            properties = media["schema"].get("properties", {})
            required = set(media["schema"].get("required", []))
            if not isinstance(properties, dict):
                continue
            for name, schema in properties.items():
                parameters.append(
                    ParameterRecord(
                        name=str(name),
                        normalized_name=str(name).strip().lower().replace("-", "_"),
                        location="json",
                        method=method,
                        required=name in required,
                        source="openapi_request_body",
                        sample_metadata={
                            "schema_type": schema.get("type") if isinstance(schema, dict) else None
                        },
                    )
                )
        return parameters


class AuthenticationDiscoveryPlugin(AssessmentPlugin):
    name = "authentication_discovery"
    description = "Authentication surface and externally observable enforcement discovery"
    requires = frozenset({"html_discovery_complete"})
    produces = frozenset({"auth_discovery"})
    phase = PentestPhase.ENUMERATION
    stage = 2
    owasp = ("A01:2021", "A07:2021")
    security_question = "Where are authentication boundaries and session material externally observable?"

    async def run(self, context: PluginContext) -> PluginResult:
        endpoints: list[EndpointRecord] = []
        findings: list[FindingCandidate] = []
        surfaces: list[str] = []
        for endpoint in context.inventory.endpoints.values():
            path = endpoint.path.lower()
            auth_surface = any(
                term in path
                for term in (
                    "login",
                    "signin",
                    "sign-in",
                    "logout",
                    "oauth",
                    "saml",
                    "password",
                    "reset",
                    "register",
                    "account",
                )
            )
            authentication_required = endpoint.authentication_required
            if endpoint.status_code in {401, 403}:
                authentication_required = True
            if auth_surface:
                surfaces.append(endpoint.url)
            endpoints.append(
                EndpointRecord(
                    url=endpoint.url,
                    origin=endpoint.origin,
                    path=endpoint.path,
                    method=endpoint.method,
                    status_code=endpoint.status_code,
                    sources=[self.name],
                    authentication_required=authentication_required,
                    api_classification=endpoint.api_classification,
                    response_metadata={"auth_surface": auth_surface},
                    confidence=Confidence.HIGH if authentication_required is not None else Confidence.MEDIUM,
                )
            )
            for name, value in parse_qsl(urlsplit(endpoint.url).query, keep_blank_values=True):
                if not SENSITIVE_PARAMETER.search(name) or not value:
                    continue
                findings.append(
                    FindingCandidate(
                        finding_type="session_token_in_url",
                        family="session_security",
                        title="Session or authentication material appears in a URL",
                        description="A discovered URL contains a populated secret-like query parameter that can leak through logs, history, and referrers.",
                        asset=endpoint.origin,
                        affected_endpoints=[endpoint.url],
                        parameters=[name],
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        validation_status=ValidationStatus.SUSPECTED,
                        evidence=[
                            EvidenceRecord(
                                kind="url_parameter",
                                summary=f"Populated secret-like URL parameter {name} was discovered",
                                location=endpoint.url,
                                parameter=name,
                                sensitive=True,
                            )
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-598"],
                        owasp=["A07:2021"],
                        remediation="Transmit session and authentication material in protected headers or secure cookies, never in URLs.",
                        manual_review=True,
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
                    observation_type="authentication_surfaces",
                    target=context.target.url,
                    data={"surfaces": sorted(set(surfaces))},
                    confidence=Confidence.HIGH,
                )
            ],
            metrics={"surfaces": len(set(surfaces)), "token_urls": len(findings)},
        )


class GraphQLDiscoveryPlugin(AssessmentPlugin):
    name = "graphql_discovery"
    requires = frozenset({"api_candidates"})
    produces = frozenset({"graphql_assessment"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP, ScanProfile.DISCOVERY_ONLY})
    owasp = ("A01:2021", "A05:2021")
    phase = PentestPhase.ENUMERATION
    stage = 2
    security_question = "Is GraphQL present and what schema capability is anonymously observable without mutations?"

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
                        json={
                            "query": (
                                "query WraithSchemaCheck { __schema { queryType { name fields { "
                                "name args { name type { kind name ofType { kind name } } } } } "
                                "types { name kind } } }"
                            )
                        },
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
                    schema = payload["data"]["__schema"]
                    query_type = schema.get("queryType") if isinstance(schema, dict) else {}
                    fields = query_type.get("fields", []) if isinstance(query_type, dict) else []
                    types = schema.get("types", []) if isinstance(schema, dict) else []
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
                                    status_code=response.status_code,
                                    matched_indicator="__schema",
                                    response={
                                        "status": response.status_code,
                                        "schema_present": True,
                                        "query_fields": len(fields),
                                        "types": len(types),
                                    },
                                )
                            ],
                            source_plugins=[self.name],
                            cwe=["CWE-200"],
                            owasp=["A05:2021"],
                            remediation="Disable production introspection when not required, while prioritizing field-level authorization and query controls.",
                        )
                    )
                    endpoints[-1].response_metadata.update(
                        {
                            "query_names": [
                                item.get("name")
                                for item in fields[:100]
                                if isinstance(item, dict) and item.get("name")
                            ],
                            "type_names": [
                                item.get("name")
                                for item in types[:200]
                                if isinstance(item, dict) and item.get("name")
                            ],
                        }
                    )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            endpoints=endpoints,
            findings=findings,
            metrics={"candidates": len(urls)},
        )


class AnonymousAPIAccessPlugin(AssessmentPlugin):
    name = "anonymous_api_access"
    description = "Bounded anonymous REST API reachability and sensitive-shape validation"
    requires = frozenset({"api_discovery_complete", "auth_discovery"})
    produces = frozenset({"anonymous_api_assessment"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP})
    owasp = ("A01:2021",)
    phase = PentestPhase.EXPLOITATION_VALIDATION
    security_question = "Which discovered read-only API endpoints answer anonymously and expose sensitive data shapes?"

    SENSITIVE_KEYS = re.compile(
        r"(?i)^(?:email|phone|address|ssn|national_id|password|token|secret|api_key|"
        r"credit_card|card_number|account_number|date_of_birth|dob)$"
    )

    async def run(self, context: PluginContext) -> PluginResult:
        candidates = [
            endpoint
            for endpoint in context.inventory.endpoints.values()
            if endpoint.method.upper() in {"GET", "HEAD"}
            and (
                endpoint.api_classification in {"rest_api", "api_candidate"}
                or re.search(r"(?i)/(?:api|v[0-9]+)(?:/|$)", endpoint.path)
            )
            and "{" not in endpoint.url
        ][: min(context.config.rate.max_candidates, 30)]
        endpoints: list[EndpointRecord] = []
        findings: list[FindingCandidate] = []
        completed = 0
        async with httpx.AsyncClient(
            timeout=context.config.rate.request_timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "Wraith-Crawler/0.1"},
        ) as client:
            for endpoint in candidates:
                try:
                    response = await client.get(endpoint.url)
                except httpx.HTTPError:
                    continue
                completed += 1
                content_type = response.headers.get("content-type", "")
                endpoints.append(
                    _endpoint(
                        endpoint.url,
                        self.name,
                        status_code=response.status_code,
                        content_type=content_type,
                        authentication_required=False
                        if response.status_code == 200
                        else endpoint.authentication_required,
                        api_classification=endpoint.api_classification or "rest_api",
                        confidence=Confidence.CONFIRMED,
                    )
                )
                if response.status_code != 200 or "json" not in content_type.lower():
                    continue
                try:
                    payload = response.json()
                except ValueError:
                    continue
                keys = self._keys(payload)
                sensitive_keys = sorted(key for key in keys if self.SENSITIVE_KEYS.search(key))
                findings.append(
                    FindingCandidate(
                        finding_type="anonymous_sensitive_api" if sensitive_keys else "reachable_api",
                        family="api_security",
                        title=(
                            "Anonymous API response contains sensitive data fields"
                            if sensitive_keys
                            else "API endpoint is anonymously reachable"
                        ),
                        description=(
                            "A read-only request without credentials returned JSON containing security-relevant field names."
                            if sensitive_keys
                            else "A read-only request without credentials returned a valid JSON response."
                        ),
                        asset=endpoint.origin,
                        affected_endpoints=[endpoint.url],
                        method="GET",
                        severity=Severity.HIGH if sensitive_keys else Severity.INFORMATIONAL,
                        confidence=Confidence.CONFIRMED,
                        validation_status=(
                            ValidationStatus.SUSPECTED
                            if sensitive_keys
                            else ValidationStatus.CONFIRMED
                        ),
                        evidence=[
                            EvidenceRecord(
                                kind="anonymous_api_response",
                                summary=(
                                    f"HTTP 200 JSON without credentials; sensitive field names: {', '.join(sensitive_keys)}"
                                    if sensitive_keys
                                    else "HTTP 200 JSON response returned without credentials"
                                ),
                                location=endpoint.url,
                                method="GET",
                                status_code=response.status_code,
                                matched_indicator=",".join(sensitive_keys) or "application/json",
                                response={
                                    "status": response.status_code,
                                    "content_type": content_type,
                                    "top_level_type": type(payload).__name__,
                                    "sensitive_field_names": sensitive_keys,
                                },
                            )
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-862" if sensitive_keys else "CWE-200"],
                        owasp=["A01:2021"],
                        remediation="Require authentication and object/function-level authorization wherever the returned API data is not intentionally public.",
                        manual_review=bool(sensitive_keys),
                        metadata={
                            "sensitive_context": bool(sensitive_keys),
                            "sensitive_field_names": sensitive_keys,
                            "review_reason": "Field names indicate sensitivity but business authorization intent requires confirmation"
                            if sensitive_keys
                            else None,
                        },
                    )
                )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            endpoints=endpoints,
            findings=findings,
            tests_attempted=len(candidates),
            tests_completed=completed,
            metrics={"candidates": len(candidates), "anonymous_json": len(findings)},
        )

    @classmethod
    def _keys(cls, payload: object, depth: int = 0) -> set[str]:
        if depth > 3:
            return set()
        if isinstance(payload, dict):
            result = {str(key) for key in payload}
            for value in list(payload.values())[:20]:
                result.update(cls._keys(value, depth + 1))
            return result
        if isinstance(payload, list):
            result: set[str] = set()
            for value in payload[:10]:
                result.update(cls._keys(value, depth + 1))
            return result
        return set()


class ReflectionAnalysisPlugin(AssessmentPlugin):
    name = "reflection_analysis"
    description = "Deterministic reflected-input analysis for XSS candidates"
    requires = frozenset({"parameter_candidates"})
    produces = frozenset({"reflection_assessment"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP})
    owasp = ("A03:2021",)
    phase = PentestPhase.EXPLOITATION_VALIDATION
    security_question = "Which XSS-relevant parameters reflect a benign marker and warrant contextual validation?"

    async def run(self, context: PluginContext) -> PluginResult:
        candidates = list(dict.fromkeys(context.queues.xss))[
            : min(context.config.rate.max_candidates, 30)
        ]
        findings: list[FindingCandidate] = []
        completed = 0
        async with httpx.AsyncClient(
            timeout=context.config.rate.request_timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "Wraith-Crawler/0.1"},
        ) as client:
            for endpoint, parameter in candidates:
                parts = urlsplit(endpoint)
                query = dict(parse_qsl(parts.query, keep_blank_values=True))
                if parameter not in query:
                    continue
                marker = f"wraith{hashlib.sha256(f'{endpoint}:{parameter}'.encode()).hexdigest()[:12]}"
                query[parameter] = marker
                from urllib.parse import urlencode, urlunsplit

                probe = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
                try:
                    response = await client.get(probe)
                except httpx.HTTPError:
                    continue
                completed += 1
                if marker not in response.text:
                    continue
                findings.append(
                    FindingCandidate(
                        finding_type="xss_reflection_candidate",
                        family="injection",
                        title="Input is reflected in the HTTP response",
                        description="A benign alphanumeric marker was reflected. Execution context was not asserted as XSS.",
                        asset=_origin(endpoint),
                        affected_endpoints=[endpoint],
                        method="GET",
                        parameters=[parameter],
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        validation_status=ValidationStatus.MANUAL_REVIEW,
                        evidence=[
                            EvidenceRecord(
                                kind="reflection_probe",
                                summary=f"Benign marker reflected for parameter {parameter}",
                                location=endpoint,
                                method="GET",
                                parameter=parameter,
                                status_code=response.status_code,
                                matched_indicator="exact alphanumeric marker",
                                request={"parameter": parameter, "marker_fingerprint": marker[-12:]},
                                response={"status": response.status_code, "reflected": True},
                            )
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-79"],
                        owasp=["A03:2021"],
                        remediation="Apply context-aware output encoding and validate with a restrictive Content Security Policy.",
                        manual_review=True,
                        metadata={
                            "review_reason": "Reflection alone does not prove executable JavaScript context",
                            "suggested_steps": [
                                "Inspect the exact HTML/attribute/JavaScript context",
                                "Use Dalfox or an approved benign context-specific payload",
                            ],
                        },
                    )
                )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            findings=findings,
            tests_attempted=len(candidates),
            tests_completed=completed,
            metrics={"candidates": len(candidates), "reflections": len(findings)},
        )


class SessionManagementPlugin(AssessmentPlugin):
    name = "session_management"
    description = "Externally observable improper-session-management indicators"
    requires = frozenset({"cookie_assessment", "auth_discovery"})
    produces = frozenset({"session_management_assessment"})
    owasp = ("A02:2021", "A07:2021")
    phase = PentestPhase.EXPLOITATION_VALIDATION
    stage = 1
    security_question = "Do observable session responses expose tokens, unsafe caching, or conflicting cookie scope?"

    async def run(self, context: PluginContext) -> PluginResult:
        findings: list[FindingCandidate] = []
        observations: list[RawObservation] = []
        for url, snapshot in context.http_snapshots.items():
            cookies = _parse_set_cookie_header(snapshot.headers.get("set-cookie", ""))
            auth_cookies = [(name, attrs) for name, attrs in cookies if _is_authentication_cookie(name)]
            cache_control = snapshot.headers.get("cache-control", "").lower()
            if auth_cookies and not ({"no-store", "private"} & set(cache_control.replace(",", " ").split())):
                findings.append(
                    FindingCandidate(
                        finding_type="session_response_cache_control",
                        family="session_security",
                        title="Session-setting response lacks explicit private or no-store caching",
                        description="A response that sets a likely authentication cookie did not advertise private or no-store caching.",
                        asset=_origin(url),
                        affected_endpoints=[url],
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        validation_status=ValidationStatus.MANUAL_REVIEW,
                        evidence=[
                            EvidenceRecord(
                                kind="session_cache_headers",
                                summary="Authentication cookie observed without Cache-Control private or no-store",
                                location=url,
                                status_code=snapshot.status_code,
                                response={
                                    "status": snapshot.status_code,
                                    "cookie_names": [name for name, _attrs in auth_cookies],
                                    "cache_control": cache_control or None,
                                },
                            )
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-525"],
                        owasp=["A07:2021"],
                        remediation="Mark authentication and personalized responses Cache-Control: no-store or appropriately private.",
                        manual_review=True,
                        metadata={
                            "review_reason": "Shared-cache behavior cannot be proven from one external response"
                        },
                    )
                )
            by_name: dict[str, set[tuple[str | None, str | None]]] = {}
            for name, attrs in auth_cookies:
                by_name.setdefault(name.lower(), set()).add((attrs.get("domain"), attrs.get("path")))
                domain = (attrs.get("domain") or "").lstrip(".").lower()
                host = urlsplit(url).hostname or ""
                if domain and host != domain:
                    findings.append(
                        FindingCandidate(
                            finding_type="broad_session_cookie_scope",
                            family="session_security",
                            title=f"Session cookie {name} is scoped to a parent domain",
                            description="A likely authentication cookie is available beyond the exact application host.",
                            asset=_origin(url),
                            affected_endpoints=[url],
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            validation_status=ValidationStatus.MANUAL_REVIEW,
                            evidence=[
                                EvidenceRecord(
                                    kind="cookie_scope",
                                    summary=f"Cookie {name} Domain attribute is {domain}",
                                    location=url,
                                )
                            ],
                            source_plugins=[self.name],
                            cwe=["CWE-565"],
                            owasp=["A07:2021"],
                            remediation="Prefer host-only session cookies, or use the narrowest required Domain and Path.",
                            manual_review=True,
                            metadata={
                                "review_reason": "Business need for cross-subdomain session scope requires confirmation"
                            },
                        )
                    )
            for name, scopes in by_name.items():
                if len(scopes) < 2:
                    continue
                findings.append(
                    FindingCandidate(
                        finding_type="conflicting_session_cookies",
                        family="session_security",
                        title=f"Conflicting scopes observed for session cookie {name}",
                        description="The same likely session-cookie name was set with multiple Domain or Path scopes.",
                        asset=_origin(url),
                        affected_endpoints=[url],
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        validation_status=ValidationStatus.CONFIRMED,
                        evidence=[
                            EvidenceRecord(
                                kind="cookie_scope_conflict",
                                summary=f"Cookie {name} used {len(scopes)} distinct Domain/Path scopes",
                                location=url,
                            )
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-384"],
                        owasp=["A07:2021"],
                        remediation="Use one unambiguous host-only session cookie and rotate it at authentication boundaries.",
                        manual_review=True,
                    )
                )
            observations.append(
                RawObservation(
                    plugin=self.name,
                    observation_type="session_management",
                    target=url,
                    data={
                        "authentication_cookies": [name for name, _attrs in auth_cookies],
                        "cache_control": cache_control,
                    },
                    confidence=Confidence.HIGH,
                )
            )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            findings=findings,
            observations=observations,
            tests_attempted=len(context.http_snapshots),
            tests_completed=len(context.http_snapshots),
            metrics={"responses_reviewed": len(context.http_snapshots), "issues": len(findings)},
        )


class RedirectTraversalAnalysisPlugin(AssessmentPlugin):
    name = "redirect_traversal_analysis"
    requires = frozenset({"parameter_candidates"})
    produces = frozenset({"redirect_traversal_assessment"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP})
    owasp = ("A01:2021", "A03:2021")
    phase = PentestPhase.EXPLOITATION_VALIDATION
    security_question = "Do redirect or file/path parameters demonstrate a safely testable injection weakness?"

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
    phase = PentestPhase.EXPLOITATION_VALIDATION
    stage = 2
    security_question = "Do public client artifacts contain format-valid credentials or sensitive connection material?"

    PATTERNS = {
        "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,255}\b"),
        "stripe_secret": re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "sendgrid_api_key": re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"),
        "azure_storage_connection": re.compile(
            r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[^;\s]+"
        ),
        "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "connection_string": re.compile(r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s'\"]+"),
    }

    async def run(self, context: PluginContext) -> PluginResult:
        findings: list[FindingCandidate] = []
        sources = {
            **{url: snapshot.body for url, snapshot in context.http_snapshots.items()},
            **context.javascript_content,
            **context.source_map_content,
        }
        seen: set[tuple[str, str, str]] = set()
        for source, content in sources.items():
            public_source = source.split("#", 1)[0]
            for secret_type, pattern in self.PATTERNS.items():
                for match in pattern.finditer(content):
                    value = match.group(0)
                    digest = hashlib.sha256(value.encode()).hexdigest()
                    key = (secret_type, digest, public_source)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        FindingCandidate(
                            finding_type="secret_exposure",
                            family="secrets",
                            title=f"Potential {secret_type.replace('_', ' ')} exposed in client content",
                            description=(
                                "A format-aware credential pattern was present in a publicly reachable "
                                "HTML, JavaScript, JSON, or source-map artifact. The value was not used."
                            ),
                            asset=_origin(context.target.url),
                            affected_endpoints=[public_source],
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            validation_status=ValidationStatus.SUSPECTED,
                            evidence=[
                                EvidenceRecord(
                                    kind="redacted_secret_match",
                                    summary=(
                                        f"{secret_type} pattern at offset {match.start()}, "
                                        f"fingerprint {digest[:12]}"
                                    ),
                                    location=public_source,
                                    matched_indicator=secret_type,
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
                                "review_reason": "Validity is intentionally not tested against an external service",
                                "suggested_steps": [
                                    "Revoke or rotate the value before any validation",
                                    "Identify the in-scope service and least privileges associated with it",
                                ],
                            },
                        )
                    )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            findings=findings,
            tests_attempted=len(sources),
            tests_completed=len(sources),
            metrics={"artifacts_scanned": len(sources), "matches": len(findings)},
        )


class FingerprintingPlugin(AssessmentPlugin):
    name = "technology_fingerprinting"
    description = "Passive web-server and client-framework fingerprinting"
    requires = frozenset({"http_metadata"})
    produces = frozenset({"technologies"})
    owasp = ("A06:2021",)
    phase = PentestPhase.RECONNAISSANCE
    security_question = "Which server, framework, proxy, and client technologies are supported by observable evidence?"

    async def run(self, context: PluginContext) -> PluginResult:
        snapshot = context.http_snapshots[context.target.url]
        technologies: list[TechnologyRecord] = []
        server = snapshot.headers.get("server")
        if server:
            match = re.search(
                r"(?i)\b(nginx|apache(?: httpd)?|microsoft-iis|iis|tomcat|caddy|openresty)"
                r"(?:[/ ]([0-9][0-9A-Za-z._-]*))?",
                server,
            )
            product = match.group(1) if match else server.split()[0].split("/", 1)[0]
            version = match.group(2) if match and match.group(2) else None
            normalized = {
                "microsoft-iis": "Microsoft IIS",
                "iis": "Microsoft IIS",
                "apache httpd": "Apache HTTP Server",
                "apache": "Apache HTTP Server",
            }.get(product.lower(), product)
            technologies.append(
                TechnologyRecord(
                    product=normalized.strip(),
                    version=version,
                    category="web_server",
                    confidence=Confidence.HIGH,
                    evidence=[f"Server header: {server}"],
                    source_plugin=self.name,
                )
            )
        powered = snapshot.headers.get("x-powered-by")
        if powered:
            for match in re.finditer(
                r"(?i)\b(PHP|ASP\.NET|Express|Node(?:\.js)?|Servlet|Next\.js)"
                r"(?:[/ ]([0-9][0-9A-Za-z._-]*))?",
                powered,
            ):
                product = {"node": "Node.js"}.get(match.group(1).lower(), match.group(1))
                technologies.append(
                    TechnologyRecord(
                        product=product,
                        version=match.group(2),
                        category="runtime_or_framework",
                        confidence=Confidence.HIGH,
                        evidence=[f"X-Powered-By header: {powered}"],
                        source_plugin=self.name,
                    )
                )
        aspnet_version = snapshot.headers.get("x-aspnet-version")
        if aspnet_version:
            technologies.append(
                TechnologyRecord(
                    product="ASP.NET",
                    version=aspnet_version.strip(),
                    category="framework",
                    confidence=Confidence.HIGH,
                    evidence=[f"X-AspNet-Version header: {aspnet_version}"],
                    source_plugin=self.name,
                )
            )
        signatures = {
            "React": (r"__REACT_DEVTOOLS_GLOBAL_HOOK__|data-reactroot", "javascript_framework"),
            "Angular": (r"ng-version=|app-root", "javascript_framework"),
            "Vue": (r"data-v-[0-9a-f]{6,}|__VUE__", "javascript_framework"),
            "Spring": (r"Whitelabel Error Page|org\.springframework", "java_framework"),
            "Apache Tomcat": (r"Apache Tomcat|The requested resource .* is not available", "application_server"),
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
        cdn_waf: str | None = None
        header_text = "\n".join(f"{key}: {value}" for key, value in snapshot.headers.items())
        for product, pattern in {
            "Cloudflare": r"(?i)(?:^server:\s*cloudflare|^cf-ray:)",
            "Amazon CloudFront": r"(?i)(?:^x-amz-cf-id:|^via:.*cloudfront)",
            "Akamai": r"(?i)(?:^akamai-|^x-akamai-)",
            "Fastly": r"(?i)(?:^x-served-by:.*cache-|^x-fastly-request-id:)",
            "Sucuri": r"(?i)(?:^x-sucuri-id:|^server:\s*sucuri)",
            "Imperva": r"(?i)(?:^x-iinfo:|incap_ses)",
        }.items():
            if re.search(pattern, header_text, re.M):
                cdn_waf = product
                technologies.append(
                    TechnologyRecord(
                        product=product,
                        category="cdn_waf",
                        confidence=Confidence.HIGH,
                        evidence=[f"Response header signature matched {product}"],
                        source_plugin=self.name,
                    )
                )
                break
        parts = urlsplit(context.target.url)
        asset = AssetRecord(
            url=context.target.url,
            origin=_origin(context.target.url),
            scheme=parts.scheme,
            hostname=parts.hostname or "",
            port=parts.port or (443 if parts.scheme == "https" else 80),
            cdn_waf=cdn_waf,
            discovery_sources=[self.name],
        )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            assets=[asset],
            technologies=technologies,
            observations=[
                RawObservation(
                    plugin=self.name,
                    observation_type="technology_fingerprints",
                    target=context.target.url,
                    data={
                        "technologies": [
                            {
                                "product": item.product,
                                "version": item.version,
                                "confidence": item.confidence.value,
                                "evidence": item.evidence,
                            }
                            for item in technologies
                        ],
                        "cdn_waf": cdn_waf,
                    },
                    confidence=Confidence.HIGH if technologies else Confidence.MEDIUM,
                )
            ],
        )


class ClientComponentAnalysisPlugin(AssessmentPlugin):
    name = "client_component_analysis"
    description = "Deterministic supplemental client-library and version detection"
    requires = frozenset({"javascript_analysis_complete"})
    produces = frozenset({"component_analysis"})
    profiles = frozenset(
        {ScanProfile.STANDARD, ScanProfile.DEEP, ScanProfile.DISCOVERY_ONLY}
    )
    owasp = ("A06:2021",)
    phase = PentestPhase.ENUMERATION
    stage = 2
    security_question = "Which client libraries and exact advertised versions remain identifiable without Retire.js?"

    PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
        ("jQuery Migrate", "javascript_library", re.compile(r"(?i)jquery[ -]migrate(?: v|[-.])([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
        ("jQuery", "javascript_library", re.compile(r"(?i)(?:jquery(?: v|[-.])|jquery\s*[:=]\s*['\"])([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
        ("Bootstrap", "css_javascript_framework", re.compile(r"(?i)bootstrap(?: v|[-.])([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
        ("AngularJS", "javascript_framework", re.compile(r"(?i)angular(?:\.min)?\.js[^\n]{0,80}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)|angular\.version[^\n]{0,80}?([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
        ("Vue", "javascript_framework", re.compile(r"(?i)(?:vue(?:\.min)?\.js\?v=|Vue\.version\s*=\s*['\"])([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
        ("React", "javascript_framework", re.compile(r"(?i)(?:react(?:-dom)?(?:\.production\.min)?\.js\?v=|React\.version\s*=\s*['\"])([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
        ("Lodash", "javascript_library", re.compile(r"(?i)(?:lodash(?:\.min)?\.js\?v=|lodash\s+)([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
        ("Moment.js", "javascript_library", re.compile(r"(?i)(?:moment(?:\.min)?\.js\?v=|moment\.version\s*=\s*['\"])([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
    )

    async def run(self, context: PluginContext) -> PluginResult:
        seed = context.http_snapshots.get(context.target.url)
        sources = {**({context.target.url: seed.body} if seed else {}), **context.javascript_content}
        detected: dict[tuple[str, str], TechnologyRecord] = {}
        for source, content in sources.items():
            for product, category, pattern in self.PATTERNS:
                for match in pattern.finditer(content):
                    version = next((value for value in match.groups() if value), None)
                    if not version:
                        continue
                    key = (product.lower(), version)
                    record = detected.get(key)
                    evidence = f"Deterministic version signature in {source.split('#', 1)[0]}"
                    if record:
                        record.evidence = sorted(set([*record.evidence, evidence]))
                    else:
                        detected[key] = TechnologyRecord(
                            product=product,
                            version=version,
                            category=category,
                            confidence=Confidence.HIGH,
                            evidence=[evidence],
                            source_plugin=self.name,
                        )
        technologies = list(detected.values())
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            technologies=technologies,
            tests_attempted=len(sources),
            tests_completed=len(sources),
            metrics={"artifacts_scanned": len(sources), "components_detected": len(technologies)},
        )


class CMSDetectionPlugin(AssessmentPlugin):
    name = "cms_detection"
    description = "Passive multi-signal CMS and hosted-site-platform detection"
    requires = frozenset({"http_metadata"})
    produces = frozenset({"cms_detection", "technologies"})
    owasp = ("A06:2021",)
    phase = PentestPhase.RECONNAISSANCE
    security_question = "Does multi-source evidence identify a CMS or hosted site platform and an advertised version?"

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
    phase = PentestPhase.EXPLOITATION_VALIDATION
    security_question = "Does a directory response behave like a real index rather than a custom 200 or soft 404?"

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
        soft_404_body: str | None = None
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
                    if soft_404_body is None:
                        baseline_url = urljoin(
                            _origin(context.target.url),
                            f"/.wraith-directory-baseline-{context.assessment_id[:12]}/",
                        )
                        try:
                            baseline_response = await client.get(baseline_url)
                            soft_404_body = baseline_response.text[: self.BODY_LIMIT]
                        except httpx.HTTPError:
                            soft_404_body = ""
                        network_requests += 1
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
                baseline_similarity = (
                    SequenceMatcher(
                        None, soft_404_body[:100_000], snapshot.body[:100_000]
                    ).ratio()
                    if soft_404_body
                    else 0.0
                )
                if baseline_similarity >= 0.9:
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
                        confidence=Confidence.CONFIRMED,
                        validation_status=ValidationStatus.CONFIRMED,
                        evidence=[
                            EvidenceRecord(
                                kind="directory_index_response",
                                summary=f"Directory index markers: {', '.join(signatures)}",
                                location=url,
                                response={
                                    "status": snapshot.status_code,
                                    "content_type": content_type or None,
                                    "signatures": signatures,
                                    "soft_404_similarity": baseline_similarity,
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


class ManagementInterfacePlugin(AssessmentPlugin):
    name = "management_interfaces"
    description = "Bounded checks for public management, health, debug, and default surfaces"
    requires = frozenset({"http_metadata"})
    produces = frozenset({"management_interfaces", "debug_interfaces"})
    owasp = ("A01:2021", "A05:2021")
    cwe = ("CWE-200", "CWE-215", "CWE-489")
    timeout_seconds = 60
    phase = PentestPhase.SCANNING
    security_question = (
        "Are recognizable management, health, debug, metrics, or default-server surfaces "
        "publicly reachable?"
    )

    CANDIDATES = (
        "/admin",
        "/administrator",
        "/actuator",
        "/actuator/health",
        "/health",
        "/metrics",
        "/server-status",
        "/phpinfo.php",
        "/debug",
        "/console",
        "/manager/html",
    )
    SIGNATURES: tuple[tuple[str, str, re.Pattern[str], Severity, bool], ...] = (
        (
            "debug_interface_exposure",
            "Public debug or interactive console",
            re.compile(
                r"(?is)(werkzeug debugger|django debug|interactive console|debug toolbar|"
                r"traceback \(most recent call last\))"
            ),
            Severity.HIGH,
            False,
        ),
        (
            "phpinfo_exposure",
            "Public PHP configuration page",
            re.compile(r"(?is)(<title>\s*phpinfo\(\)|php version\s*</h1>|php credits)"),
            Severity.MEDIUM,
            False,
        ),
        (
            "server_status_exposure",
            "Public web-server status page",
            re.compile(r"(?is)(apache server status|server uptime:|scoreboard key:)"),
            Severity.MEDIUM,
            False,
        ),
        (
            "management_metrics_exposure",
            "Public application metrics endpoint",
            re.compile(r"(?m)^(?:#\s+(?:HELP|TYPE)\s+|process_(?:cpu|resident|virtual)_|jvm_)"),
            Severity.MEDIUM,
            False,
        ),
        (
            "management_interface_exposure",
            "Public application management interface",
            re.compile(
                r"(?is)(tomcat web application manager|spring boot actuator|"
                r"(?:admin|administrator|management)\s+(?:login|console|dashboard)|"
                r'\"_links\"\s*:\s*\{.{0,500}\"health\")'
            ),
            Severity.LOW,
            True,
        ),
        (
            "detailed_health_exposure",
            "Public detailed health endpoint",
            re.compile(
                r'(?is)\"status\"\s*:\s*\"(?:up|down|ok|healthy)\".{0,1000}'
                r'\"(?:components|details|diskSpace|db|redis|mail)\"\s*:'
            ),
            Severity.LOW,
            True,
        ),
    )
    DEFAULT_PAGE_SIGNATURES = (
        re.compile(r"(?is)<title>\s*apache2? (?:debian|ubuntu )?default page"),
        re.compile(r"(?is)<title>\s*welcome to nginx!?\s*</title>"),
        re.compile(r"(?is)<title>\s*iis windows server\s*</title>"),
        re.compile(r"(?is)internet information services.{0,300}welcome"),
    )

    @staticmethod
    def _soft_404_similarity(baseline: str, body: str) -> float:
        if not baseline or not body:
            return 0.0
        return SequenceMatcher(None, baseline[:100_000], body[:100_000]).ratio()

    async def run(self, context: PluginContext) -> PluginResult:
        origin = _origin(context.target.url)
        baseline_url = urljoin(
            f"{origin}/", f".wraith-management-baseline-{context.assessment_id[:12]}"
        )
        endpoints: list[EndpointRecord] = []
        findings: list[FindingCandidate] = []
        completed = 0
        failures = 0
        baseline_body = ""
        baseline_status: int | None = None
        async with httpx.AsyncClient(
            timeout=min(context.config.rate.request_timeout_seconds, 5.0),
            follow_redirects=False,
            headers={"User-Agent": "Wraith-Crawler/0.1 authorized-security-assessment"},
        ) as client:
            try:
                baseline = await client.get(baseline_url)
                baseline_body = baseline.text[:1_048_576]
                baseline_status = baseline.status_code
            except httpx.HTTPError:
                failures += 1
            for path in self.CANDIDATES:
                url = canonical_url(urljoin(f"{origin}/", path.lstrip("/")))
                if not context.scope.check(url).allowed:
                    continue
                try:
                    response = await client.get(url)
                except httpx.HTTPError:
                    failures += 1
                    continue
                completed += 1
                body = response.text[:1_048_576]
                similarity = self._soft_404_similarity(baseline_body, body)
                authentication_required = response.status_code in {401, 403}
                endpoints.append(
                    _endpoint(
                        url,
                        self.name,
                        status_code=response.status_code,
                        content_type=response.headers.get("content-type"),
                        authentication_required=authentication_required,
                        response_metadata={"soft_404_similarity": similarity},
                        confidence=Confidence.CONFIRMED,
                    )
                )
                if response.status_code != 200 or similarity >= 0.9:
                    continue
                for finding_type, title, signature, severity, manual_review in self.SIGNATURES:
                    match = signature.search(body)
                    if not match:
                        continue
                    indicator = re.sub(r"\s+", " ", match.group(0))[:160]
                    findings.append(
                        FindingCandidate(
                            finding_type=finding_type,
                            family="security_misconfiguration",
                            title=title,
                            description=(
                                "A bounded unauthenticated GET request returned a recognizable "
                                "management or diagnostic surface that was distinct from the soft-404 baseline."
                            ),
                            asset=origin,
                            affected_endpoints=[url],
                            method="GET",
                            severity=severity,
                            confidence=Confidence.HIGH,
                            validation_status=(
                                ValidationStatus.MANUAL_REVIEW
                                if manual_review
                                else ValidationStatus.CONFIRMED
                            ),
                            evidence=[
                                EvidenceRecord(
                                    kind="management_surface_response",
                                    summary=f"HTTP 200 matched {finding_type.replace('_', ' ')} signature",
                                    location=url,
                                    status_code=response.status_code,
                                    matched_indicator=indicator,
                                    response={
                                        "status": response.status_code,
                                        "content_type": response.headers.get("content-type"),
                                        "soft_404_similarity": similarity,
                                    },
                                )
                            ],
                            source_plugins=[self.name],
                            cwe=["CWE-489" if "debug" in finding_type else "CWE-200"],
                            owasp=["A05:2021"],
                            remediation=(
                                "Remove the surface from production or require strong authentication and "
                                "network-layer access controls; minimize diagnostic detail."
                            ),
                            manual_review=manual_review,
                        )
                    )
                    break

        seed = context.http_snapshots[context.target.url]
        if seed.status_code == 200 and any(
            signature.search(seed.body) for signature in self.DEFAULT_PAGE_SIGNATURES
        ):
            findings.append(
                FindingCandidate(
                    finding_type="default_server_page",
                    family="security_misconfiguration",
                    title="Default web-server page is exposed",
                    description="The supplied URL returned a recognizable default web-server page.",
                    asset=origin,
                    affected_endpoints=[context.target.url],
                    method="GET",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    validation_status=ValidationStatus.CONFIRMED,
                    evidence=[
                        EvidenceRecord(
                            kind="default_page_response",
                            summary="HTTP 200 matched a known default web-server page signature",
                            location=context.target.url,
                            status_code=seed.status_code,
                            matched_indicator="default server page",
                        )
                    ],
                    source_plugins=[self.name],
                    cwe=["CWE-16"],
                    owasp=["A05:2021"],
                    remediation="Replace the default virtual-host page and remove unused default content.",
                )
            )

        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            endpoints=endpoints,
            findings=findings,
            tests_attempted=len(self.CANDIDATES) + 1,
            tests_completed=completed + (1 if baseline_status is not None else 0),
            observations=[
                RawObservation(
                    plugin=self.name,
                    observation_type="management_surface_checks",
                    target=context.target.url,
                    data={
                        "candidate_count": len(self.CANDIDATES),
                        "responses_received": completed,
                        "matches": len(findings),
                        "baseline_status": baseline_status,
                    },
                    confidence=Confidence.HIGH,
                )
            ],
            metrics={
                "requests": len(self.CANDIDATES) + 1,
                "responses_received": completed + (1 if baseline_status is not None else 0),
                "failed_requests": failures,
                "validated_surfaces": len(findings),
            },
        )


class PassiveExposurePlugin(AssessmentPlugin):
    name = "passive_exposure"
    requires = frozenset({"http_metadata", "endpoints"})
    produces = frozenset({"passive_exposure_assessment"})
    owasp = ("A01:2021", "A05:2021", "A08:2021")
    phase = PentestPhase.SCANNING
    security_question = "Do responses disclose debug data, sensitive implementation details, or public management surfaces?"

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
        disclosure_patterns = {
            "database_error": re.compile(
                r"(?i)(?:SQLSTATE\[|ORA-[0-9]{5}|mysql_fetch|psql:|unterminated quoted string|sqlite3?\.(?:OperationalError|DatabaseError))"
            ),
            "filesystem_path": re.compile(
                r"(?i)(?:[A-Z]:\\(?:inetpub|users|windows)\\|/(?:var/www|home|opt|srv|usr/local)/)[^\s<'\"]{2,}"
            ),
            "internal_ip": re.compile(
                r"\b(?:10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|192\.168\.(?:[0-9]{1,3}\.)[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.(?:[0-9]{1,3}\.)[0-9]{1,3})\b"
            ),
            "internal_hostname": re.compile(
                r"(?i)\b[a-z0-9][a-z0-9.-]*\.(?:internal|local|corp|lan)\b"
            ),
        }
        matches = {
            name: pattern.search(body)
            for name, pattern in disclosure_patterns.items()
        }
        matched_names = sorted(name for name, match in matches.items() if match)
        if matched_names:
            security_impacting = "database_error" in matched_names
            findings.append(
                FindingCandidate(
                    finding_type="sensitive_information_disclosure",
                    family="information_exposure",
                    title=(
                        "Security-impacting implementation details are exposed"
                        if security_impacting
                        else "Internal implementation details are disclosed"
                    ),
                    description="The public response contains deterministic database, filesystem, private-address, or internal-host indicators.",
                    asset=_origin(snapshot.url),
                    affected_endpoints=[snapshot.url],
                    severity=Severity.MEDIUM if security_impacting else Severity.LOW,
                    confidence=Confidence.HIGH,
                    validation_status=ValidationStatus.CONFIRMED,
                    evidence=[
                        EvidenceRecord(
                            kind="information_disclosure_signature",
                            summary=f"Matched disclosure classes: {', '.join(matched_names)}",
                            location=snapshot.url,
                            matched_indicator=",".join(matched_names),
                            status_code=snapshot.status_code,
                        )
                    ],
                    source_plugins=[self.name],
                    cwe=["CWE-209", "CWE-200"],
                    owasp=["A05:2021"],
                    remediation="Return generic public errors and remove internal paths, hosts, addresses, and database diagnostics from responses.",
                    metadata={"disclosure_class": "security_impacting" if security_impacting else "informational"},
                )
            )
        advertised = {
            header: value
            for header, value in {
                "server": snapshot.headers.get("server"),
                "x-powered-by": snapshot.headers.get("x-powered-by"),
                "x-aspnet-version": snapshot.headers.get("x-aspnet-version"),
            }.items()
            if value and re.search(r"[0-9]+\.[0-9]+", value)
        }
        if advertised:
            findings.append(
                FindingCandidate(
                    finding_type="version_disclosure",
                    family="information_exposure",
                    title="Technology versions are advertised in HTTP headers",
                    description="Response headers disclose exact server or framework versions that can accelerate vulnerability research.",
                    asset=_origin(snapshot.url),
                    affected_endpoints=[snapshot.url],
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.CONFIRMED,
                    validation_status=ValidationStatus.CONFIRMED,
                    evidence=[
                        EvidenceRecord(
                            kind="version_headers",
                            summary=f"Version-bearing headers: {', '.join(sorted(advertised))}",
                            location=snapshot.url,
                            response={"headers": advertised},
                        )
                    ],
                    source_plugins=[self.name],
                    cwe=["CWE-200"],
                    owasp=["A05:2021"],
                    remediation="Suppress unnecessary version tokens while keeping components fully patched.",
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
    phase = PentestPhase.ENUMERATION
    stage = 0
    security_question = "What additional in-scope paths are disclosed by robots.txt and sitemap documents?"

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
    phase = PentestPhase.EXPLOITATION_VALIDATION
    security_question = "Are curated deployment, source, backup, or configuration artifacts publicly retrievable?"

    PATHS = {
        "/.env": ("environment file", re.compile(r"(?im)^(?:DB_|DATABASE_|API_|SECRET_|APP_KEY)")),
        "/.env.backup": ("environment backup", re.compile(r"(?im)^(?:DB_|DATABASE_|API_|SECRET_|APP_KEY)")),
        "/.git/HEAD": ("Git metadata", re.compile(r"^ref: refs/heads/")),
        "/.git/config": ("Git configuration", re.compile(r"(?im)^\[core\]|^\[remote ")),
        "/.svn/entries": ("Subversion metadata", re.compile(r"(?i)(?:dir\n|svn:|has-props)")),
        "/web.config": ("IIS configuration", re.compile(r"(?i)<configuration[\s>]")),
        "/web.config.bak": ("IIS configuration backup", re.compile(r"(?i)<configuration[\s>]")),
        "/appsettings.json": ("application settings", re.compile(r'(?i)"(?:ConnectionStrings|Logging)"\s*:')),
        "/package.json": ("Node package manifest", re.compile(r'"(?:name|dependencies)"\s*:')),
        "/package-lock.json": ("Node dependency lock", re.compile(r'"lockfileVersion"\s*:')),
        "/composer.json": ("Composer manifest", re.compile(r'"(?:require|autoload)"\s*:')),
        "/composer.lock": ("Composer dependency lock", re.compile(r'"packages"\s*:')),
        "/Dockerfile": ("Docker build file", re.compile(r"(?im)^FROM\s+\S+")),
        "/docker-compose.yml": ("Compose manifest", re.compile(r"(?im)^(?:services|version):")),
        "/kubernetes.yaml": ("Kubernetes manifest", re.compile(r"(?im)^apiVersion:\s*|^kind:\s*(?:Deployment|Service|Secret)")),
        "/.gitlab-ci.yml": ("GitLab CI configuration", re.compile(r"(?im)^(?:stages|image|variables):")),
        "/.github/workflows/ci.yml": ("GitHub Actions workflow", re.compile(r"(?im)^on:\s*|^jobs:\s*")),
        "/backup.sql": ("database dump", re.compile(r"(?i)(CREATE TABLE|INSERT INTO)")),
        "/database.sql": ("database dump", re.compile(r"(?i)(CREATE TABLE|INSERT INTO)")),
        "/backup.zip": ("ZIP backup", re.compile(r"^PK")),
        "/app.log": ("application log", re.compile(r"(?i)(?:exception|traceback|error\s*[:\[])")),
        "/debug.log": ("debug log", re.compile(r"(?i)(?:exception|traceback|debug|error\s*[:\[])")),
    }

    async def run(self, context: PluginContext) -> PluginResult:
        origin = _origin(context.target.url)
        baseline_body = ""
        findings: list[FindingCandidate] = []
        endpoints: list[EndpointRecord] = []
        async with httpx.AsyncClient(timeout=context.config.rate.request_timeout_seconds, follow_redirects=False) as client:
            baseline_url = urljoin(origin, f"/.wraith-not-found-{context.assessment_id[:12]}")
            try:
                baseline_response = await client.get(
                    baseline_url, headers={"User-Agent": "Wraith-Crawler/0.1"}
                )
                baseline_body = baseline_response.text[:1_000_000]
            except httpx.HTTPError:
                baseline_response = None
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
                similarity = (
                    SequenceMatcher(None, baseline_body[:100_000], body[:100_000]).ratio()
                    if baseline_body
                    else 0.0
                )
                valid = response.status_code == 200 and validator.search(body) and similarity < 0.9
                endpoints.append(_endpoint(url, self.name, status_code=response.status_code, content_type=response.headers.get("content-type")))
                if not valid:
                    continue
                context.http_snapshots[url] = HTTPResponseSnapshot(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body=body,
                    elapsed_ms=0,
                )
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
                                summary=(
                                    f"HTTP 200 and deterministic {label} signature; "
                                    f"soft-404 similarity {similarity:.2f}; body hash {body_hash[:12]}"
                                ),
                                location=url,
                                status_code=response.status_code,
                                matched_indicator=label,
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
            tests_attempted=len(self.PATHS) + 1,
            tests_completed=len(endpoints) + (1 if baseline_response is not None else 0),
            metrics={"requests": len(self.PATHS) + 1, "validated": len(findings)},
        )


class SourceMapPlugin(AssessmentPlugin):
    name = "source_maps"
    requires = frozenset({"javascript_analysis_complete"})
    produces = frozenset({"source_map_analysis_complete"})
    owasp = ("A08:2021",)
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP, ScanProfile.DISCOVERY_ONLY})
    phase = PentestPhase.ENUMERATION
    stage = 2
    security_question = "Are referenced source maps actually public and do they disclose original source structure?"

    async def run(self, context: PluginContext) -> PluginResult:
        references = {
            endpoint.url
            for endpoint in context.inventory.endpoints.values()
            if urlsplit(endpoint.url).path.lower().endswith(".map")
        }
        for source, content in context.javascript_content.items():
            for raw in re.findall(
                r"(?im)[#@]\s*sourceMappingURL\s*=\s*(\S+\.map(?:\?\S*)?)", content
            ):
                try:
                    references.add(context.scope.resolve(raw, source.split("#", 1)[0]))
                except ValueError:
                    continue
        endpoints: list[EndpointRecord] = []
        findings: list[FindingCandidate] = []
        completed = 0
        async with httpx.AsyncClient(
            timeout=context.config.rate.request_timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "Wraith-Crawler/0.1"},
        ) as client:
            for url in sorted(references)[: min(context.config.rate.max_candidates, 50)]:
                if not context.scope.check(url).allowed:
                    continue
                try:
                    response = await client.get(url)
                except httpx.HTTPError:
                    continue
                completed += 1
                endpoints.append(
                    _endpoint(
                        url,
                        self.name,
                        status_code=response.status_code,
                        content_type=response.headers.get("content-type"),
                    )
                )
                if response.status_code != 200 or len(response.content) > 5_000_000:
                    continue
                try:
                    payload = response.json()
                except ValueError:
                    continue
                if not isinstance(payload, dict) or not isinstance(payload.get("sources"), list):
                    continue
                source_count = len(payload["sources"])
                context.source_map_content[url] = response.text
                findings.append(
                    FindingCandidate(
                        finding_type="source_map_exposure",
                        family="client_side_exposure",
                        title="Public JavaScript source map is accessible",
                        description="A referenced source map returned valid source-map JSON and discloses original source structure.",
                        asset=_origin(url),
                        affected_endpoints=[url],
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        validation_status=ValidationStatus.CONFIRMED,
                        evidence=[
                            EvidenceRecord(
                                kind="source_map_response",
                                summary=f"HTTP 200 valid source map with {source_count} source entries",
                                location=url,
                                status_code=response.status_code,
                                matched_indicator="sources array",
                                response={"status": response.status_code, "source_count": source_count},
                            )
                        ],
                        source_plugins=[self.name],
                        cwe=["CWE-200"],
                        owasp=["A08:2021"],
                        remediation="Do not publish production source maps unless required; remove secrets and internal-only metadata from builds.",
                        metadata={"source_count": source_count, "sensitive_context": bool(payload.get("sourcesContent"))},
                    )
                )
        return self.success(
            self.name,
            capabilities_produced=set(self.produces),
            endpoints=endpoints,
            findings=findings,
            tests_attempted=len(references),
            tests_completed=completed,
            metrics={"candidates": len(references), "validated": len(findings)},
        )


BUILTIN_PLUGINS = (
    SeedHTTPPlugin,
    DNSReconPlugin,
    TLSPlugin,
    HTMLDiscoveryPlugin,
    JavaScriptAnalysisPlugin,
    ClientComponentAnalysisPlugin,
    SecurityHeadersPlugin,
    CookieSecurityPlugin,
    SessionManagementPlugin,
    CORSPlugin,
    HTTPMethodsPlugin,
    FingerprintingPlugin,
    CMSDetectionPlugin,
    DirectoryListingPlugin,
    ManagementInterfacePlugin,
    PassiveExposurePlugin,
    RobotsSitemapPlugin,
    OpenAPIDiscoveryPlugin,
    SensitiveFilesPlugin,
    SourceMapPlugin,
    SecretsPlugin,
    ParameterAnalysisPlugin,
    AuthenticationDiscoveryPlugin,
    GraphQLDiscoveryPlugin,
    AnonymousAPIAccessPlugin,
    ReflectionAnalysisPlugin,
    RedirectTraversalAnalysisPlugin,
)
