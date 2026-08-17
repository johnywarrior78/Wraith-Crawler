from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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
from ..tool_identity import projectdiscovery_httpx_version
from .base import ExternalToolPlugin, PluginContext


def _origin(url: str) -> str:
    parts = urlsplit(url)
    port = parts.port
    default = (parts.scheme == "http" and port in {None, 80}) or (
        parts.scheme == "https" and port in {None, 443}
    )
    return f"{parts.scheme}://{parts.hostname}" + ("" if default else f":{port}")


def _severity(value: str | None) -> Severity:
    normalized = (value or "informational").lower()
    aliases = {"info": "informational", "unknown": "informational"}
    try:
        return Severity(aliases.get(normalized, normalized))
    except ValueError:
        return Severity.INFORMATIONAL


class ProjectDiscoveryHTTPXPlugin(ExternalToolPlugin):
    name = "httpx"
    description = "ProjectDiscovery HTTPX enrichment from the seed URL"
    external_tool = "httpx"
    requires = frozenset({"seed_url"})
    produces = frozenset({"httpx_metadata", "validated_origin", "endpoints"})
    profiles = frozenset({ScanProfile.QUICK, ScanProfile.STANDARD, ScanProfile.DEEP, ScanProfile.DISCOVERY_ONLY})

    async def run(self, context: PluginContext) -> PluginResult:
        tool = self.resolve_tool(context)
        if not tool:
            return self.blocked(self.name, FailureReason.TOOL_MISSING, "ProjectDiscovery httpx was not found")
        identity = await self._identity(tool)
        if not identity:
            return self.blocked(
                self.name,
                FailureReason.CONFIGURATION_ERROR,
                "Resolved httpx is not ProjectDiscovery httpx",
            )
        command = [
            tool,
            "-u",
            context.target.url,
            "-json",
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-ip",
            "-cname",
            "-response-time",
            "-location",
            "-tls-grab",
            "-cdn",
            "-timeout",
            str(max(1, int(context.config.rate.request_timeout_seconds))),
        ]
        code, stdout, stderr, timed_out = await self.execute(
            command, timeout=context.config.rate.tool_timeout_seconds
        )
        rows, malformed = self.parse_jsonl(stdout)
        assets: list[AssetRecord] = []
        endpoints: list[EndpointRecord] = []
        technologies: list[TechnologyRecord] = []
        observations: list[RawObservation] = []
        for row in rows:
            url = row.get("url") or row.get("input")
            if not isinstance(url, str):
                continue
            try:
                url = canonical_url(url)
            except ValueError:
                continue
            if not context.scope.check(url).allowed:
                continue
            parts = urlsplit(url)
            tech_values = row.get("tech") or row.get("technologies") or []
            if isinstance(tech_values, str):
                tech_values = [tech_values]
            for tech in tech_values:
                product, _, version = str(tech).partition(":")
                technologies.append(
                    TechnologyRecord(
                        product=product,
                        version=version or None,
                        category="detected",
                        confidence=Confidence.HIGH,
                        evidence=[f"ProjectDiscovery httpx technology result: {tech}"],
                        source_plugin=self.name,
                    )
                )
            ips = row.get("a") or row.get("ip") or []
            if isinstance(ips, str):
                ips = [ips]
            cnames = row.get("cname") or []
            if isinstance(cnames, str):
                cnames = [cnames]
            assets.append(
                AssetRecord(
                    url=url,
                    origin=_origin(url),
                    scheme=parts.scheme,
                    hostname=parts.hostname or "",
                    port=parts.port or (443 if parts.scheme == "https" else 80),
                    resolved_ips=list(map(str, ips)),
                    cname=str(cnames[0]) if cnames else None,
                    status_code=row.get("status_code"),
                    redirect_chain=[row["location"]] if row.get("location") else [],
                    title=row.get("title"),
                    server=row.get("webserver"),
                    cdn_waf=row.get("cdn_name") or ("detected" if row.get("cdn") else None),
                    tls=row.get("tls") or {},
                    discovery_sources=[self.name],
                )
            )
            endpoints.append(
                EndpointRecord(
                    url=url,
                    origin=_origin(url),
                    path=parts.path or "/",
                    status_code=row.get("status_code"),
                    content_type=row.get("content_type"),
                    response_metadata={
                        "content_length": row.get("content_length"),
                        "response_time": row.get("time"),
                    },
                    sources=[self.name],
                    confidence=Confidence.CONFIRMED,
                )
            )
            observations.append(
                RawObservation(
                    plugin=self.name,
                    observation_type="httpx_result",
                    target=url,
                    data={key: value for key, value in row.items() if key not in {"body", "raw"}},
                    confidence=Confidence.CONFIRMED,
                )
            )
        if timed_out:
            state = PluginState.PARTIAL if rows else PluginState.TIMED_OUT
            reason = FailureReason.TIMEOUT
        elif code != 0:
            state = PluginState.PARTIAL if rows else PluginState.FAILED
            reason = FailureReason.TOOL_EXECUTION_FAILED
        elif malformed and not rows:
            state = PluginState.FAILED
            reason = FailureReason.PARSING_ERROR
        else:
            state = PluginState.COMPLETED
            reason = None
        return PluginResult(
            plugin=self.name,
            state=state,
            failure_reason=reason,
            message=stderr.decode(errors="replace")[-500:] or None,
            capabilities_produced=set(self.produces) if rows else set(),
            assets=assets,
            endpoints=endpoints,
            technologies=technologies,
            observations=observations,
            metrics={"valid_rows": len(rows), "malformed_rows": malformed, "exit_code": code, "tool_identity": identity},
            partial_output_trustworthy=bool(rows),
        )

    async def _identity(self, tool: str) -> str | None:
        for args in (("-version",), ("-h",)):
            code, stdout, stderr, _ = await self.execute([tool, *args], timeout=10)
            text = (stdout + stderr).decode(errors="replace")
            identity = projectdiscovery_httpx_version(text)
            if identity:
                return identity
            if code == 0 and args == ("-version",):
                break
        return None


class KatanaPlugin(ExternalToolPlugin):
    name = "katana"
    external_tool = "katana"
    requires = frozenset({"seed_url"})
    produces = frozenset({"crawler_endpoints", "endpoints", "javascript_urls"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP, ScanProfile.DISCOVERY_ONLY})

    async def run(self, context: PluginContext) -> PluginResult:
        tool = self.resolve_tool(context)
        if not tool:
            return self.blocked(self.name, FailureReason.TOOL_MISSING, "Katana was not found")
        command = [
            tool,
            "-u",
            context.target.url,
            "-jsonl",
            "-silent",
            "-depth",
            str(context.config.rate.crawl_depth),
            "-concurrency",
            str(max(1, min(context.config.rate.plugin_concurrency, 10))),
            "-rate-limit",
            str(max(1, int(context.config.rate.global_requests_per_second))),
            "-timeout",
            str(max(1, int(context.config.rate.request_timeout_seconds))),
        ]
        code, stdout, stderr, timed_out = await self.execute(command, timeout=context.config.rate.tool_timeout_seconds)
        rows, malformed = self.parse_jsonl(stdout)
        endpoints: list[EndpointRecord] = []
        for row in rows:
            request = row.get("request") if isinstance(row.get("request"), dict) else {}
            response = row.get("response") if isinstance(row.get("response"), dict) else {}
            url = request.get("endpoint") or request.get("url") or row.get("url")
            if not isinstance(url, str):
                continue
            try:
                url = canonical_url(url)
            except ValueError:
                continue
            if not context.scope.check(url).allowed:
                continue
            parts = urlsplit(url)
            endpoints.append(
                EndpointRecord(
                    url=url,
                    origin=_origin(url),
                    path=parts.path or "/",
                    method=str(request.get("method") or "GET").upper(),
                    status_code=response.get("status_code") or response.get("status"),
                    content_type=(response.get("headers") or {}).get("content-type") if isinstance(response.get("headers"), dict) else None,
                    response_metadata={"source": row.get("source")},
                    sources=[self.name],
                    javascript_source=row.get("source") if str(row.get("source", "")).endswith(".js") else None,
                    confidence=Confidence.HIGH,
                )
            )
        state = PluginState.COMPLETED
        reason = None
        if timed_out:
            state, reason = (PluginState.PARTIAL if endpoints else PluginState.TIMED_OUT), FailureReason.TIMEOUT
        elif code != 0:
            state, reason = (PluginState.PARTIAL if endpoints else PluginState.FAILED), FailureReason.TOOL_EXECUTION_FAILED
        return PluginResult(
            plugin=self.name,
            state=state,
            failure_reason=reason,
            message=stderr.decode(errors="replace")[-500:] or None,
            capabilities_produced=set(self.produces) if endpoints else set(),
            endpoints=endpoints[: context.config.rate.max_endpoints],
            metrics={"valid_rows": len(rows), "malformed_rows": malformed, "in_scope_endpoints": len(endpoints)},
            partial_output_trustworthy=bool(endpoints),
        )


class NucleiPlugin(ExternalToolPlugin):
    name = "nuclei"
    external_tool = "nuclei"
    requires = frozenset({"seed_url"})
    produces = frozenset({"nuclei_assessment"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP})
    owasp = ("A03:2021", "A05:2021", "A06:2021")

    SAFE_EXCLUDE_TAGS = "dos,fuzz,bruteforce,intrusive,destructive"

    @staticmethod
    def collapse_origins(urls: list[str]) -> list[str]:
        return sorted({_origin(canonical_url(url)) for url in urls})

    async def run(self, context: PluginContext) -> PluginResult:
        tool = self.resolve_tool(context)
        if not tool:
            return self.blocked(self.name, FailureReason.TOOL_MISSING, "Nuclei was not found")
        urls = [context.target.url, *(endpoint.url for endpoint in context.inventory.endpoints.values())]
        mode = context.config.tools.nuclei_target_mode
        targets = (
            sorted({canonical_url(url) for url in urls})[: context.config.rate.max_endpoints]
            if mode == "endpoints"
            else self.collapse_origins(urls)
        )
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as stream:
            for target in targets:
                stream.write(target + "\n")
            target_file = Path(stream.name)
        try:
            command = [
                tool,
                "-list",
                str(target_file),
                "-jsonl",
                "-silent",
                "-severity",
                "info,low,medium,high,critical",
                "-exclude-tags",
                self.SAFE_EXCLUDE_TAGS,
                "-rate-limit",
                str(max(1, int(context.config.rate.global_requests_per_second))),
                "-timeout",
                str(max(1, int(context.config.rate.request_timeout_seconds))),
                "-retries",
                str(context.config.rate.retries),
            ]
            code, stdout, stderr, timed_out = await self.execute(command, timeout=context.config.rate.tool_timeout_seconds)
        finally:
            target_file.unlink(missing_ok=True)
        rows, malformed = self.parse_jsonl(stdout)
        findings = [finding for row in rows if (finding := self.parse_finding(row)) is not None]
        state, reason = PluginState.COMPLETED, None
        if timed_out:
            state, reason = (PluginState.PARTIAL if findings else PluginState.TIMED_OUT), FailureReason.TIMEOUT
        elif code != 0:
            state, reason = (PluginState.PARTIAL if findings else PluginState.FAILED), FailureReason.TOOL_EXECUTION_FAILED
        return PluginResult(
            plugin=self.name,
            state=state,
            failure_reason=reason,
            message=stderr.decode(errors="replace")[-500:] or None,
            capabilities_produced=set(self.produces) if rows else set(),
            findings=findings,
            metrics={
                "target_mode": mode,
                "targets": len(targets),
                "valid_rows": len(rows),
                "malformed_rows": malformed,
            },
            partial_output_trustworthy=bool(findings),
        )

    def parse_finding(self, row: dict[str, Any]) -> FindingCandidate | None:
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        template_id = str(row.get("template-id") or row.get("template_id") or "nuclei-observation")
        matched = row.get("matched-at") or row.get("matched") or row.get("host")
        if not isinstance(matched, str):
            return None
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        cwe = classification.get("cwe-id") or []
        cve = classification.get("cve-id") or []
        if isinstance(cwe, str):
            cwe = [cwe]
        if isinstance(cve, str):
            cve = [cve]
        cvss = classification.get("cvss-score")
        try:
            cvss = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            cvss = None
        evidence_text = row.get("matcher-name") or row.get("extracted-results") or template_id
        return FindingCandidate(
            finding_type=f"nuclei:{template_id}",
            family="nuclei",
            title=str(info.get("name") or template_id),
            description=str(info.get("description") or "Nuclei matched a safe template against the target."),
            asset=_origin(matched),
            affected_endpoints=[matched],
            severity=_severity(info.get("severity")),
            confidence=Confidence.HIGH,
            validation_status=ValidationStatus.SUSPECTED,
            evidence=[
                EvidenceRecord(
                    kind="nuclei_match",
                    summary=f"Template {template_id} matched: {evidence_text}",
                    location=matched,
                )
            ],
            source_plugins=[self.name],
            cwe=list(map(str, cwe)),
            cve=list(map(str, cve)),
            owasp=[],
            cvss=cvss,
            remediation=str(info.get("remediation") or "Apply the vendor or control-specific remediation and verify the affected endpoint."),
            references=list(map(str, info.get("reference") or [])),
            metadata={"template_id": template_id, "template_url": row.get("template-url")},
        )


class NiktoPlugin(ExternalToolPlugin):
    name = "nikto"
    external_tool = "nikto"
    requires = frozenset({"seed_url"})
    produces = frozenset({"nikto_assessment"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP})
    owasp = ("A05:2021",)

    STABLE_TYPES = {
        "directory indexing": "directory_listing",
        "x-frame-options": "missing_security_headers",
        "x-content-type-options": "missing_security_headers",
        "server leaks": "version_disclosure",
    }

    async def run(self, context: PluginContext) -> PluginResult:
        tool = self.resolve_tool(context)
        if not tool:
            return self.blocked(self.name, FailureReason.TOOL_MISSING, "Nikto was not found")
        command = [tool, "-h", context.target.url, "-nointeractive", "-Format", "json", "-output", "-"]
        code, stdout, stderr, timed_out = await self.execute(command, timeout=context.config.rate.tool_timeout_seconds)
        findings = self.parse_output(stdout.decode(errors="replace"), context.target.url)
        state, reason = PluginState.COMPLETED, None
        if timed_out:
            state, reason = (PluginState.PARTIAL if findings else PluginState.TIMED_OUT), FailureReason.TIMEOUT
        elif code != 0 and not findings:
            state, reason = PluginState.FAILED, FailureReason.TOOL_EXECUTION_FAILED
        return PluginResult(
            plugin=self.name,
            state=state,
            failure_reason=reason,
            message=stderr.decode(errors="replace")[-500:] or None,
            capabilities_produced=set(self.produces) if findings or code == 0 else set(),
            findings=findings,
            partial_output_trustworthy=bool(findings),
        )

    def parse_output(self, text: str, target: str) -> list[FindingCandidate]:
        try:
            parsed = json.loads(text)
            vulnerabilities = parsed.get("vulnerabilities", []) if isinstance(parsed, dict) else []
        except json.JSONDecodeError:
            vulnerabilities = []
            for line in text.splitlines():
                if line.startswith("+ "):
                    vulnerabilities.append({"msg": line[2:], "url": target})
        findings: list[FindingCandidate] = []
        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue
            message = str(item.get("msg") or item.get("message") or "Nikto observation")
            url = str(item.get("url") or item.get("uri") or target)
            finding_type = next(
                (stable for marker, stable in self.STABLE_TYPES.items() if marker in message.lower()),
                "nikto_manual_review",
            )
            manual = finding_type == "nikto_manual_review"
            findings.append(
                FindingCandidate(
                    finding_type=finding_type,
                    family="security_misconfiguration",
                    title=message[:200],
                    description="Nikto reported an externally observable web-server condition.",
                    asset=_origin(target),
                    affected_endpoints=[url],
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    validation_status=ValidationStatus.MANUAL_REVIEW if manual else ValidationStatus.SUSPECTED,
                    evidence=[EvidenceRecord(kind="nikto_observation", summary=message, location=url)],
                    source_plugins=[self.name],
                    cwe=["CWE-16"],
                    owasp=["A05:2021"],
                    remediation="Review the exact observation, confirm target behavior, and apply the control-specific hardening.",
                    manual_review=manual,
                    metadata={"nikto_id": item.get("id"), "review_reason": "Observation has no stable deterministic Wraith taxonomy" if manual else None},
                )
            )
        return findings


class RetireJSPlugin(ExternalToolPlugin):
    name = "retirejs"
    external_tool = "retire"
    requires = frozenset({"javascript_content"})
    produces = frozenset({"javascript_component_assessment"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP})
    owasp = ("A06:2021",)

    async def run(self, context: PluginContext) -> PluginResult:
        tool = self.resolve_tool(context)
        if not tool:
            return self.blocked(self.name, FailureReason.TOOL_MISSING, "Retire.js was not found")
        if not context.javascript_content:
            return PluginResult(plugin=self.name, state=PluginState.NOT_APPLICABLE, message="No downloaded JavaScript content")
        with tempfile.TemporaryDirectory(prefix="wraith-retire-") as directory:
            root = Path(directory)
            for index, content in enumerate(context.javascript_content.values()):
                (root / f"script-{index}.js").write_text(content, encoding="utf-8")
            command = [tool, "--path", str(root), "--outputformat", "json", "--exitwith", "0"]
            code, stdout, stderr, timed_out = await self.execute(command, timeout=context.config.rate.tool_timeout_seconds)
        findings, technologies = self.parse_output(stdout, context.target.url)
        state, reason = PluginState.COMPLETED, None
        if timed_out:
            state, reason = (PluginState.PARTIAL if findings else PluginState.TIMED_OUT), FailureReason.TIMEOUT
        elif code != 0 and not findings:
            state, reason = PluginState.FAILED, FailureReason.TOOL_EXECUTION_FAILED
        return PluginResult(
            plugin=self.name,
            state=state,
            failure_reason=reason,
            message=stderr.decode(errors="replace")[-500:] or None,
            capabilities_produced=set(self.produces) if code == 0 or findings else set(),
            findings=findings,
            technologies=technologies,
            partial_output_trustworthy=bool(findings),
        )

    def parse_output(self, payload: bytes, target: str) -> tuple[list[FindingCandidate], list[TechnologyRecord]]:
        try:
            data = json.loads(payload or b"{}")
        except json.JSONDecodeError:
            return [], []
        rows = data.get("data", []) if isinstance(data, dict) else []
        findings: list[FindingCandidate] = []
        technologies: list[TechnologyRecord] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            for result in row.get("results", []):
                component = str(result.get("component") or "JavaScript component")
                version = str(result.get("version") or "unknown")
                vulnerabilities = result.get("vulnerabilities") or []
                references = [str(v.get("identifiers", {}).get("CVE", "")) for v in vulnerabilities if isinstance(v, dict)]
                references = [ref for ref in references if ref]
                technologies.append(
                    TechnologyRecord(
                        product=component,
                        version=version,
                        category="javascript_library",
                        confidence=Confidence.HIGH,
                        evidence=[f"Retire.js identified {component} {version}"],
                        source_plugin=self.name,
                        vulnerability_references=references,
                    )
                )
                if vulnerabilities:
                    findings.append(
                        FindingCandidate(
                            finding_type="vulnerable_javascript_component",
                            family="vulnerable_component",
                            title=f"Vulnerable JavaScript component: {component} {version}",
                            description="Retire.js matched the client library version to known vulnerability data.",
                            asset=_origin(target),
                            affected_endpoints=[target],
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            validation_status=ValidationStatus.SUSPECTED,
                            evidence=[EvidenceRecord(kind="retirejs_match", summary=f"{component} {version}", location=target)],
                            source_plugins=[self.name],
                            cwe=["CWE-1104"],
                            cve=references,
                            owasp=["A06:2021"],
                            remediation="Upgrade to a supported non-vulnerable release and regression-test affected pages.",
                            metadata={"component": component, "version": version},
                        )
                    )
        return findings, technologies


class DalfoxPlugin(ExternalToolPlugin):
    name = "dalfox"
    external_tool = "dalfox"
    requires = frozenset({"parameter_candidates"})
    produces = frozenset({"xss_validation"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP})
    owasp = ("A03:2021",)

    async def run(self, context: PluginContext) -> PluginResult:
        tool = self.resolve_tool(context)
        if not tool:
            return self.blocked(self.name, FailureReason.TOOL_MISSING, "Dalfox was not found")
        findings: list[FindingCandidate] = []
        errors = 0
        for url, parameter in context.queues.xss[: min(context.config.rate.max_candidates, 25)]:
            command = [tool, "url", url, "--silence", "--format", "json", "--param", parameter, "--skip-bav"]
            code, stdout, _stderr, timed_out = await self.execute(command, timeout=min(context.config.rate.tool_timeout_seconds, 120))
            if timed_out or code != 0:
                errors += 1
            rows, _ = self.parse_jsonl(stdout)
            for row in rows:
                if str(row.get("type", "")).lower() not in {"vuln", "verified", "xss"} and not row.get("poc"):
                    continue
                findings.append(
                    FindingCandidate(
                        finding_type="cross_site_scripting",
                        family="injection",
                        title="Cross-site scripting validated by Dalfox",
                        description="Dalfox produced a validated XSS proof against a targeted candidate parameter.",
                        asset=_origin(url),
                        affected_endpoints=[url],
                        parameters=[parameter],
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        validation_status=ValidationStatus.CONFIRMED,
                        evidence=[EvidenceRecord(kind="dalfox_result", summary=str(row.get("type") or "validated XSS"), location=url)],
                        source_plugins=[self.name],
                        cwe=["CWE-79"],
                        owasp=["A03:2021"],
                        remediation="Use context-aware output encoding, input sanitization, and a restrictive CSP.",
                    )
                )
        state = PluginState.PARTIAL if errors and findings else PluginState.COMPLETED
        return PluginResult(
            plugin=self.name,
            state=state,
            failure_reason=FailureReason.TOOL_EXECUTION_FAILED if errors and not findings else None,
            capabilities_produced=set(self.produces),
            findings=findings,
            metrics={"candidates": len(context.queues.xss), "errors": errors},
            partial_output_trustworthy=bool(findings),
        )


class SQLMapPlugin(ExternalToolPlugin):
    name = "sqlmap"
    external_tool = "sqlmap"
    requires = frozenset({"parameter_candidates"})
    produces = frozenset({"sqli_validation"})
    profiles = frozenset({ScanProfile.STANDARD, ScanProfile.DEEP})
    owasp = ("A03:2021",)

    async def run(self, context: PluginContext) -> PluginResult:
        tool = self.resolve_tool(context)
        if not tool:
            return self.blocked(self.name, FailureReason.TOOL_MISSING, "SQLMap was not found")
        findings: list[FindingCandidate] = []
        errors = 0
        for url, parameter in context.queues.sqli[: min(context.config.rate.max_candidates, 10)]:
            command = [
                tool,
                "-u",
                url,
                "-p",
                parameter,
                "--batch",
                "--level=1",
                "--risk=1",
                "--threads=1",
                "--timeout=10",
                "--retries=1",
                "--smart",
                "--disable-coloring",
            ]
            code, stdout, stderr, timed_out = await self.execute(command, timeout=min(context.config.rate.tool_timeout_seconds, 180))
            text = (stdout + stderr).decode(errors="replace")
            if timed_out or code not in {0, 1}:
                errors += 1
            if "parameter" in text.lower() and "is vulnerable" in text.lower():
                findings.append(
                    FindingCandidate(
                        finding_type="sql_injection",
                        family="injection",
                        title="SQL injection validated by SQLMap",
                        description="Bounded SQLMap validation identified an injectable parameter without dumping data.",
                        asset=_origin(url),
                        affected_endpoints=[url],
                        parameters=[parameter],
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        validation_status=ValidationStatus.CONFIRMED,
                        evidence=[EvidenceRecord(kind="sqlmap_result", summary=f"SQLMap reported parameter {parameter} as vulnerable", location=url)],
                        source_plugins=[self.name],
                        cwe=["CWE-89"],
                        owasp=["A03:2021"],
                        remediation="Use parameterized queries and least-privileged database credentials; validate server-side input.",
                        metadata={"sensitive_context": True},
                    )
                )
        return PluginResult(
            plugin=self.name,
            state=PluginState.PARTIAL if errors and findings else PluginState.COMPLETED,
            failure_reason=FailureReason.TOOL_EXECUTION_FAILED if errors and not findings else None,
            capabilities_produced=set(self.produces),
            findings=findings,
            metrics={"candidates": len(context.queues.sqli), "errors": errors},
            partial_output_trustworthy=bool(findings),
        )


EXTERNAL_PLUGINS = (
    ProjectDiscoveryHTTPXPlugin,
    KatanaPlugin,
    NucleiPlugin,
    NiktoPlugin,
    RetireJSPlugin,
    DalfoxPlugin,
    SQLMapPlugin,
)
