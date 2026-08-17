from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from .domain import AssetRecord, EndpointRecord, ParameterRecord, TechnologyRecord, canonical_url


@dataclass(slots=True)
class SharedInventory:
    assets: dict[str, AssetRecord] = field(default_factory=dict)
    endpoints: dict[tuple[str, str], EndpointRecord] = field(default_factory=dict)
    technologies: dict[tuple[str, str | None], TechnologyRecord] = field(default_factory=dict)

    def add_asset(self, asset: AssetRecord) -> None:
        key = canonical_url(asset.url)
        existing = self.assets.get(key)
        if existing:
            existing.discovery_sources = sorted(
                set(existing.discovery_sources + asset.discovery_sources)
            )
            for attr in ("status_code", "title", "server", "cname", "cdn_waf"):
                value = getattr(asset, attr)
                if value is not None:
                    setattr(existing, attr, value)
            existing.redirect_chain = asset.redirect_chain or existing.redirect_chain
            existing.resolved_ips = sorted(set(existing.resolved_ips + asset.resolved_ips))
            existing.tls.update(asset.tls)
        else:
            self.assets[key] = asset

    def add_endpoint(self, endpoint: EndpointRecord) -> None:
        endpoint.url = canonical_url(endpoint.url)
        key = (endpoint.method.upper(), endpoint.url)
        self._merge_url_parameters(endpoint)
        existing = self.endpoints.get(key)
        if not existing:
            endpoint.sources = sorted(set(endpoint.sources))
            self.endpoints[key] = endpoint
            return
        existing.sources = sorted(set(existing.sources + endpoint.sources))
        existing.parameters = self._merge_parameters(existing.parameters, endpoint.parameters)
        for attr in (
            "status_code",
            "content_type",
            "authentication_required",
            "api_classification",
            "javascript_source",
        ):
            value = getattr(endpoint, attr)
            if value is not None:
                setattr(existing, attr, value)
        existing.response_metadata.update(endpoint.response_metadata)

    def add_technology(self, technology: TechnologyRecord) -> None:
        key = (technology.product.lower(), technology.version)
        existing = self.technologies.get(key)
        if not existing:
            self.technologies[key] = technology
            return
        existing.evidence = sorted(set(existing.evidence + technology.evidence))
        existing.vulnerability_references = sorted(
            set(existing.vulnerability_references + technology.vulnerability_references)
        )

    @staticmethod
    def _merge_parameters(
        left: list[ParameterRecord], right: list[ParameterRecord]
    ) -> list[ParameterRecord]:
        merged = {(p.location, p.normalized_name): p for p in left}
        for parameter in right:
            key = (parameter.location, parameter.normalized_name)
            if key not in merged or parameter.risk_score > merged[key].risk_score:
                merged[key] = parameter
        return list(merged.values())

    @staticmethod
    def _merge_url_parameters(endpoint: EndpointRecord) -> None:
        existing = {(p.location, p.normalized_name) for p in endpoint.parameters}
        for name, value in parse_qsl(urlsplit(endpoint.url).query, keep_blank_values=True):
            normalized = name.strip().lower().replace("-", "_")
            if ("query", normalized) in existing:
                continue
            endpoint.parameters.append(
                ParameterRecord(
                    name=name,
                    normalized_name=normalized,
                    location="query",
                    method=endpoint.method,
                    source="url",
                    sample_metadata={"length": len(value), "present": bool(value)},
                )
            )
