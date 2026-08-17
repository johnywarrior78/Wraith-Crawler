from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urljoin, urlsplit

from .domain import TargetInput, canonical_url


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    allowed: bool
    reason: str


class ScopeManager:
    """Strict target scope. Descendants stay on the seed host unless explicitly included."""

    def __init__(self, target: TargetInput) -> None:
        self.target = target
        self.seed = urlsplit(target.url)
        self.allowed_hosts = {self.seed.hostname or "", *map(str.lower, target.include_hosts)}

    def resolve(self, value: str, base: str | None = None) -> str:
        return canonical_url(urljoin(base or self.target.url, value))

    def check(self, value: str) -> ScopeDecision:
        try:
            url = urlsplit(canonical_url(value))
        except (ValueError, UnicodeError):
            return ScopeDecision(False, "invalid_url")
        host = (url.hostname or "").lower()
        if any(fnmatch(host, pattern.lower()) for pattern in self.target.exclude_hosts):
            return ScopeDecision(False, "excluded_host")
        if not any(host == allowed or fnmatch(host, allowed) for allowed in self.allowed_hosts):
            return ScopeDecision(False, "unrelated_host")
        if any(fnmatch(url.path, pattern) for pattern in self.target.exclude_paths):
            return ScopeDecision(False, "excluded_path")
        if self.target.include_paths and not any(
            fnmatch(url.path, pattern) for pattern in self.target.include_paths
        ):
            return ScopeDecision(False, "outside_included_paths")
        return ScopeDecision(True, "explicit_scope")

    @staticmethod
    def is_public_address(value: str) -> bool:
        """Used to prevent SSRF validators from probing internal infrastructure."""
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return True
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
        )
