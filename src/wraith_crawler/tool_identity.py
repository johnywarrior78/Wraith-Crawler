from __future__ import annotations

import re

ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
PD_CURRENT_VERSION = re.compile(
    r"\bcurrent(?:\s+httpx)?\s+version\s*:\s*v?([0-9][\w.-]*)",
    re.IGNORECASE,
)
PD_NAMED_VERSION = re.compile(
    r"\bhttpx\s+(?:version\s*)?v?([0-9][\w.-]*)",
    re.IGNORECASE,
)


def strip_ansi(value: str) -> str:
    return ANSI_ESCAPE.sub("", value)


def projectdiscovery_httpx_version(output: str) -> str | None:
    """Return a ProjectDiscovery HTTPX version without accepting Python HTTPX."""
    clean = strip_ansi(output)
    current = PD_CURRENT_VERSION.search(clean)
    if current:
        return current.group(1)
    if "projectdiscovery" not in clean.lower():
        return None
    named = PD_NAMED_VERSION.search(clean)
    return named.group(1) if named else "projectdiscovery"
