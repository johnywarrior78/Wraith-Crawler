from __future__ import annotations

import asyncio
import json
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, Field, ValidationError

from ..domain import FindingCandidate


class TriageOutput(BaseModel):
    executive_summary: str
    remediation_explanation: str
    attack_path_narrative: str
    evidence_references: list[int] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


class LLMProvider(Protocol):
    async def complete_json(self, prompt: str, schema: dict[str, Any]) -> dict[str, Any]: ...


class OllamaProvider:
    def __init__(self, endpoint: str, model: str, timeout: float = 30.0) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout

    async def complete_json(self, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.endpoint}/api/generate",
                json={"model": self.model, "prompt": prompt, "format": schema, "stream": False},
            )
            response.raise_for_status()
            payload = response.json()
            content = payload.get("response")
            if not isinstance(content, str):
                raise ValueError("LLM response did not include JSON text")
            return json.loads(content)


class LLMEnrichmentService:
    def __init__(self, provider: LLMProvider, timeout: float = 30.0, retries: int = 1) -> None:
        self.provider = provider
        self.timeout = timeout
        self.retries = retries

    async def enrich(self, finding: FindingCandidate) -> tuple[TriageOutput | None, str | None]:
        evidence = [record.safe_payload() for record in finding.evidence]
        prompt = (
            "You are enriching a deterministic security finding. Never add facts not present in "
            "the supplied finding or evidence. Clearly label assumptions. Return only schema-valid JSON.\n"
            + json.dumps(
                {
                    "finding": finding.model_dump(mode="json", exclude={"evidence"}),
                    "evidence": evidence,
                },
                sort_keys=True,
            )
        )
        last_error: str | None = None
        for attempt in range(self.retries + 1):
            try:
                raw = await asyncio.wait_for(
                    self.provider.complete_json(prompt, TriageOutput.model_json_schema()),
                    timeout=self.timeout,
                )
                output = TriageOutput.model_validate(raw)
                if any(index < 0 or index >= len(evidence) for index in output.evidence_references):
                    raise ValueError("LLM cited evidence outside the supplied evidence boundary")
                return output, None
            except (TimeoutError, httpx.HTTPError, ValidationError, ValueError, json.JSONDecodeError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < self.retries:
                    await asyncio.sleep(min(2**attempt, 4))
        return None, last_error
