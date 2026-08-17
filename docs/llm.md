# Optional LLM Enrichment

LLM enrichment is disabled by default and is never required for scan completion. The built-in provider targets local Ollama and sends a bounded finding plus redacted evidence under a strict JSON schema.

Permitted uses are executive wording, remediation explanation, attack-path narrative, and analyst assistance. The output cannot modify deterministic CVE/CWE/CVSS facts, validation status, scanner evidence, or priority inputs. Evidence references are range-checked against the supplied evidence list.

Timeouts, transport errors, bad JSON, schema violations, or unsupported providers are stored as failed `llm_triage` records while the assessment continues. Requests are serialized to protect local model memory. Provider, model, schema version, status, output, and error metadata are persisted separately.

Enable explicitly:

```bash
wraith-crawler -u https://authorized.example --llm --llm-model qwen2.5:7b
```

Keep sensitive assessment data local unless the operator has separately approved an external provider and its data handling.
