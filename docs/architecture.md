# Architecture

Wraith Crawler is a modular monolith with explicit domain boundaries. Scanner output never flows directly to reports or dashboards: it moves through shared inventories and a canonical evidence pipeline first.

```text
URL intake and scope
  -> phase and capability-driven plugin runtime
     -> reconnaissance -> scanning -> enumeration -> safe validation -> analysis
  -> shared assets/endpoints/parameters/technologies
  -> raw observations and evidence
  -> canonical candidates and aggregation
  -> deterministic priority and history
  -> evidence-bounded attack paths -> post-exploitation reasoning
  -> PostgreSQL
     -> REST API
     -> PDF and Excel reports
     -> reporting views -> read-only Metabase
```

The seed URL is always a capability. Crawlers enrich the endpoint inventory but never gate independent HTTP, TLS, header, Nuclei, or Nikto work. The runtime enforces phase and stage barriers, then schedules plugins whose required data capability exists concurrently within each barrier. It isolates exceptions and timeouts and retains trustworthy partial output.

Every phase records status, test counts, finding counts, limitations, and the next safe test. Every finding requires structured evidence. Capability, impact, and post-exploitation statements are persisted as confirmed, inferred, or speculative rather than being presented as actions the scanner performed.

## Boundaries

- `domain.py`, `enums.py`: scanner-neutral contracts and lifecycle states.
- `scope.py`, `inventory.py`: strict authorization boundary and canonical deduplication.
- `plugins/`: isolated built-in and external capabilities.
- `services/findings.py`: aggregation, policy, priority, and scan-to-scan finding state.
- `attack_paths.py`: deterministic graph rules and evidence boundaries.
- `persistence/`: SQLAlchemy transactional schema and reporting contracts.
- `api.py`, `cli.py`: operator interfaces and RBAC.
- `reporting/`: canonical-state PDF and Excel output.
- `deploy/`, `scripts/`: service, Metabase, and dashboard provisioning.

Flexible scanner payloads use JSON/JSONB, while fields used for identity, history, authorization, sorting, or dashboards are normalized columns with indexes. PostgreSQL is mandatory in production; SQLite exists only for development tests.

## Trust model

Deterministic scanner observations and HTTP behavior are authoritative. Knowledge mappings add sourced classifications without replacing evidence. Optional LLM output is schema-validated, stored separately, and unavailable without affecting assessment completion. Attack-path graph edges explicitly distinguish confirmed, inferred, and speculative statements.
