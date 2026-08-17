# Testing

The local suite covers URL/scope validation, special-character database URLs, no default password, Argon2id/RBAC/CSRF/lock behavior, schema creation, inventories, aggregation/deduplication, priority, attack-path classification, runtime failure isolation, timeouts, malformed JSONL, HTTPX identity, Nuclei origin deduplication, Nikto fallback taxonomy, session-cookie value redaction and control checks, CMS multi-signal/false-positive fixtures, directory-index signatures and bounds, API reads, and PDF/Excel content.

```bash
pytest
pytest --cov=wraith_crawler --cov-report=term-missing
ruff check src tests migrations scripts
```

Release validation additionally requires:

1. Fresh Debian, Ubuntu, and Kali VM/container installation.
2. PostgreSQL migration and every reporting view query.
3. Metabase setup, data-source sync, dashboard availability, and read-only privilege audit.
4. A single URL scan and a mixed success/failure target file.
5. Authorized scans of intentionally vulnerable training applications.
6. External tool missing/timeout/partial-output cases.
7. PDF render inspection with Poppler and a visual pass of every Excel sheet.
8. Backup, upgrade, doctor, and restore rehearsal.

Never point end-to-end tests at systems without explicit authorization.

CI runs the full suite, a clean SQLite migration, a clean PostgreSQL 16 migration, and a queryability check across every versioned reporting view.
