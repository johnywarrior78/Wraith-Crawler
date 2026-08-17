# Implementation Plan

The repository follows this greenfield build order:

1. Domain, configuration, strict scope, and canonical inventories.
2. SQLAlchemy persistence, Alembic migrations, reporting views, users, and sessions.
3. Capability-driven plugin runtime and safe built-in/external scanners.
4. Finding aggregation, knowledge, priority, manual review, and history.
5. Persisted attack-path graph, scoring, critical-path labels, and break points.
6. Authenticated REST API and CLI/batch orchestration.
7. PDF, Excel, reporting views, Metabase provisioning, and dashboards.
8. Interactive installer, doctor, services, upgrades, backups, and restore.
9. Unit, integration, artifact, migration, and authorized target validation.

Each phase is validated before the next is treated as stable. The automated suite is the local gate; a clean supported Linux VM with PostgreSQL, Docker/Metabase, and intentionally vulnerable authorized targets is the release gate.
