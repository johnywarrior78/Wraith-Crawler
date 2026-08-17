# Database

PostgreSQL is the production system of record. Alembic owns schema changes. Run `alembic upgrade head` using `WRAITH_DATABASE_URL`; never modify production tables manually.

The normalized schema covers users/roles/sessions, applications and assessments, assets/endpoints/parameters/technologies, plugin executions and scan metrics, observations/evidence/candidates/findings/history/priorities, knowledge and LLM triage, reports, manual review, and attack paths/nodes/edges/findings/capabilities/impacts.

Identity and dashboard paths are indexed by application, assessment, status, severity, priority, plugin, first/last seen, and time. JSONB is limited to flexible metadata, scanner payload fragments, mappings, and inventory evidence. Credentials and session tokens are never stored in plaintext: passwords use Argon2id and session/CSRF tokens are SHA-256 digests.

Sensitive assessment evidence is redacted before storage when the plugin marks it sensitive. Reporting views never expose evidence payloads, application password hashes, session tokens, configuration secrets, or raw secret-bearing scanner data.

SQLite may be used for unit/development tests. Doctor rejects it as a production database.
