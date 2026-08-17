# Metabase

The supported deployment is a loopback-bound persistent Metabase container backed by its own PostgreSQL database and role. Metabase metadata is not stored in the Wraith application database. The Compose file pins the current supported open-source minor line (`v0.63.2.x`) rather than using the mutable `latest` tag; upgrades remain backup-gated.

`scripts/provision_metabase.py` is idempotent: it initializes Metabase when needed, authenticates, registers `Wraith Crawler Reporting` with the read-only role, restricts schema discovery to `reporting`, creates the Wraith collection, creates one bounded native-SQL question per versioned reporting view, attaches those questions to the required dashboards, and triggers schema synchronization. `deploy/metabase/dashboards.json` is the reproducible dashboard-to-view contract.

The nine dashboards are Executive, Risk, OWASP Top 10, Attack Paths, Technology/Vulnerable Components, Plugin Health, Historical Trends, Assessment Operations, and Manual Review.

Metabase binds to `127.0.0.1:3000`. Use a TLS reverse proxy for remote access and apply Metabase updates through `upgrade.sh`. Credentials are stored in `/etc/wraith-crawler/metabase.env`, mode 0640, and must not be printed or committed.

Doctor requires `/api/health` to return healthy and verifies every reporting view separately.
