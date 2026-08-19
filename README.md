# Wraith Crawler

Wraith Crawler is an evidence-first external web application security assessment platform. It discovers an authorized target's reachable attack surface, runs bounded non-destructive checks, normalizes findings, records assessment history in PostgreSQL, and produces API, PDF, Excel, and Metabase outputs.

It is designed for repeatable assessment workflows where scope, evidence, scanner health, and reporting matter as much as detection. 

> [!CAUTION]
> Only scan systems you own or have explicit permission to test. Wraith Crawler does not authorize testing and is not designed for denial of service, brute force, credential reuse, destructive payloads, database dumping, persistence, lateral movement, or unrestricted internal SSRF probing.

## Highlights

- Strict HTTP(S) scope enforcement and bounded concurrency, rate, depth, and timeout controls.
- Phase-driven workflow: Reconnaissance → Scanning → Enumeration → Safe Validation → Analysis → Attack Path → Post-Exploitation Reasoning.
- Built-in checks for HTTP behavior, TLS, headers, session cookies, CORS, forms, JavaScript, APIs, management/debug/health surfaces, directory listings, CMS/technology fingerprints, exposed files, and manual-review candidates.
- Integrated ProjectDiscovery HTTPX, Katana, Nuclei, Dalfox, SQLMap, Nikto, and Retire.js adapters.
- Evidence-backed finding lifecycle, scan-specific OWASP coverage, MITRE ATT&CK mappings, attacker narratives, attack paths, priorities, and scan history.
- PostgreSQL persistence with Alembic migrations and stable read-only reporting views.
- PDF and Excel reports, REST API, and nine provisioned Metabase dashboards.
- Optional local LLM enrichment that cannot replace deterministic evidence or alter authoritative security facts.

## Supported production systems

The production installer supports current Debian, Ubuntu, and Kali Linux systems with Python 3.12 or newer. It installs the application directly against the selected system Python; it does not create a production virtual environment.

The installer provisions:

- Wraith Crawler under `/opt/wraith-crawler`;
- a protected `wraith-crawler` service account and runtime configuration;
- the `wraith-crawler` command in `/usr/bin` and `/usr/local/bin`;
- PostgreSQL roles, database migrations, and reporting views;
- external security tools and service-owned scanner state;
- the loopback-only API service and Metabase deployment.

## Installation

Clone the repository on the target Linux system, then run:

```bash
chmod +x install.sh
sudo ./install.sh
```

The installer prompts separately for PostgreSQL and application-administrator credentials. It can be safely rerun and provides **Upgrade**, **Repair**, and **Reconfigure Database** workflows for an existing installation.

Verify the completed installation:

```bash
command -v wraith-crawler
sudo wraith-crawler --help
sudo wraith-crawler doctor
```

See the full [installation guide](docs/installation.md), [configuration reference](docs/configuration.md), and [troubleshooting guide](docs/troubleshooting.md).

## CLI usage

Run a standard assessment against an explicitly authorized target:

```bash
sudo wraith-crawler --url https://authorized.example --profile standard
```

Additional examples:

```bash
# Scan several authorized targets from an absolute-path input file.
sudo wraith-crawler --file /absolute/path/to/targets.txt --profile standard

# Select or exclude individual plugins.
sudo wraith-crawler --url https://authorized.example \
  --plugin seed_http --plugin tls
sudo wraith-crawler --url https://authorized.example --exclude-plugin katana

# Run the focused session-cookie, CMS, and directory-listing workflow.
sudo wraith-crawler --url https://authorized.example \
  --plugin seed_http --plugin html_discovery --plugin cookie_security \
  --plugin cms_detection --plugin directory_listing

# Inspect coverage and installation health.
sudo wraith-crawler coverage
sudo wraith-crawler doctor --json

# Generate both report formats from a completed assessment.
sudo wraith-crawler report ASSESSMENT_ID --format both --output output
```

Target files accept one absolute `http://` or `https://` URL per line, ignore blank lines and comments, canonicalize URLs, and deduplicate entries. Use an absolute file path readable by the service account.

Read the complete [CLI reference](docs/cli.md), [plugin contracts](docs/plugins.md), and [security model](docs/security-model.md) before operating the scanner.

## Services and outputs

Default production endpoints bind only to loopback:

| Service | Address | Purpose |
| --- | --- | --- |
| Wraith Crawler API | `http://127.0.0.1:8080` | Authenticated application and assessment API |
| Metabase | `http://127.0.0.1:3000` | Provisioned reporting dashboards |

Place a maintained reverse proxy with TLS and appropriate access controls in front of either endpoint before remote exposure.

Reports are generated from persisted canonical data rather than raw scanner output. See [reporting](docs/reporting.md), [dashboard metrics](docs/dashboard-metrics.md), and [reporting views](docs/reporting-views.md).

## Development

Development and tests may use a virtual environment:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
ruff check src tests migrations scripts
pytest
```

PostgreSQL is required for production behavior and reporting-view integration. SQLite is limited to development tests.

Before submitting changes, read [CONTRIBUTING.md](CONTRIBUTING.md) and the [development guide](docs/development.md).

## Documentation

- [Architecture](docs/architecture.md)
- [Attack paths](docs/attack-paths.md)
- [Backup and restore](docs/backup-restore.md)
- [Database model](docs/database.md)
- [Metabase](docs/metabase.md)
- [MITRE ATT&CK mapping](docs/mitre-attack.md)
- [OWASP coverage](docs/owasp-coverage.md)
- [Testing](docs/testing.md)
- [Security policy](SECURITY.md)

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
