# Contributing to Wraith Crawler

Thank you for helping improve Wraith Crawler. Contributions should preserve its evidence-first, explicitly authorized, and non-destructive security model.

## Development setup

Use Python 3.12 or newer:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

Run the required checks before opening a pull request:

```bash
bash -n install.sh upgrade.sh backup.sh restore.sh deploy/wraith-crawler-launcher
ruff check src tests migrations scripts
pytest
```

PostgreSQL is required for reporting-view integration and release validation. See [docs/development.md](docs/development.md) and [docs/testing.md](docs/testing.md).

## Change requirements

- Keep all network activity inside the operator-authorized scope.
- Do not add destructive, denial-of-service, brute-force, credential-reuse, persistence, or lateral-movement behavior.
- Bound external tools by explicit concurrency, rate, depth, candidate, and timeout limits.
- Redact credentials, cookies, tokens, authorization values, and sensitive evidence.
- Add parser fixtures and failure-isolation tests for scanner changes.
- Add an Alembic revision for schema changes and maintain reporting-view compatibility.
- Update user-facing documentation when commands, configuration, installation, or output contracts change.

## Pull requests

Keep pull requests focused. Explain the problem, implementation, safety implications, and verification performed. Never include real target data, credentials, runtime environment files, generated reports, or sensitive scanner output.

Security vulnerabilities should be reported privately according to [SECURITY.md](SECURITY.md), not through a public issue.
