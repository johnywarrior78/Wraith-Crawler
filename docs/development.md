# Development

Requirements are Python 3.12 or newer and the development extras:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
WRAITH_DATABASE_URL='sqlite+pysqlite:///development.sqlite3' alembic upgrade head
pytest
ruff check src tests migrations scripts
```

PostgreSQL is required for reporting-view integration and release validation. Keep scanner parsers fixture-driven. A plugin must expose a capability contract, bounded execution, structured failure reason, safe evidence, and explicit OWASP/CWE/validation metadata.

Do not put generated reports, local databases, environment files, secret files, scanner caches, or Metabase data in Git. Schema changes require an Alembic revision and reporting-view compatibility review.

The domain pipeline is scanner-neutral by design. Replace or add scanner adapters without coupling reports, finding identity, priority, history, or attack-path logic to tool-specific output.
