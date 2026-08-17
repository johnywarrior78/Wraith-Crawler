# Configuration

Configuration is YAML plus explicit environment-secret overrides. Start from `config.example.yaml` and store the installed file at `/etc/wraith-crawler/config.yaml`.

Important controls include:

- database pool and connection settings;
- `quick`, `standard`, `deep`, and `discovery_only` profiles;
- global request rate, target/plugin concurrency, request/tool timeouts, retries, crawl depth, endpoint and candidate limits;
- explicit external tool paths;
- optional local Ollama endpoint/model and timeout;
- Metabase URL and health timeout;
- session duration, secure-cookie policy, and environment.
- `report_output_directory`, the API's filesystem boundary for generated artifacts.

`WRAITH_DATABASE_URL`, `WRAITH_ENVIRONMENT`, `WRAITH_LOG_LEVEL`, and `WRAITH_METABASE_URL` override YAML. Production configuration rejects an absent database secret at connection time. For passwords containing `@`, `:`, `/`, `?`, `#`, or brackets, construct URLs through SQLAlchemy or use the interactive installer.

Target scope is provided with each target: allowed hosts, excluded hosts, include paths, and exclude paths. Subdomains are not implicitly in scope. A discovered third-party URL remains out of scope unless the operator explicitly includes it.

API callers may generate reports in `report_output_directory` or one of its child directories, but cannot request a write elsewhere on the host.
