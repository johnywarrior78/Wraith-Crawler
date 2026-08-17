# Installation

## Supported production systems

The installer targets Debian, Ubuntu, and Kali. Run it from a fresh checkout as root:

```bash
sudo ./install.sh
```

It installs system dependencies, Python packaging support, Go/Node tooling, ProjectDiscovery HTTPX, Katana, Nuclei, Dalfox, SQLMap, Nikto, Retire.js, PostgreSQL, Docker, and Metabase. It uses the selected system Python interpreter, creates a service user, systemd API service, migrations, reporting views, a read-only reporting account, and nine Metabase dashboards.

Production installation uses a system Python 3.12+ interpreter directly—no virtual environment is created. Dependencies are installed into `/usr/local` with `python -m pip install --break-system-packages --ignore-installed`; this avoids attempting to uninstall Kali/Debian-owned modules under `/usr/lib/python3/dist-packages`, whose package metadata intentionally has no pip `RECORD`. The selected absolute interpreter is recorded as `WRAITH_PYTHON_EXECUTABLE` in the protected runtime environment. A managed launcher is installed at `/usr/local/bin/wraith-crawler` with a PATH-visible `/usr/bin/wraith-crawler` command link; run operational commands as `sudo wraith-crawler ...`. The launcher loads `/etc/wraith-crawler/runtime.env` without putting the database password on the command line, changes to the application directory, and drops privileges to the `wraith-crawler` service account.

ProjectDiscovery HTTPX is installed and identity-checked explicitly at `/usr/local/lib/wraith-crawler/bin/httpx`. Its private path avoids the identically named Python HTTPX console command in `/usr/local/bin`.

External scanner state is owned by the `wraith-crawler` service account under `/var/lib/wraith-crawler`. CLI, installer checks, and systemd consistently set `HOME` and the XDG configuration/cache/data directories there. Nuclei templates are updated as the service account rather than root.

The database prompt requests host, port, database name, database username, password, and password confirmation. The password is hidden, non-empty, strength-checked, and URL-encoded by SQLAlchemy rather than interpolated. Existing roles or databases are never dropped; an existing role password is not silently replaced. The installer must connect with the exact supplied credentials before proceeding.

If multiple Python installations exist, set the interpreter explicitly: `sudo WRAITH_PYTHON_EXECUTABLE=/usr/local/bin/python3.12 ./install.sh`. That interpreter must provide `pip`; install the matching distribution package or run its supported `ensurepip` mechanism first.

The application administrator prompt is separate. Its password is hashed with Argon2id and never reused as a PostgreSQL credential.

## Non-interactive deployment

Provision the database and a mode-0640 environment file through a secret-management system, then run:

```bash
export WRAITH_DATABASE_URL='postgresql+psycopg://user:encoded-password@db.example/wraith_crawler'
alembic upgrade head
printf '%s\n' "$WRAITH_INITIAL_ADMIN_PASSWORD" | wraith-crawler admin create \
  --username "$WRAITH_INITIAL_ADMIN" --password-stdin --role admin
```

No default database or application password exists. Do not place credentials in source-controlled YAML, shell history, process arguments, or logs.

## Network exposure

The API and Metabase bind to loopback by default. Place a maintained reverse proxy with TLS, request limits, and appropriate identity controls in front of either service before remote exposure.
