# Troubleshooting

Run `sudo wraith-crawler doctor` first. It distinguishes database, migration, reporting-view, Metabase, binary identity, optional-tool, and version failures.

- “wraith-crawler: command not found”: first check the spelling (`wraith`, not `wriath`). Rerun the current `sudo ./install.sh` and choose **Repair**. It installs the managed launcher at `/usr/local/bin/wraith-crawler` and a `/usr/bin/wraith-crawler` command link for Kali environments whose `sudo` PATH omits `/usr/local/bin`. Confirm with `command -v wraith-crawler`; use `sudo wraith-crawler --help` because runtime credentials are deliberately protected.
- “No module named pip” under `/opt/wraith-crawler/.venv`: that path came from an older interrupted installer. The current installer uses system Python directly. Confirm `python3.12 -m pip --version`, then rerun `sudo WRAITH_PYTHON_EXECUTABLE="$(command -v python3.12)" ./install.sh`. The stale `.venv` is ignored.
- “uninstall-no-record-file” for Starlette or another Kali/Debian module: pip attempted to remove a distribution-owned package. Current direct-system installation uses `--ignore-installed` with `--break-system-packages`, placing a coherent application dependency set in `/usr/local` without deleting files managed by APT. It then restores the ProjectDiscovery HTTPX scanner if Python's unrelated `httpx` console script replaced it.
- Installer exits during pip and `/usr/local/bin/wraith-crawler` starts with Python instead of `#!/usr/bin/env bash`: the source tree predates the guarded pip installation. Current installers restore the managed launcher even when pip fails. Transfer the complete current source tree, verify that `install.sh` contains `pip_status=$?`, and rerun while capturing the full output.

Common cases:

- “wrong httpx binary”: Python HTTPX and ProjectDiscovery HTTPX share a command name. Current installations isolate the scanner at `/usr/local/lib/wraith-crawler/bin/httpx` and configure that absolute path. Rerun the current installer; it builds the scanner in a temporary directory, validates its identity, and installs it without touching Python's `/usr/local/bin/httpx` command.
- Katana or Nuclei reports `permission denied` below `/root/.config`: an older launcher preserved root's home while dropping privileges. Current launchers use `/var/lib/wraith-crawler` for `HOME` and XDG state, create the directories with service-account ownership, and update Nuclei templates as that account. Rerun **Repair**.
- Doctor says the private HTTPX binary is wrong even though `httpx -version` reports `Current Version`: an older identity parser expected the literal word `projectdiscovery`. Current validation recognizes ProjectDiscovery's documented version output while continuing to reject Python HTTPX.
- “group wraith-crawler exists”: this is residue from an interrupted installation. Current `install.sh` reuses the existing system group, creates the missing service user with that group, and can be rerun safely. The PostgreSQL role created before the interruption is preserved and validated with the password you supply.
- database connection failure: test the exact host/port/name/user/password with `psql`; do not URL-interpolate special characters.
- `permission denied for schema public` while Alembic creates `alembic_version`: the selected role can connect but lacks migration DDL privileges. Current installers grant `CREATE` on a selected local database and `USAGE, CREATE` on its `public` schema without changing ownership. For a remote PostgreSQL server, its administrator must grant those privileges before installation.
- Metabase repeatedly resets connections and never becomes healthy: a container using bridge networking cannot reach host PostgreSQL at `127.0.0.1`. Current Linux deployments use host networking with Metabase Jetty bound to `127.0.0.1`, so both the application database and reporting database remain local-only. On failure, the installer prints the last 120 container log lines.
- reporting views missing: run `alembic upgrade head` as the application role, then rerun doctor.
- optional scanner disabled: install its official binary or correct the configured path; other plugins will continue.
- Katana timeout: inspect the Katana plugin execution. Seed HTTP, TLS, headers, Nuclei, and Nikto remain independent.
- Metabase unhealthy: inspect `docker compose ... logs metabase`, its metadata database, and `/api/health`.
- suspected finding: use the manual-review queue and preserve the documented evidence boundary.
- rate limit/WAF: lower request rate and concurrency; do not evade access controls.

Logs are JSON on console and rotated files when configured. They include assessment, target, plugin, event, and severity but redact secret-bearing fields.
