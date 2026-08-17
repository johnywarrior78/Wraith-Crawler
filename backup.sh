#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || { printf 'Run as root.\n' >&2; exit 1; }
CONFIG_DIR="/etc/wraith-crawler"
target="${1:-/var/backups/wraith-crawler/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$target"
chmod 0700 "$target"
set -a; . "$CONFIG_DIR/runtime.env"; . "$CONFIG_DIR/metabase.env"; set +a
PYTHON_BIN="${WRAITH_PYTHON_EXECUTABLE:-/opt/wraith-crawler/.venv/bin/python}"
"$PYTHON_BIN" - "$target/wraith.sql" <<'PY'
import os, subprocess, sys
from sqlalchemy.engine import make_url
url = make_url(os.environ["WRAITH_DATABASE_URL"])
env = os.environ.copy(); env["PGPASSWORD"] = url.password or ""
subprocess.run(["pg_dump", "--host", url.host or "127.0.0.1", "--port", str(url.port or 5432), "--username", url.username or "", "--format", "custom", "--file", sys.argv[1], url.database or ""], env=env, check=True)
PY
PGPASSWORD="$MB_DB_PASS" pg_dump --host="$MB_DB_HOST" --port="$MB_DB_PORT" --username="$MB_DB_USER" --format=custom --file="$target/metabase.sql" "$MB_DB_DBNAME"
install -m 0600 "$CONFIG_DIR/runtime.env" "$target/runtime.env"
install -m 0600 "$CONFIG_DIR/metabase.env" "$target/metabase.env"
sha256sum "$target"/*.sql "$target"/*.env > "$target/SHA256SUMS"
printf 'Backup created at %s. It contains secrets; retain mode 0700 and encrypt off-host copies.\n' "$target"
