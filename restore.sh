#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || { printf 'Run as root.\n' >&2; exit 1; }
backup_dir="${1:-}"
[[ -n "$backup_dir" && -d "$backup_dir" ]] || { printf 'Usage: restore.sh BACKUP_DIRECTORY\n' >&2; exit 2; }
cd "$backup_dir"
sha256sum -c SHA256SUMS
printf 'Restore is destructive to the destination databases and requires an explicit confirmation.\nType RESTORE to continue: '
read -r confirmation
[[ "$confirmation" == "RESTORE" ]] || exit 1
set -a; . /etc/wraith-crawler/runtime.env; . /etc/wraith-crawler/metabase.env; set +a
PYTHON_BIN="${WRAITH_PYTHON_EXECUTABLE:-/opt/wraith-crawler/.venv/bin/python}"
systemctl stop wraith-crawler-api || true
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
else
  COMPOSE=(docker-compose)
fi
"${COMPOSE[@]}" --env-file /etc/wraith-crawler/metabase.env -f /opt/wraith-crawler/docker-compose.metabase.yml stop metabase
"$PYTHON_BIN" - "$backup_dir/wraith.sql" <<'PY'
import os, subprocess, sys
from sqlalchemy.engine import make_url
url = make_url(os.environ["WRAITH_DATABASE_URL"])
env = os.environ.copy(); env["PGPASSWORD"] = url.password or ""
subprocess.run(["pg_restore", "--clean", "--if-exists", "--no-owner", "--host", url.host or "127.0.0.1", "--port", str(url.port or 5432), "--username", url.username or "", "--dbname", url.database or "", sys.argv[1]], env=env, check=True)
PY
PGPASSWORD="$MB_DB_PASS" pg_restore --clean --if-exists --no-owner --host="$MB_DB_HOST" --port="$MB_DB_PORT" --username="$MB_DB_USER" --dbname="$MB_DB_DBNAME" "$backup_dir/metabase.sql"
"${COMPOSE[@]}" --env-file /etc/wraith-crawler/metabase.env -f /opt/wraith-crawler/docker-compose.metabase.yml start metabase
systemctl start wraith-crawler-api
printf 'Restore completed. Run wraith-crawler doctor and verify assessment/reporting history.\n'
