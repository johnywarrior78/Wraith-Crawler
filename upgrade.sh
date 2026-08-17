#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || { printf 'Run as root.\n' >&2; exit 1; }
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/wraith-crawler"
CONFIG_DIR="/etc/wraith-crawler"
[[ -f "$CONFIG_DIR/runtime.env" ]] || { printf 'Wraith Crawler is not installed.\n' >&2; exit 1; }
. "$SOURCE_DIR/install.sh"
set -a; . "$CONFIG_DIR/runtime.env"; set +a
PYTHON_BIN="${WRAITH_PYTHON_EXECUTABLE:-$INSTALL_DIR/.venv/bin/python}"
[[ -x "$PYTHON_BIN" ]] || { printf 'Configured Python is unavailable: %s\n' "$PYTHON_BIN" >&2; exit 1; }

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
"$SOURCE_DIR/backup.sh" "/var/backups/wraith-crawler/pre-upgrade-$timestamp"
systemctl stop wraith-crawler-api || true
rsync -a --exclude '.git' --exclude '.venv' --exclude 'output' "$SOURCE_DIR/" "$INSTALL_DIR/"
"$PYTHON_BIN" -m pip install --break-system-packages --ignore-installed --upgrade "$INSTALL_DIR"
install_projectdiscovery_httpx
migrate_httpx_config_path
install_cli_launcher
cd "$INSTALL_DIR"
runuser -u wraith-crawler --preserve-environment -- "$PYTHON_BIN" -m alembic upgrade head
if docker compose version >/dev/null 2>&1; then
  docker compose --env-file "$CONFIG_DIR/metabase.env" -f "$INSTALL_DIR/docker-compose.metabase.yml" up -d
else
  docker-compose --env-file "$CONFIG_DIR/metabase.env" -f "$INSTALL_DIR/docker-compose.metabase.yml" up -d
fi
systemctl daemon-reload
systemctl start wraith-crawler-api
run_as_application "$PYTHON_BIN" -m wraith_crawler.cli --config "$CONFIG_DIR/config.yaml" doctor
printf 'Upgrade completed. Backup: /var/backups/wraith-crawler/pre-upgrade-%s\n' "$timestamp"
