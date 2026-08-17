#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="wraith-crawler"
APP_USER="wraith-crawler"
INSTALL_DIR="/opt/wraith-crawler"
CONFIG_DIR="/etc/wraith-crawler"
DATA_DIR="/var/lib/wraith-crawler"
LOG_DIR="/var/log/wraith-crawler"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN=""
PD_HTTPX="/usr/local/lib/wraith-crawler/bin/httpx"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
require_root() { [[ ${EUID} -eq 0 ]] || fail "Run install.sh as root."; }

run_as_application() {
  runuser -u "$APP_USER" --preserve-environment -- env \
    HOME="$DATA_DIR" \
    XDG_CONFIG_HOME="$DATA_DIR/.config" \
    XDG_CACHE_HOME="$DATA_DIR/.cache" \
    XDG_DATA_HOME="$DATA_DIR/.local/share" \
    "$@"
}

validate_identifier() {
  [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]] || fail "Invalid PostgreSQL identifier: $1"
}

strong_password() {
  local value="$1"
  [[ ${#value} -ge 12 ]] || return 1
  [[ "$value" =~ [[:lower:]] ]] || return 1
  [[ "$value" =~ [[:upper:]] ]] || return 1
  [[ "$value" =~ [[:digit:]] ]] || return 1
}

prompt_secret_confirmed() {
  local prompt="$1" first second
  while true; do
    read -r -s -p "$prompt: " first; printf '\n'
    read -r -s -p "Confirm $prompt: " second; printf '\n'
    [[ -n "$first" ]] || { printf 'Password cannot be empty.\n' >&2; continue; }
    [[ "$first" == "$second" ]] || { printf 'Passwords do not match.\n' >&2; continue; }
    strong_password "$first" || { printf 'Use at least 12 characters with upper, lower, and numeric characters.\n' >&2; continue; }
    REPLY_SECRET="$first"
    return
  done
}

detect_os() {
  [[ -r /etc/os-release ]] || fail "Cannot identify the operating system."
  . /etc/os-release
  case "${ID:-}" in
    debian|ubuntu|kali) ;;
    *) fail "Supported systems are Debian, Ubuntu, and Kali (found ${ID:-unknown})." ;;
  esac
}

install_system_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl git jq build-essential python3 python3-pip python3-dev \
    postgresql postgresql-client libpq-dev nodejs npm golang-go nikto sqlmap docker.io \
    docker-compose rsync openssl
  apt-get install -y docker-compose-plugin 2>/dev/null || true
  systemctl enable --now postgresql docker
}

docker_compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  else
    docker-compose "$@"
  fi
}

install_security_tools() {
  local gobin="/usr/local/bin"
  export GOBIN="$gobin"
  install_projectdiscovery_httpx
  [[ -x "$gobin/katana" ]] || go install github.com/projectdiscovery/katana/cmd/katana@latest
  [[ -x "$gobin/nuclei" ]] || go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  [[ -x "$gobin/dalfox" ]] || go install github.com/hahwul/dalfox/v2@latest
  command -v retire >/dev/null 2>&1 || npm install --global retire
  projectdiscovery_httpx "$PD_HTTPX" \
    || fail "ProjectDiscovery httpx installation failed identity validation at $PD_HTTPX."
}

install_projectdiscovery_httpx() {
  local build_dir go_status
  projectdiscovery_httpx "$PD_HTTPX" && return 0

  # Build outside GOBIN so Go never collides with Python HTTPX's identically
  # named console script in /usr/local/bin. Only the verified scanner is then
  # installed into Wraith Crawler's private executable directory.
  printf 'Installing ProjectDiscovery httpx at %s.\n' "$PD_HTTPX"
  build_dir="$(mktemp -d)"
  set +e
  GOBIN="$build_dir" go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go_status=$?
  set -e
  if (( go_status != 0 )); then
    rm -rf -- "$build_dir"
    fail "ProjectDiscovery httpx build failed."
  fi
  projectdiscovery_httpx "$build_dir/httpx" || {
    rm -rf -- "$build_dir"
    fail "Downloaded ProjectDiscovery httpx failed identity validation."
  }
  install -d -o root -g root -m 0755 "$(dirname "$PD_HTTPX")"
  install -o root -g root -m 0755 "$build_dir/httpx" "$PD_HTTPX"
  rm -rf -- "$build_dir"
}

projectdiscovery_httpx() {
  local binary="$1" output=""
  [[ -x "$binary" ]] || return 1
  output="$("$binary" -version 2>&1 || true)"
  grep -Eqi 'projectdiscovery|current version:[[:space:]]*v[0-9]+' <<<"$output"
}

migrate_httpx_config_path() {
  local config="$CONFIG_DIR/config.yaml"
  [[ -f "$config" ]] || return 0
  sed -i \
    's#^  httpx: /usr/local/bin/httpx$#  httpx: /usr/local/lib/wraith-crawler/bin/httpx#' \
    "$config"
}

prompt_database() {
  printf '\nWraith Crawler - Database Configuration\n'
  read -r -p 'Database host [127.0.0.1]: ' DB_HOST; DB_HOST="${DB_HOST:-127.0.0.1}"
  read -r -p 'Database port [5432]: ' DB_PORT; DB_PORT="${DB_PORT:-5432}"
  read -r -p 'Database name [wraith_crawler]: ' DB_NAME; DB_NAME="${DB_NAME:-wraith_crawler}"
  read -r -p 'Database username [wraith_crawler]: ' DB_USER; DB_USER="${DB_USER:-wraith_crawler}"
  [[ "$DB_PORT" =~ ^[0-9]{1,5}$ ]] || fail "Invalid database port."
  (( DB_PORT >= 1 && DB_PORT <= 65535 )) || fail "Database port must be between 1 and 65535."
  validate_identifier "$DB_NAME"; validate_identifier "$DB_USER"
  prompt_secret_confirmed 'Database password'; DB_PASSWORD="$REPLY_SECRET"; unset REPLY_SECRET
}

create_or_validate_database() {
  if [[ "$DB_HOST" == "127.0.0.1" || "$DB_HOST" == "localhost" ]]; then
    local role_exists db_exists
    role_exists="$(runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname = '$DB_USER'" | tr -d '[:space:]')"
    if [[ "$role_exists" != "1" ]]; then
      runuser -u postgres -- psql --set=role="$DB_USER" --set=password="$DB_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'role', :'password') \gexec
SQL
    fi
    db_exists="$(runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | tr -d '[:space:]')"
    if [[ "$db_exists" != "1" ]]; then
      runuser -u postgres -- createdb --owner="$DB_USER" "$DB_NAME"
    fi
    # PostgreSQL 15+ no longer grants CREATE on the public schema to every
    # role. An existing database may also be owned by postgres after a manual
    # or interrupted setup. Grant the selected application role only the DDL
    # privileges its migrations require, without changing database ownership.
    runuser -u postgres -- psql --dbname=postgres --set=db="$DB_NAME" --set=role="$DB_USER" <<'SQL'
SELECT format('GRANT CONNECT, CREATE, TEMPORARY ON DATABASE %I TO %I', :'db', :'role') \gexec
SQL
    runuser -u postgres -- psql --dbname="$DB_NAME" --set=role="$DB_USER" <<'SQL'
SELECT format('GRANT USAGE, CREATE ON SCHEMA public TO %I', :'role') \gexec
SQL
  fi
  PGPASSWORD="$DB_PASSWORD" psql --host="$DB_HOST" --port="$DB_PORT" --username="$DB_USER" --dbname="$DB_NAME" -v ON_ERROR_STOP=1 -c 'SELECT 1' >/dev/null \
    || fail "The exact supplied database credentials did not connect. Existing roles are never overwritten automatically."
  local ddl_ready
  ddl_ready="$(PGPASSWORD="$DB_PASSWORD" psql --host="$DB_HOST" --port="$DB_PORT" --username="$DB_USER" --dbname="$DB_NAME" -tAc \
    "SELECT has_database_privilege(current_user, current_database(), 'CREATE') AND has_schema_privilege(current_user, 'public', 'CREATE')" | tr -d '[:space:]')"
  [[ "$ddl_ready" == "t" ]] \
    || fail "Database role $DB_USER needs CREATE on database $DB_NAME and USAGE, CREATE on schema public before migrations can run."
}

select_system_python() {
  local python_bin="${WRAITH_PYTHON_EXECUTABLE:-}"
  if [[ -n "$python_bin" ]]; then
    [[ -x "$python_bin" ]] || fail "WRAITH_PYTHON_EXECUTABLE is not executable: $python_bin"
  elif command -v python3.12 >/dev/null 2>&1; then
    python_bin="$(command -v python3.12)"
  elif python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 12))'; then
    python_bin="$(command -v python3)"
  else
    fail "A system Python 3.12+ interpreter is required. Install Python 3.12 and rerun, or set WRAITH_PYTHON_EXECUTABLE to its absolute path."
  fi
  "$python_bin" -c 'import sys; raise SystemExit(sys.version_info < (3, 12))' \
    || fail "Wraith Crawler requires Python 3.12 or newer: $python_bin"
  [[ "$python_bin" == /* ]] || python_bin="$(command -v "$python_bin")"
  PYTHON_BIN="$python_bin"
  run_as_application "$PYTHON_BIN" -c 'import sys; raise SystemExit(sys.version_info < (3, 12))' \
    || fail "The service account cannot execute the selected Python interpreter: $PYTHON_BIN"
  if ! "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
    "$PYTHON_BIN" -m ensurepip --upgrade >/dev/null 2>&1 \
      || fail "pip is unavailable for $PYTHON_BIN. Install the matching python3.12-pip/ensurepip package and rerun."
  fi
}

install_python_package() {
  # Kali/Debian Python packages intentionally lack pip RECORD metadata. Install
  # a coherent application dependency set into /usr/local without attempting
  # to uninstall distribution-owned files from /usr/lib/python3/dist-packages.
  # pip can replace the CLI entry point before a later dependency fails. Keep
  # control long enough to restore the managed launcher on either outcome.
  local pip_status
  set +e
  "$PYTHON_BIN" -m pip install \
    --break-system-packages --ignore-installed --upgrade "$INSTALL_DIR"
  pip_status=$?
  set -e
  install_cli_launcher
  (( pip_status == 0 )) \
    || fail "Python package installation failed. The managed launcher was restored; review the pip error above."
}

record_python_runtime() {
  [[ -f "$CONFIG_DIR/runtime.env" ]] || return 0
  local temporary
  temporary="$(mktemp "$CONFIG_DIR/runtime.env.XXXXXX")"
  grep -v '^WRAITH_PYTHON_EXECUTABLE=' "$CONFIG_DIR/runtime.env" > "$temporary" || true
  printf 'WRAITH_PYTHON_EXECUTABLE=%q\n' "$PYTHON_BIN" >> "$temporary"
  chown root:"$APP_USER" "$temporary"
  chmod 0640 "$temporary"
  mv "$temporary" "$CONFIG_DIR/runtime.env"
}

ensure_service_account() {
  if ! getent group "$APP_USER" >/dev/null 2>&1; then
    groupadd --system "$APP_USER"
  fi
  if ! id "$APP_USER" >/dev/null 2>&1; then
    useradd --system --gid "$APP_USER" --home-dir "$DATA_DIR" --create-home \
      --shell /usr/sbin/nologin "$APP_USER"
  else
    # Normalize an account left by an interrupted installation without
    # deleting it or changing its UID.
    usermod --gid "$APP_USER" --home "$DATA_DIR" --shell /usr/sbin/nologin "$APP_USER"
  fi
}

install_cli_launcher() {
  local destination="/usr/local/bin/wraith-crawler"
  local command_link="/usr/bin/wraith-crawler"
  if [[ -L "$destination" ]]; then
    [[ "$(readlink "$destination")" == "$INSTALL_DIR/.venv/bin/wraith-crawler" ]] \
      || fail "$destination is an unmanaged symbolic link; move it aside before installation."
    unlink "$destination"
  elif [[ -e "$destination" ]] \
    && ! grep -qE '^# Wraith Crawler managed launcher$|from wraith_crawler\.cli import main' "$destination"; then
      fail "$destination already exists and is not managed by Wraith Crawler; move it aside before installation."
  fi
  install -o root -g root -m 0755 "$SOURCE_DIR/deploy/wraith-crawler-launcher" "$destination"
  if [[ -L "$command_link" ]]; then
    [[ "$(readlink "$command_link")" == "$destination" ]] \
      || fail "$command_link points somewhere other than the managed Wraith Crawler launcher."
  elif [[ -e "$command_link" ]]; then
    fail "$command_link already exists and is not the managed Wraith Crawler command link."
  else
    ln -s "$destination" "$command_link"
  fi
}

verify_cli_launcher() {
  local launcher="/usr/local/bin/wraith-crawler"
  local command_link="/usr/bin/wraith-crawler"
  [[ -x "$launcher" ]] || fail "Managed CLI launcher is missing: $launcher"
  grep -q '^# Wraith Crawler managed launcher$' "$launcher" \
    || fail "$launcher was replaced by an unmanaged Python console script."
  [[ -L "$command_link" && "$(readlink "$command_link")" == "$launcher" ]] \
    || fail "PATH-visible CLI command link is missing: $command_link"
  [[ -r "$CONFIG_DIR/runtime.env" ]] || fail "Runtime configuration is missing: $CONFIG_DIR/runtime.env"
  "$command_link" coverage >/dev/null \
    || fail "Managed CLI launcher could not load the installed runtime configuration."
}

install_application() {
  ensure_service_account
  install -d -o "$APP_USER" -g "$APP_USER" -m 0750 "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR" "$INSTALL_DIR/output"
  install -d -o "$APP_USER" -g "$APP_USER" -m 0750 \
    "$DATA_DIR/.config" "$DATA_DIR/.cache" "$DATA_DIR/.local" \
    "$DATA_DIR/.local/share" "$DATA_DIR/nuclei-templates"
  install -d -o root -g "$APP_USER" -m 0750 "$CONFIG_DIR"
  rsync -a --delete --exclude '.git' --exclude '.venv' --exclude 'output' "$SOURCE_DIR/" "$INSTALL_DIR/"
  # Publish the command before Python installation so interrupted installs
  # never leave the operator with an unexplained "command not found".
  install_cli_launcher
  select_system_python
  install_python_package
  # pip writes its generated wraith-crawler console entry point. Replace it
  # immediately so any subsequent interruption still leaves the safe launcher.
  install_cli_launcher
  # The Python httpx distribution may write an unrelated /usr/local/bin/httpx
  # console script. The scanner lives at a collision-free private path.
  install_projectdiscovery_httpx
  chown -R "$APP_USER:$APP_USER" "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
  run_as_application /usr/local/bin/nuclei -update-templates -silent || true
  record_python_runtime
  migrate_httpx_config_path
  # pip creates its own console entry point; restore the managed launcher that
  # loads protected runtime configuration and drops privileges.
  install_cli_launcher
}

write_runtime_secret() {
  local database_url
  database_url="$(DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_NAME="$DB_NAME" DB_USER="$DB_USER" DB_PASSWORD="$DB_PASSWORD" "$PYTHON_BIN" - <<'PY'
import os
from sqlalchemy.engine import URL
print(URL.create(
    "postgresql+psycopg",
    username=os.environ["DB_USER"], password=os.environ["DB_PASSWORD"],
    host=os.environ["DB_HOST"], port=int(os.environ["DB_PORT"]), database=os.environ["DB_NAME"],
).render_as_string(hide_password=False))
PY
)"
  umask 077
  {
    printf 'WRAITH_DATABASE_URL=%q\n' "$database_url"
    printf 'WRAITH_ENVIRONMENT=production\n'
    printf 'WRAITH_CONFIG=%q\n' "$CONFIG_DIR/config.yaml"
    printf 'WRAITH_PYTHON_EXECUTABLE=%q\n' "$PYTHON_BIN"
  } > "$CONFIG_DIR/runtime.env"
  install -o root -g "$APP_USER" -m 0640 "$SOURCE_DIR/config.example.yaml" "$CONFIG_DIR/config.yaml"
  chown root:"$APP_USER" "$CONFIG_DIR/runtime.env"
  chmod 0640 "$CONFIG_DIR/runtime.env"
}

run_migrations() {
  set -a; . "$CONFIG_DIR/runtime.env"; set +a
  cd "$INSTALL_DIR"
  run_as_application "$PYTHON_BIN" -m alembic upgrade head
}

prompt_admin() {
  printf '\nWraith Crawler - Administrator Account\n'
  while true; do
    read -r -p 'Administrator username: ' ADMIN_USER
    [[ -n "$ADMIN_USER" ]] && break
  done
  prompt_secret_confirmed 'Administrator password'; ADMIN_PASSWORD="$REPLY_SECRET"; unset REPLY_SECRET
  set -a; . "$CONFIG_DIR/runtime.env"; set +a
  printf '%s\n' "$ADMIN_PASSWORD" | run_as_application \
    "$PYTHON_BIN" -m wraith_crawler.cli --config "$CONFIG_DIR/config.yaml" admin create \
    --username "$ADMIN_USER" --password-stdin --role admin
  unset ADMIN_PASSWORD
}

ensure_initial_admin() {
  local admin_count
  admin_count="$(PGPASSWORD="$DB_PASSWORD" psql --host="$DB_HOST" --port="$DB_PORT" --username="$DB_USER" --dbname="$DB_NAME" -tAc 'SELECT count(*) FROM users' | tr -d '[:space:]')"
  if [[ "$admin_count" == "0" ]]; then
    prompt_admin
  else
    printf 'Application users already exist; the installer will not replace an administrator.\n'
  fi
}

configure_reporting_role() {
  REPORTING_USER="wraith_metabase_reader"
  METABASE_DB="wraith_metabase"
  if [[ -f "$CONFIG_DIR/metabase.env" ]]; then
    set -a; . "$CONFIG_DIR/metabase.env"; set +a
    REPORTING_PASSWORD="${WRAITH_REPORTING_PASSWORD:?Existing reporting password is missing}"
    METABASE_DB_PASSWORD="${MB_DB_PASS:?Existing Metabase database password is missing}"
    METABASE_ADMIN_PASSWORD="${METABASE_ADMIN_PASSWORD:?Existing Metabase administrator password is missing}"
  else
    REPORTING_PASSWORD="$(openssl rand -base64 36 | tr -d '\n')"
    METABASE_DB_PASSWORD="$(openssl rand -base64 36 | tr -d '\n')"
    METABASE_ADMIN_PASSWORD="$(openssl rand -base64 36 | tr -d '\n')"
  fi
  if [[ "$DB_HOST" == "127.0.0.1" || "$DB_HOST" == "localhost" ]]; then
    runuser -u postgres -- psql --set=role="$REPORTING_USER" --set=password="$REPORTING_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'role', :'password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'role') \gexec
SQL
    runuser -u postgres -- psql --set=role="wraith_metabase" --set=password="$METABASE_DB_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'role', :'password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'role') \gexec
SQL
    runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname='$METABASE_DB'" | grep -q 1 \
      || runuser -u postgres -- createdb --owner=wraith_metabase "$METABASE_DB"
    runuser -u postgres -- psql --dbname=postgres --set=db="$DB_NAME" --set=reader="$REPORTING_USER" <<'SQL'
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'db', :'reader') \gexec
SQL
  fi
  PGPASSWORD="$DB_PASSWORD" psql --host="$DB_HOST" --port="$DB_PORT" --username="$DB_USER" --dbname="$DB_NAME" -v ON_ERROR_STOP=1 \
    --set=reader="$REPORTING_USER" <<'SQL'
SELECT format('GRANT USAGE ON SCHEMA reporting TO %I', :'reader') \gexec
SELECT format('GRANT SELECT ON ALL TABLES IN SCHEMA reporting TO %I', :'reader') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES IN SCHEMA reporting GRANT SELECT ON TABLES TO %I', :'reader') \gexec
SQL
  umask 077
  {
    printf 'MB_DB_TYPE=postgres\n'
    printf 'MB_DB_DBNAME=%q\n' "$METABASE_DB"
    printf 'MB_DB_PORT=%q\n' "$DB_PORT"
    printf 'MB_DB_USER=wraith_metabase\n'
    printf 'MB_DB_PASS=%q\n' "$METABASE_DB_PASSWORD"
    printf 'MB_DB_HOST=%q\n' "$DB_HOST"
    printf 'WRAITH_REPORTING_HOST=%q\n' "$DB_HOST"
    printf 'WRAITH_REPORTING_PORT=%q\n' "$DB_PORT"
    printf 'WRAITH_REPORTING_DB=%q\n' "$DB_NAME"
    printf 'WRAITH_REPORTING_USER=%q\n' "$REPORTING_USER"
    printf 'WRAITH_REPORTING_PASSWORD=%q\n' "$REPORTING_PASSWORD"
    printf 'METABASE_ADMIN_EMAIL=admin@wraith.local\n'
    printf 'METABASE_ADMIN_PASSWORD=%q\n' "$METABASE_ADMIN_PASSWORD"
  } > "$CONFIG_DIR/metabase.env"
  chown root:"$APP_USER" "$CONFIG_DIR/metabase.env"; chmod 0640 "$CONFIG_DIR/metabase.env"
  unset REPORTING_PASSWORD METABASE_DB_PASSWORD METABASE_ADMIN_PASSWORD
}

migrate_metabase_environment_defaults() {
  local environment="$CONFIG_DIR/metabase.env" temporary
  [[ -f "$environment" ]] || return 0
  grep -q '^METABASE_ADMIN_EMAIL=admin@localhost$' "$environment" || return 0
  temporary="$(mktemp "$CONFIG_DIR/metabase.env.XXXXXX")"
  sed 's/^METABASE_ADMIN_EMAIL=admin@localhost$/METABASE_ADMIN_EMAIL=admin@wraith.local/' \
    "$environment" > "$temporary"
  chown root:"$APP_USER" "$temporary"
  chmod 0640 "$temporary"
  mv "$temporary" "$environment"
}

ensure_reporting_database_access() {
  set -a; . "$CONFIG_DIR/metabase.env"; set +a
  if [[ "$WRAITH_REPORTING_HOST" == "127.0.0.1" || "$WRAITH_REPORTING_HOST" == "localhost" ]]; then
    validate_identifier "$WRAITH_REPORTING_DB"
    validate_identifier "$WRAITH_REPORTING_USER"
    runuser -u postgres -- psql --dbname=postgres \
      --set=db="$WRAITH_REPORTING_DB" --set=reader="$WRAITH_REPORTING_USER" <<'SQL'
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'db', :'reader') \gexec
SQL
  fi
  PGPASSWORD="$WRAITH_REPORTING_PASSWORD" psql \
    --host="$WRAITH_REPORTING_HOST" --port="$WRAITH_REPORTING_PORT" \
    --username="$WRAITH_REPORTING_USER" --dbname="$WRAITH_REPORTING_DB" \
    -v ON_ERROR_STOP=1 -c 'SELECT 1' >/dev/null \
    || fail "The Metabase reporting role cannot connect to the reporting database."
}

install_metabase() {
  migrate_metabase_environment_defaults
  ensure_reporting_database_access
  install -m 0644 "$SOURCE_DIR/deploy/docker-compose.metabase.yml" "$INSTALL_DIR/docker-compose.metabase.yml"
  docker_compose --env-file "$CONFIG_DIR/metabase.env" -f "$INSTALL_DIR/docker-compose.metabase.yml" up -d
  local attempt healthy=false
  for attempt in $(seq 1 150); do
    if curl -fsS http://127.0.0.1:3000/api/health 2>/dev/null \
      | jq -e '.status == "ok"' >/dev/null 2>&1; then
      healthy=true
      break
    fi
    if (( attempt < 150 )); then
      sleep 2
    fi
  done
  if [[ "$healthy" != true ]]; then
    printf 'Metabase container logs (last 120 lines):\n' >&2
    docker logs --tail 120 wraith-metabase >&2 || true
    fail "Metabase did not become healthy within five minutes."
  fi
  set -a; . "$CONFIG_DIR/metabase.env"; set +a
  "$PYTHON_BIN" "$INSTALL_DIR/scripts/provision_metabase.py" --url http://127.0.0.1:3000
}

repair_existing() {
  install_system_packages
  install_security_tools
  install_application
  run_migrations
  verify_cli_launcher
  [[ -f "$CONFIG_DIR/metabase.env" ]] || fail "Repair requires the existing $CONFIG_DIR/metabase.env secret file."
  install_services
  install_metabase
  set -a; . "$CONFIG_DIR/runtime.env"; set +a
  run_as_application "$PYTHON_BIN" -m wraith_crawler.cli --config "$CONFIG_DIR/config.yaml" doctor
  printf '\nWraith Crawler repair completed without changing database or administrator credentials.\n'
}

install_services() {
  install -m 0644 "$SOURCE_DIR/deploy/wraith-crawler-api.service" /etc/systemd/system/wraith-crawler-api.service
  install -m 0644 "$SOURCE_DIR/deploy/wraith-crawler-worker.service" /etc/systemd/system/wraith-crawler-worker.service
  systemctl daemon-reload
  systemctl enable --now wraith-crawler-api
}

main() {
  require_root; detect_os
  if [[ -f "$CONFIG_DIR/runtime.env" ]]; then
    printf 'Existing installation detected.\n1) Upgrade\n2) Repair\n3) Reconfigure Database\n4) Cancel\n'
    read -r -p 'Select [4]: ' action; action="${action:-4}"
    case "$action" in
      1) exec "$SOURCE_DIR/upgrade.sh" ;;
      2) repair_existing; exit 0 ;;
      3) ;;
      *) exit 0 ;;
    esac
  fi
  install_system_packages
  install_security_tools
  prompt_database
  create_or_validate_database
  install_application
  write_runtime_secret
  verify_cli_launcher
  run_migrations
  ensure_initial_admin
  configure_reporting_role
  install_services
  install_metabase
  set -a; . "$CONFIG_DIR/runtime.env"; set +a
  run_as_application "$PYTHON_BIN" -m wraith_crawler.cli --config "$CONFIG_DIR/config.yaml" doctor
  unset DB_PASSWORD
  printf '\nWraith Crawler installed.\nAPI: http://127.0.0.1:8080\nMetabase: http://127.0.0.1:3000\n'
  printf 'Commands: systemctl status wraith-crawler-api | sudo wraith-crawler doctor | %s/backup.sh\n' "$INSTALL_DIR"
  printf 'Metabase credentials are stored root-readable in %s/metabase.env. Reverse-proxy TLS before remote exposure.\n' "$CONFIG_DIR"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
