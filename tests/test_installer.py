from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _identity_check(binary: Path) -> subprocess.CompletedProcess[str]:
    install_script = Path(__file__).resolve().parents[1] / "install.sh"
    return subprocess.run(  # noqa: S603
        [
            "/bin/bash",
            "-c",
            'source "$1"; projectdiscovery_httpx "$2"',
            "wraith-installer-test",
            str(install_script),
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_installer_rejects_python_httpx_name_collision(tmp_path: Path) -> None:
    binary = tmp_path / "httpx"
    binary.write_text("#!/usr/bin/env bash\nprintf 'The httpx command line client 0.28.1\\n'\n")
    binary.chmod(0o755)
    assert _identity_check(binary).returncode != 0


def test_installer_accepts_projectdiscovery_httpx_identity(tmp_path: Path) -> None:
    binary = tmp_path / "httpx"
    binary.write_text("#!/usr/bin/env bash\nprintf 'projectdiscovery httpx current version: v1.7.2\\n'\n")
    binary.chmod(0o755)
    assert _identity_check(binary).returncode == 0


def test_installer_builds_projectdiscovery_httpx_away_from_python_cli() -> None:
    root = Path(__file__).resolve().parents[1]
    install_script = (root / "install.sh").read_text()
    config = (root / "config.example.yaml").read_text()
    assert 'PD_HTTPX="/usr/local/lib/wraith-crawler/bin/httpx"' in install_script
    assert 'GOBIN="$build_dir" go install' in install_script
    assert "httpx: /usr/local/lib/wraith-crawler/bin/httpx" in config


def test_installer_reuses_preexisting_service_group() -> None:
    install_script = Path(__file__).resolve().parents[1] / "install.sh"
    command = r'''
source "$1"
getent() { return 0; }
id() { return 1; }
groupadd() { printf 'unexpected groupadd\n'; return 99; }
useradd() { printf '%s\n' "$*"; }
ensure_service_account
'''
    result = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", command, "wraith-installer-test", str(install_script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "--gid wraith-crawler" in result.stdout
    assert "unexpected groupadd" not in result.stdout


def test_installer_grants_required_local_database_ddl_privileges() -> None:
    installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
    assert "GRANT CONNECT, CREATE, TEMPORARY ON DATABASE %I TO %I" in installer
    assert "GRANT USAGE, CREATE ON SCHEMA public TO %I" in installer
    assert "has_database_privilege" in installer
    assert "has_schema_privilege" in installer


def test_metabase_uses_loopback_safe_linux_host_networking() -> None:
    compose = (
        Path(__file__).resolve().parents[1] / "deploy" / "docker-compose.metabase.yml"
    ).read_text()
    assert "network_mode: host" in compose
    assert "MB_JETTY_HOST: 127.0.0.1" in compose
    assert '"127.0.0.1:3000:3000"' not in compose


def test_metabase_connectivity_is_verified_before_container_start() -> None:
    installer = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
    function = installer.split("install_metabase() {", 1)[1].split("\n}", 1)[0]
    assert function.index("ensure_reporting_database_access") < function.index("docker_compose")
    assert "The Metabase reporting role cannot connect" in installer


def test_system_launcher_refuses_unprivileged_execution() -> None:
    if os.geteuid() == 0:
        return
    launcher = Path(__file__).resolve().parents[1] / "deploy" / "wraith-crawler-launcher"
    result = subprocess.run(  # noqa: S603
        ["/bin/bash", str(launcher), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 77
    assert "sudo wraith-crawler" in result.stderr


def test_production_package_install_uses_system_python_break_flag(tmp_path: Path) -> None:
    install_script = Path(__file__).resolve().parents[1] / "install.sh"
    fake_python = tmp_path / "python3.12"
    argument_log = tmp_path / "arguments"
    fake_python.write_text('#!/bin/bash\nprintf "%s\\n" "$@" > "$WRAITH_TEST_ARGUMENT_LOG"\n')
    fake_python.chmod(0o755)
    command = r'''
source "$1"
PYTHON_BIN="$2"
INSTALL_DIR="/opt/wraith-crawler"
install_cli_launcher() { :; }
install_python_package
'''
    environment = {**os.environ, "WRAITH_TEST_ARGUMENT_LOG": str(argument_log)}
    result = subprocess.run(  # noqa: S603
        [
            "/bin/bash",
            "-c",
            command,
            "wraith-installer-test",
            str(install_script),
            str(fake_python),
        ],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    assert result.returncode == 0
    assert argument_log.read_text().splitlines() == [
        "-m",
        "pip",
        "install",
        "--break-system-packages",
        "--ignore-installed",
        "--upgrade",
        "/opt/wraith-crawler",
    ]


def test_installer_publishes_launcher_before_python_package_install() -> None:
    install_script = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
    function = install_script.split("install_application() {", 1)[1].split("\n}", 1)[0]
    assert function.index("install_cli_launcher") < function.index("install_python_package")
    assert function.index("install_python_package") < function.index("install_cli_launcher", function.index("install_python_package"))


def test_installer_publishes_cli_on_standard_kali_sudo_path() -> None:
    install_script = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
    function = install_script.split("install_cli_launcher() {", 1)[1].split("\n}", 1)[0]
    verification = install_script.split("verify_cli_launcher() {", 1)[1].split("\n}", 1)[0]
    assert 'command_link="/usr/bin/wraith-crawler"' in function
    assert 'ln -s "$destination" "$command_link"' in function
    assert 'command_link="/usr/bin/wraith-crawler"' in verification


def test_scanners_run_with_service_account_home() -> None:
    root = Path(__file__).resolve().parents[1]
    installer = (root / "install.sh").read_text()
    launcher = (root / "deploy" / "wraith-crawler-launcher").read_text()
    service = (root / "deploy" / "wraith-crawler-api.service").read_text()
    for content in (installer, launcher, service):
        assert any(
            assignment in content
            for assignment in (
                "HOME=/var/lib/wraith-crawler",
                'HOME="$DATA_DIR"',
                'HOME="$APP_HOME"',
            )
        )
        assert "XDG_CONFIG_HOME" in content
        assert "XDG_CACHE_HOME" in content
    assert 'run_as_application /usr/local/bin/nuclei -update-templates -silent' in installer


def test_upgrade_doctor_runs_with_service_account_home() -> None:
    upgrade = (Path(__file__).resolve().parents[1] / "upgrade.sh").read_text()
    assert (
        'run_as_application "$PYTHON_BIN" -m wraith_crawler.cli '
        '--config "$CONFIG_DIR/config.yaml" doctor'
    ) in upgrade


def test_installer_restores_launcher_when_pip_fails() -> None:
    install_script = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
    function = install_script.split("install_python_package() {", 1)[1].split("\n}", 1)[0]
    assert "pip_status=$?" in function
    assert function.index("pip_status=$?") < function.index("install_cli_launcher")
    assert "The managed launcher was restored" in function
