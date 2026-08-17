from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config as AlembicConfig
from pydantic import SecretStr

from .api import create_app
from .config import AppConfig, load_config
from .coverage import coverage_matrix
from .doctor import Doctor
from .domain import TargetInput
from .engine import ScanEngine
from .enums import RoleName, ScanProfile
from .logging import configure_logging
from .persistence.database import Database
from .persistence.models import Report
from .reporting import ExcelReportGenerator, PDFReportGenerator
from .services.auth import AuthService


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="wraith-crawler", description="Evidence-first external web security assessment")
    root.add_argument("-u", "--url", action="append", help="Authorized target URL; may be repeated")
    root.add_argument("-f", "--file", help="File containing authorized target URLs")
    root.add_argument("--config", help="YAML configuration file")
    root.add_argument("--database-url", help="Explicit SQLAlchemy database URL (prefer an environment secret)")
    root.add_argument("--plugin", action="append", help="Run only the named plugin; may be repeated")
    root.add_argument("--exclude-plugin", action="append", default=[], help="Disable a plugin; may be repeated")
    root.add_argument("--profile", choices=[profile.value for profile in ScanProfile])
    root.add_argument("--llm", action="store_true", help="Enable configured optional LLM enrichment")
    root.add_argument("--llm-model")
    root.add_argument("--environment", choices=["production", "staging", "development", "test"])
    root.add_argument("--output", default="output", help="Report output directory")
    root.add_argument("--verbose", action="store_true")
    sub = root.add_subparsers(dest="command")
    doctor = sub.add_parser("doctor", help="Validate database, migrations, views, tools, and Metabase")
    doctor.add_argument("--json", action="store_true")
    serve = sub.add_parser("serve", help="Run the REST API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    admin = sub.add_parser("admin", help="Application administrator management")
    admin_sub = admin.add_subparsers(dest="admin_command", required=True)
    create = admin_sub.add_parser("create", help="Create an application user")
    create.add_argument("--username")
    create.add_argument("--password-stdin", action="store_true")
    create.add_argument("--role", action="append", choices=[role.value for role in RoleName])
    report = sub.add_parser("report", help="Generate reports from a persisted assessment")
    report.add_argument("assessment_id")
    report.add_argument("--format", choices=["pdf", "xlsx", "both"], default="both")
    report.add_argument(
        "--output",
        default=argparse.SUPPRESS,
        help="Report output directory (accepted before or after the report subcommand)",
    )
    sub.add_parser("coverage", help="Print the machine-readable OWASP coverage matrix")
    sub.add_parser("migrate", help="Run Alembic migrations")
    return root


def build_config(args: argparse.Namespace) -> AppConfig:
    config = load_config(args.config)
    updates: dict[str, Any] = {}
    if args.database_url:
        updates["database"] = config.database.model_copy(update={"url": SecretStr(args.database_url)})
    if args.profile:
        updates["profile"] = ScanProfile(args.profile)
    if args.environment:
        updates["environment"] = args.environment
    if args.llm:
        updates["llm"] = config.llm.model_copy(update={"enabled": True, "model": args.llm_model or config.llm.model})
    return config.model_copy(update=updates)


def load_targets(urls: list[str] | None, file_path: str | None) -> list[TargetInput]:
    raw = list(urls or [])
    if file_path:
        for line in Path(file_path).read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if value and not value.startswith("#"):
                raw.append(value)
    targets: list[TargetInput] = []
    seen: set[str] = set()
    for value in raw:
        target = TargetInput(url=value)
        if target.url not in seen:
            seen.add(target.url)
            targets.append(target)
    return targets


def run_migrations(database_url: str) -> None:
    previous = os.environ.get("WRAITH_DATABASE_URL")
    os.environ["WRAITH_DATABASE_URL"] = database_url
    try:
        command.upgrade(AlembicConfig("alembic.ini"), "head")
    finally:
        if previous is None:
            os.environ.pop("WRAITH_DATABASE_URL", None)
        else:
            os.environ["WRAITH_DATABASE_URL"] = previous


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        config = build_config(args)
        configure_logging("DEBUG" if args.verbose else config.log_level)
    except (ValueError, FileNotFoundError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    if args.command == "coverage":
        print(json.dumps(coverage_matrix(), indent=2))
        return 0
    try:
        database_url = config.database.sqlalchemy_url()
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        if "database password or WRAITH_DATABASE_URL" in str(exc):
            print(
                "Installed systems must use the managed launcher: "
                "sudo /usr/local/bin/wraith-crawler ...; if that still fails, "
                "the installer did not create /etc/wraith-crawler/runtime.env.",
                file=sys.stderr,
            )
        return 2

    if args.command == "migrate":
        run_migrations(database_url)
        print("Migrations completed")
        return 0
    database = Database(database_url)
    if args.command == "doctor":
        checks = Doctor(database, config).run()
        if args.json:
            print(json.dumps(Doctor.as_dicts(checks), indent=2))
        else:
            for check in checks:
                print(f"{check.status.upper():8} {check.name:20} {check.message}")
        return 0 if Doctor(database, config).healthy(checks) else 1
    if args.command == "admin":
        return _admin_command(args, database, config)
    if args.command == "report":
        return _report_command(args, database)
    if args.command == "serve":
        import uvicorn

        app = create_app(config, database)
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    try:
        targets = load_targets(args.url, args.file)
    except (ValueError, OSError) as exc:
        print(f"Target input error: {exc}", file=sys.stderr)
        return 2
    if not targets:
        parser().error("provide --url or --file, or use a subcommand")
    engine = ScanEngine(database, config)
    results = asyncio.run(
        engine.scan_batch(
            targets,
            include_plugins=args.plugin,
            exclude_plugins=args.exclude_plugin,
        )
    )
    failures = 0
    for target, result in results.items():
        if isinstance(result, Exception):
            failures += 1
            print(f"FAILED {target}: {type(result).__name__}: {result}")
        else:
            print(f"COMPLETED {target}: assessment {result}")
    return 1 if failures == len(results) else 0


def _admin_command(args: argparse.Namespace, database: Database, config: AppConfig) -> int:
    username = args.username or input("Administrator username: ").strip()
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("Administrator password: ")
        confirmation = getpass.getpass("Confirm administrator password: ")
        if password != confirmation:
            print("Passwords do not match", file=sys.stderr)
            return 2
    auth = AuthService(config.session_ttl_minutes)
    try:
        with database.session() as session:
            selected_roles = args.role or [RoleName.ADMIN.value]
            user = auth.create_user(session, username, password, [RoleName(role) for role in selected_roles])
            print(f"Created application user {user.username} ({user.id})")
    except ValueError as exc:
        print(f"Unable to create user: {exc}", file=sys.stderr)
        return 2
    return 0


def _report_command(args: argparse.Namespace, database: Database) -> int:
    output_dir = Path(args.output).resolve()
    formats = ("pdf", "xlsx") if args.format == "both" else (args.format,)
    with database.session() as session:
        for report_format in formats:
            path = output_dir / f"wraith-{args.assessment_id}.{report_format}"
            generator = PDFReportGenerator() if report_format == "pdf" else ExcelReportGenerator()
            generator.generate(session, args.assessment_id, path)
            report = Report(
                assessment_id=args.assessment_id,
                report_type=report_format,
                path=str(path),
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                size_bytes=path.stat().st_size,
            )
            session.add(report)
            print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
