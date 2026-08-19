from collections.abc import Callable, Generator
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import __version__
from .config import AppConfig, load_config
from .coverage import coverage_matrix
from .domain import TargetInput
from .engine import ScanEngine
from .enums import RoleName
from .mitre import attack_catalog
from .persistence.database import Database
from .persistence.models import (
    Application,
    Assessment,
    AssessmentCoverage,
    Asset,
    AttackPath,
    AttackPathEdge,
    AttackPathNode,
    Endpoint,
    Evidence,
    Finding,
    ManualReviewItem,
    PentestPhaseProgress,
    PluginExecution,
    PostExploitationStep,
    Report,
    Role,
    ScanMetric,
    Technology,
    User,
)
from .reporting import ExcelReportGenerator, PDFReportGenerator
from .services.auth import AuthenticationError, AuthService


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreateRequest(BaseModel):
    username: str
    password: str
    roles: list[RoleName] = Field(default_factory=lambda: [RoleName.VIEWER])


class TargetCreateRequest(TargetInput):
    name: str | None = None
    business_metadata: dict[str, Any] = Field(default_factory=dict)


class ScanRequest(TargetInput):
    plugins: list[str] | None = None
    exclude_plugins: list[str] = Field(default_factory=list)


class BatchScanRequest(BaseModel):
    targets: list[TargetInput]
    plugins: list[str] | None = None
    exclude_plugins: list[str] = Field(default_factory=list)


class ManualReviewUpdate(BaseModel):
    status: str
    resolution: str | None = None
    assigned_to_id: str | None = None


class ReportRequest(BaseModel):
    report_type: str
    output_directory: str | None = None


def create_app(config: AppConfig | None = None, database: Database | None = None) -> FastAPI:
    config = config or load_config()
    database = database or Database(config.database.sqlalchemy_url())
    engine = ScanEngine(database, config)
    auth = AuthService(config.session_ttl_minutes)
    app = FastAPI(
        title="Wraith Crawler API",
        version=__version__,
        description="Evidence-first external web application security assessment API",
    )
    if config.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
        )
    app.state.database = database
    app.state.config = config
    app.state.engine = engine
    app.state.auth = auth

    def db_session() -> Generator[Session, None, None]:
        session = database.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def current_user(
        request: Request,
        session: Annotated[Session, Depends(db_session)],
        authorization: Annotated[str | None, Header()] = None,
        x_csrf_token: Annotated[str | None, Header()] = None,
    ) -> User:
        bearer = None
        if authorization and authorization.lower().startswith("bearer "):
            bearer = authorization.split(" ", 1)[1]
        cookie_token = request.cookies.get("wraith_session")
        token = bearer or cookie_token
        if not token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
        csrf = None
        if bearer is None and cookie_token and request.method not in {"GET", "HEAD", "OPTIONS"}:
            csrf = x_csrf_token
            if not csrf:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token required")
        user = auth.validate_session(session, token, csrf)
        if not user:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired session")
        return user

    def roles(*allowed: RoleName) -> Callable[[User], User]:
        def dependency(user: Annotated[User, Depends(current_user)]) -> User:
            try:
                auth.require_role(user, *allowed)
            except PermissionError as exc:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role") from exc
            return user

        return dependency

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok" if database.ping() else "degraded", "version": app.version}

    @app.post("/api/v1/auth/login")
    def login(payload: LoginRequest, response: Response, session: Annotated[Session, Depends(db_session)]) -> dict[str, Any]:
        try:
            tokens = auth.authenticate(session, payload.username, payload.password)
        except AuthenticationError as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
        response.set_cookie(
            "wraith_session",
            tokens.session_token,
            httponly=True,
            secure=config.session_cookie_secure,
            samesite="strict",
            max_age=config.session_ttl_minutes * 60,
            path="/",
        )
        response.set_cookie(
            "wraith_csrf",
            tokens.csrf_token,
            httponly=False,
            secure=config.session_cookie_secure,
            samesite="strict",
            max_age=config.session_ttl_minutes * 60,
            path="/",
        )
        return {"expires_at": tokens.expires_at, "csrf_token": tokens.csrf_token, "session_token": tokens.session_token}

    @app.post("/api/v1/auth/logout", status_code=204)
    def logout(
        request: Request,
        response: Response,
        session: Annotated[Session, Depends(db_session)],
        _user: Annotated[User, Depends(current_user)],
        authorization: Annotated[str | None, Header()] = None,
    ) -> Response:
        token = request.cookies.get("wraith_session")
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1]
        if token:
            auth.logout(session, token)
        response.delete_cookie("wraith_session", path="/")
        response.delete_cookie("wraith_csrf", path="/")
        response.status_code = 204
        return response

    @app.get("/api/v1/auth/me")
    def me(user: Annotated[User, Depends(current_user)]) -> dict[str, Any]:
        return {"id": user.id, "username": user.username, "roles": [role.name for role in user.roles]}

    @app.get("/api/v1/users")
    def list_users(
        session: Annotated[Session, Depends(db_session)],
        _admin: Annotated[User, Depends(roles(RoleName.ADMIN))],
    ) -> list[dict[str, Any]]:
        return [
            {"id": user.id, "username": user.username, "active": user.active, "roles": [role.name for role in user.roles]}
            for user in session.scalars(select(User).order_by(User.username))
        ]

    @app.post("/api/v1/users", status_code=201)
    def create_user(
        payload: UserCreateRequest,
        session: Annotated[Session, Depends(db_session)],
        _admin: Annotated[User, Depends(roles(RoleName.ADMIN))],
    ) -> dict[str, Any]:
        try:
            user = auth.create_user(session, payload.username, payload.password, payload.roles)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"id": user.id, "username": user.username, "roles": [role.name for role in user.roles]}

    @app.get("/api/v1/roles")
    def list_roles(
        session: Annotated[Session, Depends(db_session)],
        _user: Annotated[User, Depends(roles(RoleName.ADMIN))],
    ) -> list[dict[str, Any]]:
        return [{"id": row.id, "name": row.name, "description": row.description} for row in session.scalars(select(Role))]

    @app.get("/api/v1/applications")
    def applications(
        session: Annotated[Session, Depends(db_session)],
        _user: Annotated[User, Depends(current_user)],
    ) -> list[dict[str, Any]]:
        return [self_serialize(row) for row in session.scalars(select(Application).order_by(Application.name))]

    @app.post("/api/v1/applications", status_code=201)
    def create_application(
        payload: TargetCreateRequest,
        session: Annotated[Session, Depends(db_session)],
        _user: Annotated[User, Depends(roles(RoleName.ADMIN, RoleName.ANALYST))],
    ) -> dict[str, Any]:
        origin = _origin(payload.url)
        existing = session.scalar(select(Application).where(Application.normalized_origin == origin))
        if existing:
            return self_serialize(existing)
        row = Application(
            name=payload.name or url_host(payload.url),
            seed_url=payload.url,
            normalized_origin=origin,
            business_metadata=payload.business_metadata,
            scope=payload.model_dump(mode="json", exclude={"url", "name", "business_metadata"}),
        )
        session.add(row)
        session.flush()
        return self_serialize(row)

    @app.post("/api/v1/scans", status_code=201)
    async def create_scan(
        payload: ScanRequest,
        user: Annotated[User, Depends(roles(RoleName.ADMIN, RoleName.ANALYST))],
    ) -> dict[str, str]:
        assessment_id = await engine.scan(
            TargetInput.model_validate(payload.model_dump()),
            include_plugins=payload.plugins,
            exclude_plugins=payload.exclude_plugins,
            requested_by_id=user.id,
        )
        return {"assessment_id": assessment_id}

    @app.post("/api/v1/scans/batch", status_code=201)
    async def create_batch_scan(
        payload: BatchScanRequest,
        user: Annotated[User, Depends(roles(RoleName.ADMIN, RoleName.ANALYST))],
    ) -> dict[str, Any]:
        results = await engine.scan_batch(
            payload.targets,
            include_plugins=payload.plugins,
            exclude_plugins=payload.exclude_plugins,
            requested_by_id=user.id,
        )
        return {url: str(result) for url, result in results.items()}

    @app.get("/api/v1/assessments")
    def assessments(
        session: Annotated[Session, Depends(db_session)],
        _user: Annotated[User, Depends(current_user)],
        application_id: str | None = None,
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[dict[str, Any]]:
        query = select(Assessment).order_by(Assessment.created_at.desc()).limit(limit)
        if application_id:
            query = query.where(Assessment.application_id == application_id)
        return [self_serialize(row) for row in session.scalars(query)]

    @app.get("/api/v1/assessments/{assessment_id}")
    def assessment_detail(
        assessment_id: str,
        session: Annotated[Session, Depends(db_session)],
        _user: Annotated[User, Depends(current_user)],
    ) -> dict[str, Any]:
        row = session.get(Assessment, assessment_id)
        if not row:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "assessment not found")
        payload = self_serialize(row)
        payload["counts"] = {
            "assets": session.scalar(select(func.count()).select_from(Asset).where(Asset.assessment_id == assessment_id)),
            "endpoints": session.scalar(select(func.count()).select_from(Endpoint).where(Endpoint.assessment_id == assessment_id)),
            "findings": session.scalar(select(func.count()).select_from(Finding).where(Finding.assessment_id == assessment_id)),
            "attack_paths": session.scalar(select(func.count()).select_from(AttackPath).where(AttackPath.assessment_id == assessment_id)),
        }
        payload["pentest_phases"] = [
            self_serialize(phase)
            for phase in session.scalars(
                select(PentestPhaseProgress)
                .where(PentestPhaseProgress.assessment_id == assessment_id)
                .order_by(PentestPhaseProgress.sequence)
            )
        ]
        return payload

    def assessment_rows(model: Any, assessment_id: str, session: Session) -> list[dict[str, Any]]:
        return [self_serialize(row) for row in session.scalars(select(model).where(model.assessment_id == assessment_id))]

    @app.get("/api/v1/assessments/{assessment_id}/assets")
    def assets(assessment_id: str, session: Annotated[Session, Depends(db_session)], _user: Annotated[User, Depends(current_user)]) -> list[dict[str, Any]]:
        return assessment_rows(Asset, assessment_id, session)

    @app.get("/api/v1/assessments/{assessment_id}/endpoints")
    def endpoints(assessment_id: str, session: Annotated[Session, Depends(db_session)], _user: Annotated[User, Depends(current_user)]) -> list[dict[str, Any]]:
        return assessment_rows(Endpoint, assessment_id, session)

    @app.get("/api/v1/assessments/{assessment_id}/technologies")
    def technologies(assessment_id: str, session: Annotated[Session, Depends(db_session)], _user: Annotated[User, Depends(current_user)]) -> list[dict[str, Any]]:
        return assessment_rows(Technology, assessment_id, session)

    @app.get("/api/v1/assessments/{assessment_id}/reconnaissance")
    def reconnaissance(assessment_id: str, session: Annotated[Session, Depends(db_session)], _user: Annotated[User, Depends(current_user)]) -> dict[str, Any]:
        return {
            "assets": assessment_rows(Asset, assessment_id, session),
            "technologies": assessment_rows(Technology, assessment_id, session),
        }

    @app.get("/api/v1/assessments/{assessment_id}/pentest-phases")
    def pentest_phases(assessment_id: str, session: Annotated[Session, Depends(db_session)], _user: Annotated[User, Depends(current_user)]) -> list[dict[str, Any]]:
        rows = session.scalars(
            select(PentestPhaseProgress)
            .where(PentestPhaseProgress.assessment_id == assessment_id)
            .order_by(PentestPhaseProgress.sequence)
        )
        return [self_serialize(row) for row in rows]

    @app.get("/api/v1/assessments/{assessment_id}/owasp-coverage")
    def assessment_owasp_coverage(assessment_id: str, session: Annotated[Session, Depends(db_session)], _user: Annotated[User, Depends(current_user)]) -> list[dict[str, Any]]:
        rows = session.scalars(
            select(AssessmentCoverage)
            .where(AssessmentCoverage.assessment_id == assessment_id)
            .order_by(AssessmentCoverage.category)
        )
        return [self_serialize(row) for row in rows]

    @app.get("/api/v1/assessments/{assessment_id}/findings")
    def findings(
        assessment_id: str,
        session: Annotated[Session, Depends(db_session)],
        _user: Annotated[User, Depends(current_user)],
        severity: str | None = None,
        status_filter: str | None = Query(default=None, alias="status"),
    ) -> list[dict[str, Any]]:
        query = select(Finding).where(Finding.assessment_id == assessment_id).order_by(Finding.priority_score.desc())
        if severity:
            query = query.where(Finding.severity == severity)
        if status_filter:
            query = query.where(Finding.status == status_filter)
        return [self_serialize(row) for row in session.scalars(query)]

    @app.get("/api/v1/findings/{finding_id}/evidence")
    def finding_evidence(finding_id: str, session: Annotated[Session, Depends(db_session)], _user: Annotated[User, Depends(current_user)]) -> list[dict[str, Any]]:
        rows = session.scalars(select(Evidence).where(Evidence.finding_id == finding_id))
        return [{**self_serialize(row), "payload": row.payload if not row.sensitive else {"redacted": True}} for row in rows]

    @app.get("/api/v1/assessments/{assessment_id}/attack-paths")
    def attack_paths(assessment_id: str, session: Annotated[Session, Depends(db_session)], _user: Annotated[User, Depends(current_user)]) -> list[dict[str, Any]]:
        return assessment_rows(AttackPath, assessment_id, session)

    @app.get("/api/v1/attack-paths/{path_id}")
    def attack_path_detail(path_id: str, session: Annotated[Session, Depends(db_session)], _user: Annotated[User, Depends(current_user)]) -> dict[str, Any]:
        path = session.get(AttackPath, path_id)
        if not path:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "attack path not found")
        payload = self_serialize(path)
        payload["nodes"] = [self_serialize(row) for row in session.scalars(select(AttackPathNode).where(AttackPathNode.attack_path_id == path_id))]
        payload["edges"] = [self_serialize(row) for row in session.scalars(select(AttackPathEdge).where(AttackPathEdge.attack_path_id == path_id))]
        payload["post_exploitation_steps"] = [
            self_serialize(row)
            for row in session.scalars(
                select(PostExploitationStep)
                .where(PostExploitationStep.attack_path_id == path_id)
                .order_by(PostExploitationStep.sequence)
            )
        ]
        return payload

    @app.get("/api/v1/assessments/{assessment_id}/post-exploitation")
    def post_exploitation(assessment_id: str, session: Annotated[Session, Depends(db_session)], _user: Annotated[User, Depends(current_user)]) -> list[dict[str, Any]]:
        rows = session.scalars(
            select(PostExploitationStep)
            .where(PostExploitationStep.assessment_id == assessment_id)
            .order_by(PostExploitationStep.attack_path_id, PostExploitationStep.sequence)
        )
        return [self_serialize(row) for row in rows]

    @app.get("/api/v1/manual-review")
    def manual_review(
        session: Annotated[Session, Depends(db_session)],
        _user: Annotated[User, Depends(current_user)],
        status_filter: str | None = Query(default=None, alias="status"),
    ) -> list[dict[str, Any]]:
        query = select(ManualReviewItem).order_by(ManualReviewItem.created_at)
        if status_filter:
            query = query.where(ManualReviewItem.status == status_filter)
        return [self_serialize(row) for row in session.scalars(query)]

    @app.patch("/api/v1/manual-review/{review_id}")
    def update_manual_review(
        review_id: str,
        payload: ManualReviewUpdate,
        session: Annotated[Session, Depends(db_session)],
        _user: Annotated[User, Depends(roles(RoleName.ADMIN, RoleName.ANALYST))],
    ) -> dict[str, Any]:
        row = session.get(ManualReviewItem, review_id)
        if not row:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "review item not found")
        if payload.status not in {"open", "in_progress", "confirmed", "dismissed", "resolved"}:
            raise HTTPException(422, "invalid review status")
        row.status = payload.status
        row.resolution = payload.resolution
        row.assigned_to_id = payload.assigned_to_id
        return self_serialize(row)

    @app.get("/api/v1/plugins")
    def plugins(_user: Annotated[User, Depends(current_user)]) -> list[dict[str, Any]]:
        return [
            {
                "name": plugin.name,
                "description": plugin.description,
                "requires": sorted(plugin.requires),
                "produces": sorted(plugin.produces),
                "owasp": plugin.owasp,
                "cwe": plugin.cwe,
                "external_tool": plugin.external_tool,
                "phase": plugin.phase.value,
                "stage": plugin.stage,
                "security_question": plugin.security_question,
            }
            for plugin in engine.registry.all()
        ]

    @app.get("/api/v1/plugin-health")
    def plugin_health(session: Annotated[Session, Depends(db_session)], _user: Annotated[User, Depends(current_user)], limit: int = Query(default=500, ge=1, le=5000)) -> list[dict[str, Any]]:
        return [self_serialize(row) for row in session.scalars(select(PluginExecution).order_by(PluginExecution.started_at.desc()).limit(limit))]

    @app.get("/api/v1/metrics")
    def metrics(session: Annotated[Session, Depends(db_session)], _user: Annotated[User, Depends(current_user)], assessment_id: str | None = None) -> list[dict[str, Any]]:
        query = select(ScanMetric).order_by(ScanMetric.recorded_at.desc())
        if assessment_id:
            query = query.where(ScanMetric.assessment_id == assessment_id)
        return [self_serialize(row) for row in session.scalars(query)]

    @app.get("/api/v1/owasp-coverage")
    def owasp_coverage(_user: Annotated[User, Depends(current_user)]) -> list[dict[str, Any]]:
        return coverage_matrix()

    @app.get("/api/v1/mitre-attack")
    def mitre_attack(_user: Annotated[User, Depends(current_user)]) -> list[dict[str, object]]:
        return attack_catalog()

    @app.post("/api/v1/assessments/{assessment_id}/reports", status_code=201)
    def create_report(
        assessment_id: str,
        payload: ReportRequest,
        session: Annotated[Session, Depends(db_session)],
        _user: Annotated[User, Depends(roles(RoleName.ADMIN, RoleName.ANALYST))],
    ) -> dict[str, Any]:
        if payload.report_type not in {"pdf", "xlsx"}:
            raise HTTPException(422, "report_type must be pdf or xlsx")
        if not session.get(Assessment, assessment_id):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "assessment not found")
        output_root = config.report_output_directory.resolve()
        directory = Path(payload.output_directory).resolve() if payload.output_directory else output_root
        if directory != output_root and output_root not in directory.parents:
            raise HTTPException(
                422,
                f"report output must remain under {output_root}",
            )
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"wraith-{assessment_id}.{payload.report_type}"
        generator = PDFReportGenerator() if payload.report_type == "pdf" else ExcelReportGenerator()
        generator.generate(session, assessment_id, path)
        import hashlib

        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        report = Report(assessment_id=assessment_id, report_type=payload.report_type, path=str(path), sha256=digest, size_bytes=path.stat().st_size)
        session.add(report)
        session.flush()
        return self_serialize(report)

    @app.get("/api/v1/reports/{report_id}/download")
    def download_report(report_id: str, session: Annotated[Session, Depends(db_session)], _user: Annotated[User, Depends(current_user)]) -> FileResponse:
        report = session.get(Report, report_id)
        if not report or not Path(report.path).is_file():
            raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
        return FileResponse(report.path, filename=Path(report.path).name)

    return app


def self_serialize(row: Any) -> dict[str, Any]:
    return {
        attribute.columns[0].name: _serialize_value(getattr(row, attribute.key))
        for attribute in row.__mapper__.column_attrs
        if attribute.columns[0].name not in {"password_hash", "token_hash", "csrf_hash"}
    }


def _serialize_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return "[REDACTED]"
    return value


def _origin(url: str) -> str:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    port = parts.port
    default = (parts.scheme == "http" and port in {None, 80}) or (parts.scheme == "https" and port in {None, 443})
    return f"{parts.scheme}://{parts.hostname}" + ("" if default else f":{port}")


def url_host(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).hostname or url


app = None
