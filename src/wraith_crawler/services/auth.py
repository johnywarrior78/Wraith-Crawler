from __future__ import annotations

import hashlib
import hmac
import secrets
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..enums import RoleName
from ..persistence.models import AuthSession, Role, User


@dataclass(frozen=True, slots=True)
class SessionTokens:
    session_token: str
    csrf_token: str
    expires_at: datetime


class AuthenticationError(ValueError):
    pass


class AuthService:
    MAX_FAILURES = 5
    LOCK_MINUTES = 15

    def __init__(self, session_ttl_minutes: int = 480) -> None:
        self.hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
        self.session_ttl = timedelta(minutes=session_ttl_minutes)

    @staticmethod
    def normalize_username(username: str) -> str:
        value = unicodedata.normalize("NFKC", username).strip().lower()
        if not 3 <= len(value) <= 128:
            raise ValueError("username must contain 3 to 128 characters")
        if not all(ch.isalnum() or ch in "._-@" for ch in value):
            raise ValueError("username contains unsupported characters")
        return value

    @staticmethod
    def validate_password_strength(password: str) -> None:
        if len(password) < 12:
            raise ValueError("password must contain at least 12 characters")
        classes = [
            any(ch.islower() for ch in password),
            any(ch.isupper() for ch in password),
            any(ch.isdigit() for ch in password),
            any(not ch.isalnum() for ch in password),
        ]
        if sum(classes) < 3:
            raise ValueError("password must use at least three character classes")

    def bootstrap_roles(self, session: Session) -> None:
        existing = {role.name for role in session.scalars(select(Role)).all()}
        descriptions = {
            RoleName.ADMIN: "Full platform administration",
            RoleName.ANALYST: "Run assessments and review findings",
            RoleName.VIEWER: "Read-only assessment and reporting access",
        }
        for name, description in descriptions.items():
            if name.value not in existing:
                session.add(Role(name=name.value, description=description))
        session.flush()

    def create_user(
        self, session: Session, username: str, password: str, roles: list[RoleName]
    ) -> User:
        username = self.normalize_username(username)
        self.validate_password_strength(password)
        if session.scalar(select(User).where(User.username == username)):
            raise ValueError("username already exists")
        self.bootstrap_roles(session)
        role_rows = session.scalars(select(Role).where(Role.name.in_([r.value for r in roles]))).all()
        user = User(username=username, password_hash=self.hasher.hash(password), roles=list(role_rows))
        session.add(user)
        session.flush()
        return user

    def authenticate(self, session: Session, username: str, password: str) -> SessionTokens:
        try:
            normalized = self.normalize_username(username)
        except ValueError as exc:
            raise AuthenticationError("invalid credentials") from exc
        user = session.scalar(select(User).where(User.username == normalized))
        now = datetime.now(UTC)
        if not user or not user.active:
            self._constant_time_dummy_verify(password)
            raise AuthenticationError("invalid credentials")
        if user.locked_until and self._as_aware(user.locked_until) > now:
            raise AuthenticationError("account temporarily locked")
        try:
            self.hasher.verify(user.password_hash, password)
        except (VerifyMismatchError, InvalidHashError) as exc:
            user.failed_login_count += 1
            if user.failed_login_count >= self.MAX_FAILURES:
                user.locked_until = now + timedelta(minutes=self.LOCK_MINUTES)
                user.failed_login_count = 0
            session.flush()
            raise AuthenticationError("invalid credentials") from exc
        if self.hasher.check_needs_rehash(user.password_hash):
            user.password_hash = self.hasher.hash(password)
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        return self._new_session(session, user)

    def _new_session(self, session: Session, user: User) -> SessionTokens:
        token = secrets.token_urlsafe(48)
        csrf = secrets.token_urlsafe(32)
        expires = datetime.now(UTC) + self.session_ttl
        session.add(
            AuthSession(
                user_id=user.id,
                token_hash=self._digest(token),
                csrf_hash=self._digest(csrf),
                expires_at=expires,
            )
        )
        session.flush()
        return SessionTokens(token, csrf, expires)

    def validate_session(
        self, session: Session, token: str, csrf_token: str | None = None
    ) -> User | None:
        row = session.scalar(select(AuthSession).where(AuthSession.token_hash == self._digest(token)))
        now = datetime.now(UTC)
        if not row or row.revoked_at or self._as_aware(row.expires_at) <= now or not row.user.active:
            return None
        if csrf_token is not None and not hmac.compare_digest(row.csrf_hash, self._digest(csrf_token)):
            return None
        row.last_seen_at = now
        return row.user

    def logout(self, session: Session, token: str) -> None:
        row = session.scalar(select(AuthSession).where(AuthSession.token_hash == self._digest(token)))
        if row and not row.revoked_at:
            row.revoked_at = datetime.now(UTC)

    @staticmethod
    def require_role(user: User, *allowed: RoleName) -> None:
        names = {role.name for role in user.roles}
        if not names.intersection(role.value for role in allowed):
            raise PermissionError("insufficient role")

    @staticmethod
    def purge_expired(session: Session) -> int:
        return session.execute(delete(AuthSession).where(AuthSession.expires_at < datetime.now(UTC))).rowcount

    def _constant_time_dummy_verify(self, password: str) -> None:
        dummy = "$argon2id$v=19$m=65536,t=3,p=4$MDEyMzQ1Njc4OWFiY2RlZg$58XbZun52f+8P6sHk5KjQjAMNaOiPLex4Sp3r9L8LhI"
        try:
            self.hasher.verify(dummy, password)
        except Exception:
            return

    @staticmethod
    def _digest(value: str) -> bytes:
        return hashlib.sha256(value.encode()).digest()

    @staticmethod
    def _as_aware(value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=UTC)
