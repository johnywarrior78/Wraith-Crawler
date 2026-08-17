from __future__ import annotations

import pytest

from wraith_crawler.enums import RoleName
from wraith_crawler.services.auth import AuthenticationError, AuthService


def test_create_authenticate_validate_logout(database) -> None:
    auth = AuthService(session_ttl_minutes=10)
    with database.session() as session:
        user = auth.create_user(session, "Analyst.User", "StrongPassword123!", [RoleName.ANALYST])
        tokens = auth.authenticate(session, "analyst.user", "StrongPassword123!")
        assert auth.validate_session(session, tokens.session_token, tokens.csrf_token).id == user.id
        assert auth.validate_session(session, tokens.session_token, "wrong") is None
        auth.logout(session, tokens.session_token)
        assert auth.validate_session(session, tokens.session_token) is None


def test_password_hash_is_argon2id(database) -> None:
    with database.session() as session:
        user = AuthService().create_user(session, "secureuser", "StrongPassword123!", [RoleName.VIEWER])
        assert user.password_hash.startswith("$argon2id$")
        assert "StrongPassword123!" not in user.password_hash


@pytest.mark.parametrize("password", ["short", "alllowercasepassword", "ALLUPPERCASE1234", "NoDigitsOrSymbol"])
def test_weak_password_rejected(database, password: str) -> None:
    with database.session() as session:
        with pytest.raises(ValueError):
            AuthService().create_user(session, "weakuser", password, [RoleName.VIEWER])


def test_duplicate_username_rejected(database) -> None:
    auth = AuthService()
    with database.session() as session:
        auth.create_user(session, "duplicate", "StrongPassword123!", [RoleName.VIEWER])
    with database.session() as session:
        with pytest.raises(ValueError):
            auth.create_user(session, "DUPLICATE", "AnotherStrong123!", [RoleName.VIEWER])


def test_bad_password_is_generic(database) -> None:
    auth = AuthService()
    with database.session() as session:
        auth.create_user(session, "knownuser", "StrongPassword123!", [RoleName.VIEWER])
    with database.session() as session:
        with pytest.raises(AuthenticationError, match="invalid credentials"):
            auth.authenticate(session, "knownuser", "IncorrectPassword123!")


def test_role_enforcement(database) -> None:
    auth = AuthService()
    with database.session() as session:
        viewer = auth.create_user(session, "viewer", "StrongPassword123!", [RoleName.VIEWER])
        auth.require_role(viewer, RoleName.VIEWER)
        with pytest.raises(PermissionError):
            auth.require_role(viewer, RoleName.ADMIN)
