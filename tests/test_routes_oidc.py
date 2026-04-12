"""Tests for gny.routes.oidc — GET /api/enroll/start and GET /.well-known/sso."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import gny.oidc_provider as oidc_module
from gny.models import Enrollment, Host, User
from gny.oidc_provider import UserInfo

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PROVIDER_CONFIG = {
    "authorization_endpoint": "https://provider.example.com/auth",
    "token_endpoint": "https://provider.example.com/token",
    "userinfo_endpoint": "https://provider.example.com/userinfo",
}


def _make_http_response(status_code: int, json_body: dict) -> httpx.Response:
    return httpx.Response(status_code, json=json_body)


def _make_user(access_level: int = 1) -> User:
    return User(
        id=1,
        uid="admin-uid",
        name="Admin",
        mail="admin@example.com",
        access_level=access_level,
    )


@pytest.fixture(autouse=True)
def reset_provider_cache():
    oidc_module._provider_config = None
    yield
    oidc_module._provider_config = None


# ---------------------------------------------------------------------------
# GET /api/enroll/start
# ---------------------------------------------------------------------------


class TestEnrollStart:
    async def test_redirects_to_provider(self, client):
        oidc_module._provider_config = _PROVIDER_CONFIG

        resp = await client.get(
            "/api/enroll/start",
            params={"token": "gny-enrolltoken"},
            follow_redirects=False,
        )

        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "provider.example.com/auth" in location
        assert "gny-enrolltoken" in location

    async def test_raises_503_when_auth_url_missing(self, client):
        oidc_module._provider_config = {}  # no authorization_endpoint

        resp = await client.get(
            "/api/enroll/start",
            params={"token": "gny-enrolltoken"},
        )

        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# GET /.well-known/sso  (oidc_callback)
# ---------------------------------------------------------------------------


class TestOidcCallback:
    def _mock_http_client(
        self, token_status: int = 200, token_body: dict | None = None
    ):
        """Return a mock httpx.AsyncClient for the token-exchange step."""
        if token_body is None:
            token_body = {"access_token": "access-tok"}
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(
            return_value=_make_http_response(token_status, token_body)
        )
        return mock_client

    def _mock_session(
        self,
        enrollment: Enrollment | None = None,
        existing_host: Host | None = None,
        user: User | None = None,
    ):
        """Return a mock AsyncSession usable as an async context manager.

        First execute() call returns the enrollment; second returns the host
        (for the Host upsert in the confirmation path).
        """
        mock_db = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        enrollment_result = MagicMock()
        enrollment_result.scalar_one_or_none.return_value = enrollment

        host_result = MagicMock()
        host_result.scalar_one_or_none.return_value = existing_host

        mock_db.execute = AsyncMock(side_effect=[enrollment_result, host_result])
        mock_db.add = MagicMock()
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()
        return mock_db

    # -- error parameter -------------------------------------------------------

    async def test_error_param_returns_400(self, client):
        resp = await client.get("/.well-known/sso", params={"error": "access_denied"})
        assert resp.status_code == 400

    # -- missing code / state --------------------------------------------------

    async def test_missing_code_returns_400(self, client):
        resp = await client.get("/.well-known/sso", params={"state": "tok"})
        assert resp.status_code == 400

    async def test_missing_state_returns_400(self, client):
        resp = await client.get("/.well-known/sso", params={"code": "authcode"})
        assert resp.status_code == 400

    # -- missing token_endpoint -----------------------------------------------

    async def test_missing_token_endpoint_returns_503(self, client):
        oidc_module._provider_config = {"userinfo_endpoint": "https://x.com/u"}

        resp = await client.get("/.well-known/sso", params={"code": "c", "state": "s"})
        assert resp.status_code == 503

    # -- token exchange failure ------------------------------------------------

    async def test_token_exchange_failure_returns_401(self, client):
        oidc_module._provider_config = _PROVIDER_CONFIG
        mock_http = self._mock_http_client(token_status=400, token_body={})

        with patch("gny.routes.oidc.httpx.AsyncClient", return_value=mock_http):
            resp = await client.get(
                "/.well-known/sso", params={"code": "c", "state": "s"}
            )

        assert resp.status_code == 401

    # -- no access_token in response ------------------------------------------

    async def test_missing_access_token_returns_401(self, client):
        oidc_module._provider_config = _PROVIDER_CONFIG
        mock_http = self._mock_http_client(token_body={})  # no access_token

        with patch("gny.routes.oidc.httpx.AsyncClient", return_value=mock_http):
            resp = await client.get(
                "/.well-known/sso", params={"code": "c", "state": "s"}
            )

        assert resp.status_code == 401

    # -- insufficient access level --------------------------------------------

    async def test_insufficient_access_level_returns_403(self, client, db_session):
        oidc_module._provider_config = _PROVIDER_CONFIG
        mock_http = self._mock_http_client()
        user_info = UserInfo(uid="uid1", name="Low", email="low@example.com")
        low_user = _make_user(access_level=0)

        mock_db = self._mock_session(enrollment=None)

        with (
            patch("gny.routes.oidc.httpx.AsyncClient", return_value=mock_http),
            patch("gny.routes.oidc.get_userinfo", return_value=user_info),
            patch("gny.routes.oidc.upsert_user", return_value=low_user),
            patch("gny.routes.oidc.SessionLocal", return_value=mock_db),
        ):
            resp = await client.get(
                "/.well-known/sso", params={"code": "c", "state": "gny-tok"}
            )

        assert resp.status_code == 403

    # -- invalid enrollment token in state ------------------------------------

    async def test_invalid_enrollment_token_returns_400(self, client):
        oidc_module._provider_config = _PROVIDER_CONFIG
        mock_http = self._mock_http_client()
        user_info = UserInfo(uid="uid1", name="Admin", email="admin@example.com")
        admin_user = _make_user(access_level=1)
        mock_db = self._mock_session(enrollment=None)  # enrollment not found

        with (
            patch("gny.routes.oidc.httpx.AsyncClient", return_value=mock_http),
            patch("gny.routes.oidc.get_userinfo", return_value=user_info),
            patch("gny.routes.oidc.upsert_user", return_value=admin_user),
            patch("gny.routes.oidc.SessionLocal", return_value=mock_db),
        ):
            resp = await client.get(
                "/.well-known/sso", params={"code": "c", "state": "gny-invalid"}
            )

        assert resp.status_code == 400

    # -- success (enrollment not yet confirmed) --------------------------------

    async def test_confirms_enrollment_on_success(self, client):
        oidc_module._provider_config = _PROVIDER_CONFIG
        mock_http = self._mock_http_client()
        user_info = UserInfo(uid="uid1", name="Admin", email="admin@example.com")
        admin_user = _make_user(access_level=1)

        enrollment = Enrollment(
            id=10,
            mail="host@example.com",
            token=Enrollment.hash_token("gny-tok"),
            ip_address="1.2.3.4",
            ptr_record="host.example.com",
        )
        # No existing Host for this IP → will create one
        mock_db = self._mock_session(enrollment=enrollment, existing_host=None)

        with (
            patch("gny.routes.oidc.httpx.AsyncClient", return_value=mock_http),
            patch("gny.routes.oidc.get_userinfo", return_value=user_info),
            patch("gny.routes.oidc.upsert_user", return_value=admin_user),
            patch("gny.routes.oidc.SessionLocal", return_value=mock_db),
        ):
            resp = await client.get(
                "/.well-known/sso", params={"code": "c", "state": "gny-tok"}
            )

        assert resp.status_code == 200
        assert "Host confirmed" in resp.text
        assert "admin@example.com" in resp.text
        assert enrollment.confirmed_at is not None
        mock_db.commit.assert_called_once()

    # -- success (already confirmed — no second commit) -----------------------

    async def test_already_confirmed_enrollment_no_extra_commit(self, client):
        from datetime import datetime, timezone

        oidc_module._provider_config = _PROVIDER_CONFIG
        mock_http = self._mock_http_client()
        user_info = UserInfo(uid="uid1", name="Admin", email="admin@example.com")
        admin_user = _make_user(access_level=1)

        enrollment = Enrollment(
            id=11,
            mail="host@example.com",
            token=Enrollment.hash_token("gny-tok2"),
            ip_address="1.2.3.4",
            ptr_record="host.example.com",
            confirmed_at=datetime.now(timezone.utc),
        )
        # Only one execute call expected (enrollment lookup); host lookup never reached
        mock_db = self._mock_session(enrollment=enrollment)

        with (
            patch("gny.routes.oidc.httpx.AsyncClient", return_value=mock_http),
            patch("gny.routes.oidc.get_userinfo", return_value=user_info),
            patch("gny.routes.oidc.upsert_user", return_value=admin_user),
            patch("gny.routes.oidc.SessionLocal", return_value=mock_db),
        ):
            resp = await client.get(
                "/.well-known/sso", params={"code": "c2", "state": "gny-tok2"}
            )

        assert resp.status_code == 200
        # No commit should be triggered when enrollment was already confirmed
        mock_db.commit.assert_not_called()
