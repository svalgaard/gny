"""Tests for gny.routes.oidc — GET /login, GET /.well-known/sso, GET /logout."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

import gny.oidc_provider as oidc_module
from gny.models import User
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
# GET /login
# ---------------------------------------------------------------------------


class TestLogin:
    async def test_redirects_to_provider(self, client):
        oidc_module._provider_config = _PROVIDER_CONFIG

        resp = await client.get("/login", follow_redirects=False)

        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "provider.example.com/auth" in location
        assert "login%3A" in location or "login:" in location
        # login_nonce cookie must be set
        assert "login_nonce" in resp.cookies

    async def test_raises_503_when_auth_url_missing(self, client):
        oidc_module._provider_config = {}  # no authorization_endpoint

        resp = await client.get("/login")

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

    # -- error parameter -------------------------------------------------------

    async def test_error_param_returns_400(self, client):
        resp = await client.get("/.well-known/sso", params={"error": "access_denied"})
        assert resp.status_code == 400

    # -- missing code / state --------------------------------------------------

    async def test_missing_code_returns_400(self, client):
        resp = await client.get("/.well-known/sso", params={"state": "login:nonce"})
        assert resp.status_code == 400

    async def test_missing_state_returns_400(self, client):
        resp = await client.get("/.well-known/sso", params={"code": "authcode"})
        assert resp.status_code == 400

    # -- invalid state format --------------------------------------------------

    async def test_invalid_state_format_returns_400(self, client):
        resp = await client.get(
            "/.well-known/sso", params={"code": "c", "state": "gny-oldtoken"}
        )
        assert resp.status_code == 400

    # -- nonce mismatch --------------------------------------------------------

    async def test_wrong_nonce_returns_400(self, client):
        client.cookies.set("login_nonce", "wrongnonce")
        resp = await client.get(
            "/.well-known/sso",
            params={"code": "c", "state": "login:correctnonce"},
        )
        assert resp.status_code == 400

    async def test_missing_nonce_cookie_returns_400(self, client):
        resp = await client.get(
            "/.well-known/sso",
            params={"code": "c", "state": "login:somenonce"},
        )
        assert resp.status_code == 400

    # -- missing token_endpoint ------------------------------------------------

    async def test_missing_token_endpoint_returns_503(self, client):
        oidc_module._provider_config = {"userinfo_endpoint": "https://x.com/u"}

        client.cookies.set("login_nonce", "testnonce")
        resp = await client.get(
            "/.well-known/sso",
            params={"code": "c", "state": "login:testnonce"},
        )
        assert resp.status_code == 503

    # -- token exchange failure ------------------------------------------------

    async def test_token_exchange_failure_returns_401(self, client):
        oidc_module._provider_config = _PROVIDER_CONFIG
        mock_http = self._mock_http_client(token_status=400, token_body={})

        client.cookies.set("login_nonce", "testnonce")
        with patch("gny.routes.oidc.httpx.AsyncClient", return_value=mock_http):
            resp = await client.get(
                "/.well-known/sso",
                params={"code": "c", "state": "login:testnonce"},
            )

        assert resp.status_code == 401

    # -- no access_token in response ------------------------------------------

    async def test_missing_access_token_returns_401(self, client):
        oidc_module._provider_config = _PROVIDER_CONFIG
        mock_http = self._mock_http_client(token_body={})  # no access_token

        client.cookies.set("login_nonce", "testnonce")
        with patch("gny.routes.oidc.httpx.AsyncClient", return_value=mock_http):
            resp = await client.get(
                "/.well-known/sso",
                params={"code": "c", "state": "login:testnonce"},
            )

        assert resp.status_code == 401

    # -- successful login creates session and redirects -----------------------

    async def test_login_creates_session_and_redirects(self, client):
        oidc_module._provider_config = _PROVIDER_CONFIG
        mock_http = self._mock_http_client()
        user_info = UserInfo(uid="uid1", name="Admin", email="admin@example.com")
        admin_user = _make_user(access_level=1)

        client.cookies.set("login_nonce", "testnonce")
        with (
            patch("gny.routes.oidc.httpx.AsyncClient", return_value=mock_http),
            patch("gny.routes.oidc.get_userinfo", return_value=user_info),
            patch("gny.routes.oidc.upsert_user", return_value=admin_user),
        ):
            resp = await client.get(
                "/.well-known/sso",
                params={"code": "c", "state": "login:testnonce"},
                follow_redirects=False,
            )

        assert resp.status_code == 302
        assert resp.headers["location"] == "/"
        assert "session_id" in resp.cookies


# ---------------------------------------------------------------------------
# GET /logout
# ---------------------------------------------------------------------------


class TestLogout:
    async def test_logout_redirects_to_login(self, client):
        resp = await client.get("/logout", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]

    async def test_logout_clears_session_cookie(self, client):
        resp = await client.get("/logout", follow_redirects=False)
        # Cookie should be cleared (set to empty / max-age=0)
        assert resp.cookies.get("session_id", "") == ""
