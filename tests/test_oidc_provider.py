"""Tests for gny.oidc_provider — mock httpx calls, no real network needed."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

import gny.oidc_provider as oidc_module
from gny.oidc_provider import get_provider_config, get_userinfo


def _make_response(status_code: int, json_body: dict) -> httpx.Response:
    return httpx.Response(status_code, json=json_body)


@pytest.fixture(autouse=True)
def reset_provider_cache():
    """Ensure the module-level cache is cleared between tests."""
    oidc_module._provider_config = None
    yield
    oidc_module._provider_config = None


# ---------------------------------------------------------------------------
# get_provider_config
# ---------------------------------------------------------------------------


class TestGetProviderConfig:
    async def test_fetches_and_caches_metadata(self):
        metadata = {
            "userinfo_endpoint": "https://example.com/userinfo",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
        }

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=_make_response(200, metadata))

        with patch("gny.oidc_provider.httpx.AsyncClient", return_value=mock_client):
            result1 = await get_provider_config()
            _ = await get_provider_config()  # cached

        assert result1 == metadata
        # Second call should NOT trigger another HTTP request (cache hit)
        assert mock_client.get.call_count == 1

    async def test_raises_503_on_http_error(self):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=_make_response(500, {}))

        with patch("gny.oidc_provider.httpx.AsyncClient", return_value=mock_client):
            from fastapi import HTTPException

            with pytest.raises(HTTPException) as exc_info:
                await get_provider_config()

        assert exc_info.value.status_code == 503


# ---------------------------------------------------------------------------
# get_userinfo
# ---------------------------------------------------------------------------


class TestGetUserinfo:
    def _setup_provider(self, userinfo_response: dict, userinfo_status: int = 200):
        """Patch provider config cache and the userinfo HTTP call."""
        oidc_module._provider_config = {
            "userinfo_endpoint": "https://example.com/userinfo",
        }

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(
            return_value=_make_response(userinfo_status, userinfo_response)
        )
        return mock_client

    async def test_returns_userinfo_on_success(self):
        payload = {
            "sub": "uid123",
            "email": "user@example.com",
            "name": "Test User",
            "email_verified": True,
        }
        mock_client = self._setup_provider(payload)

        with patch("gny.oidc_provider.httpx.AsyncClient", return_value=mock_client):
            info = await get_userinfo("token123")

        assert info.uid == "uid123"
        assert info.email == "user@example.com"
        assert info.name == "Test User"

    async def test_name_falls_back_to_email(self):
        payload = {"sub": "uid123", "email": "user@example.com", "email_verified": True}
        mock_client = self._setup_provider(payload)

        with patch("gny.oidc_provider.httpx.AsyncClient", return_value=mock_client):
            info = await get_userinfo("token123")

        assert info.name == "user@example.com"

    async def test_raises_401_on_userinfo_http_error(self):
        mock_client = self._setup_provider({}, userinfo_status=401)

        with patch("gny.oidc_provider.httpx.AsyncClient", return_value=mock_client):
            from fastapi import HTTPException

            with pytest.raises(HTTPException) as exc_info:
                await get_userinfo("bad_token")

        assert exc_info.value.status_code == 401

    async def test_raises_401_on_missing_sub(self):
        payload = {"email": "user@example.com", "email_verified": True}
        mock_client = self._setup_provider(payload)

        with patch("gny.oidc_provider.httpx.AsyncClient", return_value=mock_client):
            from fastapi import HTTPException

            with pytest.raises(HTTPException) as exc_info:
                await get_userinfo("token123")

        assert exc_info.value.status_code == 401

    async def test_raises_401_on_missing_email(self):
        payload = {"sub": "uid123"}
        mock_client = self._setup_provider(payload)

        with patch("gny.oidc_provider.httpx.AsyncClient", return_value=mock_client):
            from fastapi import HTTPException

            with pytest.raises(HTTPException) as exc_info:
                await get_userinfo("token123")

        assert exc_info.value.status_code == 401

    async def test_raises_403_on_unverified_email(self):
        payload = {
            "sub": "uid123",
            "email": "user@example.com",
            "email_verified": False,
        }
        mock_client = self._setup_provider(payload)

        with patch("gny.oidc_provider.httpx.AsyncClient", return_value=mock_client):
            from fastapi import HTTPException

            with pytest.raises(HTTPException) as exc_info:
                await get_userinfo("token123")

        assert exc_info.value.status_code == 403

    async def test_absent_email_verified_treated_as_true(self):
        """Azure AD omits email_verified — should be accepted."""
        payload = {"sub": "uid123", "email": "user@example.com", "name": "Azure User"}
        mock_client = self._setup_provider(payload)

        with patch("gny.oidc_provider.httpx.AsyncClient", return_value=mock_client):
            info = await get_userinfo("token123")

        assert info.uid == "uid123"

    async def test_missing_userinfo_endpoint_raises_503(self):
        oidc_module._provider_config = {}  # no userinfo_endpoint key

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await get_userinfo("token123")

        assert exc_info.value.status_code == 503
