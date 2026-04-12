"""Tests for gny.main — lifespan and generic exception handler."""

import json
from unittest.mock import AsyncMock, patch

from fastapi import Request

from gny.main import app, generic_exception_handler, lifespan


class TestLifespan:
    async def test_lifespan_calls_init_db(self):
        """The lifespan context manager should call init_db on startup."""
        with patch("gny.main.init_db", new_callable=AsyncMock) as mock_init:
            async with lifespan(app):
                pass
        mock_init.assert_called_once()


class TestGenericExceptionHandler:
    async def test_returns_detail_when_display_errors_true(self):
        """With display_errors=true the actual exception message is returned."""
        mock_request = object.__new__(Request)
        exc = ValueError("something went wrong")

        with patch("gny.main.settings") as mock_settings:
            mock_settings.display_errors = "true"
            resp = await generic_exception_handler(mock_request, exc)

        body = json.loads(resp.body)
        assert resp.status_code == 500
        assert body["error"] == "something went wrong"

    async def test_returns_generic_message_when_display_errors_false(self):
        """With display_errors=false the detail is replaced with a generic message."""
        mock_request = object.__new__(Request)
        exc = RuntimeError("internal details")

        with patch("gny.main.settings") as mock_settings:
            mock_settings.display_errors = "false"
            resp = await generic_exception_handler(mock_request, exc)

        body = json.loads(resp.body)
        assert resp.status_code == 500
        assert body["error"] == "Internal server error"

    async def test_display_errors_1_returns_detail(self):
        """'1' is treated as truthy for display_errors."""
        mock_request = object.__new__(Request)
        exc = ValueError("exposed detail")

        with patch("gny.main.settings") as mock_settings:
            mock_settings.display_errors = "1"
            resp = await generic_exception_handler(mock_request, exc)

        body = json.loads(resp.body)
        assert body["error"] == "exposed detail"
