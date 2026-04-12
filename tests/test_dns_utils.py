"""Tests for gny.dns_utils — pure unit tests, no DB or network required."""

from unittest.mock import MagicMock, patch

import pytest

from gny.dns_utils import get_ptr_record

# ---------------------------------------------------------------------------
# get_ptr_record
# ---------------------------------------------------------------------------


class TestGetPtrRecord:
    @pytest.mark.asyncio
    async def test_returns_hostname_on_success(self):
        mock_answer = MagicMock()
        mock_answer.__str__ = lambda self: "host.example.com."

        with patch("gny.dns_utils.dns.resolver.resolve", return_value=[mock_answer]):
            result = await get_ptr_record("1.2.3.4")

        assert result == "host.example.com"

    @pytest.mark.asyncio
    async def test_returns_none_on_no_record(self):
        import dns.resolver

        with patch(
            "gny.dns_utils.dns.resolver.resolve",
            side_effect=dns.resolver.NXDOMAIN(),
        ):
            result = await get_ptr_record("1.2.3.4")

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_exception(self):
        with patch(
            "gny.dns_utils.dns.resolver.resolve",
            side_effect=Exception("network error"),
        ):
            result = await get_ptr_record("1.2.3.4")

        assert result is None
