"""Tests for gny.dns_utils — pure unit tests, no DB or network required."""

from unittest.mock import MagicMock, patch

import pytest

from gny.dns_utils import get_a_records, get_ptr_record, get_unique_ptr_record

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


# ---------------------------------------------------------------------------
# get_unique_ptr_record
# ---------------------------------------------------------------------------


class TestGetUniquePtrRecord:
    async def test_returns_hostname_when_single_record(self):
        mock_answer = MagicMock()
        mock_answer.__str__ = lambda self: "host.example.com."

        with patch("gny.dns_utils.dns.resolver.resolve", return_value=[mock_answer]):
            result = await get_unique_ptr_record("1.2.3.4")

        assert result == "host.example.com"

    async def test_returns_none_when_multiple_records(self):
        mock_a = MagicMock()
        mock_a.__str__ = lambda self: "host1.example.com."
        mock_b = MagicMock()
        mock_b.__str__ = lambda self: "host2.example.com."

        with patch("gny.dns_utils.dns.resolver.resolve", return_value=[mock_a, mock_b]):
            result = await get_unique_ptr_record("1.2.3.4")

        assert result is None

    async def test_returns_none_on_no_record(self):
        import dns.resolver

        with patch(
            "gny.dns_utils.dns.resolver.resolve",
            side_effect=dns.resolver.NXDOMAIN(),
        ):
            result = await get_unique_ptr_record("1.2.3.4")

        assert result is None

    async def test_returns_none_on_exception(self):
        with patch(
            "gny.dns_utils.dns.resolver.resolve",
            side_effect=Exception("network error"),
        ):
            result = await get_unique_ptr_record("1.2.3.4")

        assert result is None

    async def test_trailing_dot_stripped(self):
        mock_answer = MagicMock()
        mock_answer.__str__ = lambda self: "host.example.com."

        with patch("gny.dns_utils.dns.resolver.resolve", return_value=[mock_answer]):
            result = await get_unique_ptr_record("1.2.3.4")

        assert result == "host.example.com"


# ---------------------------------------------------------------------------
# get_a_records
# ---------------------------------------------------------------------------


class TestGetARecords:
    async def test_returns_list_of_ips(self):
        mock_a = MagicMock()
        mock_a.__str__ = lambda self: "1.2.3.4"
        mock_b = MagicMock()
        mock_b.__str__ = lambda self: "5.6.7.8"

        with patch("gny.dns_utils.dns.resolver.resolve", return_value=[mock_a, mock_b]):
            result = await get_a_records("host.example.com")

        assert result == ["1.2.3.4", "5.6.7.8"]

    async def test_returns_empty_list_on_no_record(self):
        import dns.resolver

        with patch(
            "gny.dns_utils.dns.resolver.resolve",
            side_effect=dns.resolver.NXDOMAIN(),
        ):
            result = await get_a_records("host.example.com")

        assert result == []

    async def test_returns_empty_list_on_exception(self):
        with patch(
            "gny.dns_utils.dns.resolver.resolve",
            side_effect=Exception("network error"),
        ):
            result = await get_a_records("host.example.com")

        assert result == []
