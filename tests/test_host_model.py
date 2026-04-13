"""Tests for Host model methods — pure unit tests, no DB required."""

from unittest.mock import AsyncMock, patch

from gny.models.host import Host


def _host(
    ptr_record: str | None,
    ip_address: str = "1.2.3.4",
    allowed_names: list[str] | None = None,
) -> Host:
    return Host(
        ptr_record=ptr_record,
        ip_address=ip_address,
        allowed_names=allowed_names or [],
    )


def _dns(ptr: str | None = "host.example.com", a: list[str] | None = None):
    """Return a pair of patches for DNS lookups used inside Host.allows_name."""
    return (
        patch(
            "gny.models.host.get_unique_ptr_record",
            new=AsyncMock(return_value=ptr),
        ),
        patch(
            "gny.models.host.get_a_records",
            new=AsyncMock(return_value=a or []),
        ),
    )


class TestAllowsName:
    # --- Failures that don't need DNS ---

    async def test_none_ptr_denied(self):
        reason = await _host(None).check_name("_acme-challenge.host.example.com")
        assert reason is not None

    async def test_no_acme_prefix_denied(self):
        reason = await _host("host.example.com").check_name("host.example.com")
        assert reason is not None

    # --- PTR liveness checks ---

    async def test_ptr_changed_denied(self):
        p, a = _dns(ptr="other.example.com")
        with p, a:
            reason = await _host("host.example.com").check_name(
                "_acme-challenge.host.example.com"
            )
        assert reason is not None

    async def test_ptr_unavailable_denied(self):
        p, a = _dns(ptr=None)
        with p, a:
            reason = await _host("host.example.com").check_name(
                "_acme-challenge.host.example.com"
            )
        assert reason is not None

    # --- Allowed via PTR match ---

    async def test_exact_ptr_match_allowed(self):
        p, a = _dns()
        with p, a:
            reason = await _host("host.example.com").check_name(
                "_acme-challenge.host.example.com"
            )
        assert reason is None

    async def test_case_insensitive_allowed(self):
        p, a = _dns()
        with p, a:
            reason = await _host("host.example.com").check_name(
                "_acme-challenge.HOST.EXAMPLE.COM"
            )
        assert reason is None

    async def test_trailing_dot_stripped(self):
        p, a = _dns()
        with p, a:
            reason = await _host("host.example.com").check_name(
                "_acme-challenge.host.example.com."
            )
        assert reason is None

    # --- Denied: not PTR, no A record, no glob ---

    async def test_unrelated_domain_denied(self):
        p, a = _dns(a=[])
        with p, a:
            reason = await _host("host.example.com").check_name(
                "_acme-challenge.evil.com"
            )
        assert reason is not None

    async def test_partial_suffix_denied(self):
        # "nothost.example.com" must NOT match ptr "host.example.com"
        p, a = _dns(a=[])
        with p, a:
            reason = await _host("host.example.com").check_name(
                "_acme-challenge.nothost.example.com"
            )
        assert reason is not None

    # --- Allowed via A record ---

    async def test_a_record_pointing_to_host_allowed(self):
        p, a = _dns(a=["1.2.3.4"])
        with p, a:
            reason = await _host("host.example.com").check_name(
                "_acme-challenge.other.example.com"
            )
        assert reason is None

    async def test_a_record_different_ip_denied(self):
        p, a = _dns(a=["9.9.9.9"])
        with p, a:
            reason = await _host("host.example.com").check_name(
                "_acme-challenge.other.example.com"
            )
        assert reason is not None

    # --- Allowed via allowed_names glob ---

    async def test_glob_exact_match_allowed(self):
        p, a = _dns(a=[])
        with p, a:
            reason = await _host(
                "host.example.com", allowed_names=["other.example.com"]
            ).check_name("_acme-challenge.other.example.com")
        assert reason is None

    async def test_glob_wildcard_match_allowed(self):
        p, a = _dns(a=[])
        with p, a:
            reason = await _host(
                "host.example.com", allowed_names=["*.example.com"]
            ).check_name("_acme-challenge.anything.example.com")
        assert reason is None

    async def test_glob_no_match_denied(self):
        p, a = _dns(a=[])
        with p, a:
            reason = await _host(
                "host.example.com", allowed_names=["*.example.com"]
            ).check_name("_acme-challenge.evil.org")
        assert reason is not None

    async def test_empty_allowed_names_denied(self):
        p, a = _dns(a=[])
        with p, a:
            reason = await _host("host.example.com", allowed_names=[]).check_name(
                "_acme-challenge.other.example.com"
            )
        assert reason is not None
