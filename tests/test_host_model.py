"""Tests for Host model methods — pure unit tests, no DB required."""

from gny.models.host import Host


def _host(ptr_record: str | None) -> Host:
    return Host(ptr_record=ptr_record)


class TestAllowsName:
    def test_exact_match(self):
        assert _host("host.example.com").allows_name("host.example.com") is True

    def test_subdomain_allowed(self):
        assert _host("host.example.com").allows_name("sub.host.example.com") is True

    def test_unrelated_domain_denied(self):
        assert _host("host.example.com").allows_name("evil.com") is False

    def test_acme_challenge_prefix_stripped(self):
        assert (
            _host("host.example.com").allows_name("_acme-challenge.host.example.com")
            is True
        )

    def test_acme_challenge_subdomain_allowed(self):
        assert (
            _host("host.example.com").allows_name(
                "_acme-challenge.sub.host.example.com"
            )
            is True
        )

    def test_acme_challenge_wrong_domain_denied(self):
        assert (
            _host("host.example.com").allows_name("_acme-challenge.evil.com") is False
        )

    def test_trailing_dot_stripped(self):
        assert _host("host.example.com").allows_name("host.example.com.") is True

    def test_case_insensitive(self):
        assert _host("host.example.com").allows_name("HOST.EXAMPLE.COM") is True

    def test_none_ptr_denied(self):
        assert _host(None).allows_name("host.example.com") is False

    def test_partial_suffix_not_allowed(self):
        # "nothost.example.com" should NOT match ptr "host.example.com"
        assert _host("host.example.com").allows_name("nothost.example.com") is False

    def test_acme_exact_ptr_match(self):
        # _acme-challenge.host.example.com with ptr=host.example.com → domain == ptr
        assert (
            _host("host.example.com").allows_name("_acme-challenge.host.example.com")
            is True
        )
