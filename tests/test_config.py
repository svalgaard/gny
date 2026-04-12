"""Tests for gny.config — Settings properties."""

from gny.config import Settings


class TestSettings:
    def test_database_url(self):
        s = Settings(
            db_username="user",
            db_password="pass",
            db_host="dbhost",
            db_database="mydb",
        )
        assert s.database_url == "mysql+aiomysql://user:pass@dbhost/mydb"

    def test_oidc_redirect_uri_full_default(self):
        s = Settings(app_url="http://localhost:8000")
        # Default oidcredirecturi is "/.well-known/sso"
        assert s.oidc_redirect_uri_full == "http://localhost:8000/.well-known/sso"

    def test_oidc_redirect_uri_full_strips_trailing_slash(self):
        s = Settings(app_url="https://example.com/")
        assert s.oidc_redirect_uri_full == "https://example.com/.well-known/sso"

    def test_oidc_redirect_uri_full_adds_leading_slash(self):
        s = Settings(app_url="https://example.com", oidcredirecturi="callback")
        assert s.oidc_redirect_uri_full == "https://example.com/callback"

    def test_oidc_redirect_uri_full_custom_path(self):
        s = Settings(app_url="https://example.com", oidcredirecturi="/sso/cb")
        assert s.oidc_redirect_uri_full == "https://example.com/sso/cb"
