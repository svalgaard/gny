from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "gny"
    app_name_long: str = "GNY"
    app_url: str = "http://localhost:8000"

    # Mail
    app_mail_address: str = ""
    app_mail_name: str = "GNY"
    mail_host: str = "localhost"
    mail_port: int = 25
    mail_encryption: str = "tls"
    mail_user: str = ""
    mail_password: str = ""

    # OIDC (Google OAuth2)
    oidc_provider_metadata_url: str = (
        "https://accounts.google.com/.well-known/openid-configuration"
    )
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = "/.well-known/sso"

    # Database (MariaDB/MySQL)
    db_host: str = "localhost"
    db_database: str = "gny_db"
    db_username: str = "gny_user"
    db_password: str = ""

    # Enrollment
    enroll_confirm_timeout_hours: int = 32

    # Session (web UI)
    session_lifetime_hours: int = 24

    # Misc
    display_errors: str = "true"
    log_level: str = "info"

    @property
    def database_url(self) -> str:
        return (
            f"mysql+aiomysql://{self.db_username}:{self.db_password}"
            f"@{self.db_host}/{self.db_database}"
        )

    @property
    def oidc_redirect_uri_full(self) -> str:
        """Absolute redirect URI computed from APP_URL and OIDC_REDIRECT_URI."""
        base = self.app_url.rstrip("/")
        path = self.oidc_redirect_uri
        if not path.startswith("/"):
            path = "/" + path
        return base + path


settings = Settings()
