"""OIDC provider discovery via RFC 8414 / OpenID Connect Discovery.

Fetches the provider metadata document from ``OIDC_PROVIDER_METADATA_URL`` and
caches it in memory for the lifetime of the process.  Any standard OIDC
provider (Google, Azure AD/Entra ID, Okta, …) is supported as long as the
metadata URL is set correctly.

Azure example::

    OIDC_PROVIDER_METADATA_URL=https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration

Google example::

    OIDC_PROVIDER_METADATA_URL=https://accounts.google.com/.well-known/openid-configuration
"""

from dataclasses import dataclass

import httpx
from fastapi import HTTPException, status

from gny.config import settings

_provider_config: dict | None = None


@dataclass
class UserInfo:
    """Normalised claims extracted from an OIDC userinfo response.

    ``uid``   — ``sub`` claim (standard OIDC subject identifier; on Azure AD
                this is the ``oid`` surfaced as ``sub`` in the v2.0 endpoint).
    ``name``  — ``name`` claim; falls back to email when absent.
    ``email`` — verified email address.
    """

    uid: str
    name: str
    email: str


async def get_provider_config() -> dict:
    """Return the cached OIDC provider metadata, fetching it on first call."""
    global _provider_config
    if _provider_config is None:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(settings.oidc_provider_metadata_url)
        if resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to fetch OIDC provider metadata",
            )
        _provider_config = resp.json()
    return _provider_config


async def get_userinfo(access_token: str) -> UserInfo:
    """Exchange an access token for user claims via the provider's userinfo endpoint.

    Returns a :class:`UserInfo` with ``uid``, ``name``, and ``email``.
    Raises ``HTTPException`` on any failure.

    Works with Google, Azure AD/Entra ID, and other standard OIDC providers.
    Azure AD omits ``email_verified``; its absence is treated as implicitly true.
    """
    config = await get_provider_config()
    userinfo_url: str = config.get("userinfo_endpoint", "")
    if not userinfo_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC provider metadata missing userinfo_endpoint",
        )

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    if resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to retrieve user info from OIDC provider",
        )

    data = resp.json()

    uid: str = data.get("sub", "")
    if not uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OIDC userinfo response missing sub claim",
        )

    email: str | None = data.get("email")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not available in OIDC userinfo response",
        )

    # Azure AD omits email_verified; treat absence as verified.
    email_verified = data.get("email_verified", True)
    if not email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email address is not verified",
        )

    name: str = data.get("name") or email

    return UserInfo(uid=uid, name=name, email=email)


async def get_userinfo_email(access_token: str) -> str:
    """Thin wrapper — returns only the email from :func:`get_userinfo`."""
    return (await get_userinfo(access_token)).email
