"""
OAuth2 / OIDC callback handler.

Flow:
  1. Client calls GET /api/enroll/start?token={enrollment_token}
     → redirected to the configured OIDC provider with state={enrollment_token}
  2. Provider redirects back to GET /.well-known/sso?code=...&state={enrollment_token}
     → server exchanges code for tokens, verifies email, confirms enrollment.

Supported providers (set OIDCProviderMetadataURL accordingly):
  - Google:    https://accounts.google.com/.well-known/openid-configuration
  - Azure AD:  https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration
  - Any other standard OIDC provider.
"""

import logging
import urllib.parse
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select

from gny.auth import upsert_user
from gny.config import settings
from gny.database import SessionLocal
from gny.models import Enrollment, Host
from gny.oidc_provider import get_provider_config, get_userinfo

router = APIRouter(tags=["oidc"])

_log = logging.getLogger(__name__)


@router.get("/api/enroll/start")
async def enroll_start(
    token: str = Query(..., description="Host token from POST /enroll"),
):
    """Redirect the browser to the configured OIDC provider
    to begin the confirmation flow."""
    config = await get_provider_config()
    auth_url: str = config.get("authorization_endpoint", "")
    if not auth_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC provider metadata missing authorization_endpoint",
        )

    params = {
        "client_id": settings.oidcclientid,
        "redirect_uri": settings.oidc_redirect_uri_full,
        "response_type": "code",
        "scope": "openid email",
        "state": token,
        "prompt": "select_account",
    }
    url = auth_url + "?" + urllib.parse.urlencode(params)
    _log.debug("OIDC redirect -> %s", url)
    return RedirectResponse(url=url, status_code=302)


@router.get(settings.oidcredirecturi)
async def oidc_callback(
    request: Request,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
):
    """Handle the OAuth2 authorization code callback
    from the configured OIDC provider."""
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth2 error: {error}",
        )
    if not code or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing code or state parameter",
        )

    # Discover token endpoint
    config = await get_provider_config()
    token_url: str = config.get("token_endpoint", "")
    if not token_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC provider metadata missing token_endpoint",
        )

    # Exchange authorization code for tokens
    async with httpx.AsyncClient(timeout=10) as client:
        token_resp = await client.post(
            token_url,
            data={
                "code": code,
                "client_id": settings.oidcclientid,
                "client_secret": settings.oidcclientsecret,
                "redirect_uri": settings.oidc_redirect_uri_full,
                "grant_type": "authorization_code",
            },
        )
    if token_resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to exchange authorization code",
        )
    token_data = token_resp.json()
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No access token in response",
        )

    # Get verified user identity via the provider's userinfo endpoint
    user_info = await get_userinfo(access_token)

    # Confirm the enrollment matching state (enrollment token)
    enrollment_token = state
    async with SessionLocal() as db:
        # Upsert the User record (creates on first login, updates on subsequent)
        user = await upsert_user(db, user_info)

        if user.access_level < 1:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient access level to confirm enrollments",
            )

        result = await db.execute(
            select(Enrollment).where(
                Enrollment.token == Enrollment.hash_token(enrollment_token)
            )
        )
        enrollment = result.scalar_one_or_none()

        if enrollment is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid enrollment token in state",
            )

        if enrollment.confirmed_at is None:
            now = datetime.now(timezone.utc)

            # Upsert Host for this IP
            host_result = await db.execute(
                select(Host).where(Host.ip_address == enrollment.ip_address)
            )
            host = host_result.scalar_one_or_none()
            if host is None:
                new_token = Enrollment.generate_token()
                host = Host(
                    ip_address=enrollment.ip_address,
                    ptr_record=enrollment.ptr_record,
                    token=Host.hash_token(new_token),
                )
                db.add(host)
                await db.flush()
            else:
                new_token = Enrollment.generate_token()
                host.token = Host.hash_token(new_token)
                host.ptr_record = enrollment.ptr_record
                host.updated_at = now

            enrollment.host_id = host.id
            enrollment.confirmed_at = now
            await db.commit()

    html = (
        "<html><body><h2>Host confirmed!</h2>"
        f"<p>Confirmed by <strong>{user_info.email}</strong>.</p>"
        f"<p>The enrollment token <code>{enrollment_token}</code> is now active.</p>"
        "</body></html>"
    )
    return HTMLResponse(content=html)
