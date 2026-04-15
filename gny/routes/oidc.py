"""
OAuth2 / OIDC login handler.

Flow:
  1. User visits GET /login
     → server generates a short-lived nonce, stores it in an HttpOnly cookie,
       and redirects to the configured OIDC provider with state="login:{nonce}".
  2. Provider redirects back to GET /.well-known/sso?code=...&state=login:{nonce}
     → server verifies the nonce, exchanges the code for tokens, upserts the User
       record, creates a Session, and sets an HttpOnly session cookie.
  3. GET /logout clears the session cookie and deletes the DB row.

Supported providers (set OIDC_PROVIDER_METADATA_URL accordingly):
  - Google:    https://accounts.google.com/.well-known/openid-configuration
  - Azure AD:  https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration
  - Any other standard OIDC provider.
"""

import hmac
import logging
import secrets
import urllib.parse
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import delete as sa_delete
from sqlalchemy.ext.asyncio import AsyncSession

from gny.auth import upsert_user
from gny.config import settings
from gny.database import get_db
from gny.models import Session
from gny.oidc_provider import get_provider_config, get_userinfo

router = APIRouter(tags=["oidc"])

_log = logging.getLogger(__name__)

# Lifetime of the login_nonce cookie (seconds)
_NONCE_MAX_AGE = 300


@router.get("/login")
async def login():
    """Start the OIDC login flow.

    Generates a short-lived nonce, stores it in an HttpOnly cookie, and
    redirects the browser to the configured OIDC provider.
    """
    config = await get_provider_config()
    auth_url: str = config.get("authorization_endpoint", "")
    if not auth_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC provider metadata missing authorization_endpoint",
        )

    nonce = secrets.token_hex(16)
    params = {
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri_full,
        "response_type": "code",
        "scope": "openid email",
        "state": "login:" + nonce,
        "prompt": "select_account",
    }
    url = auth_url + "?" + urllib.parse.urlencode(params)
    _log.debug("OIDC login redirect -> %s", url)

    response = RedirectResponse(url=url, status_code=302)
    response.set_cookie(
        "login_nonce",
        nonce,
        max_age=_NONCE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return response


@router.get(settings.oidc_redirect_uri)
async def oidc_callback(
    request: Request,
    db: AsyncSession = Depends(get_db),
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
):
    """Handle the OAuth2 authorisation code callback from the OIDC provider."""
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

    # Only the login flow is supported; state must be "login:{nonce}"
    if not state.startswith("login:"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameter",
        )
    nonce = state.removeprefix("login:")

    # Verify the nonce against the short-lived cookie (constant-time comparison)
    cookie_nonce = request.cookies.get("login_nonce", "")
    if not hmac.compare_digest(cookie_nonce, nonce):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Login nonce mismatch; please try logging in again",
        )

    # Discover token endpoint
    config = await get_provider_config()
    token_url: str = config.get("token_endpoint", "")
    if not token_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC provider metadata missing token_endpoint",
        )

    # Exchange authorisation code for tokens
    async with httpx.AsyncClient(timeout=10) as client:
        token_resp = await client.post(
            token_url,
            data={
                "code": code,
                "client_id": settings.oidc_client_id,
                "client_secret": settings.oidc_client_secret,
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

    # Resolve user identity via the provider's userinfo endpoint
    user_info = await get_userinfo(access_token)

    # Upsert the User record (creates on first login, updates on subsequent)
    user = await upsert_user(db, user_info)
    request.state.user_id = user.id

    # Create a new session
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=settings.session_lifetime_hours)
    session = Session(
        id=secrets.token_hex(32),
        user_id=user.id,
        expires_at=expires_at,
    )
    db.add(session)
    await db.commit()

    _log.info(
        "User %s (%s) logged in; session %s… created",
        user.mail,
        user.id,
        session.id[:8],
    )

    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        "session_id",
        session.id,
        max_age=settings.session_lifetime_hours * 3600,
        httponly=True,
        samesite="lax",
    )
    response.delete_cookie("login_nonce")
    return response


@router.get("/logout")
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete the current session and redirect to the login page."""
    session_id = request.cookies.get("session_id")
    if session_id:
        await db.execute(sa_delete(Session).where(Session.id == session_id))
        await db.commit()

    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session_id")
    return response
