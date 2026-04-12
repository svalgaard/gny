from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gny.database import get_db
from gny.models import Host, User
from gny.oidc_provider import UserInfo, get_userinfo

_bearer = HTTPBearer()


async def upsert_user(db: AsyncSession, info: UserInfo) -> User:
    """Create or update the :class:`User` record for the authenticated subject.

    New users are inserted with ``access_level=0``.  On subsequent logins,
    ``name``, ``mail``, ``last_login_at``, and ``updated_at`` are refreshed.
    """
    now = datetime.now(timezone.utc)
    result = await db.execute(select(User).where(User.uid == info.uid))
    user = result.scalar_one_or_none()
    if user is None:
        user = User(
            uid=info.uid,
            name=info.name,
            mail=info.email,
            access_level=0,
            last_login_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(user)
    else:
        user.name = info.name
        user.mail = info.email
        user.last_login_at = now
        user.updated_at = now
    await db.commit()
    await db.refresh(user)
    return user


async def get_authenticated_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    """FastAPI dependency: validate Bearer token against the OIDC userinfo
    endpoint, upsert the :class:`User` record, and return it."""
    info = await get_userinfo(credentials.credentials)
    user = await upsert_user(db, info)
    request.state.user_id = user.id
    return user


async def get_current_enrollment(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> Host:
    """Validate Bearer token, enforce IP binding, update last_used_at,
    and return the confirmed Host."""
    token = credentials.credentials
    result = await db.execute(
        select(Host).where(
            Host.token == Host.hash_token(token),
        )
    )
    enrollment = result.scalar_one_or_none()
    if enrollment is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    client_host = request.client.host if request.client else None
    if client_host != enrollment.ip_address:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token not valid for this IP address",
            headers={"WWW-Authenticate": "Bearer"},
        )
    enrollment.last_used_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(enrollment)
    request.state.host_id = enrollment.id
    return enrollment
