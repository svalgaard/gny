"""API tests for POST /api/enroll and POST /api/enroll/confirm."""

from unittest.mock import patch

from gny.auth import get_authenticated_user
from gny.main import app
from gny.models import Enrollment, Host, User

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user(access_level: int = 1) -> User:
    return User(
        id=1,
        uid="test-uid",
        name="Admin",
        mail="admin@example.com",
        access_level=access_level,
    )


# ---------------------------------------------------------------------------
# POST /api/enroll
# ---------------------------------------------------------------------------


class TestEnroll:
    async def test_enroll_success(self, client, db_session):
        """Valid request with a resolvable PTR record returns a token."""
        with patch("gny.routes.enroll.get_ptr_record", return_value="host.example.com"):
            resp = await client.post(
                "/api/enroll",
                json={"mail": "user@example.com"},
                headers={"X-Forwarded-For": "1.2.3.4"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data
        assert data["token"].startswith("gny-")

    async def test_enroll_no_ptr_returns_409(self, client):
        """IP without a PTR record should be rejected with 409."""
        with patch("gny.routes.enroll.get_ptr_record", return_value=None):
            resp = await client.post(
                "/api/enroll",
                json={"mail": "user@example.com"},
            )

        assert resp.status_code == 409

    async def test_enroll_invalid_email_returns_422(self, client):
        """Malformed email address triggers Pydantic validation error."""
        with patch("gny.routes.enroll.get_ptr_record", return_value="host.example.com"):
            resp = await client.post(
                "/api/enroll",
                json={"mail": "not-an-email"},
            )

        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /api/enroll/confirm
# ---------------------------------------------------------------------------


class TestConfirmEnrollment:
    async def _create_enrollment(
        self, db_session, confirmed: bool = False, ip_address: str = "1.2.3.4"
    ) -> str:
        from gny.models._utils import _utcnow

        token = Enrollment.generate_token()
        enrollment = Enrollment(
            mail="user@example.com",
            token=Enrollment.hash_token(token),
            ip_address=ip_address,
            ptr_record="host.example.com",
            confirmed_at=_utcnow() if confirmed else None,
        )
        if confirmed:
            # Also create the corresponding Host so the FK is valid
            host_token = Enrollment.generate_token()
            host = Host(
                ip_address=ip_address,
                ptr_record="host.example.com",
                token=Host.hash_token(host_token),
            )
            db_session.add(host)
            await db_session.flush()
            enrollment.host_id = host.id
        db_session.add(enrollment)
        await db_session.commit()
        return token

    async def test_confirm_success(self, client, db_session):
        token = await self._create_enrollment(db_session)
        user = _make_user(access_level=1)

        app.dependency_overrides[get_authenticated_user] = lambda: user
        try:
            resp = await client.post("/api/enroll/confirm", json={"token": token})
        finally:
            app.dependency_overrides.pop(get_authenticated_user, None)

        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    async def test_confirm_already_confirmed_is_idempotent(self, client, db_session):
        token = await self._create_enrollment(db_session, confirmed=True)
        user = _make_user(access_level=1)

        app.dependency_overrides[get_authenticated_user] = lambda: user
        try:
            resp = await client.post("/api/enroll/confirm", json={"token": token})
        finally:
            app.dependency_overrides.pop(get_authenticated_user, None)

        assert resp.status_code == 200

    async def test_confirm_invalid_token_returns_400(self, client):
        user = _make_user(access_level=1)

        app.dependency_overrides[get_authenticated_user] = lambda: user
        try:
            resp = await client.post(
                "/api/enroll/confirm", json={"token": "gny-doesnotexist"}
            )
        finally:
            app.dependency_overrides.pop(get_authenticated_user, None)

        assert resp.status_code == 400

    async def test_confirm_insufficient_access_level_returns_403(
        self, client, db_session
    ):
        token = await self._create_enrollment(db_session)
        user = _make_user(access_level=0)

        app.dependency_overrides[get_authenticated_user] = lambda: user
        try:
            resp = await client.post("/api/enroll/confirm", json={"token": token})
        finally:
            app.dependency_overrides.pop(get_authenticated_user, None)

        assert resp.status_code == 403

    async def test_confirm_no_bearer_returns_401(self, client, db_session):
        """No Authorization header → 401 from HTTPBearer."""
        token = await self._create_enrollment(db_session)
        resp = await client.post("/api/enroll/confirm", json={"token": token})
        assert resp.status_code == 401

    async def test_confirm_deactivates_previous_active_enrollment(
        self, client, db_session
    ):
        """Confirming a new enrollment for the same IP rotates
        the Host token in-place."""
        from sqlalchemy import select

        from gny.models import Host

        # Create a confirmed enrollment (and Host) for the IP
        await self._create_enrollment(db_session, confirmed=True, ip_address="1.2.3.4")
        result = await db_session.execute(
            select(Host).where(Host.ip_address == "1.2.3.4")
        )
        existing_host = result.scalar_one()
        old_token = existing_host.token

        # New pending enrollment for the same IP
        new_token = await self._create_enrollment(
            db_session, confirmed=False, ip_address="1.2.3.4"
        )

        user = _make_user(access_level=1)
        app.dependency_overrides[get_authenticated_user] = lambda: user
        try:
            resp = await client.post("/api/enroll/confirm", json={"token": new_token})
        finally:
            app.dependency_overrides.pop(get_authenticated_user, None)

        assert resp.status_code == 200

        # Still only one Host row for this IP
        all_hosts = await db_session.execute(
            select(Host).where(Host.ip_address == "1.2.3.4")
        )
        assert len(all_hosts.scalars().all()) == 1

        # Token was rotated
        await db_session.refresh(existing_host)
        assert existing_host.token != old_token

    async def test_enroll_deactivates_previous_pending_enrollment(
        self, client, db_session
    ):
        """A new /enroll request soft-deletes existing pending Enrollment rows for the
        same IP."""
        from gny.models import Enrollment

        # The test ASGI transport fixes request.client.host = "127.0.0.1", so
        # create the pending enrollment with that IP to match.
        token = Enrollment.generate_token()
        pending = Enrollment(
            mail="user@example.com",
            token=Enrollment.hash_token(token),
            ip_address="127.0.0.1",
            ptr_record="host.example.com",
        )
        db_session.add(pending)
        await db_session.commit()
        assert pending.deleted_at is None

        # New enrollment from the same IP (client IP = 127.0.0.1 via ASGI transport)
        with patch("gny.routes.enroll.get_ptr_record", return_value="host.example.com"):
            resp = await client.post(
                "/api/enroll",
                json={"mail": "user@example.com"},
            )

        assert resp.status_code == 200
        await db_session.refresh(pending)
        assert pending.deleted_at is not None

    async def test_confirm_expired_token_returns_400(self, client, db_session):
        """An enrollment token that exceeds the confirmation window is rejected
        with 400."""
        from datetime import datetime, timedelta, timezone

        token = Enrollment.generate_token()
        old_created_at = datetime.now(timezone.utc) - timedelta(hours=33)
        enrollment = Enrollment(
            mail="user@example.com",
            token=Enrollment.hash_token(token),
            ip_address="1.2.3.4",
            ptr_record="host.example.com",
            created_at=old_created_at,
        )
        db_session.add(enrollment)
        await db_session.commit()

        user = _make_user(access_level=1)
        app.dependency_overrides[get_authenticated_user] = lambda: user
        try:
            resp = await client.post("/api/enroll/confirm", json={"token": token})
        finally:
            app.dependency_overrides.pop(get_authenticated_user, None)

        assert resp.status_code == 400
        assert "expired" in resp.json().get("detail", "").lower()
