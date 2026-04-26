"""Tests for gny.auth — upsert_user and the two FastAPI dependency functions."""

from unittest.mock import AsyncMock, patch

from sqlalchemy.ext.asyncio import AsyncSession

from gny.auth import upsert_user
from gny.models import Enrollment, Host
from gny.oidc_provider import UserInfo

# ---------------------------------------------------------------------------
# upsert_user
# ---------------------------------------------------------------------------


class TestUpsertUser:
    async def test_creates_new_user(self, db_session: AsyncSession):
        info = UserInfo(uid="new-uid", name="Alice", email="alice@example.com")
        user = await upsert_user(db_session, info)

        assert user.id is not None
        assert user.uid == "new-uid"
        assert user.name == "Alice"
        assert user.mail == "alice@example.com"
        assert user.access_level == 0
        assert user.last_login_at is not None

    async def test_updates_existing_user(self, db_session: AsyncSession):
        info_first = UserInfo(uid="existing-uid", name="Bob", email="bob@example.com")
        user_first = await upsert_user(db_session, info_first)

        info_second = UserInfo(
            uid="existing-uid", name="Bob Updated", email="bob2@example.com"
        )
        user_second = await upsert_user(db_session, info_second)

        assert user_second.id == user_first.id
        assert user_second.name == "Bob Updated"
        assert user_second.mail == "bob2@example.com"
        # access_level should be unchanged
        assert user_second.access_level == 0

    async def test_existing_user_last_login_refreshed(self, db_session: AsyncSession):
        info = UserInfo(uid="login-uid", name="Carol", email="carol@example.com")
        user_first = await upsert_user(db_session, info)
        ts_first = user_first.last_login_at

        user_second = await upsert_user(db_session, info)
        # last_login_at should be updated (≥ first)
        assert user_second.last_login_at >= ts_first


# ---------------------------------------------------------------------------
# get_authenticated_user (via FastAPI dependency, tested through the API)
# ---------------------------------------------------------------------------


class TestGetAuthenticatedUser:
    async def test_creates_user_on_valid_oidc_token(self, client, db_session):
        """A valid Bearer token triggers get_userinfo → upsert_user → User returned."""
        userinfo = UserInfo(uid="oidc-uid", name="Dave", email="dave@example.com")

        with patch("gny.auth.get_userinfo", return_value=userinfo):
            # Use confirm-enrollment endpoint as a convenient route that uses
            # get_authenticated_user; supply a dummy token body so we hit auth first.
            resp = await client.post(
                "/api/enroll/confirm",
                json={"token": "gny-doesnotexist"},
                headers={"Authorization": "Bearer fake-oidc-token"},
            )

        # access_level=0 → 403 Forbidden (auth succeeded, permission denied)
        assert resp.status_code == 403

    async def test_propagates_oidc_error(self, client):
        """When get_userinfo raises, the error propagates to the caller."""
        from fastapi import HTTPException

        with patch(
            "gny.auth.get_userinfo",
            side_effect=HTTPException(status_code=401, detail="bad token"),
        ):
            resp = await client.post(
                "/api/enroll/confirm",
                json={"token": "gny-doesnotexist"},
                headers={"Authorization": "Bearer bad-token"},
            )

        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# get_current_enrollment
# ---------------------------------------------------------------------------


# IP used by the test client (set explicitly in conftest's ASGITransport).
_TEST_CLIENT_IP = "10.0.0.1"


class TestGetCurrentEnrollment:
    async def _add_confirmed_enrollment(
        self, db_session: AsyncSession, ip_address: str = _TEST_CLIENT_IP
    ) -> str:
        token = Host.generate_token()
        host = Host(
            token=Host.hash_token(token),
            ip_address=ip_address,
            ptr_record="host.example.com",
        )
        db_session.add(host)
        await db_session.commit()
        return token

    async def _add_unconfirmed_enrollment(self, db_session: AsyncSession) -> str:
        """Create an Enrollment token that has never been confirmed (no Host row)."""
        token = Enrollment.generate_token()
        enrollment = Enrollment(
            mail="host@example.com",
            token=Enrollment.hash_token(token),
            ip_address=_TEST_CLIENT_IP,
            ptr_record="host.example.com",
        )
        db_session.add(enrollment)
        await db_session.commit()
        return token

    async def test_valid_confirmed_token_returns_enrollment(self, client, db_session):
        token = await self._add_confirmed_enrollment(db_session)
        with (
            patch(
                "gny.models.host.get_ptr_records",
                new=AsyncMock(return_value=["host.example.com"]),
            ),
            patch(
                "gny.models.host.get_a_records",
                new=AsyncMock(return_value=[]),
            ),
        ):
            resp = await client.get(
                "/api/txt/test",
                params={"name": "_acme-challenge.host.example.com"},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 200

    async def test_valid_token_sets_last_used_at(self, client, db_session):
        from sqlalchemy import select as sa_select

        from gny.models import Host as EnrollmentModel

        token = await self._add_confirmed_enrollment(db_session)

        # Verify last_used_at is None before first use
        token_hash = EnrollmentModel.hash_token(token)
        result = await db_session.execute(
            sa_select(EnrollmentModel).where(EnrollmentModel.token == token_hash)
        )
        enrollment_before = result.scalar_one()
        assert enrollment_before.last_used_at is None

        await client.get(
            "/api/txt/test",
            params={"name": "_acme-challenge.host.example.com"},
            headers={"Authorization": f"Bearer {token}"},
        )

        await db_session.refresh(enrollment_before)
        assert enrollment_before.last_used_at is not None

    async def test_last_used_at_updated_on_repeated_use(self, client, db_session):
        from sqlalchemy import select as sa_select

        from gny.models import Host as EnrollmentModel

        token = await self._add_confirmed_enrollment(db_session)
        token_hash = EnrollmentModel.hash_token(token)

        await client.get(
            "/api/txt/test",
            params={"name": "_acme-challenge.host.example.com"},
            headers={"Authorization": f"Bearer {token}"},
        )

        result = await db_session.execute(
            sa_select(EnrollmentModel).where(EnrollmentModel.token == token_hash)
        )
        enrollment = result.scalar_one()
        first_used_at = enrollment.last_used_at
        assert first_used_at is not None

        await client.get(
            "/api/txt/test",
            params={"name": "_acme-challenge.host.example.com"},
            headers={"Authorization": f"Bearer {token}"},
        )

        await db_session.refresh(enrollment)
        assert enrollment.last_used_at >= first_used_at

    async def test_invalid_token_does_not_set_last_used_at(self, client, db_session):
        from sqlalchemy import select as sa_select

        from gny.models import Host as EnrollmentModel

        token = await self._add_confirmed_enrollment(db_session)
        token_hash = EnrollmentModel.hash_token(token)

        await client.get(
            "/api/txt/test",
            params={"name": "_acme-challenge.host.example.com"},
            headers={"Authorization": "Bearer gny-badtoken"},
        )

        result = await db_session.execute(
            sa_select(EnrollmentModel).where(EnrollmentModel.token == token_hash)
        )
        enrollment = result.scalar_one()
        assert enrollment.last_used_at is None

    async def test_wrong_ip_returns_401(self, client, db_session):
        # Host registered from a different IP than the test client.
        token = await self._add_confirmed_enrollment(db_session, ip_address="9.9.9.9")
        resp = await client.get(
            "/api/txt/test",
            params={"name": "_acme-challenge.host.example.com"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    async def test_wrong_ip_does_not_set_last_used_at(self, client, db_session):
        from sqlalchemy import select as sa_select

        from gny.models import Host as EnrollmentModel

        token = await self._add_confirmed_enrollment(db_session, ip_address="9.9.9.9")
        token_hash = EnrollmentModel.hash_token(token)

        await client.get(
            "/api/txt/test",
            params={"name": "_acme-challenge.host.example.com"},
            headers={"Authorization": f"Bearer {token}"},
        )

        result = await db_session.execute(
            sa_select(EnrollmentModel).where(EnrollmentModel.token == token_hash)
        )
        enrollment = result.scalar_one()
        assert enrollment.last_used_at is None

    async def test_unconfirmed_token_returns_401(self, client, db_session):
        token = await self._add_unconfirmed_enrollment(db_session)
        resp = await client.get(
            "/api/txt/test",
            params={"name": "_acme-challenge.host.example.com"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    async def test_unknown_token_returns_401(self, client):
        resp = await client.get(
            "/api/txt/test",
            params={"name": "_acme-challenge.host.example.com"},
            headers={"Authorization": "Bearer gny-doesnotexist"},
        )
        assert resp.status_code == 401
