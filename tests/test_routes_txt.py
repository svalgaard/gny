"""API tests for POST/DELETE/GET /api/txt."""

from unittest.mock import AsyncMock, patch

from gny.auth import get_current_enrollment
from gny.main import app
from gny.models import Host

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_enrollment(ptr_record: str = "host.example.com") -> Host:
    return Host(
        id=99,
        token="gny-testtoken",
        ip_address="1.2.3.4",
        ptr_record=ptr_record,
        allowed_names=[],
    )


def _mock_dns(ptr: str | None = "host.example.com", a: list[str] | None = None):
    """Return a pair of patches for DNS lookups used inside Host.allows_name."""
    ptr_list = [ptr] if ptr is not None else []
    return (
        patch(
            "gny.models.host.get_ptr_records",
            new=AsyncMock(return_value=ptr_list),
        ),
        patch(
            "gny.models.host.get_a_records",
            new=AsyncMock(return_value=a or []),
        ),
    )


# ---------------------------------------------------------------------------
# POST /api/txt
# ---------------------------------------------------------------------------


class TestAddTxtRecord:
    async def test_add_record_success(self, client, db_session):
        enrollment = _make_enrollment()
        app.dependency_overrides[get_current_enrollment] = lambda: enrollment

        p, a = _mock_dns()
        try:
            with p, a:
                resp = await client.post(
                    "/api/txt",
                    params={
                        "name": "_acme-challenge.host.example.com",
                        "text": "some-acme-token",
                    },
                )
        finally:
            app.dependency_overrides.pop(get_current_enrollment, None)

        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    async def test_add_record_idempotent(self, client, db_session):
        """Adding the same record twice should not raise an error."""
        enrollment = _make_enrollment()
        app.dependency_overrides[get_current_enrollment] = lambda: enrollment

        params = {"name": "_acme-challenge.host.example.com", "text": "dedup-token"}
        p, a = _mock_dns()
        try:
            with p, a:
                resp1 = await client.post("/api/txt", params=params)
                resp2 = await client.post("/api/txt", params=params)
        finally:
            app.dependency_overrides.pop(get_current_enrollment, None)

        assert resp1.status_code == 200
        assert resp2.status_code == 200

    async def test_add_record_forbidden_domain(self, client, db_session):
        enrollment = _make_enrollment(ptr_record="host.example.com")
        app.dependency_overrides[get_current_enrollment] = lambda: enrollment

        p, a = _mock_dns()
        try:
            with p, a:
                resp = await client.post(
                    "/api/txt",
                    params={"name": "_acme-challenge.evil.com", "text": "token"},
                )
        finally:
            app.dependency_overrides.pop(get_current_enrollment, None)

        assert resp.status_code == 403

    async def test_add_record_no_bearer_returns_401(self, client):
        resp = await client.post(
            "/api/txt",
            params={"name": "_acme-challenge.host.example.com", "text": "token"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# DELETE /api/txt
# ---------------------------------------------------------------------------


class TestDeleteTxtRecord:
    async def _add_record(self, client, enrollment, name: str, text: str):
        app.dependency_overrides[get_current_enrollment] = lambda: enrollment
        p, a = _mock_dns()
        with p, a:
            resp = await client.post("/api/txt", params={"name": name, "text": text})
        app.dependency_overrides.pop(get_current_enrollment, None)
        assert resp.status_code == 200

    async def test_delete_existing_record(self, client, db_session):
        enrollment = _make_enrollment()
        name = "_acme-challenge.host.example.com"
        text = "delete-me"

        await self._add_record(client, enrollment, name, text)

        app.dependency_overrides[get_current_enrollment] = lambda: enrollment
        p, a = _mock_dns()
        try:
            with p, a:
                resp = await client.delete(
                    "/api/txt", params={"name": name, "text": text}
                )
        finally:
            app.dependency_overrides.pop(get_current_enrollment, None)

        assert resp.status_code == 200

    async def test_delete_nonexistent_record_is_ok(self, client, db_session):
        """Deleting a record that doesn't exist should not raise an error."""
        enrollment = _make_enrollment()
        app.dependency_overrides[get_current_enrollment] = lambda: enrollment

        p, a = _mock_dns()
        try:
            with p, a:
                resp = await client.delete(
                    "/api/txt",
                    params={
                        "name": "_acme-challenge.host.example.com",
                        "text": "ghost",
                    },
                )
        finally:
            app.dependency_overrides.pop(get_current_enrollment, None)

        assert resp.status_code == 200

    async def test_delete_forbidden_domain(self, client, db_session):
        """Name without _acme-challenge. prefix is rejected before DNS lookup."""
        enrollment = _make_enrollment(ptr_record="host.example.com")
        app.dependency_overrides[get_current_enrollment] = lambda: enrollment

        try:
            resp = await client.delete(
                "/api/txt",
                params={"name": "evil.com", "text": "token"},
            )
        finally:
            app.dependency_overrides.pop(get_current_enrollment, None)

        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /api/txt/test
# ---------------------------------------------------------------------------


class TestTestTxtRecord:
    async def test_allowed_domain_returns_ok(self, client):
        enrollment = _make_enrollment()
        app.dependency_overrides[get_current_enrollment] = lambda: enrollment

        p, a = _mock_dns()
        try:
            with p, a:
                resp = await client.get(
                    "/api/txt/test",
                    params={"name": "_acme-challenge.host.example.com"},
                )
        finally:
            app.dependency_overrides.pop(get_current_enrollment, None)

        assert resp.status_code == 200

    async def test_forbidden_domain_returns_403(self, client):
        """Name without _acme-challenge. prefix is rejected before DNS lookup."""
        enrollment = _make_enrollment(ptr_record="host.example.com")
        app.dependency_overrides[get_current_enrollment] = lambda: enrollment

        try:
            resp = await client.get(
                "/api/txt/test",
                params={"name": "totally-different.org"},
            )
        finally:
            app.dependency_overrides.pop(get_current_enrollment, None)

        assert resp.status_code == 403
