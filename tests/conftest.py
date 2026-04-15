"""Shared pytest fixtures for the GNY test suite.

The production app uses aiomysql/MariaDB.  Tests replace it with an in-memory
SQLite database so no external service is required.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from gny.database import Base, get_db
from gny.main import app

# ---------------------------------------------------------------------------
# In-memory SQLite engine (one per test session, recreated between tests via
# the db_session fixture that rolls back after each test).
# ---------------------------------------------------------------------------

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = async_sessionmaker(test_engine, expire_on_commit=False)


@pytest.fixture(scope="session", autouse=True)
async def create_test_tables():
    """Create all tables once for the test session."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def db_session() -> AsyncSession:
    """Yield an AsyncSession; truncate all tables afterwards to keep tests isolated."""
    async with TestSessionLocal() as session:
        yield session
        await session.rollback()
        # Delete all rows from every table in dependency order so the next test
        # starts with an empty database.
        for table in reversed(Base.metadata.sorted_tables):
            await session.execute(text(f"DELETE FROM {table.name}"))  # noqa: S608
        await session.commit()


@pytest.fixture
async def client(db_session: AsyncSession) -> AsyncClient:
    """Return an httpx AsyncClient wired to the FastAPI app with the test DB."""

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app, client=("10.0.0.1", 50000))
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
