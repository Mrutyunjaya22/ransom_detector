"""
Async Relational Database Integration.

Provides async SQLAlchemy engine initialization, session lifecycle management,
and automatic schema creation for both SQLite (local development/sandboxing)
and PostgreSQL (enterprise cloud production).
"""

from __future__ import annotations

import os
import sys
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

ROOT = os.path.dirname(__file__)
REPO_ROOT = os.path.dirname(ROOT)
DEFAULT_DB_FILE = os.path.join(REPO_ROOT, "edr_storage.db")

# Read database URI from environment or default to local asynchronous SQLite
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite+aiosqlite:///{DEFAULT_DB_FILE}",
)

# Enforce async driver prefixes for PostgreSQL if provided in standard format
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("sqlite://") and not DATABASE_URL.startswith("sqlite+aiosqlite://"):
    DATABASE_URL = DATABASE_URL.replace("sqlite://", "sqlite+aiosqlite://", 1)


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy ORM models."""

    pass


# Asynchronous database engine
async_engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    # SQLite-specific timeout handling to avoid database locks under high concurrency
    connect_args={"timeout": 30.0} if "sqlite" in DATABASE_URL else {},
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for scoped asynchronous database sessions."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Creates all registered relational tables asynchronously upon application boot."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
