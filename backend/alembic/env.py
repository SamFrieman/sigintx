"""
Alembic environment configuration — SIGINTX v3.0.0

Supports both synchronous (offline) and asynchronous (online) migration modes.
Reads DATABASE_URL from the environment; falls back to the value in alembic.ini.
"""
import os
import asyncio
import logging
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine

from alembic import context

# ── Import all models so that Base.metadata is fully populated ────────────────
# Adjust the Python path so that 'database' resolves from backend/.
import sys
from pathlib import Path

# backend/ is the parent of alembic/
_backend_dir = Path(__file__).resolve().parent.parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

from database import Base  # noqa: E402  (import after sys.path fix)
# Importing individual models is not strictly required because they are all
# defined in database.py and registered on Base.metadata when that module loads.
# But we import them explicitly to make the dependency crystal-clear:
from database import (  # noqa: F401
    NewsItem, CVEItem, ThreatActor, SettingItem, IOCItem,
    AlertLog, AiBriefing, AiChatMessage, RssFeed,
    User, AuditLog, Watchlist, AlertRule, CVEStatus, Asset, IOCEnrichment,
)

# ── Alembic config object ─────────────────────────────────────────────────────

config = context.config

# Optionally set up Python logging from the config file.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

logger = logging.getLogger("alembic.env")

# Prefer DATABASE_URL from environment; fall back to alembic.ini value.
_db_url: str = os.getenv("DATABASE_URL") or config.get_main_option("sqlalchemy.url", "")

# Alembic offline / online modes work with *sync* drivers only, so convert
# asyncpg → psycopg2 and aiosqlite → pysqlite for sync usage.
def _sync_url(url: str) -> str:
    return (
        url
        .replace("postgresql+asyncpg://", "postgresql+psycopg2://")
        .replace("sqlite+aiosqlite://", "sqlite://")
    )


target_metadata = Base.metadata


# ── Offline migrations (no live DB connection) ────────────────────────────────

def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    Emits SQL to stdout without connecting to the database.
    Useful for generating SQL scripts for review or manual application.
    """
    sync_url = _sync_url(_db_url)
    logger.info("Running offline migrations against: %s", sync_url)

    context.configure(
        url=sync_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# ── Online migrations (async engine) ─────────────────────────────────────────

def do_run_migrations(connection) -> None:
    """Configure the migration context and execute pending migrations."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online_async() -> None:
    """
    Run migrations in 'online' mode using an async engine.

    Alembic itself is synchronous, so we run the actual migration inside
    ``run_sync`` on the async connection.
    """
    logger.info("Running online migrations against: %s", _db_url)

    connectable: AsyncEngine = create_async_engine(
        _db_url,
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_migrations_online_async())


# ── Entry point ───────────────────────────────────────────────────────────────

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
