"""SIGINTX — IOC deduplication: change unique constraint from (value) to (value, source)

Previously IOCItem had a single UNIQUE constraint on `value`, which prevented
the same indicator appearing from two different sources (e.g. the same SHA256
hash in both MalwareBazaar and ThreatFox).

This migration:
  1. Drops the old unique index on ioc_items.value.
  2. Creates a new composite unique index on (value, source).

Safe to run against both a fresh DB and an existing one.

Revision ID: 002
Revises: 001
Create Date: 2026-04-07 12:00:00.000000
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _index_exists(index_name: str, table_name: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return any(idx["name"] == index_name for idx in insp.get_indexes(table_name))


def _unique_constraint_exists(constraint_name: str, table_name: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return any(
        uc.get("name") == constraint_name
        for uc in insp.get_unique_constraints(table_name)
    )


def upgrade() -> None:
    # ── Drop the old single-column unique constraint on value ─────────────────
    # SQLite doesn't support DROP CONSTRAINT — we detect the dialect and skip
    # the explicit constraint drop; the index drop achieves the same effect.
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        # PostgreSQL: drop the unique constraint by name if it exists.
        # SQLAlchemy names implicit unique constraints as uq_<table>_<col>.
        for constraint_name in ("uq_ioc_items_value", "ioc_items_value_key"):
            try:
                op.drop_constraint(constraint_name, "ioc_items", type_="unique")
                break
            except Exception:
                pass
    else:
        # SQLite: unique constraints are implemented as unique indexes.
        # Drop whichever unique index covers the value column.
        for idx_name in ("uq_ioc_items_value", "ix_ioc_items_value"):
            if _index_exists(idx_name, "ioc_items"):
                op.drop_index(idx_name, table_name="ioc_items")

    # ── Create composite unique index on (value, source) ─────────────────────
    if not _index_exists("uq_ioc_value_source", "ioc_items"):
        op.create_index(
            "uq_ioc_value_source",
            "ioc_items",
            ["value", "source"],
            unique=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    # Drop composite index
    if _index_exists("uq_ioc_value_source", "ioc_items"):
        op.drop_index("uq_ioc_value_source", table_name="ioc_items")

    # Restore original single-column unique index
    if not _index_exists("uq_ioc_items_value", "ioc_items"):
        op.create_index(
            "uq_ioc_items_value",
            "ioc_items",
            ["value"],
            unique=True,
        )
