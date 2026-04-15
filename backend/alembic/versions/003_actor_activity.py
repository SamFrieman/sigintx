"""SIGINTX — Add last_activity column to threat_actors

Records when the actor was last mentioned in ingested news, enabling
active/dormant/resurged status computation without a full table scan.

Revision ID: 003
Revises: 002
Create Date: 2026-04-07 13:00:00.000000
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _column_exists(table: str, column: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return column in [c["name"] for c in insp.get_columns(table)]


def upgrade() -> None:
    if not _column_exists("threat_actors", "last_activity"):
        op.add_column(
            "threat_actors",
            sa.Column("last_activity", sa.DateTime(), nullable=True),
        )
        op.create_index("ix_threat_actors_last_activity", "threat_actors", ["last_activity"])


def downgrade() -> None:
    if _column_exists("threat_actors", "last_activity"):
        op.drop_index("ix_threat_actors_last_activity", table_name="threat_actors")
        op.drop_column("threat_actors", "last_activity")
