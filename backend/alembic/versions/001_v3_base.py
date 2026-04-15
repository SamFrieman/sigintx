"""SIGINTX v3.0.0 — Base schema migration

Creates all v3-new tables and adds v3 columns to existing tables.
Safe to run against both a brand-new database and an existing v2 database.

Revision ID: 001
Revises:
Create Date: 2026-04-07 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _table_exists(table_name: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return insp.has_table(table_name)


def _column_exists(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    cols = [c["name"] for c in insp.get_columns(table_name)]
    return column_name in cols


# ── Upgrade ───────────────────────────────────────────────────────────────────

def upgrade() -> None:
    # ── users ─────────────────────────────────────────────────────────────────
    if not _table_exists("users"):
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("username", sa.String(64), nullable=False),
            sa.Column("hashed_password", sa.String(256), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("last_login", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("username"),
        )

    # ── audit_logs ────────────────────────────────────────────────────────────
    if not _table_exists("audit_logs"):
        op.create_table(
            "audit_logs",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("timestamp", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("action", sa.String(64), nullable=False),
            sa.Column("actor", sa.String(64), nullable=False, server_default="system"),
            sa.Column("entity_type", sa.String(32), nullable=True),
            sa.Column("entity_id", sa.String(64), nullable=True),
            sa.Column("details", sa.Text(), nullable=True),
            sa.Column("ip_address", sa.String(45), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])

    # ── watchlists ────────────────────────────────────────────────────────────
    if not _table_exists("watchlists"):
        op.create_table(
            "watchlists",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(128), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("conditions", sa.Text(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("last_checked", sa.DateTime(), nullable=True),
            sa.Column("last_hit", sa.DateTime(), nullable=True),
            sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("notify_webhook", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.PrimaryKeyConstraint("id"),
        )

    # ── alert_rules ───────────────────────────────────────────────────────────
    if not _table_exists("alert_rules"):
        op.create_table(
            "alert_rules",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(128), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("conditions", sa.Text(), nullable=False),
            sa.Column("min_severity", sa.String(16), nullable=False, server_default="HIGH"),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_triggered", sa.DateTime(), nullable=True),
            sa.Column("cooldown_minutes", sa.Integer(), nullable=False, server_default="60"),
            sa.PrimaryKeyConstraint("id"),
        )

    # ── cve_status ────────────────────────────────────────────────────────────
    if not _table_exists("cve_status"):
        op.create_table(
            "cve_status",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("cve_id", sa.String(32), nullable=False),
            sa.Column("status", sa.String(16), nullable=False, server_default="open"),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_by", sa.String(64), nullable=False, server_default="user"),
            sa.Column("patched_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("cve_id"),
        )
        op.create_index("ix_cve_status_cve_id", "cve_status", ["cve_id"])

    # ── assets ────────────────────────────────────────────────────────────────
    if not _table_exists("assets"):
        op.create_table(
            "assets",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(128), nullable=False),
            sa.Column("asset_type", sa.String(32), nullable=False),
            sa.Column("value", sa.String(256), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("monitor_shodan", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("last_scanned", sa.DateTime(), nullable=True),
            sa.Column("open_ports", sa.Text(), nullable=True),
            sa.Column("vulns_detected", sa.Text(), nullable=True),
            sa.Column("tags", sa.Text(), nullable=True),
            sa.Column("risk_score", sa.Float(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("value"),
        )

    # ── ioc_enrichments ───────────────────────────────────────────────────────
    if not _table_exists("ioc_enrichments"):
        op.create_table(
            "ioc_enrichments",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("ioc_id", sa.Integer(), nullable=False),
            sa.Column("ioc_value", sa.String(512), nullable=False),
            sa.Column("source", sa.String(64), nullable=False),
            sa.Column("data", sa.Text(), nullable=False),
            sa.Column("fetched_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_ioc_enrichments_ioc_id", "ioc_enrichments", ["ioc_id"])
        op.create_index("ix_ioc_enrichments_ioc_value", "ioc_enrichments", ["ioc_value"])

    # ── Add v3 columns to existing tables ─────────────────────────────────────

    # news_items.title_hash
    if _table_exists("news_items") and not _column_exists("news_items", "title_hash"):
        op.add_column(
            "news_items",
            sa.Column("title_hash", sa.String(64), nullable=True),
        )
        op.create_index("ix_news_items_title_hash", "news_items", ["title_hash"])

    # cve_items.priority_score
    if _table_exists("cve_items") and not _column_exists("cve_items", "priority_score"):
        op.add_column(
            "cve_items",
            sa.Column("priority_score", sa.Float(), nullable=True),
        )


# ── Downgrade ─────────────────────────────────────────────────────────────────

def downgrade() -> None:
    # Remove v3 columns from existing tables
    if _table_exists("cve_items") and _column_exists("cve_items", "priority_score"):
        op.drop_column("cve_items", "priority_score")

    if _table_exists("news_items") and _column_exists("news_items", "title_hash"):
        op.drop_index("ix_news_items_title_hash", table_name="news_items")
        op.drop_column("news_items", "title_hash")

    # Drop new tables (in reverse dependency order)
    for tbl in (
        "ioc_enrichments",
        "assets",
        "cve_status",
        "alert_rules",
        "watchlists",
        "audit_logs",
        "users",
    ):
        if _table_exists(tbl):
            op.drop_table(tbl)
