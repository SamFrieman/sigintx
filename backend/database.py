"""
SIGINTX — Database layer (PostgreSQL/SQLite dual support via SQLAlchemy async)
v3.0.0
"""
import os
import logging
from datetime import datetime
from sqlalchemy import (
    String, Text, Float, DateTime, Boolean, Integer, Index, UniqueConstraint, event, text
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool

logger = logging.getLogger(__name__)

DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./sigintx.db",
)

# ── Engine factory ────────────────────────────────────────────────────────────

def _make_engine():
    if DATABASE_URL.startswith("postgresql"):
        return create_async_engine(
            DATABASE_URL,
            echo=False,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
        )
    else:
        # SQLite — NullPool is safest for aiosqlite, but async_sessionmaker
        # manages connections well; we keep the default pool and add WAL mode.
        eng = create_async_engine(
            DATABASE_URL,
            echo=False,
            connect_args={"check_same_thread": False},
        )

        # Enable WAL mode for better concurrent read/write performance.
        # The sync event fires on every new underlying DBAPI connection.
        from sqlalchemy import event as _event

        @_event.listens_for(eng.sync_engine, "connect")
        def _set_sqlite_pragmas(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.close()

        return eng


engine = _make_engine()
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


# ── ORM Base ──────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


# ── Existing models (unchanged except small additions noted) ──────────────────

class NewsItem(Base):
    __tablename__ = "news_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(512))
    url: Mapped[str] = mapped_column(String(1024), unique=True)
    source: Mapped[str] = mapped_column(String(128))
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    published_at: Mapped[datetime] = mapped_column(DateTime)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    severity: Mapped[str] = mapped_column(String(16), default="INFO")
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)           # JSON list
    threat_actors: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    cve_refs: Mapped[str | None] = mapped_column(Text, nullable=True)       # JSON list
    # v3 addition
    title_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # v3.5 addition
    category: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)  # security|tech|crypto|layoffs|conference


class CVEItem(Base):
    __tablename__ = "cve_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(256), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    affected_products: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)               # JSON
    threat_actors: Mapped[str | None] = mapped_column(Text, nullable=True)      # JSON
    # v3 addition
    priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)


class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(256), unique=True)
    aliases: Mapped[str | None] = mapped_column(Text, nullable=True)            # JSON
    mitre_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    country: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    techniques: Mapped[str | None] = mapped_column(Text, nullable=True)         # JSON
    motivation: Mapped[str | None] = mapped_column(String(256), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_activity: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)  # last news mention


class SettingItem(Base):
    """Persistent runtime configuration — API keys, webhook URL, etc."""
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class IOCItem(Base):
    """Indicators of Compromise from Abuse.ch (MalwareBazaar/URLhaus/ThreatFox) and OTX."""
    __tablename__ = "ioc_items"
    __table_args__ = (
        # Same indicator value from two different sources = two distinct rows.
        UniqueConstraint("value", "source", name="uq_ioc_value_source"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_type: Mapped[str] = mapped_column(String(32))           # hash_sha256, hash_md5, url, ip, domain, email
    value: Mapped[str] = mapped_column(String(512), index=True)  # not unique alone — see uq_ioc_value_source
    malware_family: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source: Mapped[str] = mapped_column(String(64))             # MalwareBazaar, URLhaus, ThreatFox, OTX
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)             # JSON list
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)    # 0.0–1.0
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AlertLog(Base):
    """Record of each webhook alert dispatch."""
    __tablename__ = "alert_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fired_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    item_type: Mapped[str] = mapped_column(String(16))          # news | cve
    count: Mapped[int] = mapped_column(Integer, default=0)
    top_severity: Mapped[str] = mapped_column(String(16))
    webhook_url: Mapped[str] = mapped_column(String(512))
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    sample_title: Mapped[str | None] = mapped_column(String(512), nullable=True)


class AiBriefing(Base):
    """AI-generated threat intelligence briefings produced by the analyst agent."""
    __tablename__ = "ai_briefings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    model_used: Mapped[str] = mapped_column(String(128))
    content: Mapped[str] = mapped_column(Text)
    news_count: Mapped[int] = mapped_column(Integer, default=0)
    cve_count: Mapped[int] = mapped_column(Integer, default=0)
    top_severity: Mapped[str] = mapped_column(String(16), default="INFO")
    threat_actors: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list


class AiChatMessage(Base):
    """Persistent AI analyst chat messages for session history."""
    __tablename__ = "ai_chat_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    role: Mapped[str] = mapped_column(String(16))               # user | assistant
    content: Mapped[str] = mapped_column(Text)
    model_used: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class RssFeed(Base):
    """User-configurable RSS feed sources (replaces the hardcoded list)."""
    __tablename__ = "rss_feeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    url: Mapped[str] = mapped_column(String(1024), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    added_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_fetch: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    item_count: Mapped[int] = mapped_column(Integer, default=0)
    # v3.5 addition
    category: Mapped[str | None] = mapped_column(String(32), nullable=True)  # security|tech|crypto|layoffs|conference


# ── v3 New models ─────────────────────────────────────────────────────────────

class User(Base):
    """Single admin user for JWT authentication."""
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuditLog(Base):
    """Immutable audit trail for all significant system actions."""
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    action: Mapped[str] = mapped_column(String(64))             # e.g. "settings.update", "collector.trigger", "auth.login"
    actor: Mapped[str] = mapped_column(String(64), default="system")  # username or "system"
    entity_type: Mapped[str | None] = mapped_column(String(32), nullable=True)   # "news" | "cve" | "ioc" | "setting" | "rule"
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)             # JSON string with extra context
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)


class Watchlist(Base):
    """Named watchlists with structured conditions for continuous monitoring."""
    __tablename__ = "watchlists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    conditions: Mapped[str] = mapped_column(Text)               # JSON: {"operator": "AND", "conditions": [...]}
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_checked: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_hit: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    notify_webhook: Mapped[bool] = mapped_column(Boolean, default=True)


class AlertRule(Base):
    """Configurable alert rules with cooldown to prevent alert storms."""
    __tablename__ = "alert_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    conditions: Mapped[str] = mapped_column(Text)               # JSON rule conditions
    min_severity: Mapped[str] = mapped_column(String(16), default="HIGH")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    last_triggered: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cooldown_minutes: Mapped[int] = mapped_column(Integer, default=60)  # don't re-fire within N minutes
    # v3.5 additions
    notification_channel: Mapped[str] = mapped_column(String(32), default="webhook")  # webhook|telegram|both
    telegram_chat_id: Mapped[str | None] = mapped_column(String(128), nullable=True)  # override global chat ID


class CVEStatus(Base):
    """Per-CVE triage status tracked by analysts."""
    __tablename__ = "cve_status"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | patched | accepted | investigating
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_by: Mapped[str] = mapped_column(String(64), default="user")
    patched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Asset(Base):
    """Tracked assets for Shodan monitoring and vulnerability correlation."""
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    asset_type: Mapped[str] = mapped_column(String(32))         # ip | domain | cidr | asn
    value: Mapped[str] = mapped_column(String(256), unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    monitor_shodan: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_scanned: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    open_ports: Mapped[str | None] = mapped_column(Text, nullable=True)         # JSON list
    vulns_detected: Mapped[str | None] = mapped_column(Text, nullable=True)     # JSON list of CVE IDs found
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)               # JSON list
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)


class IOCEnrichment(Base):
    """Cached enrichment data for IOC values from external sources."""
    __tablename__ = "ioc_enrichments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_id: Mapped[int] = mapped_column(Integer, index=True)    # soft FK to ioc_items.id
    ioc_value: Mapped[str] = mapped_column(String(512), index=True)
    source: Mapped[str] = mapped_column(String(64))             # "abuseipdb" | "github_poc" | "whois" | "shodan"
    data: Mapped[str] = mapped_column(Text)                     # JSON enrichment payload
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ── DB initialisation ─────────────────────────────────────────────────────────

async def init_db() -> None:
    """Create all tables and (for SQLite) build FTS5 virtual tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        if DATABASE_URL.startswith("sqlite"):
            # FTS5 virtual tables for full-text search
            await conn.execute(text(
                "CREATE VIRTUAL TABLE IF NOT EXISTS news_fts "
                "USING fts5(title, summary, content='news_items', content_rowid='id')"
            ))
            await conn.execute(text(
                "CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts "
                "USING fts5(cve_id, description, content='cve_items', content_rowid='id')"
            ))
            # Populate/rebuild FTS index from existing rows
            await conn.execute(text("INSERT INTO news_fts(news_fts) VALUES('rebuild')"))
            await conn.execute(text("INSERT INTO cve_fts(cve_fts) VALUES('rebuild')"))

            # ── Safe migrations: ADD COLUMN IF NOT EXISTS (SQLite ignores errors) ──
            _migrations = [
                # Sprint 2 — ThreatActor activity tracking
                "ALTER TABLE threat_actors ADD COLUMN last_activity DATETIME",
                "ALTER TABLE threat_actors ADD COLUMN activity_status VARCHAR(16)",
                # Sprint 2 — CVE priority score + status
                "ALTER TABLE cve_items ADD COLUMN priority_score FLOAT",
                # Sprint 4 — IOC enrichment linkage
                "ALTER TABLE ioc_items ADD COLUMN enriched_at DATETIME",
                # Sprint 5 — Watchlist / AuditLog tables are handled by create_all above
                # v3.5 — Category tagging, Telegram alerts
                "ALTER TABLE news_items ADD COLUMN category VARCHAR(32)",
                "ALTER TABLE rss_feeds ADD COLUMN category VARCHAR(32)",
                "ALTER TABLE alert_rules ADD COLUMN notification_channel VARCHAR(32) DEFAULT 'webhook'",
                "ALTER TABLE alert_rules ADD COLUMN telegram_chat_id VARCHAR(128)",
            ]
            for stmt in _migrations:
                try:
                    await conn.execute(text(stmt))
                except Exception:
                    pass  # column already exists — SQLite doesn't support IF NOT EXISTS

    await get_or_create_admin()


async def rebuild_fts() -> None:
    """Resync SQLite FTS index after bulk inserts. No-op on PostgreSQL."""
    if not DATABASE_URL.startswith("sqlite"):
        return
    async with engine.begin() as conn:
        await conn.execute(text("INSERT INTO news_fts(news_fts) VALUES('rebuild')"))
        await conn.execute(text("INSERT INTO cve_fts(cve_fts) VALUES('rebuild')"))


async def get_or_create_admin() -> None:
    """
    Create the initial admin user if no users exist.

    Password resolution order:
      1. ADMIN_PASSWORD environment variable (set this in production).
      2. A cryptographically random 20-character password generated at first boot
         and printed once to stdout — copy it immediately.

    The seeded password is never stored in plaintext after this function returns.
    """
    import os as _os
    import secrets as _secrets
    from sqlalchemy import select as _select

    try:
        from passlib.context import CryptContext
        _pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    except ImportError:
        logger.warning(
            "passlib not installed — skipping default admin creation. "
            "Run: pip install passlib[bcrypt]"
        )
        return

    async with SessionLocal() as session:
        result = await session.execute(_select(User).limit(1))
        if result.scalar_one_or_none() is not None:
            return  # users already exist — nothing to do

        env_pw = _os.getenv("ADMIN_PASSWORD", "").strip()
        if env_pw:
            password = env_pw
            source = "ADMIN_PASSWORD env var"
        else:
            password = _secrets.token_urlsafe(20)
            source = "auto-generated"

        hashed = _pwd_context.hash(password)
        admin = User(username="admin", hashed_password=hashed)
        session.add(admin)
        await session.commit()

        # Print the password to stdout regardless of log level so it is never missed.
        border = "=" * 60
        print(f"\n{border}")
        print("  SIGINTX — INITIAL ADMIN CREDENTIALS ({source})".format(source=source.upper()))
        print(f"  Username : admin")
        print(f"  Password : {password}")
        print(f"  ⚠  Change this password immediately after first login.")
        print(f"{border}\n")
        logger.warning(
            "Default admin created (source=%s). Change the password after first login.",
            source,
        )


# ── Session dependency ────────────────────────────────────────────────────────

async def get_db():
    async with SessionLocal() as session:
        yield session
