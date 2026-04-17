"""
SIGINTX — FastAPI Application
REST API + WebSocket for real-time cyber intelligence.
v3.0.0: Auth layer, alert rules engine, keyboard shortcuts, model manager.
"""
from dotenv import load_dotenv
load_dotenv()  # must run before any local imports that read os.getenv at module level

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, Query, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, desc, func, text
from sqlalchemy.ext.asyncio import AsyncSession

from time import monotonic

from database import (
    init_db, get_db, rebuild_fts,
    NewsItem, ThreatActor, SettingItem,
    AiBriefing, AiChatMessage, RssFeed, AlertRule, Asset,
)
from auth import (
    authenticate_user, create_access_token, get_current_user, AUTH_DISABLED,
)
from rules_engine import evaluate_rules_against_recent
from correlate import build_campaigns, fire_webhook_if_needed
from scheduler import create_scheduler, set_broadcast
from collectors import (
    seed_threat_actors, collect_all_rss,
    collect_ransomwatch, scan_assets,
)
from agents import (
    build_threat_context, stream_ollama,
    generate_briefing as _gen_briefing, stream_briefing as _stream_briefing,
    agentic_stream, compute_delta,
)

# ── Simple in-memory rate limiter for manual trigger endpoints ───────────────
_last_trigger: dict[str, float] = {}
_TRIGGER_COOLDOWN = 30.0   # seconds between manual triggers

def _assert_rate_limit(key: str) -> None:
    now  = monotonic()
    last = _last_trigger.get(key, 0.0)
    if now - last < _TRIGGER_COOLDOWN:
        wait = int(_TRIGGER_COOLDOWN - (now - last))
        raise HTTPException(429, f"Rate limited — wait {wait}s before triggering again")
    _last_trigger[key] = now

from session_logger import setup_session_logging, get_recent_logs, RequestLoggingMiddleware

setup_session_logging()   # must run before any other logging calls
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("sigintx.api")

# Validate model names — allows Ollama, Groq, OpenRouter, and generic model IDs
# e.g. llama3.2:3b  /  llama-3.1-8b-instant  /  google/gemini-2.0-flash  /  gpt-4o-mini
import re as _re
_MODEL_NAME_RE = _re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{0,119}$')


def _validate_model(model: Optional[str]) -> bool:
    if not model:
        return True   # None/empty → provider uses its configured default
    return bool(_MODEL_NAME_RE.match(model))


def _sanitize_fts(q: str) -> str:
    """Escape FTS5 special characters to prevent syntax errors."""
    # Wrap in double quotes for phrase matching; escape internal quotes
    cleaned = q.replace('"', '""').strip()
    return f'"{cleaned}"'


async def _get_setting(db: AsyncSession, key: str, default: str = "") -> str:
    row = await db.get(SettingItem, key)
    return row.value if row else default

# ── WebSocket manager ────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        logger.info(f"WS connected. Total: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)
        logger.info(f"WS disconnected. Total: {len(self.active)}")

    async def broadcast(self, payload: dict):
        dead = []
        msg = json.dumps(payload, default=str)
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)


manager = ConnectionManager()
scheduler = None

# ── Redis pub/sub subscriber (production mode) ────────────────────────────────

_redis_subscriber_task: asyncio.Task | None = None


async def _redis_broadcast_subscriber() -> None:
    """
    Subscribe to the ``sigintx:broadcast`` Redis channel and forward every
    message to all connected WebSocket clients.

    Runs as a persistent background asyncio task when REDIS_URL is set.
    Reconnects automatically on connection loss.
    """
    import os as _os
    redis_url = _os.getenv("REDIS_URL", "")
    if not redis_url:
        return

    import redis.asyncio as aioredis

    CHANNEL = "sigintx:broadcast"
    backoff = 2.0

    while True:
        try:
            client = aioredis.from_url(redis_url, decode_responses=True)
            pubsub = client.pubsub()
            await pubsub.subscribe(CHANNEL)
            logger.info("Redis pub/sub: subscribed to %s", CHANNEL)
            backoff = 2.0  # reset on successful connection

            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                try:
                    payload = json.loads(message["data"])
                    await manager.broadcast(payload)
                except Exception as exc:
                    logger.debug("Redis broadcast parse error: %s", exc)

        except asyncio.CancelledError:
            return
        except Exception as exc:
            logger.warning("Redis pub/sub disconnected (%s); retrying in %.0fs", exc, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)
        finally:
            try:
                await client.aclose()
            except Exception:
                pass


async def _bootstrap_ollama() -> None:
    """Full Ollama lifecycle: install OS binary → start server → pull model."""
    await asyncio.sleep(3)   # let DB/feeds settle first
    from ollama_manager import ensure_ollama_ready
    await ensure_ollama_ready()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global scheduler, _redis_subscriber_task
    await init_db()
    logger.info("Database initialized")

    await seed_threat_actors()

    from collectors.rss_collector import seed_default_feeds
    await seed_default_feeds()

    # Always kick off an initial collection pass so the DB is populated on first boot.
    asyncio.create_task(_initial_collection())
    asyncio.create_task(_bootstrap_ollama())

    # Start Redis pub/sub subscriber when Redis is available (production).
    import os as _os
    if _os.getenv("REDIS_URL"):
        _redis_subscriber_task = asyncio.create_task(_redis_broadcast_subscriber())
        logger.info("Redis pub/sub subscriber started")

    set_broadcast(manager.broadcast)
    scheduler = create_scheduler()
    if scheduler:
        scheduler.start()
        logger.info("APScheduler started (dev mode)")

    yield

    if _redis_subscriber_task:
        _redis_subscriber_task.cancel()
        try:
            await _redis_subscriber_task
        except asyncio.CancelledError:
            pass
    if scheduler:
        scheduler.shutdown(wait=False)
    logger.info("Shutdown complete")


async def _initial_collection():
    from scheduler import _record_run
    await asyncio.sleep(2)
    for label, factory in [
        ("RSS",         collect_all_rss),
        ("RansomWatch", collect_ransomwatch),
    ]:
        try:
            count = await factory()
            _record_run(label, count)
            if count > 0:
                await manager.broadcast({"type": "rss_update", "new_items": count})
        except Exception as e:
            _record_run(label, error=str(e))
            logger.warning(f"Initial {label} collection error: {e}")
    await rebuild_fts()


app = FastAPI(
    title="SIGINTX API",
    description="Cyber World Monitor — Real-time threat intelligence API with Agentic Layer",
    version="3.5.0",
    lifespan=lifespan,
)

# ALLOWED_ORIGINS: comma-separated list of allowed origins.
# Defaults to localhost dev ports; override in production with your real domain.
# Example: ALLOWED_ORIGINS=https://sigintx.yourdomain.com
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000,http://localhost:8080")
_allowed_origins: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
)
app.add_middleware(RequestLoggingMiddleware)


# ── WebSocket ────────────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        await ws.send_text(json.dumps({"type": "connected", "message": "SIGINTX stream active"}))
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ── Health ───────────────────────────────────────────────────────────────────
@app.get("/api/v1/health")
async def health():
    return {
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "ws_connections": len(manager.active),
        "version": "3.5.0",
    }


# ── Auth ─────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/v1/auth/login")
async def login(req: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Authenticate a user and return a JWT access token."""
    ip = request.client.host if request.client else None
    user = await authenticate_user(req.username, req.password, db, ip_address=ip)
    if user is None:
        raise HTTPException(401, detail="Invalid username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer", "username": user.username}


@app.get("/api/v1/auth/me")
async def me(user=Depends(get_current_user)):
    """Return the current authenticated user (or confirms auth is disabled)."""
    return {
        "username": user.username,
        "auth_disabled": AUTH_DISABLED,
    }


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


@app.post("/api/v1/auth/change-password")
async def change_password(
    req: ChangePasswordRequest,
    request: Request,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change the authenticated user's password."""
    from auth import verify_password, hash_password
    from database import AuditLog

    if user.id == 0:
        raise HTTPException(400, detail="Cannot change password when auth is disabled")

    # Re-fetch user with current hash
    from sqlalchemy import select as _select
    db_user = (await db.execute(_select(User).where(User.id == user.id))).scalar_one_or_none()
    if db_user is None:
        raise HTTPException(404, detail="User not found")

    if not verify_password(req.current_password, db_user.hashed_password):
        raise HTTPException(400, detail="Current password is incorrect")

    db_user.hashed_password = hash_password(req.new_password)
    db.add(AuditLog(
        action="auth.password_changed",
        actor=user.username,
        ip_address=request.client.host if request.client else None,
    ))
    await db.commit()
    return {"status": "ok"}


# ── Alert Rules ───────────────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    conditions: str          # JSON string
    min_severity: str = "HIGH"
    cooldown_minutes: int = Field(default=60, ge=1, le=10080)
    notification_channel: str = "webhook"      # webhook | telegram | both
    telegram_chat_id: Optional[str] = None     # per-rule override; falls back to global


class RulePatch(BaseModel):
    enabled: Optional[bool] = None
    name: Optional[str] = None
    description: Optional[str] = None
    conditions: Optional[str] = None
    min_severity: Optional[str] = None
    cooldown_minutes: Optional[int] = None
    notification_channel: Optional[str] = None
    telegram_chat_id: Optional[str] = None


def _serialize_rule(r: AlertRule) -> dict:
    return {
        "id":                   r.id,
        "name":                 r.name,
        "description":          r.description,
        "conditions":           r.conditions,
        "min_severity":         r.min_severity,
        "enabled":              r.enabled,
        "hit_count":            r.hit_count,
        "last_triggered":       r.last_triggered.isoformat() if r.last_triggered else None,
        "cooldown_minutes":     r.cooldown_minutes,
        "notification_channel": getattr(r, "notification_channel", "webhook") or "webhook",
        "telegram_chat_id":     getattr(r, "telegram_chat_id", None),
    }


@app.get("/api/v1/rules")
async def list_rules(db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(AlertRule).order_by(AlertRule.id))
    return [_serialize_rule(r) for r in rows.all()]


@app.post("/api/v1/rules", status_code=201)
async def create_rule(body: RuleCreate, db: AsyncSession = Depends(get_db)):
    rule = AlertRule(
        name=body.name,
        description=body.description,
        conditions=body.conditions,
        min_severity=body.min_severity,
        cooldown_minutes=body.cooldown_minutes,
        notification_channel=body.notification_channel,
        telegram_chat_id=body.telegram_chat_id,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return _serialize_rule(rule)


@app.patch("/api/v1/rules/{rule_id}")
async def patch_rule(rule_id: int, body: RulePatch, db: AsyncSession = Depends(get_db)):
    rule = await db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(404, "Rule not found")
    if body.enabled is not None:
        rule.enabled = body.enabled
    if body.name is not None:
        rule.name = body.name
    if body.description is not None:
        rule.description = body.description
    if body.conditions is not None:
        rule.conditions = body.conditions
    if body.min_severity is not None:
        rule.min_severity = body.min_severity
    if body.cooldown_minutes is not None:
        rule.cooldown_minutes = body.cooldown_minutes
    if body.notification_channel is not None:
        rule.notification_channel = body.notification_channel
    if body.telegram_chat_id is not None:
        rule.telegram_chat_id = body.telegram_chat_id
    await db.commit()
    await db.refresh(rule)
    return _serialize_rule(rule)


@app.delete("/api/v1/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    rule = await db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(404, "Rule not found")
    await db.delete(rule)
    await db.commit()


@app.post("/api/v1/rules/{rule_id}/test")
async def test_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    """Dry-run the rule against the last 50 news items and return the match count."""
    rule = await db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(404, "Rule not found")
    try:
        matches = await evaluate_rules_against_recent([rule], db, limit=50)
        return {"matches": matches, "message": f"Rule matched {matches} of the last 50 news items"}
    except Exception as exc:
        logger.warning("Rule test failed: %s", exc)
        return {"matches": 0, "message": str(exc)}


# ── Stats ────────────────────────────────────────────────────────────────────
@app.get("/api/v1/stats")
async def stats(db: AsyncSession = Depends(get_db)):
    news_count    = await db.scalar(select(func.count()).select_from(NewsItem))
    actor_count   = await db.scalar(select(func.count()).select_from(ThreatActor))
    critical_news = await db.scalar(select(func.count()).select_from(NewsItem).where(NewsItem.severity == "CRITICAL"))

    return {
        "news_total":     news_count or 0,
        "threat_actors":  actor_count or 0,
        "critical_news":  critical_news or 0,
        "ws_connections": len(manager.active),
    }


# ── Cyber Threat Level ───────────────────────────────────────────────────────
@app.get("/api/v1/threat-level")
async def get_threat_level(db: AsyncSession = Depends(get_db)):
    """
    Return a DEFCON-style cyber threat level (1–5) calculated from live data.
      1 = CRITICAL  — Active mass exploitation / widespread critical incidents
      2 = HIGH      — Multiple critical events, active APT campaigns detected
      3 = ELEVATED  — Notable threats; heightened monitoring required
      4 = GUARDED   — Standard elevated awareness
      5 = LOW       — Normal operating baseline
    """
    from datetime import timedelta as _td
    cutoff_24h = datetime.utcnow() - _td(hours=24)
    cutoff_7d  = datetime.utcnow() - _td(days=7)

    critical_news = await db.scalar(
        select(func.count()).select_from(NewsItem)
        .where(NewsItem.severity == "CRITICAL")
        .where(NewsItem.published_at >= cutoff_24h)
    ) or 0
    high_news = await db.scalar(
        select(func.count()).select_from(NewsItem)
        .where(NewsItem.severity == "HIGH")
        .where(NewsItem.published_at >= cutoff_24h)
    ) or 0
    active_actors = await db.scalar(
        select(func.count()).select_from(ThreatActor)
        .where(ThreatActor.last_activity >= cutoff_7d)
    ) or 0

    # Score accumulation — higher = higher threat
    score = 0
    if critical_news >= 10:  score += 5
    elif critical_news >= 5: score += 4
    elif critical_news >= 2: score += 3
    elif critical_news >= 1: score += 2
    if high_news >= 20:      score += 2
    elif high_news >= 5:     score += 1
    if active_actors >= 5:   score += 2
    elif active_actors >= 2: score += 1

    if score >= 8:   level = 1
    elif score >= 5: level = 2
    elif score >= 3: level = 3
    elif score >= 1: level = 4
    else:            level = 5

    labels = {1: "CRITICAL", 2: "HIGH", 3: "ELEVATED", 4: "GUARDED", 5: "LOW"}
    descriptions = {
        1: "Active mass exploitation detected. Immediate response required.",
        2: "Multiple critical incidents. Active APT campaign in progress.",
        3: "Elevated threat activity. Increased monitoring advised.",
        4: "Guarded posture. Standard heightened awareness.",
        5: "Normal baseline. No significant active threats detected.",
    }
    return {
        "level":             level,
        "label":             labels[level],
        "description":       descriptions[level],
        "critical_news_24h": critical_news,
        "high_news_24h":     high_news,
        "active_actors_7d":  active_actors,
        "score":             score,
        "updated_at":        datetime.utcnow().isoformat(),
    }


# ── News Feed ────────────────────────────────────────────────────────────────
@app.get("/api/v1/news")
async def get_news(
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(NewsItem).order_by(desc(NewsItem.published_at))
    if severity:
        q = q.where(NewsItem.severity == severity.upper())
    if source:
        q = q.where(NewsItem.source == source)
    if category:
        q = q.where(NewsItem.category == category.lower())
    if search:
        try:
            fts = await db.execute(
                text("SELECT rowid FROM news_fts WHERE news_fts MATCH :q ORDER BY rank"),
                {"q": _sanitize_fts(search)},
            )
            ids = [r[0] for r in fts]
            q = q.where(NewsItem.id.in_(ids)) if ids else q.where(NewsItem.title.ilike(f"%{search}%"))
        except Exception:
            q = q.where(NewsItem.title.ilike(f"%{search}%"))
    q = q.limit(limit).offset(offset)

    result = await db.scalars(q)
    return [_serialize_news(item) for item in result.all()]


def _serialize_news(item: NewsItem) -> dict:
    return {
        "id": item.id,
        "title": item.title,
        "url": item.url,
        "source": item.source,
        "summary": item.summary,
        "published_at": item.published_at.isoformat() if item.published_at else None,
        "severity": item.severity,
        "tags": json.loads(item.tags) if item.tags else [],
        "threat_actors": json.loads(item.threat_actors) if item.threat_actors else [],
        "cve_refs": json.loads(item.cve_refs) if item.cve_refs else [],
        "category": getattr(item, "category", None) or "security",
    }


# ── Threat Actors ─────────────────────────────────────────────────────────────
@app.get("/api/v1/actors")
async def get_actors(
    limit: int = Query(50, le=200),
    search: Optional[str] = Query(None),
    country: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(ThreatActor).order_by(ThreatActor.name)
    if search:
        q = q.where(ThreatActor.name.ilike(f"%{search}%"))
    if country:
        q = q.where(ThreatActor.country == country)
    q = q.limit(limit)
    result = await db.scalars(q)
    return [_serialize_actor(a) for a in result.all()]


def _actor_activity_status(last_activity) -> str:
    if last_activity is None:
        return "dormant"
    delta = datetime.utcnow() - last_activity
    if delta.days <= 7:
        return "active"
    if delta.days <= 30:
        return "resurged"
    return "dormant"


def _serialize_actor(a: ThreatActor) -> dict:
    return {
        "id": a.id,
        "name": a.name,
        "aliases": json.loads(a.aliases) if a.aliases else [],
        "mitre_id": a.mitre_id,
        "country": a.country,
        "description": a.description,
        "motivation": a.motivation,
        "techniques": json.loads(a.techniques) if a.techniques else [],
        "last_activity": a.last_activity.isoformat() if a.last_activity else None,
        "activity_status": _actor_activity_status(a.last_activity),
    }


# ── Correlation Graph ─────────────────────────────────────────────────────────
@app.get("/api/v1/correlation")
async def get_correlation(
    limit: int = Query(25, le=75),
    days_back: int = Query(30, le=180),
    db: AsyncSession = Depends(get_db),
):
    """Return graph nodes and edges linking News ↔ Threat Actors."""
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=days_back)
    news_items = (await db.scalars(
        select(NewsItem)
        .where(NewsItem.published_at >= cutoff)
        .order_by(desc(NewsItem.published_at))
        .limit(limit)
    )).all()

    nodes: list[dict] = []
    edges: list[dict] = []
    seen_actors: dict[str, str] = {}
    seen_edge_keys: set[tuple] = set()

    def add_edge(src: str, tgt: str, etype: str):
        key = (src, tgt)
        if key not in seen_edge_keys:
            seen_edge_keys.add(key)
            edges.append({"id": f"{src}__{tgt}", "source": src, "target": tgt, "type": etype})

    for n in news_items:
        nodes.append({
            "id": f"news_{n.id}",
            "node_type": "news",
            "label": n.title[:65] + ("…" if len(n.title) > 65 else ""),
            "severity": n.severity,
            "published_at": n.published_at.isoformat() if n.published_at else None,
        })
        actors = json.loads(n.threat_actors) if n.threat_actors else []
        for actor in actors:
            k = actor.lower()
            seen_actors.setdefault(k, actor)
            add_edge(f"news_{n.id}", f"actor_{k}", "mentions_actor")

    for k, name in seen_actors.items():
        nodes.append({"id": f"actor_{k}", "node_type": "actor", "label": name})

    return {"nodes": nodes, "edges": edges}


# ── AI Correlation Graph ──────────────────────────────────────────────────────

# Cache: keyed by hours_back → (monotonic_ts, result_dict)
_ai_correlation_cache: dict[int, tuple[float, dict]] = {}
_AI_CACHE_TTL = 600.0   # 10 minutes

# In-flight deduplication: prevents multiple simultaneous LLM calls for same key
_ai_correlation_inflight: dict[int, "asyncio.Future[dict]"] = {}


@app.get("/api/v1/correlation/ai")
async def get_ai_correlation(
    hours_back: int = Query(48, le=168),
    force_refresh: bool = Query(False),
    model: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Ask the configured LLM to analyse recent threat intelligence and return a
    structured correlation graph (nodes + edges).  All AI-generated items are
    marked ``verified: false`` so the UI can show a verification badge.

    Results are cached for 10 minutes.  Duplicate simultaneous requests share
    a single in-flight LLM call to avoid hammering Ollama.
    """
    from time import monotonic
    from datetime import timedelta

    # ── Return cached result if still fresh ──────────────────────────────────
    cached = _ai_correlation_cache.get(hours_back)
    if cached and not force_refresh:
        ts, payload = cached
        if monotonic() - ts < _AI_CACHE_TTL:
            return payload

    # ── Deduplicate in-flight requests ────────────────────────────────────────
    # If another request for the same hours_back is already running, wait for it
    if not force_refresh and hours_back in _ai_correlation_inflight:
        try:
            return await asyncio.wait_for(
                asyncio.shield(_ai_correlation_inflight[hours_back]),
                timeout=120.0,
            )
        except Exception:
            pass  # fallthrough if the in-flight request failed

    # Register a future so concurrent requests can share this result
    loop   = asyncio.get_event_loop()
    future: asyncio.Future[dict] = loop.create_future()
    _ai_correlation_inflight[hours_back] = future

    try:
        result = await _build_ai_correlation(hours_back, db, model_override=model)
        _ai_correlation_cache[hours_back] = (monotonic(), result)
        future.set_result(result)
        return result
    except Exception as exc:
        if not future.done():
            future.set_exception(exc)
        raise
    finally:
        _ai_correlation_inflight.pop(hours_back, None)


async def _build_ai_correlation(hours_back: int, db: AsyncSession, model_override: Optional[str] = None) -> dict:
    """Heavy lifting for the AI correlation graph — called once per unique request."""
    from time import monotonic
    from datetime import timedelta
    import re as _re

    cutoff = datetime.utcnow() - timedelta(hours=hours_back)

    news_rows = (await db.scalars(
        select(NewsItem)
        .where(NewsItem.published_at >= cutoff)
        .where(NewsItem.severity.in_(["CRITICAL", "HIGH"]))
        .order_by(desc(NewsItem.published_at))
        .limit(30)
    )).all()

    actor_rows = (await db.scalars(
        select(ThreatActor).order_by(ThreatActor.last_activity.desc().nullslast()).limit(20)
    )).all()

    news_ctx = "\n".join(
        f"- [id:{n.id}][{n.severity}] {n.title[:120]} "
        f"(actors: {', '.join(json.loads(n.threat_actors) if n.threat_actors else []) or 'unknown'})"
        for n in news_rows
    ) or "No recent high-severity news."

    actors_ctx = "\n".join(
        f"- [id:{a.name.lower().replace(' ','_')}] {a.name} ({a.country or 'unknown'}) | "
        + "techniques: " + ", ".join((json.loads(a.techniques) if a.techniques else [])[:5])
        for a in actor_rows
    ) or "No actors in database."

    prompt = f"""\
You are a threat intelligence analyst. Analyse the news and actors below and produce a JSON correlation graph.

=== RECENT HIGH/CRITICAL NEWS (last {hours_back}h) ===
{news_ctx}

=== KNOWN THREAT ACTORS ===
{actors_ctx}

=== OUTPUT RULES ===
Return ONLY a single valid JSON object — no markdown fences, no explanation.
IMPORTANT: Edge "source" and "target" values MUST exactly match an "id" value from your nodes array.
Schema:
{{
  "nodes": [
    {{"id": "unique_snake_case_id", "type": "actor|news|campaign|technique", "label": "max 40 chars", "description": "1 sentence max", "severity": "CRITICAL|HIGH|MEDIUM|INFO"}}
  ],
  "edges": [
    {{"id": "e1", "source": "exact_node_id", "target": "exact_node_id", "label": "max 25 chars", "type": "linked_to|uses_technique|targets|mentioned_in"}}
  ]
}}
Produce 6-10 nodes and 6-14 edges. Make sure every actor and campaign node has at least 2 edges.
Group related nodes: actors link to campaigns they run; campaigns link to techniques used; news items link to relevant actors/campaigns."""

    messages = [
        {"role": "system", "content": "You are a cybersecurity analyst. Output ONLY valid JSON with no markdown formatting."},
        {"role": "user",   "content": prompt},
    ]

    from llm import call_llm
    text, provider = await call_llm(messages, db, temperature=0.1, max_tokens=3500, timeout_s=90.0, json_mode=True, model_override=model_override)

    if not text:
        raise HTTPException(503, "AI provider unavailable — check Ollama status or configure Groq/OpenRouter.")

    # ── Parse LLM JSON ────────────────────────────────────────────────────────
    clean = text.strip()
    if clean.startswith("```"):
        clean = "\n".join(clean.split("\n")[1:])
        clean = clean.rsplit("```", 1)[0].strip()

    graph = None
    # Attempt 1: direct parse
    try:
        graph = json.loads(clean)
    except json.JSONDecodeError:
        pass

    # Attempt 2: extract outermost {} block
    if graph is None:
        match = _re.search(r'\{[\s\S]+\}', clean)
        if match:
            try:
                graph = json.loads(match.group())
            except json.JSONDecodeError:
                pass

    # Attempt 3: repair truncated JSON by closing unclosed brackets
    if graph is None:
        candidate = match.group() if match else clean
        # Find last complete object before a truncated entry
        # Try truncating at the last valid comma-separated item in arrays
        for trim_pat in [r',\s*\{[^}]*$', r',\s*"[^"]*$', r',?\s*\{?\s*$']:
            trimmed = _re.sub(trim_pat, '', candidate)
            # Re-balance brackets
            open_b = trimmed.count('{') - trimmed.count('}')
            open_s = trimmed.count('[') - trimmed.count(']')
            if open_b >= 0 and open_s >= 0:
                repaired = trimmed + (']' * open_s) + ('}' * open_b)
                try:
                    graph = json.loads(repaired)
                    break
                except json.JSONDecodeError:
                    pass

    if graph is None:
        raise HTTPException(422, "LLM returned unparseable JSON — retry in a moment.")

    # ── Validate nodes ────────────────────────────────────────────────────────
    nodes = []
    for n in graph.get("nodes", []):
        if not n.get("id") or not n.get("label"):
            continue
        ntype = n.get("type", "news")
        if ntype not in ("actor", "news", "campaign", "technique"):
            ntype = "news"
        nodes.append({
            "id":           str(n["id"])[:64],
            "type":         ntype,
            "label":        str(n.get("label", ""))[:40],
            "description":  str(n.get("description", ""))[:300],
            "severity":     n.get("severity") if n.get("severity") in ("CRITICAL", "HIGH", "MEDIUM", "INFO") else None,
            "verified":     False,
            "ai_generated": True,
        })

    # ── Validate edges (case-insensitive ID matching) ─────────────────────────
    # Build a lowercase → canonical-id lookup so IDs like "APT29" match "apt29"
    node_id_map: dict[str, str] = {n["id"].lower(): n["id"] for n in nodes}

    edges = []
    seen_edge_pairs: set[tuple[str, str]] = set()
    for e in graph.get("edges", []):
        src_lower = str(e.get("source", "")).lower()
        tgt_lower = str(e.get("target", "")).lower()
        src_id = node_id_map.get(src_lower)
        tgt_id = node_id_map.get(tgt_lower)
        if not src_id or not tgt_id or src_id == tgt_id:
            continue
        pair = (src_id, tgt_id)
        if pair in seen_edge_pairs:
            continue
        seen_edge_pairs.add(pair)
        etype = e.get("type", "linked_to")
        if etype not in ("linked_to", "uses_technique", "targets", "mentioned_in"):
            etype = "linked_to"
        edges.append({
            "id":           str(e.get("id", f"e_{len(edges)}"))[:64],
            "source":       src_id,
            "target":       tgt_id,
            "label":        str(e.get("label", ""))[:25],
            "type":         etype,
            "verified":     False,
            "ai_generated": True,
        })

    return {
        "nodes":        nodes,
        "edges":        edges,
        "provider":     provider or "unknown",
        "hours_back":   hours_back,
        "generated_at": datetime.utcnow().isoformat(),
        "ai_generated": True,
    }


# ── Ollama Streaming Analysis ─────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    item_type: str              # "news" | "cve"
    item_id: int
    model: Optional[str] = None  # None → provider uses its configured default


@app.post("/api/v1/analyze")
async def analyze_item(req: AnalyzeRequest, db: AsyncSession = Depends(get_db)):
    """Stream LLM analysis of a news item or CVE via the provider chain."""
    if not _validate_model(req.model):
        raise HTTPException(400, f"Invalid model name: {req.model!r}")
    if req.item_type == "news":
        item = await db.get(NewsItem, req.item_id)
        if not item:
            raise HTTPException(404, "News item not found")
        prompt = (
            f"You are a cybersecurity analyst. Concisely analyze this threat intelligence:\n\n"
            f"Title: {item.title}\n"
            f"Source: {item.source}\n"
            f"Severity: {item.severity}\n"
            f"Tags: {', '.join(json.loads(item.tags) if item.tags else [])}\n"
            f"Threat Actors: {', '.join(json.loads(item.threat_actors) if item.threat_actors else [])}\n"
            f"CVE References: {', '.join(json.loads(item.cve_refs) if item.cve_refs else [])}\n"
            f"Summary: {item.summary or 'N/A'}\n\n"
            f"Provide a concise analysis: (1) What happened, (2) Who is affected, (3) Recommended actions."
        )
    else:
        raise HTTPException(400, "item_type must be 'news'")

    from llm import stream_llm

    messages = [
        {"role": "system", "content": "You are a cybersecurity analyst. Be concise and operationally focused."},
        {"role": "user",   "content": prompt},
    ]

    async def event_stream():
        async for chunk in stream_llm(messages, db, model_override=req.model, timeout_s=90.0):
            yield chunk

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Campaigns ────────────────────────────────────────────────────────────────
@app.get("/api/v1/campaigns")
async def get_campaigns(days_back: int = Query(30, le=90)):
    """Return actor-grouped campaign timelines reconstructed from news co-occurrence."""
    return await build_campaigns(days_back=days_back)


# In-flight lock so only one AI campaign-discover LLM call runs at a time
_ai_campaign_inflight: dict[int, asyncio.Future] = {}
_ai_campaign_cache: dict[int, tuple[float, dict]] = {}
_AI_CAMPAIGN_TTL = 600.0  # 10 minutes


@app.post("/api/v1/campaigns/ai-discover")
async def ai_discover_campaigns(
    days_back: int = Query(30, le=90),
    db: AsyncSession = Depends(get_db),
):
    """
    Use LLM to detect hidden campaigns from news patterns that don't have
    explicit known-actor attribution. Returns structured hidden-campaign analysis.
    """
    global _ai_campaign_inflight, _ai_campaign_cache
    from time import monotonic

    # Return cached result within TTL (keyed by days_back)
    if days_back in _ai_campaign_cache:
        ts, payload = _ai_campaign_cache[days_back]
        if monotonic() - ts < _AI_CAMPAIGN_TTL:
            return payload

    # Deduplicate concurrent callers for same days_back
    if days_back in _ai_campaign_inflight and not _ai_campaign_inflight[days_back].done():
        return await asyncio.shield(_ai_campaign_inflight[days_back])

    loop = asyncio.get_event_loop()
    fut: asyncio.Future = loop.create_future()
    _ai_campaign_inflight[days_back] = fut

    try:
        cutoff = datetime.utcnow() - timedelta(days=days_back)

        # Pull recent news items — include those WITHOUT known actor attribution
        # (that's where hidden campaigns hide)
        all_news = (await db.scalars(
            select(NewsItem)
            .where(NewsItem.published_at >= cutoff)
            .where(NewsItem.severity.in_(["CRITICAL", "HIGH", "MEDIUM"]))
            .order_by(desc(NewsItem.published_at))
            .limit(60)
        )).all()

        if not all_news:
            result = {"campaigns": [], "note": "No recent news available for analysis."}
            _ai_campaign_cache[days_back] = (monotonic(), result)
            fut.set_result(result)
            return result

        # Build news context — flag items WITHOUT actor attribution
        news_lines = []
        for n in all_news:
            actors = json.loads(n.threat_actors) if n.threat_actors else []
            cves   = json.loads(n.cve_refs)      if n.cve_refs      else []
            actor_str = ", ".join(actors) if actors else "UNATTRIBUTED"
            cve_str   = f" CVEs:{','.join(cves[:3])}" if cves else ""
            news_lines.append(
                f"- [{n.severity}][{actor_str}]{cve_str} {n.title[:140]} "
                f"(src:{n.source}, {n.published_at.strftime('%m/%d') if n.published_at else '?'})"
            )
        news_ctx = "\n".join(news_lines)

        prompt = f"""\
You are a threat intelligence analyst specialising in uncovering hidden campaigns.

Analyse the {len(all_news)} news items below from the last {days_back} days.
Identify HIDDEN or UNNAMED campaigns — coordinated attack patterns that appear across
multiple news items but may not yet have known actor attribution.

Focus especially on UNATTRIBUTED items and look for:
- Shared techniques, targets, or victim sectors across multiple items
- Temporal clustering (multiple events in a short window)
- Common CVEs being exploited across different incidents
- Geographic or industry-specific targeting patterns

=== RECENT THREAT INTELLIGENCE ({days_back}d window) ===
{news_ctx}

=== OUTPUT RULES ===
Return ONLY a single valid JSON object — no markdown fences, no explanation.
Schema:
{{
  "campaigns": [
    {{
      "name": "descriptive campaign name (e.g. 'Healthcare Ransomware Wave Q1 2025')",
      "confidence": "HIGH|MEDIUM|LOW",
      "description": "2-3 sentence summary of the pattern",
      "suspected_actor": "actor name or null if truly unknown",
      "techniques": ["list", "of", "TTPs"],
      "targeted_sectors": ["list of sectors"],
      "key_indicators": ["IOCs or observable patterns"],
      "severity": "CRITICAL|HIGH|MEDIUM|INFO",
      "news_titles": ["up to 4 article titles that support this cluster"]
    }}
  ],
  "analysis_summary": "1-2 sentence overview of the threat landscape"
}}
Produce 3-7 distinct hidden campaigns. Only include well-supported patterns with at least 2 news items."""

        messages = [
            {"role": "system", "content": "You are a senior threat intelligence analyst. Output ONLY valid JSON with no markdown formatting."},
            {"role": "user",   "content": prompt},
        ]

        from llm import call_llm
        text, provider = await call_llm(messages, db, temperature=0.15, max_tokens=3500, timeout_s=90.0, json_mode=True)

        if not text:
            raise HTTPException(503, "AI provider unavailable — check Ollama status.")

        clean = text.strip()
        if clean.startswith("```"):
            clean = "\n".join(clean.split("\n")[1:])
            clean = clean.rsplit("```", 1)[0].strip()

        try:
            parsed = json.loads(clean)
        except json.JSONDecodeError:
            match = _re.search(r'\{[\s\S]+\}', clean)
            if not match:
                raise HTTPException(422, "LLM returned non-JSON response")
            parsed = json.loads(match.group())

        # Validate and normalise
        valid_campaigns = []
        for c in parsed.get("campaigns", []):
            if not c.get("name") or not c.get("description"):
                continue
            valid_campaigns.append({
                "name":             str(c.get("name", ""))[:80],
                "confidence":       c.get("confidence", "MEDIUM") if c.get("confidence") in ("HIGH", "MEDIUM", "LOW") else "MEDIUM",
                "description":      str(c.get("description", ""))[:500],
                "suspected_actor":  (lambda v: v if v and str(v).lower() not in ("null","none","unknown","n/a","") else None)(c.get("suspected_actor")),
                "techniques":       [str(t)[:60] for t in (c.get("techniques") or [])[:8]],
                "targeted_sectors": [str(s)[:40] for s in (c.get("targeted_sectors") or [])[:6]],
                "key_indicators":   [str(i)[:80] for i in (c.get("key_indicators") or [])[:6]],
                "severity":         c.get("severity") if c.get("severity") in ("CRITICAL", "HIGH", "MEDIUM", "INFO") else "MEDIUM",
                "news_titles":      [str(t)[:120] for t in (c.get("news_titles") or [])[:4]],
            })

        result = {
            "campaigns":        valid_campaigns,
            "analysis_summary": str(parsed.get("analysis_summary", ""))[:400],
            "provider":         provider,
            "generated_at":     datetime.utcnow().isoformat(),
            "days_back":        days_back,
            "news_analyzed":    len(all_news),
        }
        _ai_campaign_cache[days_back] = (monotonic(), result)
        fut.set_result(result)
        return result

    except Exception as exc:
        if not fut.done():
            fut.set_exception(exc)
        raise
    finally:
        if _ai_campaign_inflight.get(days_back) is fut:
            del _ai_campaign_inflight[days_back]


# ── AI Analyst (v2.0.0) ──────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str
    model: Optional[str] = None   # None → provider chain picks default
    hours_back: int = 24


class BriefingRequest(BaseModel):
    model: Optional[str] = None


@app.get("/api/v1/ollama/setup-status")
async def ollama_setup_status():
    """Return current Ollama bootstrap stage (install / serve / pull / ready / error)."""
    from ollama_manager import setup_status
    return setup_status


_ai_status_cache: tuple[float, dict] | None = None
_AI_STATUS_TTL = 30.0  # seconds — avoids hammering Ollama /api/tags on every render


@app.get("/api/v1/ai/status")
async def ai_status(db: AsyncSession = Depends(get_db)):
    """Check provider chain availability and return threat context summary.
    Result is cached for 30 s to prevent Ollama /api/tags saturation."""
    global _ai_status_cache
    from time import monotonic
    if _ai_status_cache:
        ts, payload = _ai_status_cache
        if monotonic() - ts < _AI_STATUS_TTL:
            return payload

    from llm import get_provider_status, fetch_available_models, get_active_provider
    ctx               = await build_threat_context(db, hours_back=24)
    provider_statuses = await get_provider_status(db)
    active_provider   = await get_active_provider(db)
    available_models  = await fetch_available_models(db)
    ollama_ok         = any(p["available"] for p in provider_statuses if p["provider"] == "ollama")
    from ollama_manager import OLLAMA_HOST
    result = {
        "ollama_reachable": ollama_ok,
        "ollama_host":      OLLAMA_HOST,
        "available_models": available_models,
        "active_provider":  active_provider,
        "providers":        provider_statuses,
        "context": {
            "news_24h":      ctx["total_news"],
            "critical_24h":  ctx["total_critical"],
            "ioc_total":     ctx["total_iocs"],
            "kev_total":     ctx["kev_count"],
            "active_actors": ctx["active_actors"],
        },
    }
    _ai_status_cache = (monotonic(), result)
    return result


@app.post("/api/v1/ai/chat")
async def ai_chat(req: ChatRequest, db: AsyncSession = Depends(get_db)):
    """Stream a chat response from the AI analyst with injected live threat context."""
    if not _validate_model(req.model):
        raise HTTPException(400, f"Invalid model name: {req.model!r}")
    if not req.message.strip():
        raise HTTPException(400, "message cannot be empty")

    ctx = await build_threat_context(db, hours_back=max(1, min(req.hours_back, 72)))

    async def event_stream():
        async for chunk in stream_ollama(req.message, ctx, db, model=req.model):
            yield chunk

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/v1/ai/briefing/generate")
async def trigger_briefing(req: BriefingRequest, db: AsyncSession = Depends(get_db)):
    """Generate a new threat intelligence briefing (non-streaming, stores in DB)."""
    if not _validate_model(req.model):
        raise HTTPException(400, f"Invalid model name: {req.model!r}")
    briefing = await _gen_briefing(db, model=req.model)
    return _serialize_briefing(briefing)


@app.get("/api/v1/ai/briefing")
async def get_latest_briefing(db: AsyncSession = Depends(get_db)):
    """Return the most recently generated briefing."""
    row = await db.scalar(
        select(AiBriefing).order_by(desc(AiBriefing.generated_at)).limit(1)
    )
    if not row:
        return {"briefing": None}
    return {"briefing": _serialize_briefing(row)}


@app.get("/api/v1/ai/briefings")
async def list_briefings(
    limit: int = Query(10, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Return list of past briefings (content excluded for list view)."""
    rows = (await db.scalars(
        select(AiBriefing)
        .order_by(desc(AiBriefing.generated_at))
        .limit(limit)
    )).all()
    return [_serialize_briefing(b, include_content=False) for b in rows]


@app.get("/api/v1/ai/context")
async def get_threat_context(
    hours_back: int = Query(24, le=72),
    db: AsyncSession = Depends(get_db),
):
    """Return the raw threat context that will be injected into AI prompts."""
    return await build_threat_context(db, hours_back=hours_back)


# ── Ollama Model Management ───────────────────────────────────────────────────

class ModelPullRequest(BaseModel):
    model: str   # e.g. "llama3.2:3b"

@app.get("/api/v1/ollama/models")
async def list_ollama_models(db: AsyncSession = Depends(get_db)):
    """Return all models currently installed on the Ollama server."""
    ollama_host = await _get_setting(db, "OLLAMA_HOST", "http://localhost:11434")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{ollama_host.rstrip('/')}/api/tags")
        if r.status_code != 200:
            raise HTTPException(502, f"Ollama returned HTTP {r.status_code}")
        raw_models = r.json().get("models", [])
        return [
            {
                "name":        m.get("name", ""),
                "size_gb":     round(m.get("size", 0) / 1_073_741_824, 2),
                "modified_at": m.get("modified_at", ""),
                "digest":      m.get("digest", "")[:12],
                "details":     m.get("details", {}),
            }
            for m in raw_models
        ]
    except httpx.ConnectError:
        raise HTTPException(503, "Ollama not reachable")


@app.post("/api/v1/ollama/pull")
async def pull_ollama_model(req: ModelPullRequest, db: AsyncSession = Depends(get_db)):
    """
    Stream a model pull from Ollama registry.
    Yields SSE events: {"status": str, "completed": int, "total": int, "done": bool}
    """
    # Basic model name validation — only alphanumeric, colon, dash, dot, slash
    import re
    if not re.match(r'^[\w.:\-/]+$', req.model) or len(req.model) > 200:
        raise HTTPException(400, "Invalid model name")

    ollama_host = await _get_setting(db, "OLLAMA_HOST", "http://localhost:11434")

    async def event_stream():
        url = f"{ollama_host.rstrip('/')}/api/pull"
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(3600.0, connect=5.0)) as client:
                async with client.stream("POST", url, json={"name": req.model, "stream": True}) as resp:
                    if resp.status_code != 200:
                        body = await resp.aread()
                        msg = body.decode()[:200]
                        yield f"data: {json.dumps({'status': f'Error: {msg}', 'done': True, 'error': True})}\n\n"
                        return
                    async for line in resp.aiter_lines():
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line)
                            status    = chunk.get("status", "")
                            completed = chunk.get("completed", 0)
                            total     = chunk.get("total", 0)
                            done      = status in ("success", "already exists")
                            yield f"data: {json.dumps({'status': status, 'completed': completed, 'total': total, 'done': done})}\n\n"
                            if done:
                                break
                        except json.JSONDecodeError:
                            pass
        except httpx.ConnectError:
            yield f"data: {json.dumps({'status': 'Ollama not reachable', 'done': True, 'error': True})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'status': f'Pull error: {e}', 'done': True, 'error': True})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.delete("/api/v1/ollama/models/{model_name:path}")
async def delete_ollama_model(model_name: str, db: AsyncSession = Depends(get_db)):
    """Delete a model from the local Ollama installation."""
    import re
    if not re.match(r'^[\w.:\-/]+$', model_name) or len(model_name) > 200:
        raise HTTPException(400, "Invalid model name")
    ollama_host = await _get_setting(db, "OLLAMA_HOST", "http://localhost:11434")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.request("DELETE", f"{ollama_host.rstrip('/')}/api/delete",
                                     json={"name": model_name})
        if r.status_code not in (200, 204):
            raise HTTPException(r.status_code, f"Ollama delete failed: {r.text[:200]}")
        return {"deleted": model_name}
    except httpx.ConnectError:
        raise HTTPException(503, "Ollama not reachable")


def _serialize_briefing(b: AiBriefing, include_content: bool = True) -> dict:
    return {
        "id":           b.id,
        "generated_at": b.generated_at.isoformat() if b.generated_at else None,
        "model_used":   b.model_used,
        "news_count":   b.news_count,
        "top_severity": b.top_severity,
        "threat_actors": json.loads(b.threat_actors) if b.threat_actors else [],
        **({"content": b.content} if include_content else {}),
    }


# ── Settings ─────────────────────────────────────────────────────────────────
# Keys that may be read back (non-secret display names).
_PUBLIC_KEYS = {"OLLAMA_HOST", "WEBHOOK_URL", "WEBHOOK_MIN_SEVERITY", "AI_MODEL",
                "LLM_API_URL", "LLM_MODEL", "TELEGRAM_CHAT_ID"}
# Secret keys — existence is confirmed but value is masked.
_SECRET_KEYS = {"OTX_API_KEY", "ABUSECH_API_KEY",
                "GROQ_API_KEY", "OPENROUTER_API_KEY", "LLM_API_KEY",
                "TELEGRAM_BOT_TOKEN"}
_ALL_KNOWN_KEYS = _PUBLIC_KEYS | _SECRET_KEYS


class SettingUpdate(BaseModel):
    key: str
    value: str


@app.get("/api/v1/settings")
async def get_settings(db: AsyncSession = Depends(get_db)):
    rows = (await db.scalars(select(SettingItem))).all()
    result = {}
    for row in rows:
        if row.key in _SECRET_KEYS:
            result[row.key] = "••••••••" if row.value else ""
        else:
            result[row.key] = row.value
    # Fill missing keys with empty string so the UI knows they exist
    for k in _ALL_KNOWN_KEYS:
        result.setdefault(k, "")
    return result


@app.post("/api/v1/settings")
async def upsert_setting(body: SettingUpdate, db: AsyncSession = Depends(get_db)):
    if body.key not in _ALL_KNOWN_KEYS:
        raise HTTPException(400, f"Unknown setting key: {body.key}")
    existing = await db.get(SettingItem, body.key)
    if existing:
        existing.value = body.value
        existing.updated_at = datetime.utcnow()
    else:
        db.add(SettingItem(key=body.key, value=body.value))
    await db.commit()
    # Apply runtime effect
    if body.key == "OTX_API_KEY":
        import os; os.environ["OTX_API_KEY"] = body.value
    elif body.key == "ABUSECH_API_KEY":
        import os; os.environ["ABUSECH_API_KEY"] = body.value
        try:
            import collectors.abusech_collector as _ac
            _ac.ABUSECH_API_KEY = body.value or None
        except Exception:
            pass
    elif body.key in ("GROQ_API_KEY", "OPENROUTER_API_KEY", "LLM_API_KEY", "LLM_API_URL", "LLM_MODEL",
                       "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        import os; os.environ[body.key] = body.value
    return {"status": "saved", "key": body.key}


# ── Source Health ─────────────────────────────────────────────────────────────
@app.get("/api/v1/source-health")
async def source_health(db: AsyncSession = Depends(get_db)):
    """Return last fetched timestamp and item count per news source."""
    result = await db.execute(
        text("""
            SELECT source,
                   MAX(fetched_at) as last_fetch,
                   COUNT(*) as item_count,
                   SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_count
            FROM news_items
            GROUP BY source
            ORDER BY last_fetch DESC
        """)
    )
    rows = result.fetchall()
    return [
        {
            "source": r[0],
            "last_fetch": r[1],
            "item_count": r[2],
            "critical_count": r[3],
        }
        for r in rows
    ]


# ── Collector Status ──────────────────────────────────────────────────────────
@app.get("/api/v1/collect/status")
async def collect_status():
    """Return last-run time, count, and error state per collector."""
    from scheduler import get_collector_status
    return get_collector_status()


# ── Alert Log ─────────────────────────────────────────────────────────────────
@app.get("/api/v1/alert-log")
async def get_alert_log(
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
):
    from database import AlertLog
    result = await db.scalars(
        select(AlertLog).order_by(desc(AlertLog.fired_at)).limit(limit)
    )
    rows = result.all()
    return [
        {
            "id": r.id,
            "fired_at": r.fired_at.isoformat() if r.fired_at else None,
            "item_type": r.item_type,
            "count": r.count,
            "top_severity": r.top_severity,
            "webhook_url": r.webhook_url,
            "success": r.success,
            "sample_title": r.sample_title,
        }
        for r in rows
    ]


# ── Settings Test Connection ──────────────────────────────────────────────────
class TestRequest(BaseModel):
    key: str   # OLLAMA_HOST or WEBHOOK_URL


@app.post("/api/v1/settings/test")
async def test_setting(body: TestRequest, db: AsyncSession = Depends(get_db)):
    """Test connectivity for OLLAMA_HOST or WEBHOOK_URL settings."""
    if body.key == "OLLAMA_HOST":
        host = await _get_setting(db, "OLLAMA_HOST", "http://localhost:11434")
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"{host.rstrip('/')}/api/tags")
            models = r.json().get("models", [])
            return {"ok": True, "message": f"Ollama reachable — {len(models)} model(s) available"}
        except Exception as e:
            return {"ok": False, "message": f"Cannot reach Ollama: {e}"}
    elif body.key == "WEBHOOK_URL":
        url = await _get_setting(db, "WEBHOOK_URL")
        if not url:
            return {"ok": False, "message": "No webhook URL configured"}
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.post(url, json={"type": "test", "source": "SIGINTX"})
            return {"ok": True, "message": f"Webhook responded with HTTP {r.status_code}"}
        except Exception as e:
            return {"ok": False, "message": f"Webhook unreachable: {e}"}
    else:
        raise HTTPException(400, "key must be OLLAMA_HOST or WEBHOOK_URL")


# ── RSS Feed Management ───────────────────────────────────────────────────────

class FeedCreate(BaseModel):
    name: str
    url:  str

class FeedUpdate(BaseModel):
    enabled: bool

@app.get("/api/v1/feeds")
async def list_feeds(db: AsyncSession = Depends(get_db)):
    rows = (await db.scalars(select(RssFeed).order_by(RssFeed.name))).all()
    return [_serialize_feed(r) for r in rows]

@app.post("/api/v1/feeds", status_code=201)
async def add_feed(body: FeedCreate, db: AsyncSession = Depends(get_db)):
    if not body.url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    exists = await db.scalar(select(RssFeed).where(RssFeed.url == body.url))
    if exists:
        raise HTTPException(409, "Feed with this URL already exists")
    feed = RssFeed(name=body.name.strip()[:128], url=body.url.strip()[:1024])
    db.add(feed)
    await db.commit()
    await db.refresh(feed)
    return _serialize_feed(feed)

@app.patch("/api/v1/feeds/{feed_id}")
async def update_feed(feed_id: int, body: FeedUpdate, db: AsyncSession = Depends(get_db)):
    feed = await db.get(RssFeed, feed_id)
    if not feed:
        raise HTTPException(404, "Feed not found")
    feed.enabled = body.enabled
    await db.commit()
    return _serialize_feed(feed)

@app.delete("/api/v1/feeds/{feed_id}", status_code=204)
async def delete_feed(feed_id: int, db: AsyncSession = Depends(get_db)):
    feed = await db.get(RssFeed, feed_id)
    if not feed:
        raise HTTPException(404, "Feed not found")
    await db.delete(feed)
    await db.commit()

@app.post("/api/v1/feeds/reset")
async def reset_feeds(db: AsyncSession = Depends(get_db)):
    """Delete all custom feeds and re-seed from defaults."""
    await db.execute(text("DELETE FROM rss_feeds"))
    await db.commit()
    from collectors.rss_collector import RSS_FEEDS, seed_default_feeds
    await seed_default_feeds()
    return {"status": "reset", "count": len(RSS_FEEDS)}

def _serialize_feed(f: RssFeed) -> dict:
    return {
        "id":         f.id,
        "name":       f.name,
        "url":        f.url,
        "enabled":    f.enabled,
        "added_at":   f.added_at.isoformat() if f.added_at else None,
        "last_fetch": f.last_fetch.isoformat() if f.last_fetch else None,
        "item_count": f.item_count,
    }


# ── AI Chat History ───────────────────────────────────────────────────────────

class SaveMessageRequest(BaseModel):
    session_id: str
    role:       str   # user | assistant
    content:    str
    model_used: Optional[str] = None

@app.get("/api/v1/ai/chat/history")
async def get_chat_history(
    session_id: str,
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.scalars(
        select(AiChatMessage)
        .where(AiChatMessage.session_id == session_id)
        .order_by(AiChatMessage.created_at)
        .limit(limit)
    )).all()
    return [
        {
            "id":         r.id,
            "role":       r.role,
            "content":    r.content,
            "model_used": r.model_used,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]

@app.post("/api/v1/ai/chat/history", status_code=201)
async def save_chat_message(body: SaveMessageRequest, db: AsyncSession = Depends(get_db)):
    if body.role not in ("user", "assistant"):
        raise HTTPException(400, "role must be 'user' or 'assistant'")
    if not body.session_id.strip() or not body.content.strip():
        raise HTTPException(400, "session_id and content are required")
    msg = AiChatMessage(
        session_id = body.session_id[:64],
        role       = body.role,
        content    = body.content,
        model_used = body.model_used,
    )
    db.add(msg)
    await db.commit()
    return {"status": "saved", "id": msg.id}

@app.delete("/api/v1/ai/chat/history/{session_id}", status_code=204)
async def clear_chat_history(session_id: str, db: AsyncSession = Depends(get_db)):
    await db.execute(
        text("DELETE FROM ai_chat_messages WHERE session_id = :sid"),
        {"sid": session_id},
    )
    await db.commit()

@app.get("/api/v1/ai/chat/sessions")
async def list_chat_sessions(
    limit: int = Query(20, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Return list of distinct session IDs with latest message timestamp."""
    rows = await db.execute(text("""
        SELECT session_id, MAX(created_at) as last_active, COUNT(*) as msg_count
        FROM ai_chat_messages
        GROUP BY session_id
        ORDER BY last_active DESC
        LIMIT :limit
    """), {"limit": limit})
    return [
        {"session_id": r[0], "last_active": r[1], "msg_count": r[2]}
        for r in rows
    ]


# ── AI Briefing Streaming ─────────────────────────────────────────────────────
@app.post("/api/v1/ai/briefing/stream")
async def stream_briefing_endpoint(req: BriefingRequest, db: AsyncSession = Depends(get_db)):
    """Stream briefing generation token-by-token as SSE, then persist to DB."""
    if not _validate_model(req.model):
        raise HTTPException(400, f"Invalid model name: {req.model!r}")

    async def event_stream():
        async for chunk in _stream_briefing(db, model=req.model):
            yield chunk

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Agentic chat (Sprint 3) ───────────────────────────────────────────────────

@app.post("/api/v1/ai/agent/chat")
async def ai_agent_chat(req: ChatRequest, db: AsyncSession = Depends(get_db)):
    """
    Multi-turn agentic chat: the model may invoke DB tools in a ReAct loop
    before producing a final answer.

    SSE event types:
      {"type": "tool_call",   "name": str, "args": dict}
      {"type": "tool_result", "name": str, "text": str}
      {"type": "text",        "text": str}   ← token chunks of final answer
      {"type": "done"}
      {"type": "error",       "text": str}
    """
    if not _validate_model(req.model):
        raise HTTPException(400, f"Invalid model name: {req.model!r}")
    if not req.message.strip():
        raise HTTPException(400, "message cannot be empty")

    async def event_stream():
        async for chunk in agentic_stream(req.message, db, model=req.model):
            yield chunk

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/v1/ai/delta")
async def get_threat_delta(
    hours_back: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
):
    """
    Compare the current threat window to the prior baseline of equal length.
    Returns counts, percentage changes, new actors, new malware families.
    """
    return await compute_delta(db, hours_back=hours_back)


# ── Manual trigger endpoints ──────────────────────────────────────────────────
@app.post("/api/v1/collect/rss")
async def trigger_rss():
    _assert_rate_limit("rss")
    asyncio.create_task(_run_rss_task())
    return {"status": "triggered", "job": "rss_collector"}


@app.post("/api/v1/collect/ransomwatch")
async def trigger_ransomwatch():
    _assert_rate_limit("ransomwatch")
    asyncio.create_task(_run_ransomwatch_task())
    return {"status": "triggered", "job": "ransomwatch_collector"}


async def _run_rss_task():
    count = await collect_all_rss()
    await rebuild_fts()
    await manager.broadcast({"type": "rss_update", "new_items": count})


async def _run_ransomwatch_task():
    count = await collect_ransomwatch()
    await rebuild_fts()
    await manager.broadcast({"type": "rss_update", "new_items": count})


@app.post("/api/v1/collect/shodan")
async def trigger_shodan():
    _assert_rate_limit("shodan")
    asyncio.create_task(_run_shodan_task())
    return {"status": "triggered", "job": "shodan_scan"}


async def _run_shodan_task():
    count = await scan_assets()
    await rebuild_fts()
    if count > 0:
        await manager.broadcast({"type": "rss_update", "new_items": count})


# ── Asset CRUD ────────────────────────────────────────────────────────────────

class AssetCreate(BaseModel):
    name: str
    asset_type: str          # ip | domain | cidr | asn
    value: str
    description: Optional[str] = None
    monitor_shodan: bool = True


class AssetPatch(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    monitor_shodan: Optional[bool] = None


def _serialize_asset(a: Asset) -> dict:
    return {
        "id":             a.id,
        "name":           a.name,
        "asset_type":     a.asset_type,
        "value":          a.value,
        "description":    a.description,
        "monitor_shodan": a.monitor_shodan,
        "last_scanned":   a.last_scanned.isoformat() if a.last_scanned else None,
        "open_ports":     json.loads(a.open_ports)     if a.open_ports     else [],
        "vulns_detected": json.loads(a.vulns_detected) if a.vulns_detected else [],
        "tags":           json.loads(a.tags)           if a.tags           else [],
        "risk_score":     a.risk_score,
        "created_at":     a.created_at.isoformat()     if a.created_at     else None,
    }


@app.get("/api/v1/assets")
async def list_assets(db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(Asset).order_by(Asset.name))
    return [_serialize_asset(a) for a in rows.all()]


@app.post("/api/v1/assets", status_code=201)
async def create_asset(body: AssetCreate, db: AsyncSession = Depends(get_db)):
    asset = Asset(
        name=body.name,
        asset_type=body.asset_type,
        value=body.value,
        description=body.description,
        monitor_shodan=body.monitor_shodan,
    )
    db.add(asset)
    try:
        await db.commit()
        await db.refresh(asset)
    except Exception:
        await db.rollback()
        raise HTTPException(409, "Asset with this value already exists")
    return _serialize_asset(asset)


@app.patch("/api/v1/assets/{asset_id}")
async def patch_asset(asset_id: int, body: AssetPatch, db: AsyncSession = Depends(get_db)):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    if body.name is not None:
        asset.name = body.name
    if body.description is not None:
        asset.description = body.description
    if body.monitor_shodan is not None:
        asset.monitor_shodan = body.monitor_shodan
    await db.commit()
    await db.refresh(asset)
    return _serialize_asset(asset)


@app.delete("/api/v1/assets/{asset_id}", status_code=204)
async def delete_asset(asset_id: int, db: AsyncSession = Depends(get_db)):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    await db.delete(asset)
    await db.commit()


# ── Watchlists (Sprint 5) ─────────────────────────────────────────────────────

class WatchlistCreate(BaseModel):
    name:            str
    description:     Optional[str] = None
    conditions:      str           # JSON string
    notify_webhook:  bool = True


class WatchlistPatch(BaseModel):
    name:           Optional[str]  = None
    description:    Optional[str]  = None
    conditions:     Optional[str]  = None
    enabled:        Optional[bool] = None
    notify_webhook: Optional[bool] = None


def _serialize_watchlist(w) -> dict:
    return {
        "id":             w.id,
        "name":           w.name,
        "description":    w.description,
        "conditions":     json.loads(w.conditions) if w.conditions else {},
        "enabled":        w.enabled,
        "notify_webhook": w.notify_webhook,
        "created_at":     w.created_at.isoformat() if w.created_at else None,
        "last_checked":   w.last_checked.isoformat() if w.last_checked else None,
        "last_hit":       w.last_hit.isoformat() if w.last_hit else None,
        "hit_count":      w.hit_count,
    }


@app.get("/api/v1/watchlists")
async def list_watchlists(db: AsyncSession = Depends(get_db)):
    from database import Watchlist
    rows = (await db.scalars(select(Watchlist).order_by(Watchlist.name))).all()
    return [_serialize_watchlist(w) for w in rows]


@app.post("/api/v1/watchlists", status_code=201)
async def create_watchlist(body: WatchlistCreate, db: AsyncSession = Depends(get_db)):
    from database import Watchlist
    # Validate conditions is valid JSON
    try:
        json.loads(body.conditions)
    except json.JSONDecodeError:
        raise HTTPException(400, "conditions must be valid JSON")
    w = Watchlist(
        name=body.name,
        description=body.description,
        conditions=body.conditions,
        notify_webhook=body.notify_webhook,
    )
    db.add(w)
    await db.commit()
    await db.refresh(w)
    return _serialize_watchlist(w)


@app.patch("/api/v1/watchlists/{wl_id}")
async def update_watchlist(wl_id: int, body: WatchlistPatch, db: AsyncSession = Depends(get_db)):
    from database import Watchlist
    w = await db.get(Watchlist, wl_id)
    if not w:
        raise HTTPException(404, "Watchlist not found")
    if body.name           is not None: w.name = body.name
    if body.description    is not None: w.description = body.description
    if body.conditions     is not None:
        try: json.loads(body.conditions)
        except json.JSONDecodeError: raise HTTPException(400, "conditions must be valid JSON")
        w.conditions = body.conditions
    if body.enabled        is not None: w.enabled = body.enabled
    if body.notify_webhook is not None: w.notify_webhook = body.notify_webhook
    await db.commit()
    await db.refresh(w)
    return _serialize_watchlist(w)


@app.delete("/api/v1/watchlists/{wl_id}", status_code=204)
async def delete_watchlist(wl_id: int, db: AsyncSession = Depends(get_db)):
    from database import Watchlist
    w = await db.get(Watchlist, wl_id)
    if not w:
        raise HTTPException(404, "Watchlist not found")
    await db.delete(w)
    await db.commit()


# ── Audit Log (Sprint 5) ──────────────────────────────────────────────────────

@app.get("/api/v1/audit-log")
async def get_audit_log(
    limit:  int = Query(100, le=500),
    action: Optional[str] = Query(None),
    actor:  Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    from database import AuditLog
    q = select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit)
    if action: q = q.where(AuditLog.action.ilike(f"%{action}%"))
    if actor:  q = q.where(AuditLog.actor == actor)
    rows = (await db.scalars(q)).all()
    return [
        {
            "id":          r.id,
            "timestamp":   r.timestamp.isoformat() if r.timestamp else None,
            "action":      r.action,
            "actor":       r.actor,
            "entity_type": r.entity_type,
            "entity_id":   r.entity_id,
            "details":     json.loads(r.details) if r.details else None,
            "ip_address":  r.ip_address,
        }
        for r in rows
    ]


# ── Session Logs ──────────────────────────────────────────────────────────────

@app.get("/api/v1/logs")
async def get_session_logs(
    limit: int  = Query(200, le=2000, description="Max entries to return (newest last)"),
    level: Optional[str] = Query(None, description="Filter by level: DEBUG|INFO|WARNING|ERROR|CRITICAL"),
):
    """
    Returns recent log entries from the in-memory ring buffer.
    Captures all backend Python logging output + every HTTP request timing.
    """
    return get_recent_logs(limit=limit, level=level)


@app.get("/api/v1/logs/stream")
async def stream_session_logs():
    """
    SSE endpoint that pushes new log entries as they arrive.
    Polls the ring buffer every second and emits any entries newer than the
    last one seen by this client.
    """
    import asyncio as _asyncio

    async def event_gen():
        last_idx = len(get_recent_logs(limit=2000))
        try:
            while True:
                await _asyncio.sleep(1)
                current = get_recent_logs(limit=2000)
                new_entries = current[last_idx:]
                last_idx = len(current)
                for entry in new_entries:
                    yield f"data: {json.dumps(entry)}\n\n"
        except _asyncio.CancelledError:
            pass

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
