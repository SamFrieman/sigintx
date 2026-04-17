"""
SIGINTX — Pipeline Scheduler

Production mode (REDIS_URL set):
    Scheduling is handled entirely by Celery Beat + the `tasks` module.
    This module is a no-op — create_scheduler() returns None and the
    main.py lifespan skips starting APScheduler.

Local dev mode (REDIS_URL absent):
    Falls back to APScheduler so you can run with just `uvicorn main:app`
    and no Redis / Celery dependency.
"""
import logging
import os
from datetime import datetime

logger = logging.getLogger("sigintx.scheduler")

REDIS_URL: str = os.getenv("REDIS_URL", "")

# Broadcast callback — set by main.py when in APScheduler (dev) mode.
_broadcast_fn = None

# In-memory collector status — updated each time a collector runs.
_collector_status: dict[str, dict] = {}


def set_broadcast(fn):
    global _broadcast_fn
    _broadcast_fn = fn


def _record_run(name: str, count: int | None = None, error: str | None = None) -> None:
    """Update in-memory status for a named collector."""
    _collector_status[name] = {
        "last_run": datetime.utcnow().isoformat(),
        "last_count": count,
        "error": error,
        "status": "error" if error else "ok",
    }


def get_collector_status() -> list[dict]:
    """Return collector status list for the /collect/status endpoint."""
    return [{"name": k, **v} for k, v in _collector_status.items()]


# ── APScheduler job implementations (dev mode only) ──────────────────────────

async def _run_rss():
    from collectors import collect_all_rss
    from database import rebuild_fts
    try:
        count = await collect_all_rss()
        await rebuild_fts()
        _record_run("RSS", count)
        if _broadcast_fn and count > 0:
            await _broadcast_fn({"type": "rss_update", "new_items": count})
    except Exception as e:
        _record_run("RSS", error=str(e))
        raise



async def _run_ransomwatch():
    from collectors import collect_ransomwatch
    from database import rebuild_fts
    try:
        count = await collect_ransomwatch()
        await rebuild_fts()
        _record_run("RansomWatch", count)
        if _broadcast_fn and count > 0:
            await _broadcast_fn({"type": "rss_update", "new_items": count})
    except Exception as e:
        _record_run("RansomWatch", error=str(e))
        raise



async def _run_briefing():
    """Auto-generate a threat briefing using the configured AI provider."""
    try:
        from database import SessionLocal
        from agents import generate_briefing
        from llm import get_active_provider
        async with SessionLocal() as db:
            active = await get_active_provider(db)
            if not active:
                logger.debug("Scheduled briefing skipped: no AI provider available")
                return
            await generate_briefing(db)
        if _broadcast_fn:
            await _broadcast_fn({"type": "briefing_ready"})
        logger.info("Scheduled briefing generated (provider=%s)", active)
    except Exception as e:
        logger.warning("Scheduled briefing skipped: %s", e)



async def _run_alert_rules():
    try:
        from rules_engine import run_scheduled_rules
        await run_scheduled_rules()
    except Exception as e:
        logger.warning("Alert rules evaluation failed: %s", e)


# ── Scheduler factory ─────────────────────────────────────────────────────────

def create_scheduler():
    """
    Always return an APScheduler instance.

    APScheduler runs inside the uvicorn event loop — no separate Celery worker
    needed. Redis (when present) is used only for WebSocket pub/sub broadcasting,
    not for task scheduling.
    """
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.interval import IntervalTrigger

    scheduler = AsyncIOScheduler()

    scheduler.add_job(_run_rss,         IntervalTrigger(minutes=3),  id="rss",         max_instances=1, replace_existing=True)
    scheduler.add_job(_run_ransomwatch, IntervalTrigger(minutes=10), id="ransomwatch", max_instances=1, replace_existing=True)
    scheduler.add_job(_run_briefing,    IntervalTrigger(hours=1),    id="briefing",    max_instances=1, replace_existing=True)
    scheduler.add_job(_run_alert_rules, IntervalTrigger(minutes=5),  id="alert_rules", max_instances=1, replace_existing=True)

    logger.info("APScheduler started (RSS=3m, RansomWatch=10m, Briefing=1h, Rules=5m)")
    return scheduler
