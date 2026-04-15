"""
SIGINTX — Celery tasks
Each collector function is wrapped in asyncio.run() so the existing
async codebase runs unchanged inside a synchronous Celery worker.

After collection, tasks publish a broadcast message to the Redis
channel ``sigintx:broadcast`` so the FastAPI process can forward
the event to connected WebSocket clients.
"""
import asyncio
import json
import logging
import os

import redis as _sync_redis

from celery_app import app

logger = logging.getLogger("sigintx.tasks")

REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
BROADCAST_CHANNEL = "sigintx:broadcast"

# ── Redis publish helper ──────────────────────────────────────────────────────

_redis_client: _sync_redis.Redis | None = None


def _get_redis() -> _sync_redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = _sync_redis.from_url(REDIS_URL, decode_responses=True)
    return _redis_client


def _broadcast(payload: dict) -> None:
    """Publish *payload* to the Redis broadcast channel (fire-and-forget)."""
    try:
        _get_redis().publish(BROADCAST_CHANNEL, json.dumps(payload))
    except Exception as exc:
        logger.warning("Redis broadcast failed: %s", exc)


# ── Task helpers ──────────────────────────────────────────────────────────────

def _run(coro):
    """Run an async coroutine in a new event loop (safe inside Celery workers)."""
    return asyncio.run(coro)


# ── Collector tasks ───────────────────────────────────────────────────────────

@app.task(bind=True, max_retries=3, default_retry_delay=60, name="tasks.collect_rss_task")
def collect_rss_task(self):
    """Ingest all active RSS feeds."""
    try:
        from collectors import collect_all_rss
        from database import rebuild_fts
        count = _run(collect_all_rss())
        _run(rebuild_fts())
        if count > 0:
            _broadcast({"type": "rss_update", "new_items": count})
        logger.info("RSS: +%d items", count)
        return count
    except Exception as exc:
        logger.error("collect_rss_task failed: %s", exc)
        raise self.retry(exc=exc)


@app.task(bind=True, max_retries=3, default_retry_delay=120, name="tasks.collect_cves_task")
def collect_cves_task(self):
    """Ingest recent CVEs from NVD + compute priority scores."""
    try:
        from collectors import collect_recent_cves
        from database import rebuild_fts
        count = _run(collect_recent_cves(days_back=3))
        _run(rebuild_fts())
        if count > 0:
            _broadcast({"type": "cve_update", "new_items": count})
        logger.info("CVE: +%d items", count)
        return count
    except Exception as exc:
        logger.error("collect_cves_task failed: %s", exc)
        raise self.retry(exc=exc)


@app.task(bind=True, max_retries=3, default_retry_delay=300, name="tasks.kev_sync_task")
def kev_sync_task(self):
    """Sync CISA KEV flags across all CVEs."""
    try:
        from collectors import update_kev_flags
        count = _run(update_kev_flags())
        logger.info("KEV sync: %d CVEs updated", count)
        return count
    except Exception as exc:
        logger.error("kev_sync_task failed: %s", exc)
        raise self.retry(exc=exc)


@app.task(bind=True, max_retries=3, default_retry_delay=60, name="tasks.collect_abusech_task")
def collect_abusech_task(self):
    """Ingest Abuse.ch MalwareBazaar / URLhaus / ThreatFox IOCs."""
    try:
        from collectors import collect_abusech
        count = _run(collect_abusech())
        if count > 0:
            _broadcast({"type": "ioc_update", "new_items": count})
        logger.info("Abuse.ch: +%d IOCs", count)
        return count
    except Exception as exc:
        logger.error("collect_abusech_task failed: %s", exc)
        raise self.retry(exc=exc)


@app.task(bind=True, max_retries=3, default_retry_delay=120, name="tasks.collect_otx_task")
def collect_otx_task(self):
    """Ingest AlienVault OTX pulses (skips gracefully if no API key)."""
    try:
        from collectors import collect_otx_pulses
        count = _run(collect_otx_pulses())
        if count > 0:
            _broadcast({"type": "ioc_update", "new_items": count})
        logger.info("OTX: +%d IOCs", count)
        return count
    except Exception as exc:
        logger.error("collect_otx_task failed: %s", exc)
        raise self.retry(exc=exc)


@app.task(bind=True, max_retries=3, default_retry_delay=60, name="tasks.collect_ransomwatch_task")
def collect_ransomwatch_task(self):
    """Ingest RansomWatch ransomware group activity."""
    try:
        from collectors import collect_ransomwatch
        from database import rebuild_fts
        count = _run(collect_ransomwatch())
        _run(rebuild_fts())
        if count > 0:
            _broadcast({"type": "rss_update", "new_items": count})
        logger.info("RansomWatch: +%d items", count)
        return count
    except Exception as exc:
        logger.error("collect_ransomwatch_task failed: %s", exc)
        raise self.retry(exc=exc)


@app.task(bind=True, max_retries=2, default_retry_delay=300, name="tasks.collect_misp_task")
def collect_misp_task(self):
    """Ingest public MISP OSINT feed (Botvrij.eu)."""
    try:
        from collectors.misp_collector import collect_misp
        result = _run(collect_misp())
        iocs = result.get("iocs", 0)
        news = result.get("news", 0)
        if iocs > 0:
            _broadcast({"type": "ioc_update", "new_items": iocs})
        if news > 0:
            _broadcast({"type": "rss_update", "new_items": news})
        logger.info("MISP: +%d IOCs, +%d news", iocs, news)
        return result
    except Exception as exc:
        logger.error("collect_misp_task failed: %s", exc)
        raise self.retry(exc=exc)


@app.task(bind=True, max_retries=2, default_retry_delay=120, name="tasks.correlate_task")
def correlate_task(self):
    """Run CVE↔actor correlation and rebuild FTS index."""
    try:
        from correlate import correlate_cve_actors
        from database import rebuild_fts
        _run(correlate_cve_actors())
        _run(rebuild_fts())
        logger.info("Correlation pass complete")
    except Exception as exc:
        logger.error("correlate_task failed: %s", exc)
        raise self.retry(exc=exc)


@app.task(bind=True, max_retries=2, default_retry_delay=60, name="tasks.run_alert_rules_task")
def run_alert_rules_task(self):
    """Evaluate alert rules against the latest news + CVE items."""
    try:
        from rules_engine import run_scheduled_rules
        fired = _run(run_scheduled_rules())
        logger.info("Alert rules: %d fired", fired)
        return fired
    except Exception as exc:
        logger.error("run_alert_rules_task failed: %s", exc)
        raise self.retry(exc=exc)


@app.task(bind=True, max_retries=2, default_retry_delay=300, name="tasks.scan_shodan_task")
def scan_shodan_task(self):
    """Scan tracked IP assets via Shodan InternetDB and alert on new critical CVEs."""
    try:
        from collectors import scan_assets
        from database import rebuild_fts
        count = _run(scan_assets())
        _run(rebuild_fts())
        if count > 0:
            _broadcast({"type": "rss_update", "new_items": count})
        logger.info("Shodan scan: %d assets updated", count)
        return count
    except Exception as exc:
        logger.error("scan_shodan_task failed: %s", exc)
        raise self.retry(exc=exc)


@app.task(bind=True, max_retries=2, default_retry_delay=120, name="tasks.enrich_iocs_task")
def enrich_iocs_task(self):
    """Enrich IOC items (IPs, hashes, URLs) via free external APIs."""
    try:
        from collectors import enrich_ioc_batch
        count = _run(enrich_ioc_batch())
        if count > 0:
            _broadcast({"type": "ioc_update", "new_items": count})
        logger.info("IOC enrichment: %d items", count)
        return count
    except Exception as exc:
        logger.error("enrich_iocs_task failed: %s", exc)
        raise self.retry(exc=exc)


@app.task(bind=True, max_retries=1, default_retry_delay=120, name="tasks.ai_briefing_task")
def ai_briefing_task(self):
    """Auto-generate an AI threat briefing if Ollama is reachable."""
    try:
        import httpx as _httpx
        from database import SessionLocal, SettingItem

        async def _maybe_generate():
            async with SessionLocal() as db:
                row = await db.get(SettingItem, "OLLAMA_HOST")
                host = row.value if row else "http://localhost:11434"
            try:
                async with _httpx.AsyncClient(timeout=3.0) as client:
                    r = await client.get(f"{host.rstrip('/')}/api/tags")
                if r.status_code != 200:
                    return False
            except Exception:
                return False
            from agents import generate_briefing
            async with SessionLocal() as db:
                await generate_briefing("llama3.2:3b", host, db)
            return True

        generated = _run(_maybe_generate())
        if generated:
            _broadcast({"type": "briefing_ready"})
            logger.info("AI briefing generated")
        return generated
    except Exception as exc:
        logger.error("ai_briefing_task failed: %s", exc)
        raise self.retry(exc=exc)
