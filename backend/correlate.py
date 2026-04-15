"""
SIGINTX — Correlation Engine (v1.3.0)
Automated CVE ↔ threat actor linkage from news co-occurrence.
Campaign timeline reconstruction.
Webhook alert digest.
"""
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from database import NewsItem, CVEItem, ThreatActor, SettingItem, SessionLocal, AlertLog

logger = logging.getLogger("sigintx.correlate")


# ── CVE ↔ Actor co-occurrence ─────────────────────────────────────────────────

async def correlate_cve_actors() -> int:
    """
    Scan news items that reference both CVEs and threat actors.
    Update CVEItem.threat_actors with actors found in co-occurring news.
    Returns number of CVE records updated.
    """
    updated = 0
    async with SessionLocal() as session:
        # Find news items that have both CVE refs and actor mentions
        news_result = await session.scalars(
            select(NewsItem)
            .where(NewsItem.cve_refs.isnot(None))
            .where(NewsItem.threat_actors.isnot(None))
            .order_by(desc(NewsItem.published_at))
            .limit(500)
        )
        news_items = news_result.all()

        # Build map: cve_id → set of actor names from co-occurring news
        cve_to_actors: dict[str, set[str]] = defaultdict(set)
        for item in news_items:
            cve_refs  = json.loads(item.cve_refs)      if item.cve_refs      else []
            actors    = json.loads(item.threat_actors) if item.threat_actors else []
            if not cve_refs or not actors:
                continue
            for cve_id in cve_refs:
                for actor in actors:
                    cve_to_actors[cve_id.upper()].add(actor)

        # Update CVEItem records
        for cve_id, actors in cve_to_actors.items():
            cve = await session.scalar(select(CVEItem).where(CVEItem.cve_id == cve_id))
            if not cve:
                continue
            existing = set(json.loads(cve.threat_actors) if cve.threat_actors else [])
            merged   = existing | actors
            if merged != existing:
                cve.threat_actors = json.dumps(sorted(merged))
                updated += 1

        if updated:
            await session.commit()

        # Update ThreatActor.last_activity — latest news published_at per actor name
        await _update_actor_last_activity(session, news_items)

    logger.info(f"Correlation: updated {updated} CVE actor links")
    return updated


async def _update_actor_last_activity(session, news_items) -> None:
    """
    For every actor mentioned in news_items, set ThreatActor.last_activity
    to the most recent published_at timestamp where they appear.
    """
    # Build map: actor_name_lower → max(published_at)
    actor_latest: dict[str, datetime] = {}
    for item in news_items:
        if not item.threat_actors or not item.published_at:
            continue
        try:
            actors = json.loads(item.threat_actors)
        except Exception:
            continue
        for actor in actors:
            key = actor.lower()
            if key not in actor_latest or item.published_at > actor_latest[key]:
                actor_latest[key] = item.published_at

    if not actor_latest:
        return

    # Fetch all actors and match by name / aliases
    all_actors = (await session.scalars(select(ThreatActor))).all()
    changed = 0
    for db_actor in all_actors:
        candidates = {db_actor.name.lower()}
        if db_actor.aliases:
            try:
                for alias in json.loads(db_actor.aliases):
                    candidates.add(alias.lower())
            except Exception:
                pass

        latest = None
        for candidate in candidates:
            if candidate in actor_latest:
                t = actor_latest[candidate]
                if latest is None or t > latest:
                    latest = t

        if latest and (db_actor.last_activity is None or latest > db_actor.last_activity):
            db_actor.last_activity = latest
            changed += 1

    if changed:
        await session.commit()
        logger.debug("Updated last_activity for %d threat actors", changed)


# ── Campaign reconstruction ───────────────────────────────────────────────────

async def build_campaigns(days_back: int = 30) -> list[dict]:
    """
    Group news + CVEs by threat actor to reconstruct campaigns.
    Returns list of campaign dicts sorted by recency.
    """
    cutoff = datetime.utcnow() - timedelta(days=days_back)
    campaigns: dict[str, dict] = {}

    async with SessionLocal() as session:
        # Gather recent news with actor mentions
        news_result = await session.scalars(
            select(NewsItem)
            .where(NewsItem.published_at >= cutoff)
            .where(NewsItem.threat_actors.isnot(None))
            .order_by(desc(NewsItem.published_at))
            .limit(300)
        )
        for item in news_result.all():
            actors = json.loads(item.threat_actors) if item.threat_actors else []
            cves   = json.loads(item.cve_refs)      if item.cve_refs      else []
            for actor in actors:
                if actor not in campaigns:
                    campaigns[actor] = {
                        "actor":      actor,
                        "news":       [],
                        "cves":       set(),
                        "severities": [],
                        "first_seen": item.published_at,
                        "last_seen":  item.published_at,
                    }
                c = campaigns[actor]
                c["news"].append({
                    "id":           item.id,
                    "title":        item.title,
                    "severity":     item.severity,
                    "published_at": item.published_at.isoformat() if item.published_at else None,
                    "source":       item.source,
                    "url":          item.url,
                })
                c["cves"].update(cves)
                c["severities"].append(item.severity)
                if item.published_at:
                    if c["first_seen"] is None or item.published_at < c["first_seen"]:
                        c["first_seen"] = item.published_at
                    if c["last_seen"] is None or item.published_at > c["last_seen"]:
                        c["last_seen"] = item.published_at

        # Gather CVEs linked to each actor
        for actor, camp in campaigns.items():
            cve_result = await session.scalars(
                select(CVEItem)
                .where(CVEItem.threat_actors.contains(actor))
                .order_by(desc(CVEItem.published_at))
                .limit(20)
            )
            for cve in cve_result.all():
                camp["cves"].add(cve.cve_id)

    # Serialize and sort by last_seen descending
    result = []
    for actor, c in campaigns.items():
        sev_priority = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1}
        top_sev = max(c["severities"], key=lambda s: sev_priority.get(s, 0)) if c["severities"] else "INFO"
        result.append({
            "actor":       actor,
            "top_severity": top_sev,
            "news_count":  len(c["news"]),
            "cve_count":   len(c["cves"]),
            "cves":        sorted(c["cves"]),
            "first_seen":  c["first_seen"].isoformat() if c["first_seen"] else None,
            "last_seen":   c["last_seen"].isoformat()  if c["last_seen"]  else None,
            "timeline":    sorted(c["news"], key=lambda n: n["published_at"] or "", reverse=True)[:20],
        })

    result.sort(key=lambda c: c["last_seen"] or "", reverse=True)
    return result


# ── Webhook alert digest ──────────────────────────────────────────────────────

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1}


async def _get_setting(key: str, default: str = "") -> str:
    async with SessionLocal() as session:
        row = await session.get(SettingItem, key)
        return row.value if row else default


async def fire_webhook_if_needed(items: list[dict], item_type: str = "news") -> bool:
    """
    POST to WEBHOOK_URL for any items at or above WEBHOOK_MIN_SEVERITY.
    Returns True if webhook was fired.
    """
    webhook_url  = await _get_setting("WEBHOOK_URL")
    min_sev      = await _get_setting("WEBHOOK_MIN_SEVERITY", "CRITICAL")
    if not webhook_url:
        return False

    min_rank = _SEV_ORDER.get(min_sev, 4)
    triggered = [i for i in items if _SEV_ORDER.get(i.get("severity", "INFO"), 0) >= min_rank]
    if not triggered:
        return False

    payload = {
        "source":    "SIGINTX",
        "timestamp": datetime.utcnow().isoformat(),
        "type":      item_type,
        "count":     len(triggered),
        "items":     triggered[:10],   # cap payload at 10 items
    }
    success = False
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(webhook_url, json=payload)
        success = True
        logger.info(f"Webhook fired: {len(triggered)} {item_type} items to {webhook_url}")
    except Exception as e:
        logger.warning(f"Webhook error: {e}")

    # Log to AlertLog regardless of success/failure
    sample = triggered[0].get("title") or triggered[0].get("cve_id") if triggered else None
    top_sev = max(triggered, key=lambda i: _SEV_ORDER.get(i.get("severity","INFO"),0)).get("severity","INFO") if triggered else "INFO"
    async with SessionLocal() as session:
        session.add(AlertLog(
            item_type=item_type,
            count=len(triggered),
            top_severity=top_sev,
            webhook_url=webhook_url,
            success=success,
            sample_title=sample,
        ))
        await session.commit()

    return success
