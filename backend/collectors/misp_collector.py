"""
SIGINTX — MISP / OSINT Feed Collector (v3.0.0)
Pulls threat intelligence from the Botvrij.eu public MISP OSINT feed.
No API key required.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import select

from database import IOCItem, NewsItem, SessionLocal
from enrichment import classify_severity, extract_tags, extract_threat_actors, extract_cve_refs

logger = logging.getLogger("sigintx.misp_collector")

BOTVRIJ_MANIFEST_URL = "https://www.botvrij.eu/data/feed-osint/manifest.json"
BOTVRIJ_EVENT_BASE   = "https://www.botvrij.eu/data/feed-osint/{hash}.json"

# MISP attribute types we care about, mapped to our ioc_type values
_ATTR_TYPE_MAP: dict[str, str] = {
    "ip-src":    "ip",
    "ip-dst":    "ip",
    "domain":    "domain",
    "url":       "url",
    "uri":       "url",
    "sha256":    "hash_sha256",
    "md5":       "hash_md5",
    "sha1":      "hash_sha1",
    "filename":  "filename",
    "hostname":  "domain",
}

SEVERITY_THREAT_LEVEL: dict[str, str] = {
    "1": "HIGH",       # High in MISP
    "2": "MEDIUM",     # Medium
    "3": "INFO",       # Low
    "4": "INFO",       # Undefined
}

_HTTP_HEADERS = {
    "User-Agent": "SIGINTX/3.0.0 threat-intelligence-platform",
    "Accept": "application/json",
}


def _parse_misp_ts(ts: Any) -> datetime | None:
    """Parse a MISP Unix timestamp (string or int) into a UTC datetime."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).replace(tzinfo=None)
    except (ValueError, TypeError, OSError):
        return None


def _extract_event_info(event_obj: dict) -> dict:
    """
    Extract the inner 'Event' dict from a MISP event JSON file.
    MISP events are wrapped: {"Event": {...}}
    """
    if "Event" in event_obj:
        return event_obj["Event"]
    return event_obj


def _event_to_news_title(event: dict) -> str:
    """Build a descriptive news title from MISP event metadata."""
    info = (event.get("info") or "").strip()
    if not info:
        info = f"MISP OSINT Event {event.get('uuid', 'unknown')}"
    return f"[MISP-OSINT] {info[:400]}"


def _event_to_severity(event: dict) -> str:
    """Map MISP threat_level_id to our severity scale."""
    tl = str(event.get("threat_level_id", "4"))
    base = SEVERITY_THREAT_LEVEL.get(tl, "INFO")
    # Let keyword enrichment potentially upgrade
    combined = f"{event.get('info', '')} {event.get('description', '')}"
    enriched = classify_severity(combined)
    # Take whichever is higher
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1}
    return max(base, enriched, key=lambda s: rank.get(s, 1))


async def collect_misp_botvrij(max_events: int = 10) -> int:
    """
    Pull recent events from the Botvrij.eu public MISP OSINT feed.

    Steps:
    1. Fetch the manifest JSON (hash -> timestamp mapping).
    2. Sort events by timestamp descending, take max_events most recent.
    3. For each event, fetch the JSON and extract IOC attributes.
    4. Persist unique IOCItems (ip, domain, url, hash, filename).
    5. Create a NewsItem for each event that has a meaningful description.

    Returns total count of new DB rows created (IOCs + news items combined).
    """
    total_created = 0

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=True,
            headers=_HTTP_HEADERS,
        ) as client:
            # 1. Fetch manifest
            logger.info("Fetching Botvrij MISP manifest...")
            try:
                manifest_resp = await client.get(BOTVRIJ_MANIFEST_URL)
                manifest_resp.raise_for_status()
                manifest: dict[str, Any] = manifest_resp.json()
            except httpx.HTTPStatusError as exc:
                logger.error(f"MISP manifest HTTP error: {exc.response.status_code}")
                return 0
            except Exception as exc:
                logger.error(f"MISP manifest fetch error: {exc}")
                return 0

            if not isinstance(manifest, dict):
                logger.error("MISP manifest is not a dict — unexpected format")
                return 0

            logger.info(f"MISP manifest contains {len(manifest)} event entries")

            # 2. Sort by timestamp descending
            def _ts(entry: Any) -> int:
                if isinstance(entry, dict):
                    return int(entry.get("timestamp", 0) or 0)
                try:
                    return int(entry)
                except (ValueError, TypeError):
                    return 0

            sorted_hashes = sorted(
                manifest.items(),
                key=lambda kv: _ts(kv[1]),
                reverse=True,
            )[:max_events]

            # 3 & 4 & 5. Process each event
            async with SessionLocal() as session:
                for event_hash, _meta in sorted_hashes:
                    event_url = BOTVRIJ_EVENT_BASE.format(hash=event_hash)
                    try:
                        ev_resp = await client.get(event_url)
                        ev_resp.raise_for_status()
                        raw_event: dict = ev_resp.json()
                    except httpx.HTTPStatusError as exc:
                        logger.debug(
                            f"MISP event {event_hash}: HTTP {exc.response.status_code} — skipping"
                        )
                        continue
                    except Exception as exc:
                        logger.debug(f"MISP event {event_hash} fetch error: {exc} — skipping")
                        continue

                    event = _extract_event_info(raw_event)
                    attributes: list[dict] = event.get("Attribute") or []
                    if not isinstance(attributes, list):
                        attributes = []

                    event_ts    = _parse_misp_ts(event.get("timestamp"))
                    event_title = _event_to_news_title(event)
                    event_sev   = _event_to_severity(event)
                    event_uuid  = event.get("uuid", event_hash)
                    event_org   = (event.get("Orgc") or {}).get("name", "MISP-OSINT")
                    ioc_count_this_event = 0

                    for attr in attributes:
                        attr_type = attr.get("type", "")
                        our_type  = _ATTR_TYPE_MAP.get(attr_type)
                        if our_type is None:
                            continue

                        value = (attr.get("value") or "").strip()[:512]
                        if not value:
                            continue

                        # Skip private/loopback IPs
                        if our_type == "ip" and (
                            value.startswith("192.168.") or
                            value.startswith("10.") or
                            value.startswith("172.") or
                            value.startswith("127.") or
                            value == "0.0.0.0"
                        ):
                            continue

                        # Dedup check — same value + same source
                        existing = await session.scalar(
                            select(IOCItem).where(
                                IOCItem.value == value,
                                IOCItem.source == "MISP-OSINT",
                            )
                        )
                        if existing:
                            continue

                        tags: list[str] = []
                        raw_tags = attr.get("Tag") or []
                        if isinstance(raw_tags, list):
                            for t in raw_tags:
                                if isinstance(t, dict):
                                    tn = t.get("name", "")
                                    if tn:
                                        tags.append(tn[:64])
                                elif isinstance(t, str):
                                    tags.append(t[:64])

                        malware_family = attr.get("comment") or event.get("info", "")
                        malware_family = (malware_family or "")[:128] or None

                        ioc = IOCItem(
                            ioc_type       = our_type,
                            value          = value,
                            malware_family = malware_family,
                            source         = "MISP-OSINT",
                            tags           = json.dumps(tags[:10]),
                            confidence     = None,
                            first_seen     = event_ts,
                        )
                        session.add(ioc)
                        ioc_count_this_event += 1
                        total_created += 1

                    # Create news item if event has meaningful description
                    info_text = (event.get("info") or "").strip()
                    if info_text and len(info_text) > 10:
                        # Use event UUID as unique URL anchor
                        pseudo_url = f"https://www.botvrij.eu/data/feed-osint/{event_uuid}"
                        news_exists = await session.scalar(
                            select(NewsItem).where(NewsItem.url == pseudo_url)
                        )
                        if not news_exists:
                            summary = (
                                f"MISP OSINT event from {event_org}. "
                                f"Contains {len(attributes)} attributes / "
                                f"{ioc_count_this_event} IOCs extracted. "
                                f"Threat level: {event.get('threat_level_id', 'unknown')}. "
                                f"{info_text[:400]}"
                            )
                            combined = f"{event_title} {summary}"
                            news = NewsItem(
                                title        = event_title[:512],
                                url          = pseudo_url,
                                source       = "MISP-OSINT",
                                summary      = summary[:2000],
                                published_at = event_ts or datetime.utcnow(),
                                severity     = event_sev,
                                tags         = json.dumps(extract_tags(combined)),
                                threat_actors= json.dumps(extract_threat_actors(combined)),
                                cve_refs     = json.dumps(extract_cve_refs(combined)),
                            )
                            session.add(news)
                            total_created += 1

                    if ioc_count_this_event:
                        logger.debug(
                            f"MISP event {event_uuid}: +{ioc_count_this_event} IOCs, "
                            f"sev={event_sev}"
                        )

                if total_created:
                    await session.commit()

    except Exception as exc:
        logger.error(f"collect_misp_botvrij unexpected error: {type(exc).__name__}: {exc}")

    logger.info(f"MISP Botvrij collector: {total_created} new rows created")
    return total_created


async def collect_misp_feeds() -> int:
    """Run all MISP collectors and return total new items created."""
    total = 0
    total += await collect_misp_botvrij()
    logger.info(f"MISP feeds total new items: {total}")
    return total


async def collect_misp() -> dict:
    """
    Wrapper used by Celery tasks.py — returns a breakdown dict instead of a
    plain int so the task can broadcast separate ioc_update / rss_update events.
    """
    total = await collect_misp_feeds()
    # We can't distinguish IOCs from news here without threading through the counts,
    # so report total as iocs (conservative — avoids double-broadcast).
    return {"iocs": total, "news": 0}
