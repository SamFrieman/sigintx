"""
SIGINTX — Abuse.ch Collector
MalwareBazaar + URLhaus + ThreatFox threat intelligence feeds.
Set ABUSECH_API_KEY env var to authenticate (required since 2024).
URLhaus falls back to public JSON download when no key is set.
"""
import json
import logging
import os
from datetime import datetime

import httpx
from sqlalchemy import select

from database import IOCItem, SessionLocal

logger = logging.getLogger("sigintx.abusech")

# Optional API key — get one free at https://bazaar.abuse.ch/account/
ABUSECH_API_KEY: str | None = os.environ.get("ABUSECH_API_KEY") or None

_THREATFOX_TYPE_MAP = {
    'sha256_hash': 'hash_sha256',
    'md5_hash':    'hash_md5',
    'ip:port':     'ip',
    'domain':      'domain',
    'url':         'url',
    'email':       'email',
}

MALWAREBAZAAR_URL   = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_URL         = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
URLHAUS_PUBLIC_URL  = "https://urlhaus.abuse.ch/downloads/json_recent/"  # no-auth fallback
THREATFOX_URL       = "https://threatfox-api.abuse.ch/api/v1/"


def _auth_headers() -> dict:
    """Return Auth-Key header dict if ABUSECH_API_KEY is set, else empty."""
    if ABUSECH_API_KEY:
        return {"Auth-Key": ABUSECH_API_KEY}
    return {}


def _parse_dt(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace(" ", "T").split("+")[0].rstrip("Z"))
    except Exception:
        return None


async def collect_malwarebazaar(time_frame_minutes: int = 60) -> int:
    """Collect recent file hashes from MalwareBazaar."""
    if not ABUSECH_API_KEY:
        logger.warning("MalwareBazaar: ABUSECH_API_KEY not set — skipping (API requires auth)")
        return 0
    count = 0
    try:
        async with httpx.AsyncClient(timeout=45.0, follow_redirects=True, headers=_auth_headers()) as client:
            resp = await client.post(MALWAREBAZAAR_URL, data={
                "query": "get_recent",
                "selector": "time_frame",
                "time_frame": str(time_frame_minutes),
            })
            resp.raise_for_status()
            data = resp.json()
        query_status = data.get("query_status")
        if query_status != "ok":
            logger.warning(f"MalwareBazaar query_status={query_status!r} — response: {str(data)[:300]}")
            return 0
        records = data.get("data") or []
        logger.info(f"MalwareBazaar returned {len(records)} records")
        async with SessionLocal() as session:
            for item in records[:150]:
                sha256 = item.get("sha256_hash", "")
                if not sha256:
                    continue
                exists = await session.scalar(
                    select(IOCItem).where(IOCItem.value == sha256, IOCItem.source == "MalwareBazaar")
                )
                if exists:
                    continue
                tags = item.get("tags") or []
                family = item.get("signature") or (tags[0] if tags else None)
                session.add(IOCItem(
                    ioc_type="hash_sha256",
                    value=sha256,
                    malware_family=family,
                    source="MalwareBazaar",
                    tags=json.dumps(tags),
                    confidence=None,
                    first_seen=_parse_dt(item.get("first_seen")),
                ))
                count += 1
            if count:
                await session.commit()
    except httpx.HTTPStatusError as e:
        logger.error(f"MalwareBazaar HTTP error: {e.response.status_code} — {e}")
    except Exception as e:
        logger.error(f"MalwareBazaar error: {type(e).__name__}: {e}")
    return count


async def collect_urlhaus() -> int:
    """Collect recent malicious URLs from URLhaus.
    Uses authenticated API if ABUSECH_API_KEY is set; otherwise falls back
    to the public JSON download (updated every 5 minutes by abuse.ch).
    """
    count = 0
    try:
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            if ABUSECH_API_KEY:
                resp = await client.get(URLHAUS_URL, headers=_auth_headers())
                resp.raise_for_status()
                data = resp.json()
                records = data.get("urls") or []
            else:
                # Public bulk download — returns a JSON array directly
                logger.info("URLhaus: no API key, using public JSON download fallback")
                resp = await client.get(URLHAUS_PUBLIC_URL)
                resp.raise_for_status()
                raw = resp.json()
                # Public download format: list of url objects
                records = raw if isinstance(raw, list) else (raw.get("urls") or [])
        logger.info(f"URLhaus returned {len(records)} records")
        async with SessionLocal() as session:
            for item in records[:150]:
                url = (item.get("url") or "")[:512]
                if not url:
                    continue
                exists = await session.scalar(
                    select(IOCItem).where(IOCItem.value == url, IOCItem.source == "URLhaus")
                )
                if exists:
                    continue
                tags = item.get("tags") or []
                session.add(IOCItem(
                    ioc_type="url",
                    value=url,
                    malware_family=tags[0] if tags else None,
                    source="URLhaus",
                    tags=json.dumps(tags),
                    confidence=None,
                    first_seen=_parse_dt(item.get("date_added")),
                ))
                count += 1
            if count:
                await session.commit()
    except httpx.HTTPStatusError as e:
        logger.error(f"URLhaus HTTP error: {e.response.status_code} — {e}")
    except Exception as e:
        logger.error(f"URLhaus error: {type(e).__name__}: {e}")
    return count


async def collect_threatfox(days: int = 3) -> int:
    """Collect recent IOCs from ThreatFox."""
    if not ABUSECH_API_KEY:
        logger.warning("ThreatFox: ABUSECH_API_KEY not set — skipping (API requires auth)")
        return 0
    count = 0
    try:
        async with httpx.AsyncClient(timeout=45.0, follow_redirects=True, headers=_auth_headers()) as client:
            resp = await client.post(THREATFOX_URL, json={"query": "get_iocs", "days": days})
            resp.raise_for_status()
            data = resp.json()
        query_status = data.get("query_status")
        if query_status != "ok":
            logger.warning(f"ThreatFox query_status={query_status!r} — response: {str(data)[:300]}")
            return 0
        records = data.get("data") or []
        logger.info(f"ThreatFox returned {len(records)} records")
        async with SessionLocal() as session:
            for item in records[:200]:
                ioc_val = (item.get("ioc") or "")[:512]
                if not ioc_val:
                    continue
                exists = await session.scalar(
                    select(IOCItem).where(IOCItem.value == ioc_val, IOCItem.source == "ThreatFox")
                )
                if exists:
                    continue
                conf_raw = item.get("confidence_level")
                session.add(IOCItem(
                    ioc_type=_THREATFOX_TYPE_MAP.get(item.get("ioc_type", "unknown"), item.get("ioc_type", "unknown")),
                    value=ioc_val,
                    malware_family=item.get("malware"),
                    source="ThreatFox",
                    tags=json.dumps(item.get("tags") or []),
                    confidence=conf_raw / 100.0 if conf_raw is not None else None,
                    first_seen=_parse_dt(item.get("first_seen")),
                ))
                count += 1
            if count:
                await session.commit()
    except httpx.HTTPStatusError as e:
        logger.error(f"ThreatFox HTTP error: {e.response.status_code} — {e}")
    except Exception as e:
        logger.error(f"ThreatFox error: {type(e).__name__}: {e}")
    return count


async def collect_abusech() -> int:
    """Run all three Abuse.ch collectors."""
    total = 0
    total += await collect_malwarebazaar()
    total += await collect_urlhaus()
    total += await collect_threatfox()
    logger.info(f"Abuse.ch total new IOCs: {total}")
    return total
