"""
SIGINTX — IOC Enrichment Pipeline (Sprint 4)

Enriches IOC items in the database using free, no-auth external APIs:
  - IPs     → Shodan InternetDB  (internetdb.shodan.io)
  - SHA256  → MalwareBazaar API  (mb-api.abuse.ch)
  - MD5     → MalwareBazaar API
  - URLs    → URLhaus API        (urlhaus-api.abuse.ch)
  - Domains → skip (most require keys; domain IOCs are de-prioritised)

Results are cached in the ioc_enrichments table with source tagging.
Re-enrichment is triggered if the cached entry is >24 hours old.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import IOCItem, IOCEnrichment, SessionLocal

logger = logging.getLogger("sigintx.ioc_enrich")

STALE_AFTER_HOURS = 24        # re-enrich if cached entry is older than this
BATCH_LIMIT       = 50        # max IOCs per enrichment run
REQUEST_TIMEOUT   = 10.0      # seconds

# ── Free API callers ──────────────────────────────────────────────────────────

async def _enrich_ip(ip: str) -> Optional[dict]:
    """Shodan InternetDB — open ports, CPEs, vulns, tags. No API key required."""
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            r = await client.get(url)
        if r.status_code == 200:
            data = r.json()
            return {
                "source":     "shodan_internetdb",
                "open_ports": data.get("ports", []),
                "cpes":       data.get("cpes", [])[:10],
                "vulns":      data.get("vulns", [])[:15],
                "tags":       data.get("tags", []),
                "hostnames":  data.get("hostnames", [])[:5],
            }
        if r.status_code == 404:
            return {"source": "shodan_internetdb", "not_found": True}
    except Exception as exc:
        logger.debug("IP enrichment failed for %s: %s", ip, exc)
    return None


async def _enrich_hash(sha256: str) -> Optional[dict]:
    """MalwareBazaar — file type, size, signature, YARA hits, tags."""
    url = "https://mb-api.abuse.ch/api/v1/"
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            r = await client.post(url, data={"query": "get_info", "hash": sha256})
        if r.status_code == 200:
            payload = r.json()
            if payload.get("query_status") == "hash_not_found":
                return {"source": "malwarebazaar", "not_found": True}
            data = payload.get("data", [{}])[0] if payload.get("data") else {}
            return {
                "source":        "malwarebazaar",
                "file_type":     data.get("file_type"),
                "file_size":     data.get("file_size"),
                "first_seen":    data.get("first_seen"),
                "last_seen":     data.get("last_seen"),
                "signature":     data.get("signature"),
                "reporter":      data.get("reporter"),
                "tags":          data.get("tags", []) or [],
                "yara_rules":    [y.get("rule_name") for y in (data.get("yara_rules") or [])[:5]],
                "delivery_method": data.get("delivery_method"),
            }
    except Exception as exc:
        logger.debug("Hash enrichment failed for %s: %s", sha256[:16], exc)
    return None


async def _enrich_url(url_val: str) -> Optional[dict]:
    """URLhaus — URL status (online/offline), threat type, tags, payload hashes."""
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            r = await client.post(api_url, data={"url": url_val})
        if r.status_code == 200:
            payload = r.json()
            if payload.get("query_status") == "no_results":
                return {"source": "urlhaus", "not_found": True}
            payloads = []
            for p in (payload.get("payloads") or [])[:5]:
                payloads.append({
                    "file_type": p.get("file_type"),
                    "sha256":    p.get("response_sha256"),
                    "signature": p.get("signature"),
                })
            return {
                "source":      "urlhaus",
                "url_status":  payload.get("url_status"),
                "threat":      payload.get("threat"),
                "date_added":  payload.get("date_added"),
                "reporter":    payload.get("reporter"),
                "tags":        payload.get("tags", []) or [],
                "payloads":    payloads,
            }
    except Exception as exc:
        logger.debug("URL enrichment failed: %s", exc)
    return None


# ── Dispatch ──────────────────────────────────────────────────────────────────

async def _enrich_one(ioc: IOCItem) -> Optional[dict]:
    """Dispatch enrichment based on IOC type. Returns dict or None."""
    ioc_type = ioc.ioc_type
    value    = ioc.value

    if ioc_type == "ip":
        return await _enrich_ip(value)
    if ioc_type in ("hash_sha256", "hash_md5"):
        return await _enrich_hash(value)
    if ioc_type == "url":
        return await _enrich_url(value)
    # domain, email — skip for now (no free no-auth API)
    return None


# ── Batch enricher ────────────────────────────────────────────────────────────

async def enrich_ioc_batch(limit: int = BATCH_LIMIT) -> int:
    """
    Pick up to `limit` IOCs that have no enrichment record or whose enrichment
    is stale (>24 h). Enrich them and persist results.

    Returns the number of newly enriched IOCs.
    """
    enriched = 0
    stale_cutoff = datetime.utcnow() - timedelta(hours=STALE_AFTER_HOURS)

    async with SessionLocal() as db:
        # Load candidates: IPs, hashes, URLs only (domain/email skipped for now)
        candidates = (await db.scalars(
            select(IOCItem)
            .where(IOCItem.ioc_type.in_(["ip", "hash_sha256", "hash_md5", "url"]))
            .order_by(IOCItem.fetched_at.desc())
            .limit(limit * 4)   # over-fetch so we can filter out fresh ones
        )).all()

        # Load existing enrichment cache timestamps in one query
        ioc_ids = [ioc.id for ioc in candidates]
        existing_rows = (await db.scalars(
            select(IOCEnrichment)
            .where(IOCEnrichment.ioc_id.in_(ioc_ids))
        )).all()
        cached: dict[int, datetime] = {r.ioc_id: r.fetched_at for r in existing_rows}
        cached_row: dict[int, IOCEnrichment] = {r.ioc_id: r for r in existing_rows}

        # Filter to unenriched or stale, up to limit
        to_enrich = [
            ioc for ioc in candidates
            if ioc.id not in cached or cached[ioc.id] < stale_cutoff
        ][:limit]

        for ioc in to_enrich:
            data = await _enrich_one(ioc)
            if data is None:
                continue

            now = datetime.utcnow()
            if ioc.id in cached_row:
                # Update existing record
                row = cached_row[ioc.id]
                row.data       = json.dumps(data)
                row.fetched_at = now
            else:
                db.add(IOCEnrichment(
                    ioc_id    = ioc.id,
                    ioc_value = ioc.value,
                    source    = data.get("source", "unknown"),
                    data      = json.dumps(data),
                    fetched_at= now,
                ))
            enriched += 1

        if enriched:
            await db.commit()

    logger.info("IOC enrichment: %d items processed", enriched)
    return enriched
