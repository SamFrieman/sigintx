"""
SIGINTX — AlienVault OTX Collector
Requires a free OTX API key: set OTX_API_KEY environment variable.
Sign up at: https://otx.alienvault.com
"""
import json
import logging
import os

import httpx
from sqlalchemy import select

from database import IOCItem, SessionLocal

logger = logging.getLogger("sigintx.otx")

OTX_BASE = "https://otx.alienvault.com/api/v1"


async def collect_otx_pulses(limit: int = 20) -> int:
    """Ingest indicators from subscribed OTX pulses."""
    api_key = os.environ.get("OTX_API_KEY", "")
    if not api_key:
        logger.debug("OTX_API_KEY not set — skipping OTX collection")
        return 0
    count = 0
    try:
        async with httpx.AsyncClient(
            timeout=30.0,
            headers={"X-OTX-API-KEY": api_key},
        ) as client:
            resp = await client.get(
                f"{OTX_BASE}/pulses/subscribed",
                params={"limit": limit, "page": 1},
            )
            data = resp.json()
        async with SessionLocal() as session:
            for pulse in data.get("results", []):
                pulse_name = (pulse.get("name") or "")[:128]
                pulse_tags = pulse.get("tags") or []
                for ind in (pulse.get("indicators") or [])[:100]:
                    ioc_val = (ind.get("indicator") or "")[:512]
                    if not ioc_val:
                        continue
                    exists = await session.scalar(
                        select(IOCItem).where(IOCItem.value == ioc_val, IOCItem.source == "OTX")
                    )
                    if exists:
                        continue
                    session.add(IOCItem(
                        ioc_type=(ind.get("type") or "unknown").lower(),
                        value=ioc_val,
                        malware_family=pulse_name or None,
                        source="OTX",
                        tags=json.dumps(pulse_tags),
                        confidence=None,
                        first_seen=None,
                    ))
                    count += 1
            if count:
                await session.commit()
    except Exception as e:
        logger.warning(f"OTX error: {e}")
    logger.info(f"OTX new IOCs: {count}")
    return count
