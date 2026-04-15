"""
SIGINTX — RansomWatch Collector
Public ransomware group monitoring feed — no API key required.
Source: https://github.com/joshhighet/ransomwatch
"""
import json
import logging
from datetime import datetime

import httpx
from sqlalchemy import select

from database import NewsItem, SessionLocal
from enrichment import classify_severity, extract_tags, extract_threat_actors, extract_cve_refs

logger = logging.getLogger("sigintx.ransomwatch")

RANSOMWATCH_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"


def _parse_dt(raw: str | None) -> datetime:
    if not raw:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(raw.replace("Z", "").split("+")[0])
    except Exception:
        return datetime.utcnow()


async def collect_ransomwatch() -> int:
    """Fetch RansomWatch posts and ingest as NewsItems."""
    count = 0
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(RANSOMWATCH_URL)
            if resp.status_code != 200:
                logger.warning(f"RansomWatch HTTP {resp.status_code}")
                return 0
            posts = resp.json()
    except Exception as e:
        logger.warning(f"RansomWatch fetch error: {e}")
        return 0

    if not isinstance(posts, list):
        logger.warning(f"RansomWatch unexpected response type: {type(posts)}")
        return 0

    logger.info(f"RansomWatch fetched {len(posts)} posts")

    try:
        async with SessionLocal() as session:
            for post in posts[:200]:
                # Try multiple field name variants
                title = (
                    post.get("post_title") or
                    post.get("title") or
                    post.get("victim") or
                    post.get("fqdn") or
                    ""
                ).strip()
                group = (
                    post.get("group_name") or
                    post.get("group") or
                    post.get("ransomware_group") or
                    "Unknown"
                ).strip()

                if not title and not group:
                    continue
                if not title:
                    title = f"Victim from {group}"

                # Use a stable synthetic URL for dedup
                url = f"ransomwatch://{group}/{title[:80]}"
                exists = await session.scalar(select(NewsItem).where(NewsItem.url == url))
                if exists:
                    continue

                full_text = f"{title} {group} ransomware"
                severity = classify_severity(full_text)
                if severity == "INFO":
                    severity = "HIGH"

                tags = list(set(extract_tags(full_text) + ["ransomware"]))
                actors = extract_threat_actors(full_text) or [group]
                cve_refs = extract_cve_refs(full_text)

                session.add(NewsItem(
                    title=f"[{group.upper()}] {title}"[:512],
                    url=url,
                    source="RansomWatch",
                    summary=f"Ransomware group '{group}' posted: {title}",
                    published_at=_parse_dt(post.get("discovered") or post.get("date") or post.get("timestamp")),
                    severity=severity,
                    tags=json.dumps(tags),
                    threat_actors=json.dumps(actors),
                    cve_refs=json.dumps(cve_refs),
                    category="security",
                ))
                count += 1

            if count:
                await session.commit()
    except Exception as e:
        logger.warning(f"RansomWatch ingest error: {e}", exc_info=True)

    logger.info(f"RansomWatch new posts: {count}")
    return count
