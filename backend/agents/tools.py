"""
SIGINTX — AI Agent Tool Definitions & Executors (v3.0.0)
Ollama function-calling tools for the threat intelligence analyst.
Each tool executor queries the local DB and returns a compact JSON string.
"""
import json
import logging
from datetime import datetime, timedelta

from sqlalchemy import select, desc, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from database import CVEItem, NewsItem, ThreatActor, IOCItem, Asset

logger = logging.getLogger("sigintx.tools")

# ── Tool schema definitions ───────────────────────────────────────────────────

TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "search_cves",
            "description": (
                "Search CVEs in the threat intelligence database by query string, "
                "severity filter, or CISA KEV (actively exploited) status. "
                "Returns CVE ID, CVSS score, severity, KEV flag, EPSS score, and truncated description."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search term: CVE ID (e.g. CVE-2024-1234) or keyword in description",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "INFO"],
                        "description": "Filter by severity level",
                    },
                    "in_kev": {
                        "type": "boolean",
                        "description": "If true, only return CVEs in CISA Known Exploited Vulnerabilities catalog",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results to return (default 10, max 20)",
                        "default": 10,
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_news",
            "description": (
                "Search recent threat intelligence news items by keyword, severity, "
                "or time window. Returns title, source, severity, threat actors, and CVE references."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Keyword to search in news titles and summaries",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "INFO"],
                        "description": "Filter by severity",
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "How many hours back to search (default 48)",
                        "default": 48,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results (default 10, max 20)",
                        "default": 10,
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_actor_profile",
            "description": (
                "Retrieve detailed profile of a known threat actor, including aliases, "
                "MITRE ATT&CK ID, country of origin, motivation, and known techniques."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Threat actor name (e.g. 'APT28', 'Lazarus Group', 'LockBit')",
                    },
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_iocs",
            "description": (
                "Search Indicators of Compromise in the IOC database by value, type, or malware family. "
                "Returns IOC type, value, malware family, source, and first-seen date."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "IOC value to search (IP, domain, hash, URL) or malware family name",
                    },
                    "ioc_type": {
                        "type": "string",
                        "enum": ["ip", "domain", "url", "hash_sha256", "hash_md5", "email", "filename"],
                        "description": "Filter by IOC type",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results (default 10)",
                        "default": 10,
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_stats",
            "description": (
                "Get current threat intelligence statistics: total counts of news, CVEs, IOCs, "
                "KEV entries, active threat actors, severity breakdown."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hours_back": {
                        "type": "integer",
                        "description": "Time window for recent stats (default 24 hours)",
                        "default": 24,
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_asset_vulns",
            "description": (
                "Get vulnerability exposure for monitored assets. "
                "Shows open ports, detected CVEs, and risk scores for tracked IP assets."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "asset_name": {
                        "type": "string",
                        "description": "Filter by asset name or IP value (optional — omit for all assets)",
                    },
                    "min_risk_score": {
                        "type": "number",
                        "description": "Only return assets with risk_score >= this value",
                    },
                },
            },
        },
    },
]


# ── Tool executor dispatcher ──────────────────────────────────────────────────

async def execute_tool(tool_name: str, args: dict, db: AsyncSession) -> str:
    """
    Execute a tool call by name and return the result as a JSON string.
    Returns an error JSON string for unknown tools.
    """
    dispatch = {
        "search_cves":       _search_cves,
        "search_news":       _search_news,
        "get_actor_profile": _get_actor_profile,
        "search_iocs":       _search_iocs,
        "get_stats":         _get_stats,
        "get_asset_vulns":   _get_asset_vulns,
    }
    fn = dispatch.get(tool_name)
    if fn is None:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})
    try:
        return await fn(args, db)
    except Exception as exc:
        logger.error(f"Tool '{tool_name}' execution error: {exc}")
        return json.dumps({"error": str(exc)})


# ── Individual tool implementations ──────────────────────────────────────────

async def _search_cves(args: dict, db: AsyncSession) -> str:
    query     = (args.get("query") or "").strip()
    severity  = args.get("severity")
    in_kev    = args.get("in_kev")
    limit     = min(int(args.get("limit") or 10), 20)

    stmt = select(CVEItem).order_by(desc(CVEItem.published_at))

    if query:
        pattern = f"%{query}%"
        stmt = stmt.where(
            or_(
                CVEItem.cve_id.ilike(pattern),
                CVEItem.description.ilike(pattern),
            )
        )
    if severity:
        stmt = stmt.where(CVEItem.severity == severity)
    if in_kev is True:
        stmt = stmt.where(CVEItem.in_kev == True)

    rows = (await db.scalars(stmt.limit(limit))).all()

    results = []
    for c in rows:
        results.append({
            "cve_id":      c.cve_id,
            "severity":    c.severity,
            "cvss":        c.cvss_score,
            "epss":        round(c.epss_score, 4) if c.epss_score else None,
            "in_kev":      c.in_kev,
            "priority":    round(c.priority_score, 2) if c.priority_score else None,
            "description": (c.description or "")[:200],
            "published":   c.published_at.isoformat() if c.published_at else None,
            "actors":      json.loads(c.threat_actors) if c.threat_actors else [],
        })

    return json.dumps({
        "count":   len(results),
        "results": results,
    })


async def _search_news(args: dict, db: AsyncSession) -> str:
    query      = (args.get("query") or "").strip()
    severity   = args.get("severity")
    hours_back = int(args.get("hours_back") or 48)
    limit      = min(int(args.get("limit") or 10), 20)
    cutoff     = datetime.utcnow() - timedelta(hours=hours_back)

    stmt = (
        select(NewsItem)
        .where(NewsItem.published_at >= cutoff)
        .order_by(desc(NewsItem.published_at))
    )

    if query:
        pattern = f"%{query}%"
        stmt = stmt.where(
            or_(
                NewsItem.title.ilike(pattern),
                NewsItem.summary.ilike(pattern),
            )
        )
    if severity:
        stmt = stmt.where(NewsItem.severity == severity)

    rows = (await db.scalars(stmt.limit(limit))).all()

    results = []
    for n in rows:
        results.append({
            "title":    n.title,
            "source":   n.source,
            "severity": n.severity,
            "url":      n.url,
            "actors":   json.loads(n.threat_actors) if n.threat_actors else [],
            "cves":     json.loads(n.cve_refs)      if n.cve_refs      else [],
            "published": n.published_at.isoformat() if n.published_at else None,
            "summary":  (n.summary or "")[:200],
        })

    return json.dumps({
        "window_hours": hours_back,
        "count":        len(results),
        "results":      results,
    })


async def _get_actor_profile(args: dict, db: AsyncSession) -> str:
    name = (args.get("name") or "").strip()
    if not name:
        return json.dumps({"error": "name is required"})

    pattern = f"%{name}%"
    actor = await db.scalar(
        select(ThreatActor).where(
            or_(
                ThreatActor.name.ilike(pattern),
                ThreatActor.aliases.ilike(pattern),
            )
        )
    )

    if not actor:
        return json.dumps({"error": f"Threat actor '{name}' not found in database"})

    return json.dumps({
        "name":        actor.name,
        "mitre_id":    actor.mitre_id,
        "country":     actor.country,
        "motivation":  actor.motivation,
        "description": (actor.description or "")[:400],
        "aliases":     json.loads(actor.aliases)    if actor.aliases    else [],
        "techniques":  json.loads(actor.techniques) if actor.techniques else [],
        "last_seen":   actor.last_seen.isoformat()  if actor.last_seen  else None,
    })


async def _search_iocs(args: dict, db: AsyncSession) -> str:
    query    = (args.get("query") or "").strip()
    ioc_type = args.get("ioc_type")
    limit    = min(int(args.get("limit") or 10), 20)

    stmt = select(IOCItem).order_by(desc(IOCItem.fetched_at))

    if query:
        pattern = f"%{query}%"
        stmt = stmt.where(
            or_(
                IOCItem.value.ilike(pattern),
                IOCItem.malware_family.ilike(pattern),
            )
        )
    if ioc_type:
        stmt = stmt.where(IOCItem.ioc_type == ioc_type)

    rows = (await db.scalars(stmt.limit(limit))).all()

    results = []
    for ioc in rows:
        results.append({
            "ioc_type":       ioc.ioc_type,
            "value":          ioc.value,
            "malware_family": ioc.malware_family,
            "source":         ioc.source,
            "confidence":     ioc.confidence,
            "tags":           json.loads(ioc.tags) if ioc.tags else [],
            "first_seen":     ioc.first_seen.isoformat() if ioc.first_seen else None,
        })

    return json.dumps({
        "count":   len(results),
        "results": results,
    })


async def _get_stats(args: dict, db: AsyncSession) -> str:
    hours_back = int(args.get("hours_back") or 24)
    cutoff     = datetime.utcnow() - timedelta(hours=hours_back)

    total_news   = await db.scalar(select(func.count()).select_from(NewsItem).where(NewsItem.published_at >= cutoff)) or 0
    critical_news = await db.scalar(select(func.count()).select_from(NewsItem).where(NewsItem.severity == "CRITICAL").where(NewsItem.published_at >= cutoff)) or 0
    high_news    = await db.scalar(select(func.count()).select_from(NewsItem).where(NewsItem.severity == "HIGH").where(NewsItem.published_at >= cutoff)) or 0
    total_cves   = await db.scalar(select(func.count()).select_from(CVEItem)) or 0
    kev_count    = await db.scalar(select(func.count()).select_from(CVEItem).where(CVEItem.in_kev == True)) or 0
    critical_cves = await db.scalar(select(func.count()).select_from(CVEItem).where(CVEItem.severity == "CRITICAL")) or 0
    total_iocs   = await db.scalar(select(func.count()).select_from(IOCItem)) or 0
    total_actors = await db.scalar(select(func.count()).select_from(ThreatActor)) or 0

    # Active actors in recent news
    recent_news_rows = (await db.scalars(
        select(NewsItem)
        .where(NewsItem.published_at >= cutoff)
        .where(NewsItem.threat_actors.isnot(None))
        .limit(50)
    )).all()
    actor_set: set[str] = set()
    for n in recent_news_rows:
        if n.threat_actors:
            try:
                actor_set.update(json.loads(n.threat_actors))
            except Exception:
                pass

    return json.dumps({
        "window_hours":   hours_back,
        "news": {
            "total":    total_news,
            "critical": critical_news,
            "high":     high_news,
        },
        "cves": {
            "total":    total_cves,
            "critical": critical_cves,
            "kev":      kev_count,
        },
        "iocs":          total_iocs,
        "threat_actors": {
            "total":  total_actors,
            "active": sorted(actor_set)[:15],
        },
    })


async def _get_asset_vulns(args: dict, db: AsyncSession) -> str:
    asset_name    = (args.get("asset_name") or "").strip()
    min_risk      = args.get("min_risk_score")

    stmt = select(Asset).where(Asset.monitor_shodan == True).order_by(desc(Asset.risk_score))

    if asset_name:
        pattern = f"%{asset_name}%"
        stmt = stmt.where(
            or_(
                Asset.name.ilike(pattern),
                Asset.value.ilike(pattern),
            )
        )
    if min_risk is not None:
        stmt = stmt.where(Asset.risk_score >= float(min_risk))

    rows = (await db.scalars(stmt.limit(20))).all()

    results = []
    for a in rows:
        vuln_ids: list[str] = []
        if a.vulns_detected:
            try:
                vuln_ids = json.loads(a.vulns_detected)
            except Exception:
                pass

        ports: list[int] = []
        if a.open_ports:
            try:
                ports = json.loads(a.open_ports)
            except Exception:
                pass

        results.append({
            "name":          a.name,
            "type":          a.asset_type,
            "value":         a.value,
            "risk_score":    a.risk_score,
            "open_ports":    ports[:20],
            "vulns":         vuln_ids[:20],
            "vuln_count":    len(vuln_ids),
            "last_scanned":  a.last_scanned.isoformat() if a.last_scanned else None,
        })

    return json.dumps({
        "count":   len(results),
        "assets":  results,
    })
