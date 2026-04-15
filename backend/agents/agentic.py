"""
SIGINTX — Agentic loop + delta analysis (Sprint 3)
Extracted from agents.py (root-level) into the agents package.
"""
import json
import logging
import re
from datetime import datetime, timedelta
from typing import AsyncGenerator

from sqlalchemy import select, func, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession

from database import NewsItem, CVEItem, ThreatActor, IOCItem, AiBriefing

logger = logging.getLogger("sigintx.agentic")

MAX_TOOL_ROUNDS = 5

_ANALYST_SYSTEM = """\
You are SIGINTX, an expert autonomous cybersecurity analyst with access to a live threat intelligence database.

To investigate threats, use tools by outputting a tool call on its own line with this exact format:
<tool_call>{{"name": "TOOL_NAME", "args": {{JSON_ARGS}}}}</tool_call>

AVAILABLE TOOLS:
- search_news    args: query(str), severity(str opt: CRITICAL/HIGH/MEDIUM/INFO), hours_back(int def 24), limit(int def 5)
- search_cves    args: query(str opt), severity(str opt), min_cvss(float opt), kev_only(bool opt), limit(int def 5)
- search_actors  args: query(str), limit(int def 5)
- search_iocs    args: ioc_type(str opt: hash_sha256/url/ip/domain), malware_family(str opt), limit(int def 10)
- get_stats      args: {{}} — overall database statistics
- get_campaigns  args: days_back(int def 7) — campaign timeline by actor

RULES:
- Use tools to find concrete evidence before answering
- Only reference CVE IDs, actor names, and IOCs that appear in tool results
- Be specific: include CVE IDs, actor names, detection rules, patch guidance
- After tool results, either call more tools or give your final answer (no more tool calls)
- Current UTC time: {utc_now}
"""

_TOOL_CALL_RE = re.compile(r"<tool_call>(.*?)</tool_call>", re.DOTALL)


# ── Tool implementations ──────────────────────────────────────────────────────

async def _tool_search_news(db, query="", severity=None, hours_back=24, limit=5):
    cutoff = datetime.utcnow() - timedelta(hours=max(1, min(hours_back, 168)))
    q = select(NewsItem).where(NewsItem.published_at >= cutoff).order_by(desc(NewsItem.published_at))
    if severity:
        q = q.where(NewsItem.severity == severity.upper())
    if query:
        q = q.where(
            NewsItem.title.ilike(f"%{query}%") |
            NewsItem.summary.ilike(f"%{query}%")
        )
    rows = (await db.scalars(q.limit(min(int(limit), 15)))).all()
    if not rows:
        return f"No news found: query={query!r} severity={severity} hours_back={hours_back}"
    parts = []
    for item in rows:
        cves   = json.loads(item.cve_refs)      if item.cve_refs      else []
        actors = json.loads(item.threat_actors) if item.threat_actors else []
        line = f"[{item.severity}] {item.title}"
        if cves:   line += f"\n  CVEs: {', '.join(cves[:5])}"
        if actors: line += f"\n  Actors: {', '.join(actors[:3])}"
        if item.source:  line += f"\n  Source: {item.source}"
        if item.summary: line += f"\n  {item.summary[:200]}"
        parts.append(line)
    return f"Found {len(rows)} news items:\n\n" + "\n\n".join(parts)


async def _tool_search_cves(db, query=None, severity=None, min_cvss=None, kev_only=False, limit=5):
    q = select(CVEItem).order_by(desc(CVEItem.priority_score))
    if severity:  q = q.where(CVEItem.severity == severity.upper())
    if min_cvss:  q = q.where(CVEItem.cvss_score >= float(min_cvss))
    if kev_only:  q = q.where(CVEItem.in_kev.is_(True))
    if query:
        q = q.where(
            CVEItem.cve_id.ilike(f"%{query}%") |
            CVEItem.description.ilike(f"%{query}%")
        )
    rows = (await db.scalars(q.limit(min(int(limit), 15)))).all()
    if not rows:
        return "No CVEs found matching the criteria."
    parts = []
    for cve in rows:
        actors = json.loads(cve.threat_actors) if cve.threat_actors else []
        line = (
            f"{cve.cve_id} [{cve.severity}]  CVSS:{cve.cvss_score or '?'}  "
            f"Priority:{cve.priority_score or '?'}  "
            f"{'CISA-KEV ' if cve.in_kev else ''}"
            f"EPSS:{(cve.epss_score or 0) * 100:.2f}%"
        )
        if cve.description: line += f"\n  {cve.description[:200]}"
        if actors:          line += f"\n  Actors: {', '.join(actors[:3])}"
        parts.append(line)
    return f"Found {len(rows)} CVEs:\n\n" + "\n\n".join(parts)


async def _tool_search_actors(db, query="", limit=5):
    q = select(ThreatActor).order_by(ThreatActor.name)
    if query:
        q = q.where(
            ThreatActor.name.ilike(f"%{query}%") |
            ThreatActor.aliases.ilike(f"%{query}%")
        )
    rows = (await db.scalars(q.limit(min(int(limit), 20)))).all()
    if not rows:
        return f"No threat actors found for query={query!r}"
    parts = []
    for actor in rows:
        aliases    = json.loads(actor.aliases)    if actor.aliases    else []
        techniques = json.loads(actor.techniques) if actor.techniques else []
        line = f"{actor.name} [{actor.country or 'Unknown'}]"
        if actor.mitre_id:    line += f"  MITRE:{actor.mitre_id}"
        if actor.motivation:  line += f"\n  Motivation: {actor.motivation}"
        if aliases:           line += f"\n  Aliases: {', '.join(aliases[:5])}"
        if techniques:        line += f"\n  Techniques: {', '.join(techniques[:5])}"
        if actor.description: line += f"\n  {actor.description[:200]}"
        parts.append(line)
    return f"Found {len(rows)} threat actors:\n\n" + "\n\n".join(parts)


async def _tool_search_iocs(db, ioc_type=None, malware_family=None, limit=10):
    q = select(IOCItem).order_by(desc(IOCItem.first_seen))
    if ioc_type:       q = q.where(IOCItem.ioc_type == ioc_type)
    if malware_family: q = q.where(IOCItem.malware_family.ilike(f"%{malware_family}%"))
    rows = (await db.scalars(q.limit(min(int(limit), 50)))).all()
    if not rows:
        return "No IOCs found matching criteria."
    parts = [
        f"[{ioc.ioc_type}] {ioc.value[:80]}  |  {ioc.malware_family or 'unknown'}  |  {ioc.source}"
        for ioc in rows
    ]
    return f"Found {len(rows)} IOCs:\n" + "\n".join(parts)


async def _tool_get_stats(db):
    now        = datetime.utcnow()
    cutoff_24h = now - timedelta(hours=24)
    total_news    = await db.scalar(select(func.count(NewsItem.id))) or 0
    news_24h      = await db.scalar(select(func.count(NewsItem.id)).where(NewsItem.published_at >= cutoff_24h)) or 0
    critical_news = await db.scalar(select(func.count(NewsItem.id)).where(NewsItem.severity == "CRITICAL")) or 0
    total_cves    = await db.scalar(select(func.count(CVEItem.id))) or 0
    kev_count     = await db.scalar(select(func.count(CVEItem.id)).where(CVEItem.in_kev.is_(True))) or 0
    total_iocs    = await db.scalar(select(func.count(IOCItem.id))) or 0
    total_actors  = await db.scalar(select(func.count(ThreatActor.id))) or 0
    return (
        f"Database Statistics:\n"
        f"  News: {total_news} total | {news_24h} last 24h | {critical_news} critical\n"
        f"  CVEs: {total_cves} total | {kev_count} in CISA KEV\n"
        f"  IOCs: {total_iocs} total\n"
        f"  Threat Actors: {total_actors}\n"
    )


async def _tool_get_campaigns(db, days_back=7):
    from correlate import build_campaigns
    campaigns = await build_campaigns(days_back=max(1, min(int(days_back), 90)))
    if not campaigns:
        return f"No campaigns found in the last {days_back} days."
    parts = []
    for c in campaigns[:8]:
        line = f"{c['actor']} [{c['top_severity']}]  news:{c['news_count']}  CVEs:{c['cve_count']}"
        if c["first_seen"]: line += f"\n  Active: {c['first_seen'][:10]} → {(c['last_seen'] or '')[:10]}"
        if c["cves"]:       line += f"\n  CVEs: {', '.join(c['cves'][:5])}"
        parts.append(line)
    return f"Found {len(campaigns)} active campaigns (showing top 8):\n\n" + "\n\n".join(parts)


async def _call_tool(db: AsyncSession, name: str, args: dict) -> str:
    safe = {k: v for k, v in args.items() if not isinstance(v, (dict, list))}
    try:
        if name == "search_news":
            return await _tool_search_news(db, **{k: v for k, v in safe.items() if k in ("query", "severity", "hours_back", "limit")})
        if name == "search_cves":
            return await _tool_search_cves(db, **{k: v for k, v in args.items() if k in ("query", "severity", "min_cvss", "kev_only", "limit")})
        if name == "search_actors":
            return await _tool_search_actors(db, **{k: v for k, v in safe.items() if k in ("query", "limit")})
        if name == "search_iocs":
            return await _tool_search_iocs(db, **{k: v for k, v in safe.items() if k in ("ioc_type", "malware_family", "limit")})
        if name == "get_stats":
            return await _tool_get_stats(db)
        if name == "get_campaigns":
            return await _tool_get_campaigns(db, **{k: v for k, v in safe.items() if k in ("days_back",)})
        return f"Unknown tool: {name}"
    except Exception as exc:
        logger.warning("Tool %s error: %s", name, exc)
        return f"Tool error: {exc}"


# ── Agentic loop ──────────────────────────────────────────────────────────────

async def agentic_stream(
    message: str,
    db: AsyncSession,
    model: str | None = None,
    # Legacy params kept for call-site compatibility — ignored
    ollama_host: str | None = None,
) -> AsyncGenerator[str, None]:
    from llm import call_llm

    utc_now    = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    system_msg = _ANALYST_SYSTEM.format(utc_now=utc_now)
    messages: list[dict] = [
        {"role": "system", "content": system_msg},
        {"role": "user",   "content": message},
    ]

    for _round in range(MAX_TOOL_ROUNDS):
        content, _ = await call_llm(
            messages, db, model_override=model, max_tokens=2000, timeout_s=90.0
        )
        if content is None:
            yield f"data: {json.dumps({'type': 'error', 'text': 'No AI provider available. Configure Ollama or a cloud provider in Settings.'})}\n\n"
            yield f"data: {json.dumps({'type': 'done'})}\n\n"
            return
        assistant_content = content

        raw_calls = _TOOL_CALL_RE.findall(assistant_content)

        if not raw_calls:
            messages.append({"role": "assistant", "content": assistant_content})
            words = assistant_content.split(" ")
            for i, word in enumerate(words):
                chunk_text = word + (" " if i < len(words) - 1 else "")
                yield f"data: {json.dumps({'type': 'text', 'text': chunk_text})}\n\n"
            yield f"data: {json.dumps({'type': 'done'})}\n\n"
            return

        messages.append({"role": "assistant", "content": assistant_content})
        tool_result_parts: list[str] = []

        for raw in raw_calls:
            try:
                call_data = json.loads(raw.strip())
                tool_name = str(call_data.get("name", ""))
                tool_args = call_data.get("args", {})
                if not isinstance(tool_args, dict):
                    tool_args = {}
            except (json.JSONDecodeError, KeyError):
                continue

            yield f"data: {json.dumps({'type': 'tool_call', 'name': tool_name, 'args': tool_args})}\n\n"
            result = await _call_tool(db, tool_name, tool_args)
            yield f"data: {json.dumps({'type': 'tool_result', 'name': tool_name, 'text': result[:600]})}\n\n"
            tool_result_parts.append(f'<tool_result name="{tool_name}">\n{result}\n</tool_result>')

        if tool_result_parts:
            messages.append({"role": "user", "content": "\n\n".join(tool_result_parts)})

    yield f"data: {json.dumps({'type': 'text', 'text': '⚠️ Reached maximum tool rounds. Answer may be incomplete.'})}\n\n"
    yield f"data: {json.dumps({'type': 'done'})}\n\n"


# ── Delta / baseline comparison ───────────────────────────────────────────────

def _pct(curr: int, base: int) -> float | None:
    if base == 0:
        return None if curr == 0 else 100.0
    return round((curr - base) / base * 100, 1)


async def compute_delta(db: AsyncSession, hours_back: int = 24) -> dict:
    now        = datetime.utcnow()
    curr_start = now - timedelta(hours=hours_back)
    base_start = now - timedelta(hours=hours_back * 2)
    base_end   = curr_start

    async def count(model, *conditions):
        return (await db.scalar(select(func.count(model.id)).where(*conditions))) or 0

    curr_news     = await count(NewsItem, NewsItem.published_at >= curr_start)
    base_news     = await count(NewsItem, NewsItem.published_at >= base_start, NewsItem.published_at < base_end)
    curr_critical = await count(NewsItem, NewsItem.published_at >= curr_start, NewsItem.severity == "CRITICAL")
    base_critical = await count(NewsItem, NewsItem.published_at >= base_start, NewsItem.published_at < base_end, NewsItem.severity == "CRITICAL")
    curr_cves     = await count(CVEItem, CVEItem.published_at >= curr_start)
    base_cves     = await count(CVEItem, CVEItem.published_at >= base_start, CVEItem.published_at < base_end)
    curr_kev      = await count(CVEItem, CVEItem.published_at >= curr_start, CVEItem.in_kev.is_(True))
    base_kev      = await count(CVEItem, CVEItem.published_at >= base_start, CVEItem.published_at < base_end, CVEItem.in_kev.is_(True))

    def _actor_set(rows) -> set[str]:
        out: set[str] = set()
        for ta_json in rows:
            try: out.update(json.loads(ta_json))
            except Exception: pass
        return out

    curr_actors = _actor_set((await db.scalars(
        select(NewsItem.threat_actors)
        .where(NewsItem.published_at >= curr_start, NewsItem.threat_actors.isnot(None))
    )).all())
    base_actors = _actor_set((await db.scalars(
        select(NewsItem.threat_actors)
        .where(NewsItem.published_at >= base_start, NewsItem.published_at < base_end, NewsItem.threat_actors.isnot(None))
    )).all())

    curr_mw = set((await db.scalars(
        select(IOCItem.malware_family)
        .where(IOCItem.first_seen >= curr_start, IOCItem.malware_family.isnot(None))
    )).all())
    base_mw = set((await db.scalars(
        select(IOCItem.malware_family)
        .where(IOCItem.first_seen >= base_start, IOCItem.first_seen < base_end, IOCItem.malware_family.isnot(None))
    )).all())

    return {
        "window_hours": hours_back,
        "generated_at": now.isoformat(),
        "news":          {"current": curr_news,     "baseline": base_news,     "pct_change": _pct(curr_news,     base_news)},
        "critical_news": {"current": curr_critical, "baseline": base_critical, "pct_change": _pct(curr_critical, base_critical)},
        "cves":          {"current": curr_cves,     "baseline": base_cves,     "pct_change": _pct(curr_cves,     base_cves)},
        "kev":           {"current": curr_kev,      "baseline": base_kev,      "pct_change": _pct(curr_kev,      base_kev)},
        "new_actors":           sorted(curr_actors - base_actors)[:20],
        "disappeared_actors":   sorted(base_actors - curr_actors)[:10],
        "new_malware_families": sorted(curr_mw - base_mw)[:20],
    }
