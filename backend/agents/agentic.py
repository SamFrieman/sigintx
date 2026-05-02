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

from database import NewsItem, CVEItem, ThreatActor, AiBriefing

logger = logging.getLogger("sigintx.agentic")

MAX_TOOL_ROUNDS = 5

_ANALYST_SYSTEM = """\
You are SIGINTX, an expert autonomous cybersecurity analyst with access to a live threat intelligence platform.

- Respond naturally to greetings and general questions — do NOT call tools for those.
- For threat queries (news, CVEs, actors, campaigns, stats), use the provided tools to retrieve live data.
- Never fabricate CVE IDs, actor names, or threat data. Only cite what appears in tool results.
- After tool results, give a concise, specific, actionable final answer.
Current UTC time: {utc_now}
"""

# OpenAI-compatible tool schemas — used for native function calling on all providers
TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "search_news",
            "description": "Search recent threat intelligence news items in the live database",
            "parameters": {
                "type": "object",
                "properties": {
                    "query":      {"type": "string",  "description": "Keyword or phrase to search"},
                    "severity":   {"type": "string",  "enum": ["CRITICAL", "HIGH", "MEDIUM", "INFO"]},
                    "hours_back": {"type": "integer", "description": "How many hours back to search (default 24)"},
                    "limit":      {"type": "integer", "description": "Max results (default 5, max 15)"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_cves",
            "description": "Search CVEs by keyword, severity, CVSS score, or KEV status",
            "parameters": {
                "type": "object",
                "properties": {
                    "query":     {"type": "string",  "description": "CVE ID or description keyword"},
                    "severity":  {"type": "string",  "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                    "min_cvss":  {"type": "number",  "description": "Minimum CVSS score (0–10)"},
                    "kev_only":  {"type": "boolean", "description": "Only CISA KEV entries"},
                    "limit":     {"type": "integer", "description": "Max results (default 5)"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_actors",
            "description": "Search threat actor profiles (name, aliases, country, TTPs)",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string",  "description": "Actor name or alias"},
                    "limit": {"type": "integer", "description": "Max results (default 5)"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_stats",
            "description": "Return overall database statistics: news counts, CVE counts, threat actor count",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_campaigns",
            "description": "Return active threat campaign timeline grouped by actor",
            "parameters": {
                "type": "object",
                "properties": {
                    "days_back": {"type": "integer", "description": "How many days back (default 7)"},
                },
            },
        },
    },
]

# Text-based fallback parsers for models that ignore function-calling schema
_TOOL_CALL_RE = re.compile(r"<tool_call>(.*?)</tool_call>", re.DOTALL)
_ALT_TOOL_CALL_RE = re.compile(
    r"<(search_news|search_actors|search_cves|get_stats|get_campaigns)\s+(\{[^>]*\})\s*>",
    re.DOTALL,
)


def _extract_tool_calls_from_text(content: str) -> list[dict]:
    """Parse tool calls from model text when native function calling wasn't used."""
    calls = []
    for raw in _TOOL_CALL_RE.findall(content):
        try:
            calls.append(json.loads(raw.strip()))
        except json.JSONDecodeError:
            pass
    if not calls:
        for m in _ALT_TOOL_CALL_RE.finditer(content):
            try:
                calls.append({"name": m.group(1), "args": json.loads(m.group(2))})
            except json.JSONDecodeError:
                pass
    return calls


def _strip_tool_syntax(text: str) -> str:
    text = _TOOL_CALL_RE.sub("", text)
    text = _ALT_TOOL_CALL_RE.sub("", text)
    return text.strip()


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


async def _tool_get_stats(db):
    now        = datetime.utcnow()
    cutoff_24h = now - timedelta(hours=24)
    total_news    = await db.scalar(select(func.count(NewsItem.id))) or 0
    news_24h      = await db.scalar(select(func.count(NewsItem.id)).where(NewsItem.published_at >= cutoff_24h)) or 0
    critical_news = await db.scalar(select(func.count(NewsItem.id)).where(NewsItem.severity == "CRITICAL")) or 0
    total_cves    = await db.scalar(select(func.count(CVEItem.id))) or 0
    kev_count     = await db.scalar(select(func.count(CVEItem.id)).where(CVEItem.in_kev.is_(True))) or 0
    total_actors  = await db.scalar(select(func.count(ThreatActor.id))) or 0
    return (
        f"Database Statistics:\n"
        f"  News: {total_news} total | {news_24h} last 24h | {critical_news} critical\n"
        f"  CVEs: {total_cves} total | {kev_count} in CISA KEV\n"
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
    ollama_host: str | None = None,  # legacy, ignored
) -> AsyncGenerator[str, None]:
    from llm import call_llm_with_tools, call_llm

    utc_now    = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    system_msg = _ANALYST_SYSTEM.format(utc_now=utc_now)
    messages: list[dict] = [
        {"role": "system", "content": system_msg},
        {"role": "user",   "content": message},
    ]

    for _round in range(MAX_TOOL_ROUNDS):
        # ── Attempt native function calling ──────────────────────────────────
        content, structured_calls, raw_api_tc, provider = await call_llm_with_tools(
            messages, db, tools=TOOL_SCHEMAS, model_override=model, timeout_s=90.0
        )

        if not provider:
            # All providers failed — try plain call as last resort
            content, provider = await call_llm(messages, db, model_override=model,
                                               max_tokens=2000, timeout_s=90.0)
            if not provider:
                yield f"data: {json.dumps({'type': 'error', 'text': 'No AI provider available.'})}\n\n"
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                return
            structured_calls = []
            raw_api_tc       = []

        # ── If native tool calls returned, use them ───────────────────────────
        if structured_calls:
            # Add assistant turn with the raw tool_calls blob for correct history
            messages.append({
                "role":       "assistant",
                "content":    content or "",
                "tool_calls": raw_api_tc,
            })

            for tc, call_data in zip(raw_api_tc, structured_calls):
                tool_name = str(call_data.get("name", ""))
                tool_args = call_data.get("args", {})
                if not isinstance(tool_args, dict):
                    tool_args = {}

                yield f"data: {json.dumps({'type': 'tool_call', 'name': tool_name, 'args': tool_args})}\n\n"
                result = await _call_tool(db, tool_name, tool_args)
                yield f"data: {json.dumps({'type': 'tool_result', 'name': tool_name, 'text': result[:600]})}\n\n"

                # Standard tool-result message expected by function-calling models
                messages.append({
                    "role":         "tool",
                    "tool_call_id": tc.get("id", f"call_{tool_name}"),
                    "content":      result,
                })
            continue  # loop back — model will synthesise final answer

        # ── Fallback: parse tool calls from text ─────────────────────────────
        text_calls = _extract_tool_calls_from_text(content or "")
        if text_calls:
            messages.append({"role": "assistant", "content": content})
            tool_result_parts: list[str] = []

            for call_data in text_calls:
                tool_name = str(call_data.get("name", ""))
                tool_args = call_data.get("args", {})
                if not isinstance(tool_args, dict):
                    tool_args = {}

                yield f"data: {json.dumps({'type': 'tool_call', 'name': tool_name, 'args': tool_args})}\n\n"
                result = await _call_tool(db, tool_name, tool_args)
                yield f"data: {json.dumps({'type': 'tool_result', 'name': tool_name, 'text': result[:600]})}\n\n"
                tool_result_parts.append(f'<tool_result name="{tool_name}">\n{result}\n</tool_result>')

            messages.append({"role": "user", "content": "\n\n".join(tool_result_parts)})
            continue  # loop back

        # ── No tool calls — stream final answer ───────────────────────────────
        messages.append({"role": "assistant", "content": content or ""})
        final_text = _strip_tool_syntax(content or "")
        words = final_text.split(" ")
        for i, word in enumerate(words):
            yield f"data: {json.dumps({'type': 'text', 'text': word + (' ' if i < len(words) - 1 else '')})}\n\n"
        yield f"data: {json.dumps({'type': 'done'})}\n\n"
        return

    yield f"data: {json.dumps({'type': 'text', 'text': '⚠️ Reached maximum tool rounds.'})}\n\n"
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

    def _malware_set(rows) -> set[str]:
        out: set[str] = set()
        for row in rows:
            try:
                tags = json.loads(row) if isinstance(row, str) else (row or [])
                out.update(t for t in tags if isinstance(t, str))
            except Exception:
                pass
        return out

    from database import IOCItem
    curr_malware = _malware_set((await db.scalars(
        select(IOCItem.malware_family)
        .where(IOCItem.fetched_at >= curr_start, IOCItem.malware_family.isnot(None))
    )).all())
    base_malware = _malware_set((await db.scalars(
        select(IOCItem.malware_family)
        .where(IOCItem.fetched_at >= base_start, IOCItem.fetched_at < base_end, IOCItem.malware_family.isnot(None))
    )).all())

    return {
        "window_hours": hours_back,
        "generated_at": now.isoformat(),
        "news":          {"current": curr_news,     "baseline": base_news,     "pct_change": _pct(curr_news,     base_news)},
        "critical_news": {"current": curr_critical, "baseline": base_critical, "pct_change": _pct(curr_critical, base_critical)},
        "cves":          {"current": curr_cves,     "baseline": base_cves,     "pct_change": _pct(curr_cves,     base_cves)},
        "kev":           {"current": curr_kev,      "baseline": base_kev,      "pct_change": _pct(curr_kev,      base_kev)},
        "new_actors":             sorted(curr_actors  - base_actors)[:20],
        "disappeared_actors":     sorted(base_actors  - curr_actors)[:10],
        "new_malware_families":   sorted(curr_malware - base_malware)[:15],
    }
