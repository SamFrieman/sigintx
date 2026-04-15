"""
SIGINTX — Agentic Intelligence Engine (v3.0.0)

Exports used by main.py:
  build_threat_context   — live DB snapshot → context dict for prompt injection
  stream_ollama          — single-turn streaming chat with context injection
  generate_briefing      — non-streaming briefing (persists AiBriefing to DB)
  stream_briefing        — streaming briefing generation (SSE, persists on done)
  agentic_stream         — multi-turn ReAct tool-calling loop (SSE)
  compute_delta          — current vs. baseline threat comparison
"""

import json
import logging
import re
from datetime import datetime, timedelta
from typing import AsyncGenerator

import httpx
from sqlalchemy import select, func, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession

from database import (
    NewsItem, CVEItem, ThreatActor, IOCItem, AiBriefing, SessionLocal,
)

logger = logging.getLogger("sigintx.agents")

MAX_TOOL_ROUNDS = 5


# ── Prompts ───────────────────────────────────────────────────────────────────

_ANALYST_SYSTEM = """\
You are SIGINTX, an expert autonomous cybersecurity analyst with access to a live threat intelligence database.

To investigate threats, use tools by outputting a tool call on its own line with this exact format:
<tool_call>{{"name": "TOOL_NAME", "args": {{JSON_ARGS}}}}</tool_call>

AVAILABLE TOOLS:
- search_news    args: query(str), severity(str opt: CRITICAL/HIGH/MEDIUM/INFO), hours_back(int def 24), limit(int def 5)
- search_actors  args: query(str), limit(int def 5)
- get_stats      args: {{}} — overall database statistics
- get_campaigns  args: days_back(int def 7) — campaign timeline by actor

RULES:
- Use tools to find concrete evidence before answering
- Only reference CVE IDs and actor names that appear explicitly in news items returned by search_news
- Be specific: include actor names, detection rules, patch guidance sourced from news
- After tool results, either call more tools or give your final answer (no more tool calls)
- Current UTC time: {utc_now}
"""

_BRIEFING_SYSTEM = """\
You are a senior cyber threat intelligence analyst producing a structured briefing.
Format your response as:
## Executive Summary
## Active Threat Campaigns
## Active Threat Actors
## Recommended Actions
Be concise, factual, and only cite CVE IDs and actor names that appear directly in the news intelligence provided.
"""

_TOOL_CALL_RE = re.compile(r"<tool_call>(.*?)</tool_call>", re.DOTALL)


# ── Tool implementations ──────────────────────────────────────────────────────

async def _tool_search_news(
    db: AsyncSession,
    query: str = "",
    severity: str | None = None,
    hours_back: int = 24,
    limit: int = 5,
) -> str:
    cutoff = datetime.utcnow() - timedelta(hours=max(1, min(hours_back, 168)))
    q = select(NewsItem).where(NewsItem.published_at >= cutoff).order_by(desc(NewsItem.published_at))
    if severity:
        q = q.where(NewsItem.severity == severity.upper())
    if query:
        q = q.where(
            NewsItem.title.ilike(f"%{query}%") |
            NewsItem.summary.ilike(f"%{query}%")
        )
    q = q.limit(min(int(limit), 15))
    rows = (await db.scalars(q)).all()
    if not rows:
        return f"No news found: query={query!r} severity={severity} hours_back={hours_back}"
    parts = []
    for item in rows:
        cves   = json.loads(item.cve_refs) if item.cve_refs else []
        actors = json.loads(item.threat_actors) if item.threat_actors else []
        line = f"[{item.severity}] {item.title}"
        if cves:   line += f"\n  CVEs: {', '.join(cves[:5])}"
        if actors: line += f"\n  Actors: {', '.join(actors[:3])}"
        if item.source: line += f"\n  Source: {item.source}"
        if item.summary: line += f"\n  {item.summary[:200]}"
        parts.append(line)
    return f"Found {len(rows)} news items:\n\n" + "\n\n".join(parts)


async def _tool_search_cves(
    db: AsyncSession,
    query: str | None = None,
    severity: str | None = None,
    min_cvss: float | None = None,
    kev_only: bool = False,
    limit: int = 5,
) -> str:
    q = select(CVEItem).order_by(desc(CVEItem.priority_score))
    if severity:
        q = q.where(CVEItem.severity == severity.upper())
    if min_cvss is not None:
        q = q.where(CVEItem.cvss_score >= float(min_cvss))
    if kev_only:
        q = q.where(CVEItem.in_kev.is_(True))
    if query:
        q = q.where(
            CVEItem.cve_id.ilike(f"%{query}%") |
            CVEItem.description.ilike(f"%{query}%")
        )
    q = q.limit(min(int(limit), 15))
    rows = (await db.scalars(q)).all()
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
        if cve.description:
            line += f"\n  {cve.description[:200]}"
        if actors:
            line += f"\n  Actors: {', '.join(actors[:3])}"
        parts.append(line)
    return f"Found {len(rows)} CVEs:\n\n" + "\n\n".join(parts)


async def _tool_search_actors(
    db: AsyncSession,
    query: str = "",
    limit: int = 5,
) -> str:
    q = select(ThreatActor).order_by(ThreatActor.name)
    if query:
        q = q.where(
            ThreatActor.name.ilike(f"%{query}%") |
            ThreatActor.aliases.ilike(f"%{query}%")
        )
    q = q.limit(min(int(limit), 20))
    rows = (await db.scalars(q)).all()
    if not rows:
        return f"No threat actors found for query={query!r}"
    parts = []
    for actor in rows:
        aliases    = json.loads(actor.aliases) if actor.aliases else []
        techniques = json.loads(actor.techniques) if actor.techniques else []
        line = f"{actor.name} [{actor.country or 'Unknown'}]"
        if actor.mitre_id:   line += f"  MITRE:{actor.mitre_id}"
        if actor.motivation: line += f"\n  Motivation: {actor.motivation}"
        if aliases:          line += f"\n  Aliases: {', '.join(aliases[:5])}"
        if techniques:       line += f"\n  Techniques: {', '.join(techniques[:5])}"
        if actor.description: line += f"\n  {actor.description[:200]}"
        parts.append(line)
    return f"Found {len(rows)} threat actors:\n\n" + "\n\n".join(parts)


async def _tool_search_iocs(
    db: AsyncSession,
    ioc_type: str | None = None,
    malware_family: str | None = None,
    limit: int = 10,
) -> str:
    q = select(IOCItem).order_by(desc(IOCItem.first_seen))
    if ioc_type:
        q = q.where(IOCItem.ioc_type == ioc_type)
    if malware_family:
        q = q.where(IOCItem.malware_family.ilike(f"%{malware_family}%"))
    q = q.limit(min(int(limit), 50))
    rows = (await db.scalars(q)).all()
    if not rows:
        return "No IOCs found matching criteria."
    parts = [
        f"[{ioc.ioc_type}] {ioc.value[:80]}  |  {ioc.malware_family or 'unknown'}  |  {ioc.source}"
        for ioc in rows
    ]
    return f"Found {len(rows)} IOCs:\n" + "\n".join(parts)


async def _tool_get_stats(db: AsyncSession) -> str:
    now = datetime.utcnow()
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


async def _tool_get_campaigns(db: AsyncSession, days_back: int = 7) -> str:
    from correlate import build_campaigns  # local import avoids circular dep at module load
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
    """Dispatch a named tool call, return formatted result string."""
    safe = {k: v for k, v in args.items() if not isinstance(v, (dict, list))}
    try:
        if name == "search_news":
            return await _tool_search_news(db, **{k: v for k, v in safe.items() if k in ("query", "severity", "hours_back", "limit")})
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


# ── Context builder ───────────────────────────────────────────────────────────

async def build_threat_context(db: AsyncSession, hours_back: int = 24) -> dict:
    """
    Assemble a live threat context dict from the DB.
    Returns structured data (used by /api/v1/ai/context) and a context_text
    string suitable for system-prompt injection.
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)

    total_news    = await db.scalar(select(func.count(NewsItem.id)).where(NewsItem.published_at >= cutoff)) or 0
    total_critical = await db.scalar(select(func.count(NewsItem.id)).where(and_(NewsItem.published_at >= cutoff, NewsItem.severity == "CRITICAL"))) or 0
    total_actors_db = await db.scalar(select(func.count(ThreatActor.id))) or 0

    # Recent high/critical news
    recent_news = (await db.scalars(
        select(NewsItem)
        .where(and_(
            NewsItem.published_at >= cutoff,
            NewsItem.severity.in_(["CRITICAL", "HIGH"]),
        ))
        .order_by(desc(NewsItem.published_at))
        .limit(10)
    )).all()

    # Active actors from recent news
    actor_rows = (await db.scalars(
        select(NewsItem.threat_actors)
        .where(and_(
            NewsItem.published_at >= cutoff,
            NewsItem.threat_actors.isnot(None),
        ))
    )).all()
    seen: set[str] = set()
    active_actors: list[str] = []
    for ta_json in actor_rows:
        try:
            for a in json.loads(ta_json):
                if a and a not in seen:
                    seen.add(a)
                    active_actors.append(a)
        except Exception:
            pass
    active_actors = active_actors[:10]

    # Build context text
    news_lines = []
    for item in recent_news:
        cves   = json.loads(item.cve_refs) if item.cve_refs else []
        actors = json.loads(item.threat_actors) if item.threat_actors else []
        line = f"  [{item.severity}] {item.title}"
        if cves:   line += f" | CVEs: {', '.join(cves[:3])}"
        if actors: line += f" | Actors: {', '.join(actors[:2])}"
        if item.source: line += f" ({item.source})"
        news_lines.append(line)

    context_text = (
        f"THREAT INTELLIGENCE SNAPSHOT ({hours_back}h window)\n"
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n\n"
        f"STATISTICS:\n"
        f"  News ({hours_back}h): {total_news}  |  Critical: {total_critical}\n"
        f"  Threat Actors in DB: {total_actors_db}\n"
        f"  Active Actors (from news): {', '.join(active_actors) or 'none detected'}\n\n"
        + "RECENT HIGH/CRITICAL INTELLIGENCE:\n"
        + ("\n".join(news_lines) or "  (none in window)")
    )

    return {
        "total_news":     total_news,
        "total_critical": total_critical,
        "total_actors":   total_actors_db,
        "active_actors":  active_actors,
        "recent_news":    [{"title": n.title, "severity": n.severity, "source": n.source} for n in recent_news],
        "context_text":   context_text,
    }


# ── Basic streaming chat ──────────────────────────────────────────────────────

async def stream_ollama(
    message: str,
    ctx: dict,
    model: str,
    ollama_host: str,
) -> AsyncGenerator[str, None]:
    """Single-turn streaming response with threat context injected as system prompt."""
    system = (
        "You are SIGINTX, a cybersecurity analyst with access to live threat intelligence.\n\n"
        "Current intelligence context:\n"
        + ctx.get("context_text", "No context available.")
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user",   "content": message},
    ]
    url = f"{ollama_host.rstrip('/')}/api/chat"
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST", url,
                json={"model": model, "messages": messages, "stream": True},
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("message", {}).get("content", "")
                        done  = chunk.get("done", False)
                        if token:
                            yield f"data: {json.dumps({'text': token, 'done': False})}\n\n"
                        if done:
                            yield f"data: {json.dumps({'text': '', 'done': True})}\n\n"
                            return
                    except json.JSONDecodeError:
                        pass
    except Exception as exc:
        logger.warning("Ollama stream error: %s", exc)
        yield f"data: {json.dumps({'text': f'⚠️ Ollama error: {exc}', 'done': False})}\n\n"
        yield f"data: {json.dumps({'text': '', 'done': True})}\n\n"


# ── Agentic loop ──────────────────────────────────────────────────────────────

async def agentic_stream(
    message: str,
    model: str,
    ollama_host: str,
    db: AsyncSession,
) -> AsyncGenerator[str, None]:
    """
    Multi-turn ReAct agentic loop.

    SSE event types:
      {"type": "tool_call",   "name": str, "args": dict}
      {"type": "tool_result", "name": str, "text": str}
      {"type": "text",        "text": str}           ← token chunks of final answer
      {"type": "done"}
      {"type": "error",       "text": str}
    """
    utc_now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    system_msg = _ANALYST_SYSTEM.format(utc_now=utc_now)

    messages: list[dict] = [
        {"role": "system", "content": system_msg},
        {"role": "user",   "content": message},
    ]
    url = f"{ollama_host.rstrip('/')}/api/chat"

    for _round in range(MAX_TOOL_ROUNDS):
        # Non-streaming call so we can parse the full response for tool calls
        try:
            async with httpx.AsyncClient(timeout=90.0) as client:
                resp = await client.post(
                    url,
                    json={"model": model, "messages": messages, "stream": False},
                )
                resp.raise_for_status()
                assistant_content = resp.json().get("message", {}).get("content", "")
        except Exception as exc:
            yield f"data: {json.dumps({'type': 'error', 'text': str(exc)})}\n\n"
            yield f"data: {json.dumps({'type': 'done'})}\n\n"
            return

        # Find all tool calls in the response
        raw_calls = _TOOL_CALL_RE.findall(assistant_content)

        if not raw_calls:
            # No tool calls — this is the final answer; stream it word-by-word
            messages.append({"role": "assistant", "content": assistant_content})
            words = assistant_content.split(" ")
            for i, word in enumerate(words):
                chunk_text = word + (" " if i < len(words) - 1 else "")
                yield f"data: {json.dumps({'type': 'text', 'text': chunk_text})}\n\n"
            yield f"data: {json.dumps({'type': 'done'})}\n\n"
            return

        # Execute each tool call and collect results
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

        # Append tool results as a user turn so the model can continue reasoning
        if tool_result_parts:
            messages.append({"role": "user", "content": "\n\n".join(tool_result_parts)})

    # Exceeded max rounds — emit a warning and whatever content we have
    yield f"data: {json.dumps({'type': 'text', 'text': '⚠️ Reached maximum tool rounds. Answer may be incomplete.'})}\n\n"
    yield f"data: {json.dumps({'type': 'done'})}\n\n"


# ── Briefing generation ───────────────────────────────────────────────────────

def _top_severity(news_list: list[dict]) -> str:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1}
    top = "INFO"
    for n in news_list:
        if order.get(n.get("severity", "INFO"), 0) > order.get(top, 0):
            top = n["severity"]
    return top


async def generate_briefing(model: str, ollama_host: str, db: AsyncSession) -> AiBriefing:
    """Non-streaming briefing generation — stores result and returns ORM object."""
    ctx = await build_threat_context(db, hours_back=24)
    user_content = "Generate a comprehensive threat briefing based on this live intelligence data:\n\n" + ctx["context_text"]
    messages = [
        {"role": "system", "content": _BRIEFING_SYSTEM},
        {"role": "user",   "content": user_content},
    ]
    url = f"{ollama_host.rstrip('/')}/api/chat"
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json={"model": model, "messages": messages, "stream": False})
            resp.raise_for_status()
            content = resp.json().get("message", {}).get("content", "")
    except Exception as exc:
        content = f"Briefing generation failed: {exc}"

    briefing = AiBriefing(
        model_used=model,
        content=content,
        news_count=ctx["total_news"],
        cve_count=0,
        top_severity=_top_severity(ctx["recent_news"]),
        threat_actors=json.dumps(ctx["active_actors"]),
    )
    db.add(briefing)
    await db.commit()
    await db.refresh(briefing)
    return briefing


async def stream_briefing(
    model: str,
    ollama_host: str,
    db: AsyncSession,
) -> AsyncGenerator[str, None]:
    """Streaming briefing — yields SSE tokens, persists completed text on done."""
    ctx = await build_threat_context(db, hours_back=24)
    user_content = "Generate a comprehensive threat briefing based on this live intelligence data:\n\n" + ctx["context_text"]
    messages = [
        {"role": "system", "content": _BRIEFING_SYSTEM},
        {"role": "user",   "content": user_content},
    ]
    url = f"{ollama_host.rstrip('/')}/api/chat"
    accumulated = ""

    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            async with client.stream(
                "POST", url,
                json={"model": model, "messages": messages, "stream": True},
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("message", {}).get("content", "")
                        done  = chunk.get("done", False)
                        if token:
                            accumulated += token
                            yield f"data: {json.dumps({'text': token, 'done': False})}\n\n"
                        if done:
                            break
                    except json.JSONDecodeError:
                        pass
    except Exception as exc:
        err = f"⚠️ Briefing generation failed: {exc}"
        accumulated = accumulated or err
        if not accumulated:
            yield f"data: {json.dumps({'text': err, 'done': False})}\n\n"

    # Persist to DB
    briefing = AiBriefing(
        model_used=model,
        content=accumulated,
        news_count=ctx["total_news"],
        cve_count=0,
        top_severity=_top_severity(ctx["recent_news"]),
        threat_actors=json.dumps(ctx["active_actors"]),
    )
    db.add(briefing)
    await db.commit()

    yield f"data: {json.dumps({'text': '', 'done': True})}\n\n"


# ── Delta / baseline comparison ───────────────────────────────────────────────

def _pct(curr: int, base: int) -> float | None:
    if base == 0:
        return None if curr == 0 else 100.0
    return round((curr - base) / base * 100, 1)


async def compute_delta(db: AsyncSession, hours_back: int = 24) -> dict:
    """
    Compare the current window (now-hours_back → now) to the prior baseline
    window (now-hours_back*2 → now-hours_back).

    Returns structured delta suitable for the frontend Delta panel.
    """
    now            = datetime.utcnow()
    curr_start     = now - timedelta(hours=hours_back)
    base_start     = now - timedelta(hours=hours_back * 2)
    base_end       = curr_start

    async def count(model, *conditions):
        return (await db.scalar(select(func.count(model.id)).where(*conditions))) or 0

    # ── News ──────────────────────────────────────────────────────────────────
    curr_news     = await count(NewsItem, NewsItem.published_at >= curr_start)
    base_news     = await count(NewsItem, NewsItem.published_at >= base_start, NewsItem.published_at < base_end)
    curr_critical = await count(NewsItem, NewsItem.published_at >= curr_start, NewsItem.severity == "CRITICAL")
    base_critical = await count(NewsItem, NewsItem.published_at >= base_start, NewsItem.published_at < base_end, NewsItem.severity == "CRITICAL")

    # ── CVEs ──────────────────────────────────────────────────────────────────
    curr_cves = await count(CVEItem, CVEItem.published_at >= curr_start)
    base_cves = await count(CVEItem, CVEItem.published_at >= base_start, CVEItem.published_at < base_end)
    curr_kev  = await count(CVEItem, CVEItem.published_at >= curr_start, CVEItem.in_kev.is_(True))
    base_kev  = await count(CVEItem, CVEItem.published_at >= base_start, CVEItem.published_at < base_end, CVEItem.in_kev.is_(True))

    # ── Actor delta ───────────────────────────────────────────────────────────
    def _actor_set(rows) -> set[str]:
        out: set[str] = set()
        for ta_json in rows:
            try:
                out.update(json.loads(ta_json))
            except Exception:
                pass
        return out

    curr_actor_json = (await db.scalars(
        select(NewsItem.threat_actors)
        .where(NewsItem.published_at >= curr_start, NewsItem.threat_actors.isnot(None))
    )).all()
    base_actor_json = (await db.scalars(
        select(NewsItem.threat_actors)
        .where(NewsItem.published_at >= base_start, NewsItem.published_at < base_end, NewsItem.threat_actors.isnot(None))
    )).all()
    curr_actors = _actor_set(curr_actor_json)
    base_actors = _actor_set(base_actor_json)
    new_actors         = sorted(curr_actors - base_actors)[:20]
    disappeared_actors = sorted(base_actors - curr_actors)[:10]

    # ── Malware family delta ───────────────────────────────────────────────────
    curr_mw = set((await db.scalars(
        select(IOCItem.malware_family)
        .where(IOCItem.first_seen >= curr_start, IOCItem.malware_family.isnot(None))
    )).all())
    base_mw = set((await db.scalars(
        select(IOCItem.malware_family)
        .where(IOCItem.first_seen >= base_start, IOCItem.first_seen < base_end, IOCItem.malware_family.isnot(None))
    )).all())
    new_malware = sorted(curr_mw - base_mw)[:20]

    return {
        "window_hours": hours_back,
        "generated_at": now.isoformat(),
        "news": {
            "current": curr_news, "baseline": base_news,
            "pct_change": _pct(curr_news, base_news),
        },
        "critical_news": {
            "current": curr_critical, "baseline": base_critical,
            "pct_change": _pct(curr_critical, base_critical),
        },
        "cves": {
            "current": curr_cves, "baseline": base_cves,
            "pct_change": _pct(curr_cves, base_cves),
        },
        "kev": {
            "current": curr_kev, "baseline": base_kev,
            "pct_change": _pct(curr_kev, base_kev),
        },
        "new_actors":          new_actors,
        "disappeared_actors":  disappeared_actors,
        "new_malware_families": new_malware,
    }
