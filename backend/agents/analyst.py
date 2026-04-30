"""
SIGINTX — AI Analyst Agent (v2.0.0)
Context-aware threat intelligence assistant backed by Ollama.
Provides streaming chat, automated threat briefings, and contextual analysis.
"""
import json
import logging
from datetime import datetime, timedelta
from typing import AsyncIterator

from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from database import NewsItem, CVEItem, IOCItem, AiBriefing

logger = logging.getLogger("sigintx.analyst")

SYSTEM_PROMPT = """You are SIGINT-X, an elite autonomous cyber threat intelligence analyst \
embedded in the SIGINTX open-source threat monitoring platform.

Your capabilities:
- Real-time analysis of threat feeds, CVEs, IOCs, and campaigns
- Threat actor attribution and TTPs identification
- Vulnerability prioritization using CVSS, EPSS, and KEV status
- Pattern detection across news, CVEs, and indicators of compromise
- Actionable remediation and hunting guidance

Operational rules:
- Be concise, direct, and operationally focused
- Reference specifics: CVE IDs, actor names, MITRE techniques, dates
- Prominently flag CRITICAL threats
- Use markdown formatting with headers for structured responses
- When uncertain, state it — never fabricate data
"""


async def build_threat_context(db: AsyncSession, hours_back: int = 24) -> dict:
    """
    Query the database and build a structured snapshot of the current threat landscape.
    Used to inject live context into every AI prompt.
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)

    # Recent critical/high news
    news_rows = (await db.scalars(
        select(NewsItem)
        .where(NewsItem.published_at >= cutoff)
        .where(NewsItem.severity.in_(["CRITICAL", "HIGH"]))
        .order_by(desc(NewsItem.published_at))
        .limit(15)
    )).all()

    # Top CVEs by severity
    cve_rows = (await db.scalars(
        select(CVEItem)
        .where(CVEItem.severity.in_(["CRITICAL", "HIGH"]))
        .order_by(desc(CVEItem.published_at))
        .limit(10)
    )).all()

    # Aggregate counts
    total_news     = await db.scalar(select(func.count()).select_from(NewsItem).where(NewsItem.published_at >= cutoff)) or 0
    total_critical = await db.scalar(select(func.count()).select_from(NewsItem).where(NewsItem.severity == "CRITICAL").where(NewsItem.published_at >= cutoff)) or 0
    total_iocs     = await db.scalar(select(func.count()).select_from(IOCItem)) or 0
    kev_count      = await db.scalar(select(func.count()).select_from(CVEItem).where(CVEItem.in_kev == True)) or 0

    # Unique active actors from news
    actor_set: set[str] = set()
    for n in news_rows:
        if n.threat_actors:
            try:
                actor_set.update(json.loads(n.threat_actors))
            except Exception:
                pass

    return {
        "window_hours":   hours_back,
        "total_news":     total_news,
        "total_critical": total_critical,
        "total_iocs":     total_iocs,
        "kev_count":      kev_count,
        "active_actors":  sorted(actor_set)[:15],
        "top_news": [
            {
                "title":    n.title,
                "source":   n.source,
                "severity": n.severity,
                "actors":   json.loads(n.threat_actors) if n.threat_actors else [],
                "cves":     json.loads(n.cve_refs)      if n.cve_refs      else [],
                "published": n.published_at.isoformat() if n.published_at else None,
            }
            for n in news_rows
        ],
        "top_cves": [
            {
                "id":          c.cve_id,
                "cvss":        c.cvss_score,
                "severity":    c.severity,
                "in_kev":      c.in_kev,
                "epss":        c.epss_score,
                "description": (c.description or "")[:250],
                "actors":      json.loads(c.threat_actors) if c.threat_actors else [],
            }
            for c in cve_rows
        ],
    }


def _format_context_prompt(ctx: dict) -> str:
    """Render the threat context dict into a concise, structured prompt block."""
    lines = [
        f"[LIVE THREAT INTELLIGENCE — Last {ctx['window_hours']}h as of {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}]",
        f"News items: {ctx['total_news']} collected | {ctx['total_critical']} CRITICAL alerts",
        f"IOC database: {ctx['total_iocs']} indicators | CISA KEV entries: {ctx['kev_count']}",
        f"Active threat actors: {', '.join(ctx['active_actors']) or 'none identified'}",
        "",
        "TOP CRITICAL/HIGH INTELLIGENCE ITEMS:",
    ]
    for i, n in enumerate(ctx["top_news"][:10], 1):
        actors = f" | Actors: {', '.join(n['actors'])}" if n["actors"] else ""
        cves   = f" | CVEs: {', '.join(n['cves'])}"    if n["cves"]   else ""
        lines.append(f"  {i}. [{n['severity']}] {n['title']} — {n['source']}{actors}{cves}")

    if ctx["top_cves"]:
        lines += ["", "TOP CRITICAL/HIGH CVEs:"]
        for c in ctx["top_cves"][:6]:
            kev    = " [⚠ CISA KEV]" if c["in_kev"] else ""
            epss   = f" EPSS:{c['epss']:.2%}" if c["epss"] else ""
            actors = f" | Actors: {', '.join(c['actors'])}" if c["actors"] else ""
            lines.append(f"  • {c['id']} CVSS:{c['cvss']} {c['severity']}{kev}{epss}{actors}")
            if c["description"]:
                lines.append(f"    {c['description'][:160]}")

    lines.append("")
    return "\n".join(lines)


async def stream_ollama(
    user_message: str,
    context: dict,
    db,                                     # AsyncSession — replaces model+ollama_host
    model: str | None = None,               # optional override; provider chain picks default
    # Legacy params kept for call-site compatibility — ignored when db is an AsyncSession
    ollama_host: str | None = None,
    history: list[dict] | None = None,      # prior {role, content} turns for memory
) -> AsyncIterator[str]:
    """
    Stream an AI response with injected live threat context.
    Routes through the multi-provider chain (Ollama → Groq → OpenRouter → Generic).
    Yields SSE: ``data: {"text": "...", "done": bool}\n\n``

    history — list of prior {"role": "user"|"assistant", "content": str} dicts in
    chronological order. Capped to last 20 messages to stay within context windows.
    """
    from llm import stream_llm

    context_block = _format_context_prompt(context)
    # Inject fresh live context into the system prompt so every turn sees current data
    system_content = f"{SYSTEM_PROMPT}\n\n{context_block}"
    # Prior conversation turns (capped to keep context window manageable)
    prior_turns = (history or [])[-20:]
    messages = [
        {"role": "system", "content": system_content},
        *prior_turns,
        {"role": "user", "content": user_message},
    ]
    async for chunk in stream_llm(messages, db, model_override=model, timeout_s=120.0):
        yield chunk


async def stream_briefing(
    db: AsyncSession,
    model: str | None = None,
    # Legacy params kept for call-site compatibility — ignored
    ollama_host: str | None = None,
) -> AsyncIterator[str]:
    """
    Stream briefing generation token-by-token via the provider chain, then persist to DB.
    Yields ``data: {"text": "...", "done": bool[, "briefing_id": int]}\n\n``
    """
    from llm import stream_llm

    ctx           = await build_threat_context(db, hours_back=24)
    context_block = _format_context_prompt(ctx)

    prompt = (
        f"{context_block}\n"
        "Generate a professional SIGINT-X Threat Intelligence Briefing.\n\n"
        "## Executive Summary\n2-3 sentence overview of the current threat landscape.\n\n"
        "## Critical Threats\nMost urgent items requiring immediate attention.\n\n"
        "## Active Campaigns\nThreat actors active in the past 24h and their TTPs.\n\n"
        "## Vulnerability Spotlight\nTop CVEs — include CVSS, KEV status, affected products.\n\n"
        "## Recommended Actions\n5-7 specific, actionable steps defenders should take now."
    )
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": prompt},
    ]

    chunks:        list[str] = []
    active_model:  str       = model or ""

    async for sse_line in stream_llm(messages, db, model_override=model, max_tokens=3000, timeout_s=180.0):
        # Capture the model name announced in the first provider chunk
        if '"provider"' in sse_line and not active_model:
            try:
                d = json.loads(sse_line[6:])
                active_model = d.get("model", "")
            except Exception:
                pass
        # Accumulate text for persistence
        if sse_line.startswith("data: "):
            try:
                d = json.loads(sse_line[6:])
                if d.get("text"):
                    chunks.append(d["text"])
            except Exception:
                pass
        yield sse_line

    # Persist completed briefing to DB
    content  = "".join(chunks)
    if not content:
        return
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1}
    top_sev  = max(
        (n["severity"] for n in ctx["top_news"]),
        key=lambda s: sev_rank.get(s, 0),
        default="INFO",
    )
    briefing = AiBriefing(
        model_used    = active_model or "unknown",
        content       = content,
        news_count    = ctx["total_news"],
        cve_count     = len(ctx["top_cves"]),
        top_severity  = top_sev,
        threat_actors = json.dumps(ctx["active_actors"]),
    )
    db.add(briefing)
    await db.commit()
    await db.refresh(briefing)
    logger.info("Streaming briefing persisted: id=%d model=%s", briefing.id, active_model)
    yield f"data: {json.dumps({'text': '', 'done': True, 'briefing_id': briefing.id})}\n\n"


async def generate_briefing(
    db: AsyncSession,
    model: str | None = None,
    # Legacy params kept for call-site compatibility — ignored
    ollama_host: str | None = None,
) -> "AiBriefing":
    """
    Generate a full automated threat intelligence briefing via the provider chain,
    persist to DB, and return the AiBriefing row.  Non-streaming.
    """
    from llm import call_llm

    ctx           = await build_threat_context(db, hours_back=24)
    context_block = _format_context_prompt(ctx)

    prompt = (
        f"{context_block}\n"
        "Generate a professional SIGINT-X Threat Intelligence Briefing.\n\n"
        "## Executive Summary\n2-3 sentence overview.\n\n"
        "## Critical Threats\nMost urgent items (with specifics).\n\n"
        "## Active Campaigns\nThreat actors active in 24h and their known TTPs.\n\n"
        "## Vulnerability Spotlight\nTop CVEs — include CVSS, KEV status, affected products.\n\n"
        "## Recommended Actions\n5-7 specific, actionable defensive steps.\n\n"
        "Be concise, specific, and operationally focused. Reference CVE IDs and actor names."
    )
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": prompt},
    ]

    content, used_provider = await call_llm(
        messages, db, max_tokens=3000, timeout_s=180.0, model_override=model
    )
    if not content:
        content = "Briefing generation failed: no AI provider available."

    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1}
    top_sev  = max(
        (n["severity"] for n in ctx["top_news"]),
        key=lambda s: sev_rank.get(s, 0),
        default="INFO",
    )
    briefing = AiBriefing(
        model_used    = used_provider or model or "unknown",
        content       = content,
        news_count    = ctx["total_news"],
        cve_count     = len(ctx["top_cves"]),
        top_severity  = top_sev,
        threat_actors = json.dumps(ctx["active_actors"]),
    )
    db.add(briefing)
    await db.commit()
    await db.refresh(briefing)
    logger.info("Briefing generated: %d chars | provider=%s", len(content), used_provider)
    return briefing
