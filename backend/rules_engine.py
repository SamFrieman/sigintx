"""
SIGINTX — Alert Rules Engine (v3.0.0)
Evaluates user-defined rules against incoming news and CVE items,
fires webhooks on matches, and respects per-rule cooldown windows.
"""
import json
import logging
from datetime import datetime, timedelta
from html import escape as _he
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import AlertRule, SettingItem, NewsItem, CVEItem, SessionLocal

# ── Telegram helper ───────────────────────────────────────────────────────────

async def _fire_telegram(bot_token: str, chat_id: str, text: str) -> bool:
    """Send a Telegram message via Bot API. Returns True on success."""
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=5.0)) as client:
            resp = await client.post(url, json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
            })
            resp.raise_for_status()
            return True
    except Exception as exc:
        logger.warning("Telegram notification failed: %s", exc)
        return False


def _build_telegram_text(rule: AlertRule, item: dict, item_type: str) -> str:
    """Format a Telegram alert message (HTML parse_mode — all user values escaped)."""
    sev   = _he(str(item.get("severity", "") or ""))
    title = _he(str(item.get("title") or item.get("cve_id") or "Alert triggered"))
    url   = str(item.get("url", "") or "")
    sev_emoji = {"CRITICAL": "\U0001f534", "HIGH": "\U0001f7e0", "MEDIUM": "\U0001f7e1", "INFO": "\U0001f535"}.get(
        item.get("severity", ""), "\u26aa"
    )
    lines = [
        f"{sev_emoji} <b>SIGINTX ALERT</b>",
        "",
        f"<b>Rule:</b> {_he(rule.name)}",
        f"<b>Type:</b> {_he(item_type.upper())}",
        f"<b>Severity:</b> {sev}",
        "",
        f"<b>{title}</b>",
    ]
    # Only include URL if it is a safe http(s) link (prevent javascript: / data: injection)
    if url and url.startswith(("http://", "https://")):
        lines.append(f'<a href="{_he(url)}">View</a>')
    actors = item.get("threat_actors", [])
    if actors:
        lines.append(f"<b>Actors:</b> {_he(', '.join(str(a) for a in actors[:3]))}")
    cves = item.get("cve_refs", [])
    if cves:
        lines.append(f"<b>CVEs:</b> {_he(', '.join(str(c) for c in cves[:4]))}")
    return "\n".join(lines)

logger = logging.getLogger("sigintx.rules_engine")

# ── Operator implementations ──────────────────────────────────────────────────

def _op_eq(field_val: Any, cmp_val: Any) -> bool:
    return field_val == cmp_val


def _op_ne(field_val: Any, cmp_val: Any) -> bool:
    return field_val != cmp_val


def _op_gt(field_val: Any, cmp_val: Any) -> bool:
    try:
        return float(field_val) > float(cmp_val)
    except (TypeError, ValueError):
        return False


def _op_lt(field_val: Any, cmp_val: Any) -> bool:
    try:
        return float(field_val) < float(cmp_val)
    except (TypeError, ValueError):
        return False


def _op_gte(field_val: Any, cmp_val: Any) -> bool:
    try:
        return float(field_val) >= float(cmp_val)
    except (TypeError, ValueError):
        return False


def _op_lte(field_val: Any, cmp_val: Any) -> bool:
    try:
        return float(field_val) <= float(cmp_val)
    except (TypeError, ValueError):
        return False


def _op_in(field_val: Any, cmp_val: Any) -> bool:
    """field_val is one of the values in cmp_val list."""
    if not isinstance(cmp_val, list):
        return False
    return field_val in cmp_val


def _op_not_in(field_val: Any, cmp_val: Any) -> bool:
    if not isinstance(cmp_val, list):
        return True
    return field_val not in cmp_val


def _op_contains(field_val: Any, cmp_val: Any) -> bool:
    """field_val (string or list) contains cmp_val."""
    if isinstance(field_val, list):
        return cmp_val in field_val
    if isinstance(field_val, str):
        return str(cmp_val).lower() in field_val.lower()
    return False


def _op_contains_any(field_val: Any, cmp_val: Any) -> bool:
    """field_val (list or string) contains any item from cmp_val list."""
    if not isinstance(cmp_val, list):
        return False
    if isinstance(field_val, list):
        field_lower = [str(v).lower() for v in field_val]
        return any(str(cv).lower() in field_lower for cv in cmp_val)
    if isinstance(field_val, str):
        field_lower = field_val.lower()
        return any(str(cv).lower() in field_lower for cv in cmp_val)
    return False


def _op_starts_with(field_val: Any, cmp_val: Any) -> bool:
    if isinstance(field_val, str):
        return field_val.lower().startswith(str(cmp_val).lower())
    return False


_OP_MAP = {
    "eq":           _op_eq,
    "ne":           _op_ne,
    "gt":           _op_gt,
    "lt":           _op_lt,
    "gte":          _op_gte,
    "lte":          _op_lte,
    "in":           _op_in,
    "not_in":       _op_not_in,
    "contains":     _op_contains,
    "contains_any": _op_contains_any,
    "starts_with":  _op_starts_with,
}


# ── Field extraction helpers ──────────────────────────────────────────────────

def _extract_field(item_data: dict, field: str) -> Any:
    """
    Extract a field value from the normalised item dict.
    JSON-list fields (threat_actors, tags) are returned as Python lists.
    Derived fields: has_cve (bool), cve_count (int).
    """
    raw = item_data.get(field)

    # Derived booleans / counts
    if field == "has_cve":
        cve_refs = item_data.get("cve_refs") or item_data.get("cve_refs_raw")
        if isinstance(cve_refs, list):
            return len(cve_refs) > 0
        if isinstance(cve_refs, str):
            try:
                return len(json.loads(cve_refs)) > 0
            except Exception:
                return bool(cve_refs)
        return False

    if field == "cve_count":
        cve_refs = item_data.get("cve_refs") or item_data.get("cve_refs_raw")
        if isinstance(cve_refs, list):
            return len(cve_refs)
        if isinstance(cve_refs, str):
            try:
                return len(json.loads(cve_refs))
            except Exception:
                return 0
        return 0

    # JSON-list fields — deserialise once if still a string
    if field in ("threat_actors", "tags", "cve_refs", "affected_products"):
        if isinstance(raw, str):
            try:
                return json.loads(raw)
            except Exception:
                return []
        return raw if isinstance(raw, list) else []

    return raw


# ── Pure rule evaluator ───────────────────────────────────────────────────────

def evaluate_single_rule(conditions_json: str, item_data: dict) -> bool:
    """
    Pure function — evaluate rule conditions against a normalised item dict.
    No DB access.

    conditions_json schema:
    {
        "operator": "AND" | "OR",   # default AND
        "conditions": [
            {"field": str, "op": str, "value": Any},
            ...
        ]
    }
    Conditions can be nested: a condition may itself have "operator"/"conditions"
    keys instead of "field"/"op"/"value" to form compound sub-expressions.
    """
    try:
        cond_obj = json.loads(conditions_json) if isinstance(conditions_json, str) else conditions_json
    except (json.JSONDecodeError, TypeError):
        logger.warning("Rules engine: failed to parse conditions JSON")
        return False

    return _eval_node(cond_obj, item_data)


def _eval_node(node: dict, item_data: dict) -> bool:
    """Recursively evaluate a condition node."""
    # Compound node
    if "conditions" in node:
        operator = str(node.get("operator", "AND")).upper()
        children = node["conditions"]
        if not children:
            return True
        results = [_eval_node(child, item_data) for child in children]
        if operator == "OR":
            return any(results)
        return all(results)   # AND (default)

    # Leaf node
    field = node.get("field")
    op_name = node.get("op")
    cmp_val = node.get("value")

    if not field or not op_name:
        logger.debug(f"Rules engine: leaf node missing field/op: {node}")
        return False

    op_fn = _OP_MAP.get(op_name)
    if op_fn is None:
        logger.warning(f"Rules engine: unknown operator '{op_name}'")
        return False

    field_val = _extract_field(item_data, field)
    try:
        return op_fn(field_val, cmp_val)
    except Exception as exc:
        logger.debug(f"Rules engine: operator error field={field} op={op_name}: {exc}")
        return False


# ── News item normalisation ───────────────────────────────────────────────────

def _news_to_dict(item: NewsItem) -> dict:
    cve_refs: list[str] = []
    if item.cve_refs:
        try:
            cve_refs = json.loads(item.cve_refs)
        except Exception:
            pass

    actors: list[str] = []
    if item.threat_actors:
        try:
            actors = json.loads(item.threat_actors)
        except Exception:
            pass

    return {
        "severity":      item.severity,
        "source":        item.source,
        "title":         item.title,
        "threat_actors": actors,
        "cve_refs":      cve_refs,
        "has_cve":       len(cve_refs) > 0,
        "cve_count":     len(cve_refs),
        "tags":          json.loads(item.tags) if item.tags else [],
    }


def _cve_to_dict(item: CVEItem) -> dict:
    actors: list[str] = []
    if item.threat_actors:
        try:
            actors = json.loads(item.threat_actors)
        except Exception:
            pass

    return {
        "severity":      item.severity,
        "in_kev":        item.in_kev,
        "cvss_score":    item.cvss_score or 0.0,
        "epss_score":    item.epss_score or 0.0,
        "priority_score": item.priority_score or 0.0,
        "threat_actors": actors,
        "tags":          json.loads(item.tags) if item.tags else [],
        "cve_id":        item.cve_id,
    }


# ── DB-backed rule evaluation ─────────────────────────────────────────────────

async def _load_enabled_rules(db: AsyncSession, item_type: str) -> list[AlertRule]:
    """Load all enabled rules for the given item_type (news | cve)."""
    # Rules without an explicit item_type column — filter by min_severity or just return all enabled
    # AlertRule in v3 DB has: conditions, min_severity, enabled, cooldown_minutes
    # No item_type column — we apply all enabled rules to both types.
    rows = (await db.scalars(
        select(AlertRule).where(AlertRule.enabled == True)
    )).all()
    return list(rows)


async def evaluate_rules_for_news(item: NewsItem, db: AsyncSession) -> list[AlertRule]:
    """Return list of enabled rules that match this news item."""
    rules = await _load_enabled_rules(db, "news")
    item_data = _news_to_dict(item)
    matched: list[AlertRule] = []
    for rule in rules:
        try:
            if evaluate_single_rule(rule.conditions, item_data):
                matched.append(rule)
        except Exception as exc:
            logger.warning(f"Rule id={rule.id} evaluation error: {exc}")
    return matched


async def evaluate_rules_for_cve(item: CVEItem, db: AsyncSession) -> list[AlertRule]:
    """Return list of enabled rules that match this CVE item."""
    rules = await _load_enabled_rules(db, "cve")
    item_data = _cve_to_dict(item)
    matched: list[AlertRule] = []
    for rule in rules:
        try:
            if evaluate_single_rule(rule.conditions, item_data):
                matched.append(rule)
        except Exception as exc:
            logger.warning(f"Rule id={rule.id} evaluation error: {exc}")
    return matched


# ── Webhook firing ────────────────────────────────────────────────────────────

async def _get_global_webhook(db: AsyncSession) -> str | None:
    """Fetch the globally configured webhook URL from settings."""
    row = await db.scalar(select(SettingItem).where(SettingItem.key == "webhook_url"))
    if row and row.value:
        return row.value.strip()
    # Also check uppercase key
    row = await db.scalar(select(SettingItem).where(SettingItem.key == "WEBHOOK_URL"))
    if row and row.value:
        return row.value.strip()
    return None


async def _get_telegram_creds(db: AsyncSession) -> tuple[str | None, str | None]:
    """Return (bot_token, chat_id) from global settings."""
    token_row = await db.scalar(select(SettingItem).where(SettingItem.key == "TELEGRAM_BOT_TOKEN"))
    chat_row  = await db.scalar(select(SettingItem).where(SettingItem.key == "TELEGRAM_CHAT_ID"))
    return (
        token_row.value.strip() if token_row and token_row.value else None,
        chat_row.value.strip()  if chat_row  and chat_row.value  else None,
    )


def _build_webhook_payload(rule: AlertRule, item: dict, item_type: str) -> dict:
    """Build the JSON body for a webhook POST."""
    return {
        "event":     "sigintx.alert",
        "rule_id":   rule.id,
        "rule_name": rule.name,
        "item_type": item_type,
        "fired_at":  datetime.utcnow().isoformat() + "Z",
        "item":      item,
    }


async def fire_rule_alerts(
    rules: list[AlertRule],
    item: dict,
    item_type: str,
    db: AsyncSession,
) -> None:
    """
    Fire webhook and/or Telegram for each matching rule, respecting cooldown_minutes.
    notification_channel: "webhook" | "telegram" | "both"
    """
    if not rules:
        return

    global_webhook                = await _get_global_webhook(db)
    global_tg_token, global_tg_id = await _get_telegram_creds(db)
    now = datetime.utcnow()

    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=5.0)) as client:
        for rule in rules:
            # Cooldown check
            if rule.last_triggered is not None:
                cooldown_delta = timedelta(minutes=rule.cooldown_minutes)
                if now - rule.last_triggered < cooldown_delta:
                    logger.debug(
                        f"Rule id={rule.id} '{rule.name}' in cooldown "
                        f"(last_triggered={rule.last_triggered.isoformat()})"
                    )
                    continue

            channel = getattr(rule, "notification_channel", "webhook") or "webhook"

            # ── Webhook ───────────────────────────────────────────────────────
            if channel in ("webhook", "both"):
                target_url = global_webhook
                if not target_url:
                    logger.debug(f"Rule id={rule.id}: no webhook URL configured")
                else:
                    payload = _build_webhook_payload(rule, item, item_type)
                    try:
                        resp = await client.post(target_url, json=payload)
                        resp.raise_for_status()
                        logger.info(
                            f"Rule id={rule.id} '{rule.name}' fired webhook "
                            f"-> {target_url} (HTTP {resp.status_code})"
                        )
                    except httpx.HTTPStatusError as exc:
                        logger.warning(
                            f"Rule id={rule.id} webhook HTTP error: "
                            f"{exc.response.status_code} {exc}"
                        )
                    except Exception as exc:
                        logger.warning(f"Rule id={rule.id} webhook error: {exc}")

            # ── Telegram ──────────────────────────────────────────────────────
            if channel in ("telegram", "both"):
                tg_token  = global_tg_token
                tg_chat   = getattr(rule, "telegram_chat_id", None) or global_tg_id
                if tg_token and tg_chat:
                    tg_text = _build_telegram_text(rule, item, item_type)
                    ok = await _fire_telegram(tg_token, tg_chat, tg_text)
                    if ok:
                        logger.info(f"Rule id={rule.id} '{rule.name}' fired Telegram -> chat={tg_chat}")
                else:
                    logger.debug(
                        f"Rule id={rule.id}: Telegram channel selected but "
                        f"TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not configured"
                    )

            # Always update counters
            rule.hit_count = (rule.hit_count or 0) + 1
            rule.last_triggered = now
            db.add(rule)

    await db.commit()


# ── Convenience: evaluate + fire in one call ──────────────────────────────────

async def process_news_item(item: NewsItem, db: AsyncSession) -> int:
    """Evaluate rules for a news item and fire alerts. Returns count fired."""
    matched = await evaluate_rules_for_news(item, db)
    if matched:
        item_dict = _news_to_dict(item)
        item_dict["id"] = item.id
        item_dict["url"] = item.url
        item_dict["title"] = item.title
        await fire_rule_alerts(matched, item_dict, "news", db)
    return len(matched)


async def process_cve_item(item: CVEItem, db: AsyncSession) -> int:
    """Evaluate rules for a CVE item and fire alerts. Returns count fired."""
    matched = await evaluate_rules_for_cve(item, db)
    if matched:
        item_dict = _cve_to_dict(item)
        item_dict["id"] = item.id
        await fire_rule_alerts(matched, item_dict, "cve", db)
    return len(matched)


async def run_scheduled_rules(lookback_minutes: int = 6) -> int:
    """
    Evaluate all enabled rules against news and CVE items ingested in the last
    *lookback_minutes* minutes.  Designed to be called every 5 minutes by the
    scheduler or Celery Beat so that every new item is evaluated exactly once.

    Returns total number of rule firings.
    """
    from datetime import timedelta as _td
    from sqlalchemy import desc as _desc

    cutoff = datetime.utcnow() - _td(minutes=lookback_minutes)
    fired = 0

    async with SessionLocal() as db:
        rules = await _load_enabled_rules(db, "news")
        if not rules:
            return 0

        # Evaluate recent news
        recent_news = (await db.scalars(
            select(NewsItem)
            .where(NewsItem.fetched_at >= cutoff)
            .order_by(_desc(NewsItem.fetched_at))
        )).all()

        for item in recent_news:
            item_dict = _news_to_dict(item)
            matched = [
                r for r in rules
                if _safe_evaluate(r, item_dict)
            ]
            if matched:
                item_dict["id"] = item.id
                item_dict["url"] = item.url
                item_dict["title"] = item.title
                await fire_rule_alerts(matched, item_dict, "news", db)
                fired += len(matched)

        # Evaluate recent CVEs
        recent_cves = (await db.scalars(
            select(CVEItem)
            .where(CVEItem.fetched_at >= cutoff)
            .order_by(_desc(CVEItem.fetched_at))
        )).all()

        for item in recent_cves:
            item_dict = _cve_to_dict(item)
            matched = [
                r for r in rules
                if _safe_evaluate(r, item_dict)
            ]
            if matched:
                item_dict["id"] = item.id
                await fire_rule_alerts(matched, item_dict, "cve", db)
                fired += len(matched)

    return fired


def _safe_evaluate(rule: AlertRule, item_data: dict) -> bool:
    try:
        return evaluate_single_rule(rule.conditions, item_data)
    except Exception:
        return False


async def evaluate_rules_against_recent(
    rules: list[AlertRule],
    db: AsyncSession,
    limit: int = 50,
) -> int:
    """
    Dry-run *rules* against the most recent *limit* news items.
    Returns the total number of (rule, item) matches without firing webhooks
    or updating counters — purely for UI test/preview.
    """
    from sqlalchemy import desc as _desc
    rows = (await db.scalars(
        select(NewsItem).order_by(_desc(NewsItem.published_at)).limit(limit)
    )).all()

    matches = 0
    for item in rows:
        item_data = _news_to_dict(item)
        for rule in rules:
            try:
                if evaluate_single_rule(rule.conditions, item_data):
                    matches += 1
            except Exception:
                pass
    return matches
