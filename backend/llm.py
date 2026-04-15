"""
SIGINTX — Multi-provider LLM client
Provider chain: Ollama (local, auto-managed) → Groq → OpenRouter → Generic

Priority order:
  1. Ollama    — managed automatically by ollama_manager.py (no config needed)
  2. Groq      — free tier (6000 RPD), needs GROQ_API_KEY in Settings
  3. OpenRouter — pay-per-use cloud router, needs OPENROUTER_API_KEY in Settings
  4. Generic   — any OpenAI-compatible endpoint (LLM_API_URL + LLM_API_KEY)
"""
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("sigintx.llm")

# ── Provider defaults ─────────────────────────────────────────────────────────

PROVIDER_CHAIN = ["ollama", "groq", "openrouter", "generic"]

# Default model per provider when none is configured in settings
_PROVIDER_DEFAULT_MODEL = {
    "ollama":      "llama3.2:3b",
    "groq":        "llama-3.3-70b-versatile",
    "openrouter":  "google/gemini-2.0-flash",
    "generic":     "gpt-4o-mini",
}

# Groq free-tier model options (fast, no cost)
GROQ_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
]

# OpenRouter recommended models
OPENROUTER_MODELS = [
    "google/gemini-2.0-flash",
    "google/gemini-2.5-flash-preview",
    "meta-llama/llama-3.3-70b-instruct",
    "anthropic/claude-3.5-haiku",
    "openai/gpt-4o-mini",
]

# Validate model names — prevents prompt injection via model param
_MODEL_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{0,119}$')


def validate_model_name(name: str) -> bool:
    return bool(_MODEL_RE.match(name)) if name else True


# ── Settings helper ───────────────────────────────────────────────────────────

async def _get_setting(db: AsyncSession, key: str, default: str = "") -> str:
    from database import SettingItem
    row = await db.get(SettingItem, key)
    val = row.value if row else ""
    return val if val else default


# ── Provider config ───────────────────────────────────────────────────────────

@dataclass
class ProviderConfig:
    name:      str
    api_url:   str
    model:     str
    headers:   dict = field(default_factory=dict)


async def get_provider_config(
    provider: str,
    db: AsyncSession,
    model_override: Optional[str] = None,
) -> Optional[ProviderConfig]:
    """Build ProviderConfig from DB settings + env vars. Returns None if provider isn't configured."""

    if provider == "ollama":
        # Host is always localhost — managed automatically by ollama_manager
        from ollama_manager import OLLAMA_HOST, DEFAULT_MODEL
        host  = OLLAMA_HOST
        model = model_override or DEFAULT_MODEL
        headers: dict = {"Content-Type": "application/json"}
        return ProviderConfig(
            name="ollama",
            api_url=f"{host.rstrip('/')}/v1/chat/completions",
            model=model,
            headers=headers,
        )

    if provider == "groq":
        key = await _get_setting(db, "GROQ_API_KEY") or os.environ.get("GROQ_API_KEY", "")
        if not key:
            return None
        model = model_override or await _get_setting(db, "AI_MODEL", _PROVIDER_DEFAULT_MODEL["groq"])
        # If model isn't a known Groq model, use default
        if "/" in model or ":" in model:
            model = _PROVIDER_DEFAULT_MODEL["groq"]
        return ProviderConfig(
            name="groq",
            api_url="https://api.groq.com/openai/v1/chat/completions",
            model=model,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type":  "application/json",
            },
        )

    if provider == "openrouter":
        key = await _get_setting(db, "OPENROUTER_API_KEY") or os.environ.get("OPENROUTER_API_KEY", "")
        if not key:
            return None
        model = model_override or await _get_setting(db, "AI_MODEL", _PROVIDER_DEFAULT_MODEL["openrouter"])
        return ProviderConfig(
            name="openrouter",
            api_url="https://openrouter.ai/api/v1/chat/completions",
            model=model,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type":  "application/json",
                "HTTP-Referer":  "https://sigintx.local",
                "X-Title":       "SIGINTX",
            },
        )

    if provider == "generic":
        api_url = await _get_setting(db, "LLM_API_URL") or os.environ.get("LLM_API_URL", "")
        key     = await _get_setting(db, "LLM_API_KEY") or os.environ.get("LLM_API_KEY", "")
        if not api_url or not key:
            return None
        model = model_override or await _get_setting(db, "LLM_MODEL", _PROVIDER_DEFAULT_MODEL["generic"])
        return ProviderConfig(
            name="generic",
            api_url=api_url,
            model=model,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type":  "application/json",
            },
        )

    return None


# ── Ollama availability check ─────────────────────────────────────────────────

async def _is_ollama_up(host: str) -> bool:
    """Ping Ollama's /api/tags to check if it's running."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{host.rstrip('/')}/api/tags")
            return r.status_code == 200
    except Exception:
        return False


# ── Non-streaming call ────────────────────────────────────────────────────────

async def call_llm(
    messages: list[dict],
    db: AsyncSession,
    temperature: float = 0.3,
    max_tokens: int = 1500,
    timeout_s: float = 30.0,
    model_override: Optional[str] = None,
    forced_provider: Optional[str] = None,
    json_mode: bool = False,
) -> tuple[Optional[str], Optional[str]]:
    """
    Call the LLM provider chain (non-streaming).
    Returns (content, provider_name) — (None, None) if all providers fail.
    """
    providers = [forced_provider] if forced_provider else PROVIDER_CHAIN

    for pname in providers:
        cfg = await get_provider_config(pname, db, model_override)
        if not cfg:
            continue

        # For Ollama, verify it's running before trying
        if pname == "ollama":
            host = cfg.api_url.split("/v1/")[0]
            if not await _is_ollama_up(host):
                logger.debug("[llm:ollama] Not reachable, skipping")
                continue

        try:
            async with httpx.AsyncClient(timeout=timeout_s) as client:
                payload = {
                    "model":       cfg.model,
                    "messages":    messages,
                    "temperature": temperature,
                    "max_tokens":  max_tokens,
                    "stream":      False,
                }
                if json_mode:
                    payload["response_format"] = {"type": "json_object"}
                resp = await client.post(cfg.api_url, headers=cfg.headers, json=payload)
                if not resp.is_success:
                    logger.warning("[llm:%s] HTTP %d: %s", pname, resp.status_code, resp.text[:200])
                    continue
                data    = resp.json()
                content = (data.get("choices") or [{}])[0].get("message", {}).get("content", "").strip()
                if content:
                    logger.info("[llm:%s] Non-streaming call succeeded (model=%s)", pname, cfg.model)
                    return content, pname
        except Exception as exc:
            logger.warning("[llm:%s] %s: %s", pname, type(exc).__name__, exc)

    return None, None


# ── Streaming call ────────────────────────────────────────────────────────────

async def stream_llm(
    messages: list[dict],
    db: AsyncSession,
    temperature: float = 0.35,
    max_tokens: int = 2000,
    timeout_s: float = 120.0,
    model_override: Optional[str] = None,
    forced_provider: Optional[str] = None,
) -> AsyncIterator[str]:
    """
    Stream a response through the provider chain.
    Yields SSE lines: ``data: {"text": "...", "done": bool[, "provider": "..."]}\n\n``

    The first yielded chunk carries a ``provider`` key so the UI can show which
    backend is responding.  Remaining chunks omit it to keep payloads minimal.
    """
    providers = [forced_provider] if forced_provider else PROVIDER_CHAIN

    for pname in providers:
        cfg = await get_provider_config(pname, db, model_override)
        if not cfg:
            continue

        if pname == "ollama":
            host = cfg.api_url.split("/v1/")[0]
            if not await _is_ollama_up(host):
                logger.debug("[llm:ollama] Not reachable, trying next provider")
                continue

        succeeded = False
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(timeout_s, connect=6.0)
            ) as client:
                async with client.stream(
                    "POST", cfg.api_url, headers=cfg.headers,
                    json={
                        "model":       cfg.model,
                        "messages":    messages,
                        "temperature": temperature,
                        "max_tokens":  max_tokens,
                        "stream":      True,
                    },
                ) as resp:
                    if not resp.is_success:
                        body = await resp.aread()
                        logger.warning(
                            "[llm:%s] HTTP %d: %s", pname, resp.status_code, body.decode()[:200]
                        )
                        continue

                    # First chunk announces the active provider
                    yield f"data: {json.dumps({'text': '', 'done': False, 'provider': pname, 'model': cfg.model})}\n\n"
                    logger.info("[llm:%s] Streaming started (model=%s)", pname, cfg.model)

                    async for line in resp.aiter_lines():
                        if not line:
                            continue
                        if line == "data: [DONE]":
                            yield f"data: {json.dumps({'text': '', 'done': True})}\n\n"
                            succeeded = True
                            break
                        if not line.startswith("data: "):
                            continue
                        try:
                            chunk  = json.loads(line[6:])
                            choice = (chunk.get("choices") or [{}])[0]
                            text   = choice.get("delta", {}).get("content") or ""
                            finish = choice.get("finish_reason")
                            if text:
                                yield f"data: {json.dumps({'text': text, 'done': False})}\n\n"
                            if finish:
                                yield f"data: {json.dumps({'text': '', 'done': True})}\n\n"
                                succeeded = True
                                break
                        except (json.JSONDecodeError, KeyError):
                            pass

                    if succeeded:
                        return

        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            logger.warning("[llm:%s] Connection failed: %s", pname, exc)
        except Exception as exc:
            logger.error("[llm:%s] Unexpected: %s", pname, exc)

    # Nothing worked — check if Ollama is still initializing before giving a generic error
    try:
        from ollama_manager import setup_status as _ollama_status
        stage    = _ollama_status.get("stage", "")
        progress = _ollama_status.get("progress", 0)
        msg      = _ollama_status.get("message", "")
        if stage == "pulling":
            yield (
                f"data: {json.dumps({'text': f'⏳ AI model is still downloading ({progress}%) — please wait a moment and try again.', 'done': True})}\n\n"
            )
            return
        if stage in ("starting", "installing", "serving"):
            yield (
                f"data: {json.dumps({'text': f'⏳ AI engine is initializing ({msg}) — please wait and try again shortly.', 'done': True})}\n\n"
            )
            return
    except Exception:
        pass

    yield (
        f"data: {json.dumps({'text': '⚠️ No AI provider available. '
        'Add a Groq or OpenRouter API key in Settings → AI Provider, or wait for local AI to finish loading.', 'done': True})}\n\n"
    )


# ── Model discovery ───────────────────────────────────────────────────────────

async def fetch_available_models(db: AsyncSession) -> list[str]:
    """Probe the local Ollama host for pulled models."""
    from ollama_manager import OLLAMA_HOST
    host = OLLAMA_HOST

    # Native Ollama endpoint
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{host.rstrip('/')}/api/tags")
            if r.status_code == 200:
                data   = r.json()
                models = [m["name"] for m in (data.get("models") or []) if "embed" not in m.get("name", "")]
                if models:
                    return models
    except Exception:
        pass

    # OpenAI-compatible fallback
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{host.rstrip('/')}/v1/models")
            if r.status_code == 200:
                data = r.json()
                return [m["id"] for m in (data.get("data") or []) if "embed" not in m.get("id", "")]
    except Exception:
        pass

    return []


# ── Provider status ───────────────────────────────────────────────────────────

async def get_provider_status(db: AsyncSession) -> list[dict]:
    """
    Return readiness info for every provider in the chain.
    Used by the /api/v1/ai/status endpoint.
    """
    statuses = []
    for pname in PROVIDER_CHAIN:
        cfg = await get_provider_config(pname, db)
        if not cfg:
            statuses.append({"provider": pname, "configured": False, "available": False, "model": None})
            continue

        available = False
        if pname == "ollama":
            host      = cfg.api_url.split("/v1/")[0]
            available = await _is_ollama_up(host)
        else:
            # Cloud providers are assumed available if the key is set
            available = True

        statuses.append({
            "provider":   pname,
            "configured": True,
            "available":  available,
            "model":      cfg.model,
        })
    return statuses


async def get_active_provider(db: AsyncSession) -> Optional[str]:
    """Return name of the first provider that is configured and available."""
    for s in await get_provider_status(db):
        if s["available"]:
            return s["provider"]
    return None
