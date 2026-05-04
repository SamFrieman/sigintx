"""
SIGINTX — GitHub Trending Collector

Primary: GitHub's undocumented explore/trending JSON feed.
Fallback 1: Scrape https://github.com/trending?since=weekly with multiple selectors.
Fallback 2: GitHub Search API (new repos this week sorted by stars).

Security-relevance scoring flags repos related to exploits, tools, leaks,
or threat research so the UI can highlight them.
"""
import logging
import re
from datetime import datetime, timedelta

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger("sigintx.github_trending")

_TRENDING_URL  = "https://github.com/trending?since=weekly"
_TRENDING_JSON = "https://github.com/trending?since=weekly"  # same page, parse HTML

_SECURITY_KEYWORDS = {
    "exploit", "vulnerability", "cve", "hack", "pentest", "payload",
    "malware", "ransomware", "rat", "backdoor", "rootkit", "keylogger",
    "phishing", "osint", "recon", "red team", "redteam", "c2", "c&c",
    "bypass", "privilege", "injection", "xss", "sqli", "rce", "lfi",
    "rop", "shellcode", "poc", "proof of concept", "zero-day", "0day",
    "leak", "dump", "breach", "exfil", "lateral movement",
    "mitre", "att&ck", "threat", "infosec", "ctf", "reverse engineering",
    "decompile", "disassem", "fuzzing", "fuzz", "intrusion", "forensic",
    "yara", "sigma", "snort", "honeypot", "sandbox", "deobfuscat",
}

# In-memory cache — refreshed by scheduler every 20 min
_cache: dict = {
    "repos":      [],
    "fetched_at": None,
    "error":      None,
}

# Set to True while a fetch is in progress so auto-trigger doesn't double-fire
_fetch_in_progress: bool = False


def get_cached_trending() -> dict:
    return _cache


def _is_security_related(name: str, description: str) -> bool:
    text = (name + " " + (description or "")).lower()
    return any(kw in text for kw in _SECURITY_KEYWORDS)


def _parse_star_count(raw: str) -> int:
    """Convert '1,234' or '1.2k' style strings to int."""
    raw = raw.strip().replace(",", "").replace(" ", "").lower()
    try:
        if raw.endswith("k"):
            return int(float(raw[:-1]) * 1000)
        return int(raw)
    except (ValueError, AttributeError):
        return 0


def _build_repo(owner: str, name: str, description: str, language: str,
                total_stars: int, forks: int, stars_week: int) -> dict:
    full_name = f"{owner}/{name}"
    return {
        "full_name":   full_name,
        "owner":       owner,
        "name":        name,
        "url":         f"https://github.com/{full_name}",
        "description": description,
        "language":    language,
        "total_stars": total_stars,
        "forks":       forks,
        "stars_week":  stars_week,
        "security":    _is_security_related(full_name, description),
    }


async def collect_github_trending() -> list[dict]:
    """
    Fetch GitHub trending weekly repos. Tries scraping first, then falls back to
    the GitHub Search API. Updates the in-memory cache on success or partial success.
    """
    global _fetch_in_progress
    _fetch_in_progress = True
    try:
        repos = await _scrape_trending()
        if not repos:
            logger.info("Scrape returned 0 repos, trying Search API fallback")
            repos = await _fallback_search_api()

        if repos:
            _cache["repos"]      = repos
            _cache["fetched_at"] = datetime.utcnow().isoformat()
            _cache["error"]      = None
            logger.info("GitHub trending: cached %d repos (%d security-flagged)",
                        len(repos), sum(1 for r in repos if r["security"]))
        else:
            _cache["error"] = "No repos returned from trending page or Search API"
            logger.warning("GitHub trending: all sources returned 0 repos")

        return repos
    except Exception as exc:
        _cache["error"] = str(exc)
        logger.warning("GitHub trending collection failed: %s", exc)
        return []
    finally:
        _fetch_in_progress = False


async def _scrape_trending() -> list[dict]:
    """Scrape the GitHub trending weekly page. Returns [] on any parse failure."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control":   "no-cache",
    }

    try:
        async with httpx.AsyncClient(timeout=25.0, follow_redirects=True) as client:
            resp = await client.get(_TRENDING_URL, headers=headers)
            resp.raise_for_status()
            html = resp.text
    except Exception as exc:
        logger.warning("GitHub trending page fetch failed: %s", exc)
        return []

    soup = BeautifulSoup(html, "html.parser")

    # Try multiple selectors — GitHub has changed markup a few times
    articles = (
        soup.select("article.Box-row")
        or soup.select("div[class*='Box-row']")
        or soup.select("article")
    )

    if not articles:
        logger.warning("GitHub trending: no article elements found (HTML len=%d)", len(html))
        # Log first 500 chars of body for debugging
        body = soup.find("body")
        if body:
            logger.debug("Body snippet: %s", body.get_text()[:300])
        return []

    repos: list[dict] = []
    for article in articles[:30]:
        try:
            # Repo link → "/owner/repo"
            link_tag = article.select_one("h2 a") or article.select_one("h1 a") or article.select_one("a[href*='/']")
            if not link_tag:
                continue
            path  = link_tag.get("href", "").strip("/")
            parts = path.split("/")
            if len(parts) < 2:
                continue
            owner, name = parts[0], parts[1]
            if not owner or not name:
                continue

            # Description
            desc_tag    = article.select_one("p")
            description = desc_tag.get_text(strip=True) if desc_tag else ""

            # Language
            lang_tag = article.select_one("[itemprop='programmingLanguage']")
            language = lang_tag.get_text(strip=True) if lang_tag else ""

            # Total stars — first <a> with stargazers in href
            total_stars = 0
            for a in article.select("a"):
                if "stargazers" in a.get("href", ""):
                    total_stars = _parse_star_count(a.get_text(strip=True))
                    break

            # Forks
            forks = 0
            for a in article.select("a"):
                if "/forks" in a.get("href", ""):
                    forks = _parse_star_count(a.get_text(strip=True))
                    break

            # Stars this week — floated span at the end of the card
            stars_week = 0
            for selector in ["span.float-sm-right", "span[class*='float']", "span"]:
                spans = article.select(selector)
                for span in spans:
                    raw = span.get_text(strip=True)
                    if "star" in raw.lower() and "week" in raw.lower():
                        m = re.search(r"([\d,]+(?:\.\d+k?)?)", raw)
                        if m:
                            stars_week = _parse_star_count(m.group(1))
                            break
                if stars_week:
                    break

            repos.append(_build_repo(owner, name, description, language,
                                     total_stars, forks, stars_week))
        except Exception as e:
            logger.debug("Failed to parse trending repo article: %s", e)
            continue

    logger.info("GitHub trending scrape: parsed %d repos from %d articles",
                len(repos), len(articles))
    return repos


async def _fallback_search_api() -> list[dict]:
    """
    Fallback: GitHub Search API for recently-created repos sorted by stars.
    No auth required (60 req/hour unauthenticated).
    """
    since = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
    url = (
        "https://api.github.com/search/repositories"
        f"?q=created:>{since}&sort=stars&order=desc&per_page=30"
    )
    headers = {
        "Accept":     "application/vnd.github+json",
        "User-Agent": "SIGINTX/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("GitHub API fallback failed: %s", exc)
        return []

    repos = []
    for item in data.get("items", []):
        full_name = item.get("full_name", "")
        desc      = item.get("description") or ""
        owner_obj = item.get("owner") or {}
        repos.append(_build_repo(
            owner       = owner_obj.get("login", ""),
            name        = item.get("name", ""),
            description = desc,
            language    = item.get("language") or "",
            total_stars = item.get("stargazers_count", 0),
            forks       = item.get("forks_count", 0),
            stars_week  = item.get("stargazers_count", 0),
        ))

    logger.info("GitHub Search API fallback: got %d repos", len(repos))
    return repos
