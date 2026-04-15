"""
SIGINTX — Async IOC Enrichment Pipeline (v3.0.0)
Enriches IOC items via Shodan InternetDB (no key) and RDAP.
Checks CVEs for GitHub PoC repositories.
"""
import json
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from database import IOCItem, IOCEnrichment, CVEItem, SessionLocal

logger = logging.getLogger("sigintx.enrichment_pipeline")

SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
RDAP_URL              = "https://rdap.org/domain/{domain}"
GITHUB_SEARCH_URL     = "https://api.github.com/search/repositories"

_HTTP_HEADERS = {
    "User-Agent": "SIGINTX/3.0.0 threat-intelligence-platform",
    "Accept": "application/json",
}


# ── IP enrichment via Shodan InternetDB ───────────────────────────────────────

async def enrich_ip(ip: str) -> dict:
    """
    Enrich an IP address using Shodan InternetDB (completely free, no API key).

    Returns a dict with keys:
        ip, ports, vulns, tags, cpes, hostnames, enriched_at
    On error, returns {"error": "...", "ip": ip}
    """
    url = SHODAN_INTERNETDB_URL.format(ip=ip)
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=5.0),
            headers=_HTTP_HEADERS,
        ) as client:
            resp = await client.get(url)
            if resp.status_code == 404:
                # IP not in Shodan index — not an error, just no data
                return {
                    "ip":           ip,
                    "ports":        [],
                    "vulns":        [],
                    "tags":         [],
                    "cpes":         [],
                    "hostnames":    [],
                    "enriched_at":  datetime.utcnow().isoformat(),
                    "source":       "shodan_internetdb",
                }
            resp.raise_for_status()
            data = resp.json()
            return {
                "ip":           data.get("ip", ip),
                "ports":        data.get("ports", []),
                "vulns":        data.get("vulns", []),
                "tags":         data.get("tags", []),
                "cpes":         data.get("cpes", []),
                "hostnames":    data.get("hostnames", []),
                "enriched_at":  datetime.utcnow().isoformat(),
                "source":       "shodan_internetdb",
            }
    except httpx.HTTPStatusError as exc:
        return {"error": f"HTTP {exc.response.status_code}", "ip": ip}
    except Exception as exc:
        return {"error": str(exc), "ip": ip}


# ── Domain enrichment via RDAP ────────────────────────────────────────────────

async def enrich_domain(domain: str) -> dict:
    """
    Enrich a domain via RDAP (free, no API key required).

    Returns dict with registration date and a 'newly_registered' flag
    (True if registered within the last 30 days — indicator of suspicious activity).
    """
    url = RDAP_URL.format(domain=domain.rstrip("."))
    result: dict = {
        "domain":            domain,
        "registration_date": None,
        "expiry_date":       None,
        "registrar":         None,
        "newly_registered":  False,
        "enriched_at":       datetime.utcnow().isoformat(),
        "source":            "rdap",
    }
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=5.0),
            follow_redirects=True,
            headers=_HTTP_HEADERS,
        ) as client:
            resp = await client.get(url)
            if resp.status_code in (404, 400):
                result["error"] = "domain not found in RDAP"
                return result
            resp.raise_for_status()
            data = resp.json()

        # Parse RDAP events for registration and expiry
        events: list[dict] = data.get("events", [])
        reg_date: datetime | None = None
        for ev in events:
            action = ev.get("eventAction", "")
            date_str = ev.get("eventDate", "")
            if not date_str:
                continue
            try:
                # Normalise timezone-aware string to naive UTC
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                dt_naive = dt.astimezone(timezone.utc).replace(tzinfo=None)
            except Exception:
                continue
            if action == "registration":
                reg_date = dt_naive
                result["registration_date"] = dt_naive.isoformat()
            elif action == "expiration":
                result["expiry_date"] = dt_naive.isoformat()

        # Registrar
        entities: list[dict] = data.get("entities", [])
        for ent in entities:
            roles = ent.get("roles", [])
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [])
                if vcard and isinstance(vcard, list) and len(vcard) > 1:
                    for prop in vcard[1]:
                        if isinstance(prop, list) and prop[0] == "fn":
                            result["registrar"] = str(prop[3])[:128]
                            break
                break

        # Flag newly registered domains (< 30 days old)
        if reg_date is not None:
            age_days = (datetime.utcnow() - reg_date).days
            result["newly_registered"] = age_days < 30
            result["domain_age_days"]  = age_days

    except httpx.HTTPStatusError as exc:
        result["error"] = f"HTTP {exc.response.status_code}"
    except Exception as exc:
        result["error"] = str(exc)[:200]

    return result


# ── GitHub PoC check ──────────────────────────────────────────────────────────

async def check_github_poc(cve_id: str) -> dict:
    """
    Search GitHub for public PoC repositories referencing a CVE ID.
    Uses the public GitHub search API (no authentication required for basic queries,
    subject to rate limiting at 10 req/min unauthenticated).

    Returns:
        {"has_poc": bool, "repos": [{"name": str, "stars": int, "url": str}], ...}
    """
    result: dict = {
        "cve_id":   cve_id,
        "has_poc":  False,
        "repos":    [],
        "checked_at": datetime.utcnow().isoformat(),
        "source":   "github_poc",
    }
    try:
        params = {
            "q":          cve_id,
            "sort":       "stars",
            "order":      "desc",
            "per_page":   5,
        }
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(20.0, connect=5.0),
            headers={
                **_HTTP_HEADERS,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        ) as client:
            resp = await client.get(GITHUB_SEARCH_URL, params=params)
            if resp.status_code == 403:
                result["error"] = "GitHub rate limited"
                return result
            resp.raise_for_status()
            data = resp.json()

        items: list[dict] = data.get("items", [])
        repos = []
        for item in items[:5]:
            name        = item.get("full_name", "")
            stars       = item.get("stargazers_count", 0)
            html_url    = item.get("html_url", "")
            description = (item.get("description") or "")[:200]
            repos.append({
                "name":        name,
                "stars":       stars,
                "url":         html_url,
                "description": description,
            })

        result["has_poc"] = len(repos) > 0
        result["repos"]   = repos
        result["total_count"] = data.get("total_count", 0)

    except httpx.HTTPStatusError as exc:
        result["error"] = f"HTTP {exc.response.status_code}"
    except Exception as exc:
        result["error"] = str(exc)[:200]

    return result


# ── Pipeline: IOC enrichment ──────────────────────────────────────────────────

async def run_enrichment_pipeline(batch_size: int = 50) -> int:
    """
    Find IOC items that don't yet have Shodan/RDAP enrichment and enrich them.

    - IPs -> Shodan InternetDB
    - Domains -> RDAP

    Stores results in ioc_enrichments table.
    Returns total count of IOCs enriched.
    """
    enriched_count = 0

    async with SessionLocal() as session:
        # IPs without Shodan enrichment
        already_enriched_ioc_ids_q = (
            select(IOCEnrichment.ioc_id)
            .where(IOCEnrichment.source == "shodan_internetdb")
        )
        ip_iocs = (await session.scalars(
            select(IOCItem)
            .where(IOCItem.ioc_type == "ip")
            .where(IOCItem.id.not_in(already_enriched_ioc_ids_q))
            .limit(batch_size)
        )).all()

        logger.info(f"Enrichment pipeline: {len(ip_iocs)} IPs to enrich via Shodan")

        for ioc in ip_iocs:
            data = await enrich_ip(ioc.value)
            enrichment = IOCEnrichment(
                ioc_id    = ioc.id,
                ioc_value = ioc.value,
                source    = "shodan_internetdb",
                data      = json.dumps(data),
            )
            session.add(enrichment)
            enriched_count += 1

        if ip_iocs:
            await session.commit()

        # Domains without RDAP enrichment
        already_enriched_domain_ids_q = (
            select(IOCEnrichment.ioc_id)
            .where(IOCEnrichment.source == "rdap")
        )
        domain_iocs = (await session.scalars(
            select(IOCItem)
            .where(IOCItem.ioc_type == "domain")
            .where(IOCItem.id.not_in(already_enriched_domain_ids_q))
            .limit(batch_size)
        )).all()

        logger.info(f"Enrichment pipeline: {len(domain_iocs)} domains to enrich via RDAP")

        for ioc in domain_iocs:
            data = await enrich_domain(ioc.value)
            enrichment = IOCEnrichment(
                ioc_id    = ioc.id,
                ioc_value = ioc.value,
                source    = "rdap",
                data      = json.dumps(data),
            )
            session.add(enrichment)
            enriched_count += 1

        if domain_iocs:
            await session.commit()

    logger.info(f"Enrichment pipeline complete: {enriched_count} IOCs enriched")
    return enriched_count


# ── Pipeline: CVE PoC check ───────────────────────────────────────────────────

async def run_cve_poc_check(batch_size: int = 20) -> int:
    """
    Find CVEs without a GitHub PoC check and check GitHub for public PoC repos.

    Stores results in ioc_enrichments with source='github_poc', ioc_id=0.
    Tags CVEItems with 'poc_available' when PoC repos are found.
    Returns count of CVEs checked.
    """
    checked_count = 0

    async with SessionLocal() as session:
        # CVEs that haven't been checked yet
        already_checked_cves_q = (
            select(IOCEnrichment.ioc_value)
            .where(IOCEnrichment.source == "github_poc")
        )
        cves = (await session.scalars(
            select(CVEItem)
            .where(CVEItem.cve_id.not_in(already_checked_cves_q))
            .order_by(CVEItem.published_at.desc())
            .limit(batch_size)
        )).all()

        logger.info(f"CVE PoC check: {len(cves)} CVEs to check")

        for cve in cves:
            poc_data = await check_github_poc(cve.cve_id)

            enrichment = IOCEnrichment(
                ioc_id    = 0,           # sentinel: not a real IOC row
                ioc_value = cve.cve_id,
                source    = "github_poc",
                data      = json.dumps(poc_data),
            )
            session.add(enrichment)

            # Tag CVE if PoC found
            if poc_data.get("has_poc"):
                existing_tags: list[str] = []
                if cve.tags:
                    try:
                        existing_tags = json.loads(cve.tags)
                    except Exception:
                        pass
                if "poc_available" not in existing_tags:
                    existing_tags.append("poc_available")
                    cve.tags = json.dumps(existing_tags)
                    session.add(cve)
                logger.info(
                    f"CVE {cve.cve_id}: PoC found "
                    f"({poc_data.get('total_count', '?')} repos on GitHub)"
                )

            checked_count += 1

        if cves:
            await session.commit()

    logger.info(f"CVE PoC check complete: {checked_count} CVEs checked")
    return checked_count
