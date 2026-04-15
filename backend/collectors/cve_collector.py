"""
SIGINTX — CVE Collector
Ingests from NVD 2.0 API (free, no key required for basic use) and CISA KEV catalog.
"""
import json
import logging
import httpx
from datetime import datetime, timedelta
from typing import Optional

from database import SessionLocal, CVEItem
from enrichment import cvss_to_severity, extract_tags, extract_threat_actors
from sqlalchemy import select

logger = logging.getLogger("sigintx.cve")

NVD_API_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_BASE  = "https://api.first.org/data/v1/epss"


async def _fetch_kev_ids() -> set[str]:
    """Fetch the full CISA KEV catalog and return a set of CVE IDs."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
            return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as e:
        logger.warning(f"CISA KEV fetch failed: {e}")
        return set()


async def _fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for a list of CVE IDs. Returns {cve_id: score}."""
    if not cve_ids:
        return {}
    try:
        # FIRST EPSS API supports comma-separated CVE IDs
        params = {"cve": ",".join(cve_ids[:100])}
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(EPSS_API_BASE, params=params)
            resp.raise_for_status()
            data = resp.json()
            return {d["cve"]: float(d["epss"]) for d in data.get("data", [])}
    except Exception as e:
        logger.warning(f"EPSS fetch failed: {e}")
        return {}


def _parse_nvd_item(item: dict, kev_ids: set[str], epss_map: dict) -> Optional[dict]:
    """Parse a single NVD CVE item into our internal format."""
    try:
        cve_id = item["id"]
        desc_list = item.get("descriptions", [])
        description = next((d["value"] for d in desc_list if d["lang"] == "en"), None)

        # CVSS v3.1 preferred, fall back to v3.0 then v2
        cvss_score = None
        cvss_vector = None
        metrics = item.get("metrics", {})

        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]["cvssData"]
                cvss_score = m.get("baseScore")
                cvss_vector = m.get("vectorString")
                break

        if cvss_score is None and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            m = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_score = m.get("baseScore")

        severity = cvss_to_severity(cvss_score) if cvss_score else "MEDIUM"
        in_kev = cve_id in kev_ids
        if in_kev and severity not in ("CRITICAL", "HIGH"):
            severity = "HIGH"   # KEV entries are at least HIGH

        epss = epss_map.get(cve_id)
        # Composite priority: CVSS (30%) + EPSS (40%) + KEV (30%)
        # All components normalised to 0–1; result in 0–1.
        cvss_norm  = (cvss_score / 10.0) if cvss_score else 0.0
        epss_norm  = float(epss)          if epss        else 0.0
        kev_norm   = 1.0                  if in_kev      else 0.0
        priority_score = round(cvss_norm * 0.3 + epss_norm * 0.4 + kev_norm * 0.3, 4)

        # Affected products
        cpe_matches = []
        for cfg in item.get("configurations", []):
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        cpe_matches.append(match.get("criteria", ""))
        affected = list({c.split(":")[4] for c in cpe_matches if len(c.split(":")) > 4})[:20]

        pub_raw = item.get("published", "")
        mod_raw = item.get("lastModified", "")

        def parse_nvd_date(s):
            if not s:
                return None
            try:
                return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                return None

        text_combined = f"{cve_id} {description or ''}"
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity,
            "in_kev": in_kev,
            "epss_score": epss,
            "priority_score": priority_score,
            "published_at": parse_nvd_date(pub_raw),
            "modified_at": parse_nvd_date(mod_raw),
            "affected_products": json.dumps(affected),
            "tags": json.dumps(extract_tags(text_combined)),
            "threat_actors": json.dumps(extract_threat_actors(text_combined)),
        }
    except Exception as e:
        logger.debug(f"CVE parse error: {e}")
        return None


async def collect_recent_cves(days_back: int = 7, max_results: int = 200) -> int:
    """Fetch recent CVEs from NVD (last N days). Returns count of new/updated items."""
    kev_ids = await _fetch_kev_ids()
    logger.info(f"CISA KEV: {len(kev_ids)} exploited CVEs loaded")

    now = datetime.utcnow()
    pub_start = (now - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
    pub_end   = now.strftime("%Y-%m-%dT23:59:59.999")

    params = {
        "pubStartDate": pub_start,
        "pubEndDate":   pub_end,
        "resultsPerPage": min(max_results, 2000),
        "startIndex": 0,
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(NVD_API_BASE, params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.error(f"NVD API error: {e}")
        return 0

    vulnerabilities = data.get("vulnerabilities", [])
    cve_ids = [v["cve"]["id"] for v in vulnerabilities]
    epss_map = await _fetch_epss(cve_ids)

    upsert_count = 0
    async with SessionLocal() as db:
        for vuln in vulnerabilities:
            parsed = _parse_nvd_item(vuln["cve"], kev_ids, epss_map)
            if not parsed:
                continue

            existing = await db.scalar(
                select(CVEItem).where(CVEItem.cve_id == parsed["cve_id"])
            )
            if existing:
                # update KEV status, EPSS, and recomputed priority score
                existing.in_kev = parsed["in_kev"]
                existing.epss_score = parsed["epss_score"]
                existing.priority_score = parsed["priority_score"]
                existing.severity = parsed["severity"]
            else:
                db.add(CVEItem(**parsed))
                upsert_count += 1

        await db.commit()

    logger.info(f"NVD: +{upsert_count} new CVEs ({len(vulnerabilities)} total fetched)")
    return upsert_count


async def update_kev_flags() -> int:
    """Re-sync KEV status for all CVEs in DB. Returns count updated."""
    kev_ids = await _fetch_kev_ids()
    if not kev_ids:
        return 0

    updated = 0
    async with SessionLocal() as db:
        result = await db.scalars(select(CVEItem))
        for cve in result.all():
            new_kev = cve.cve_id in kev_ids
            if cve.in_kev != new_kev:
                cve.in_kev = new_kev
                if new_kev and cve.severity == "MEDIUM":
                    cve.severity = "HIGH"
                updated += 1
        await db.commit()

    logger.info(f"KEV sync: {updated} CVEs updated")
    return updated
