"""
SIGINTX — Shodan Asset Monitor (v3.0.0)
Monitors tracked assets via Shodan InternetDB — completely free, no API key.
Detects open ports, known vulnerabilities, and computes per-asset risk scores.
"""
import json
import logging
from datetime import datetime

import httpx
from sqlalchemy import select

from database import Asset, CVEItem, NewsItem, SessionLocal

logger = logging.getLogger("sigintx.shodan_collector")

SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

_HTTP_HEADERS = {
    "User-Agent": "SIGINTX/3.0.0 threat-intelligence-platform",
    "Accept": "application/json",
}

# Risk scoring weights
_RISK_CRITICAL_CVE = 10
_RISK_HIGH_CVE     = 5
_RISK_MEDIUM_CVE   = 2
_RISK_PORT         = 1


async def enrich_asset(asset: Asset) -> dict:
    """
    Fetch Shodan InternetDB data for a single IP asset.

    Returns a dict with: ports, vulns, tags, cpes, hostnames
    On error, returns {"error": "...", "ip": asset.value}
    """
    ip  = asset.value.strip()
    url = SHODAN_INTERNETDB_URL.format(ip=ip)
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=5.0),
            headers=_HTTP_HEADERS,
        ) as client:
            resp = await client.get(url)
            if resp.status_code == 404:
                return {
                    "ip":        ip,
                    "ports":     [],
                    "vulns":     [],
                    "tags":      [],
                    "cpes":      [],
                    "hostnames": [],
                    "not_found": True,
                }
            resp.raise_for_status()
            data = resp.json()
            return {
                "ip":        data.get("ip", ip),
                "ports":     data.get("ports", []),
                "vulns":     data.get("vulns", []),
                "tags":      data.get("tags", []),
                "cpes":      data.get("cpes", []),
                "hostnames": data.get("hostnames", []),
            }
    except httpx.HTTPStatusError as exc:
        logger.warning(f"Shodan InternetDB HTTP {exc.response.status_code} for {ip}")
        return {"error": f"HTTP {exc.response.status_code}", "ip": ip}
    except Exception as exc:
        logger.warning(f"Shodan InternetDB error for {ip}: {exc}")
        return {"error": str(exc)[:200], "ip": ip}


def _compute_risk_score(
    cve_severity_map: dict[str, str],
    open_ports: list[int],
) -> float:
    """
    Compute a numeric risk score for an asset.

    Formula:
        critical_cves * 10  +  high_cves * 5  +  medium_cves * 2  +  port_count * 1
    """
    score = 0
    for _cve_id, sev in cve_severity_map.items():
        if sev == "CRITICAL":
            score += _RISK_CRITICAL_CVE
        elif sev == "HIGH":
            score += _RISK_HIGH_CVE
        elif sev == "MEDIUM":
            score += _RISK_MEDIUM_CVE
    score += len(open_ports) * _RISK_PORT
    return float(score)


async def scan_assets() -> int:
    """
    For each Asset with monitor_shodan=True and asset_type='ip',
    query Shodan InternetDB, update the asset record, cross-reference CVEs,
    and create urgent news items for newly detected critical vulnerabilities.

    Returns count of assets successfully scanned.
    """
    scanned = 0

    async with SessionLocal() as session:
        assets = (await session.scalars(
            select(Asset)
            .where(Asset.monitor_shodan == True)
            .where(Asset.asset_type == "ip")
        )).all()

        logger.info(f"Shodan scan: {len(assets)} IP assets to check")

        for asset in assets:
            shodan_data = await enrich_asset(asset)
            if "error" in shodan_data:
                logger.debug(f"Asset {asset.value}: enrichment error — {shodan_data['error']}")
                continue

            ports: list[int]    = shodan_data.get("ports", [])
            vulns: list[str]    = shodan_data.get("vulns", [])    # CVE ID strings
            tags: list[str]     = shodan_data.get("tags", [])
            hostnames: list[str] = shodan_data.get("hostnames", [])

            # Cross-reference detected CVEs with our DB
            cve_severity_map: dict[str, str] = {}
            newly_critical: list[str]        = []

            if vulns:
                # Load existing vulns for comparison
                previous_vulns: set[str] = set()
                if asset.vulns_detected:
                    try:
                        previous_vulns = set(json.loads(asset.vulns_detected))
                    except Exception:
                        pass

                for cve_id in vulns:
                    cve_row = await session.scalar(
                        select(CVEItem).where(CVEItem.cve_id == cve_id.upper())
                    )
                    if cve_row:
                        sev = cve_row.severity
                    else:
                        # Unknown CVE — default to HIGH if listed by Shodan
                        sev = "HIGH"

                    cve_severity_map[cve_id.upper()] = sev

                    # Track newly detected critical CVEs
                    if cve_id.upper() not in previous_vulns and sev == "CRITICAL":
                        newly_critical.append(cve_id.upper())

            # Compute risk score
            risk = _compute_risk_score(cve_severity_map, ports)

            # Persist updated asset fields
            asset.open_ports      = json.dumps(ports)
            asset.vulns_detected  = json.dumps(list(cve_severity_map.keys()))
            asset.tags            = json.dumps(list(set(tags)))
            asset.hostnames       = json.dumps(hostnames) if hasattr(asset, "hostnames") else asset.tags
            asset.risk_score      = risk
            asset.last_scanned    = datetime.utcnow()
            session.add(asset)

            # Create news items for newly detected critical CVEs
            for cve_id in newly_critical:
                pseudo_url = f"internal://asset-alert/{asset.id}/{cve_id}/{datetime.utcnow().date()}"
                existing_news = await session.scalar(
                    select(NewsItem).where(NewsItem.url == pseudo_url)
                )
                if not existing_news:
                    cve_row = await session.scalar(
                        select(CVEItem).where(CVEItem.cve_id == cve_id)
                    )
                    desc = ""
                    if cve_row and cve_row.description:
                        desc = cve_row.description[:300]

                    kev_note = ""
                    if cve_row and cve_row.in_kev:
                        kev_note = " [CISA KEV — ACTIVELY EXPLOITED]"

                    title = (
                        f"[ASSET ALERT] Critical CVE {cve_id}{kev_note} "
                        f"detected on {asset.name} ({asset.value})"
                    )
                    summary = (
                        f"Shodan InternetDB detected {cve_id} on asset '{asset.name}' "
                        f"({asset.value}). Open ports: {ports[:20]}. "
                        f"Risk score: {risk:.0f}. {desc}"
                    )
                    news = NewsItem(
                        title        = title[:512],
                        url          = pseudo_url,
                        source       = "Shodan-Monitor",
                        summary      = summary[:2000],
                        published_at = datetime.utcnow(),
                        severity     = "CRITICAL",
                        tags         = json.dumps(["asset-monitor", "shodan", "vulnerability"]),
                        threat_actors= json.dumps([]),
                        cve_refs     = json.dumps([cve_id]),
                    )
                    session.add(news)
                    logger.warning(
                        f"CRITICAL CVE {cve_id} newly detected on asset "
                        f"{asset.name} ({asset.value})"
                    )

            scanned += 1
            logger.info(
                f"Asset {asset.name} ({asset.value}): "
                f"ports={len(ports)} vulns={len(cve_severity_map)} "
                f"risk={risk:.0f}"
            )

        if scanned:
            await session.commit()

    logger.info(f"Shodan scan complete: {scanned} assets updated")
    return scanned
