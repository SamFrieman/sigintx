"""
SIGINTX — MITRE ATT&CK Collector
Fetches the official STIX bundle from GitHub and seeds ThreatActor profiles.
"""
import json
import logging
import httpx
from datetime import datetime

from database import SessionLocal, ThreatActor
from sqlalchemy import select

logger = logging.getLogger("sigintx.mitre")

MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Fallback static actor list if MITRE bundle is unavailable
STATIC_ACTORS = [
    {"name": "Lazarus Group",    "mitre_id": "G0032", "country": "North Korea",  "motivation": "Financial, Espionage"},
    {"name": "APT28",            "mitre_id": "G0007", "country": "Russia",        "motivation": "Espionage, Information Operations"},
    {"name": "APT29",            "mitre_id": "G0016", "country": "Russia",        "motivation": "Espionage"},
    {"name": "APT41",            "mitre_id": "G0096", "country": "China",         "motivation": "Espionage, Financial"},
    {"name": "Sandworm",         "mitre_id": "G0034", "country": "Russia",        "motivation": "Disruption, Destruction"},
    {"name": "Volt Typhoon",     "mitre_id": "G1017", "country": "China",         "motivation": "Pre-positioning, Espionage"},
    {"name": "Salt Typhoon",     "mitre_id": "G1036", "country": "China",         "motivation": "Espionage"},
    {"name": "LockBit",          "mitre_id": "G0139", "country": "Unknown",       "motivation": "Financial (Ransomware)"},
    {"name": "ALPHV/BlackCat",   "mitre_id": "G1006", "country": "Unknown",       "motivation": "Financial (Ransomware)"},
    {"name": "Cl0p",             "mitre_id": "G0092", "country": "Unknown",       "motivation": "Financial (Ransomware, Extortion)"},
    {"name": "Scattered Spider", "mitre_id": "G1015", "country": "Unknown",       "motivation": "Financial, Espionage"},
    {"name": "FIN7",             "mitre_id": "G0046", "country": "Unknown",       "motivation": "Financial"},
    {"name": "Kimsuky",          "mitre_id": "G0094", "country": "North Korea",   "motivation": "Espionage"},
    {"name": "Turla",            "mitre_id": "G0010", "country": "Russia",        "motivation": "Espionage"},
    {"name": "MuddyWater",       "mitre_id": "G0069", "country": "Iran",          "motivation": "Espionage, Disruption"},
    {"name": "Charming Kitten",  "mitre_id": "G0058", "country": "Iran",          "motivation": "Espionage"},
    {"name": "REvil",            "mitre_id": "G0115", "country": "Unknown",       "motivation": "Financial (Ransomware)"},
    {"name": "Equation Group",   "mitre_id": "G0020", "country": "United States", "motivation": "Espionage"},
    {"name": "Cozy Bear",        "mitre_id": "G0016", "country": "Russia",        "motivation": "Espionage"},
    {"name": "Gamaredon Group",  "mitre_id": "G0047", "country": "Russia",        "motivation": "Espionage, Disruption"},
]


def _parse_stix_actor(obj: dict) -> dict | None:
    """Parse a STIX intrusion-set object into our actor schema."""
    try:
        name = obj.get("name", "")
        if not name:
            return None

        aliases = obj.get("aliases", [])
        description = obj.get("description", "")[:500] if obj.get("description") else None

        # Extract country from description heuristic
        country = None
        if description:
            for country_kw in ["Russia", "China", "North Korea", "Iran", "United States", "Israel", "Vietnam"]:
                if country_kw.lower() in description.lower():
                    country = country_kw
                    break

        mitre_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id")
                break

        return {
            "name": name,
            "aliases": json.dumps(aliases),
            "mitre_id": mitre_id,
            "country": country,
            "description": description,
            "motivation": None,
        }
    except Exception:
        return None


async def seed_threat_actors() -> int:
    """Seed threat actor profiles from MITRE ATT&CK STIX or static fallback."""
    actors_to_seed = []

    try:
        logger.info("Fetching MITRE ATT&CK STIX bundle...")
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(MITRE_STIX_URL)
            resp.raise_for_status()
            stix = resp.json()

        for obj in stix.get("objects", []):
            if obj.get("type") == "intrusion-set" and not obj.get("revoked", False):
                parsed = _parse_stix_actor(obj)
                if parsed:
                    actors_to_seed.append(parsed)

        logger.info(f"MITRE STIX: parsed {len(actors_to_seed)} intrusion sets")
    except Exception as e:
        logger.warning(f"MITRE STIX unavailable ({e}), using static actor list")
        actors_to_seed = [
            {
                "name": a["name"],
                "aliases": json.dumps([]),
                "mitre_id": a["mitre_id"],
                "country": a["country"],
                "description": None,
                "motivation": a["motivation"],
            }
            for a in STATIC_ACTORS
        ]

    seeded = 0
    async with SessionLocal() as db:
        for actor_data in actors_to_seed:
            existing = await db.scalar(
                select(ThreatActor).where(ThreatActor.name == actor_data["name"])
            )
            if not existing:
                db.add(ThreatActor(**actor_data))
                seeded += 1
        await db.commit()

    logger.info(f"ThreatActors: seeded {seeded} new records")
    return seeded
