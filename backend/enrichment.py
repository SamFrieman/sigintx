"""
SIGINTX — Enrichment Engine
Severity classification, keyword tagging, threat actor detection, CVE extraction.
"""
import re
import json
from typing import Optional

# ── Severity keyword rules ──────────────────────────────────────────────────
CRITICAL_KEYWORDS = [
    "zero-day", "0-day", "actively exploited", "ransomware", "nation-state",
    "critical infrastructure", "supply chain attack", "rce", "remote code execution",
    "wormable", "mass exploitation", "emergency patch", "critical zero",
    "backdoor", "apt", "state-sponsored", "cvss 9", "cvss 10",
]
HIGH_KEYWORDS = [
    "exploit", "exploitation", "privilege escalation", "data breach", "breach",
    "malware", "botnet", "credential theft", "phishing campaign", "c2",
    "command and control", "apt group", "threat actor", "high severity",
    "critical vulnerability", "patch now", "emergency", "attack campaign",
    "trojan", "spyware", "keylogger", "ddos",
]
MEDIUM_KEYWORDS = [
    "vulnerability", "cve-", "advisory", "patch", "security update",
    "disclosure", "poc", "proof of concept", "scanner", "exposed",
    "misconfiguration", "leaked", "credential", "authentication bypass",
]
INFO_KEYWORDS = [
    "report", "research", "analysis", "whitepaper", "conference",
    "defcon", "blackhat", "tips", "guide", "best practice",
]

# ── MITRE ATT&CK threat actor keyword map ───────────────────────────────────
THREAT_ACTOR_MAP: dict[str, list[str]] = {
    # Nation-state / country-level (broad — catches generic attribution)
    "Russia-nexus": [
        "russia", "russian hackers", "russian threat", "russian intelligence",
        "gru unit", "fsb hackers", "svr hackers", "kremlin hackers",
        "russian cybercriminals", "russian apt",
    ],
    "China-nexus": [
        "china", "chinese hackers", "chinese apt", "pla unit",
        "mss hackers", "beijing hackers", "chinese state", "prc hackers",
        "chinese cyber", "people's republic",
    ],
    "North Korea-nexus": [
        "north korea", "dprk", "kim jong", "pyongyang",
        "north korean hackers", "north korean apt",
    ],
    "Iran-nexus": [
        "iran", "iranian hackers", "irgc", "tehran",
        "iranian apt", "iranian state", "iranian threat",
    ],
    # Specific groups
    "Lazarus Group": ["lazarus", "hidden cobra", "apt38", "bluenoroff", "andariel"],
    "APT28": ["apt28", "fancy bear", "sofacy", "strontium", "sednit"],
    "APT29": ["apt29", "cozy bear", "nobelium", "midnight blizzard"],
    "APT41": ["apt41", "barium", "winnti", "double dragon", "wicked panda"],
    "APT10": ["apt10", "stone panda", "menupass", "potassium"],
    "APT40": ["apt40", "bronze mohawk", "temp.periscope"],
    "Sandworm": ["sandworm", "voodoo bear", "iridium", "notpetya", "industroyer", "blackenergy"],
    "Volt Typhoon": ["volt typhoon", "bronzesilhouette"],
    "Salt Typhoon": ["salt typhoon", "ghostemperor", "telecom hack"],
    "LockBit": ["lockbit", "lockbit 3.0", "lockbit ransomware"],
    "ALPHV/BlackCat": ["alphv", "blackcat ransomware", "blackcat group"],
    "Cl0p": ["cl0p", "clop", "ta505", "fin11"],
    "REvil": ["revil", "sodinokibi", "gold southfield"],
    "Scattered Spider": ["scattered spider", "unc3944", "oktapus", "star fraud"],
    "FIN7": ["fin7", "carbanak", "navigator group"],
    "Kimsuky": ["kimsuky", "thallium", "velvet chollima", "black banshee"],
    "Turla": ["turla", "snake malware", "uroburos", "venomous bear"],
    "MuddyWater": ["muddywater", "mercury", "static kitten"],
    "Charming Kitten": ["charming kitten", "phosphorus", "apt35", "mint sandstorm"],
    "Gamaredon": ["gamaredon", "primitive bear", "armageddon", "actinium"],
    "BlackBasta": ["black basta", "blackbasta"],
    "Akira": ["akira ransomware", "akira group"],
    "Rhysida": ["rhysida ransomware", "rhysida group"],
    "Play": ["play ransomware", "play group"],
    "8Base": ["8base ransomware", "8base group"],
}

# ── Tag keyword map ──────────────────────────────────────────────────────────
TAG_MAP: dict[str, list[str]] = {
    "ransomware": ["ransomware", "ransom", "encrypted files", "decryptor"],
    "zero-day": ["zero-day", "0-day", "zero day", "zeroday"],
    "APT": ["apt", "advanced persistent", "nation-state", "state-sponsored"],
    "malware": ["malware", "trojan", "spyware", "worm", "virus", "backdoor", "rat"],
    "phishing": ["phishing", "spear-phish", "credential harvest", "smishing", "vishing"],
    "vulnerability": ["vulnerability", "vuln", "cve-", "flaw", "weakness"],
    "exploitation": ["exploit", "exploited", "exploitation", "poc", "proof of concept"],
    "data-breach": ["breach", "data leak", "exfiltrat", "stolen data", "dump"],
    "critical-infra": ["critical infrastructure", "ics", "scada", "ot network", "power grid", "water"],
    "cloud": ["aws", "azure", "gcp", "s3 bucket", "cloud storage", "kubernetes", "k8s"],
    "supply-chain": ["supply chain", "3rd party", "dependency", "npm package", "pypi"],
    "DDoS": ["ddos", "denial of service", "botnet", "flood attack"],
    "patch": ["patch", "update", "security advisory", "fix released", "hotfix"],
    "CISA": ["cisa", "kev", "known exploited", "binding operational"],
    "windows": ["windows", "microsoft", "msrc", "patch tuesday"],
    "linux": ["linux", "ubuntu", "debian", "rhel", "kernel vulnerability"],
    "ios/android": ["ios", "android", "mobile", "iphone", "samsung"],
    "network": ["firewall", "router", "vpn", "cisco", "juniper", "fortinet"],
}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def classify_severity(text: str, cvss: Optional[float] = None) -> str:
    """Return CRITICAL / HIGH / MEDIUM / INFO based on text and optional CVSS."""
    if cvss is not None:
        if cvss >= 9.0:
            return "CRITICAL"
        elif cvss >= 7.0:
            return "HIGH"
        elif cvss >= 4.0:
            return "MEDIUM"
        else:
            return "INFO"

    lower = text.lower()
    for kw in CRITICAL_KEYWORDS:
        if kw in lower:
            return "CRITICAL"
    for kw in HIGH_KEYWORDS:
        if kw in lower:
            return "HIGH"
    for kw in MEDIUM_KEYWORDS:
        if kw in lower:
            return "MEDIUM"
    return "INFO"


def extract_tags(text: str) -> list[str]:
    """Return list of matched tag names."""
    lower = text.lower()
    matched = []
    for tag, keywords in TAG_MAP.items():
        if any(kw in lower for kw in keywords):
            matched.append(tag)
    return matched[:8]   # cap at 8 tags


def extract_threat_actors(text: str) -> list[str]:
    """Return list of matched threat actor names."""
    lower = text.lower()
    matched = []
    for actor, keywords in THREAT_ACTOR_MAP.items():
        if any(kw in lower for kw in keywords):
            matched.append(actor)
    return matched


def extract_cve_refs(text: str) -> list[str]:
    """Extract CVE IDs from text."""
    return list({m.upper() for m in CVE_PATTERN.findall(text)})[:10]


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    return "INFO"


def enrich_news_item(title: str, summary: str = "") -> dict:
    """Run full enrichment on a news item. Returns enrichment dict."""
    combined = f"{title} {summary}"
    return {
        "severity": classify_severity(combined),
        "tags": json.dumps(extract_tags(combined)),
        "threat_actors": json.dumps(extract_threat_actors(combined)),
        "cve_refs": json.dumps(extract_cve_refs(combined)),
    }
