"""
SIGINTX — Demo Seed
Injects realistic cyber intelligence mock data so the UI is populated on first run,
even before live RSS and NVD collection completes.
All CVE IDs and ATT&CK IDs are real; news items are representative examples.
"""
import json
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from datetime import datetime, timedelta
from database import init_db, SessionLocal, NewsItem, CVEItem
from sqlalchemy import select

# ── Mock news items (representative of real intel) ────────────────────────────
DEMO_NEWS = [
    {
        "title": "CISA Adds Six Known Exploited Vulnerabilities to Catalog Including Fortinet FortiOS",
        "url": "https://www.cisa.gov/news-events/alerts/2025/04/01/cisa-adds-six-known-exploited-vulnerabilities",
        "source": "US-CERT CISA",
        "summary": "CISA has added six new vulnerabilities to its Known Exploited Vulnerabilities Catalog, based on evidence of active exploitation. These types of vulnerabilities are frequent attack vectors for malicious cyber actors and pose significant risks to the federal enterprise. Binding Operational Directive 22-01 requires FCEB agencies to remediate identified vulnerabilities by the due date.",
        "severity": "CRITICAL",
        "tags": json.dumps(["CISA", "exploitation", "vulnerability", "patch"]),
        "threat_actors": json.dumps([]),
        "cve_refs": json.dumps(["CVE-2024-55591", "CVE-2024-23113"]),
        "published_at": datetime.utcnow() - timedelta(hours=2),
    },
    {
        "title": "Salt Typhoon Breach Expanded: Nine US Telecoms Confirmed Compromised in Ongoing Campaign",
        "url": "https://www.bleepingcomputer.com/news/security/salt-typhoon-breach-nine-us-telecoms-compromised/",
        "source": "BleepingComputer",
        "summary": "The FBI and CISA have confirmed that Chinese state-sponsored threat actor Salt Typhoon has compromised at least nine major US telecommunications providers. The attackers maintained persistent access for over 18 months, intercepting communications and metadata from high-value government and political targets.",
        "severity": "CRITICAL",
        "tags": json.dumps(["APT", "zero-day", "data-breach", "network"]),
        "threat_actors": json.dumps(["Salt Typhoon"]),
        "cve_refs": json.dumps([]),
        "published_at": datetime.utcnow() - timedelta(hours=4),
    },
    {
        "title": "LockBit 4.0 Infrastructure Seized in Operation Cronos Phase II — Affiliates Arrested",
        "url": "https://www.europol.europa.eu/newsroom/news/operation-cronos-phase-ii",
        "source": "SecurityWeek",
        "summary": "Law enforcement agencies from 10 countries have seized LockBit's new infrastructure and arrested four affiliates in a coordinated operation. Despite the February 2024 takedown, LockBit attempted to rebuild under version 4.0. Europol, FBI, and NCA led the operation which also obtained decryption keys for over 800 victims.",
        "severity": "HIGH",
        "tags": json.dumps(["ransomware", "APT"]),
        "threat_actors": json.dumps(["LockBit"]),
        "cve_refs": json.dumps([]),
        "published_at": datetime.utcnow() - timedelta(hours=6),
    },
    {
        "title": "Critical RCE in Ivanti Connect Secure (CVE-2025-0282) Exploited Before Patch Available",
        "url": "https://www.bleepingcomputer.com/news/security/critical-ivanti-connect-secure-zero-day-exploited/",
        "source": "BleepingComputer",
        "summary": "Ivanti has confirmed active exploitation of CVE-2025-0282, a critical stack-based buffer overflow in Ivanti Connect Secure, Policy Secure, and ZTA gateways. The vulnerability allows unauthenticated remote code execution with a CVSS score of 9.0. Multiple threat actors including UNC5337 have been observed deploying SPAWN malware families.",
        "severity": "CRITICAL",
        "tags": json.dumps(["zero-day", "exploitation", "vulnerability", "network"]),
        "threat_actors": json.dumps([]),
        "cve_refs": json.dumps(["CVE-2025-0282", "CVE-2025-0283"]),
        "published_at": datetime.utcnow() - timedelta(hours=8),
    },
    {
        "title": "Volt Typhoon Pre-Positions in US Critical Infrastructure: CISA Emergency Directive",
        "url": "https://www.cisa.gov/news-events/directives/ed-25-01",
        "source": "US-CERT CISA",
        "summary": "CISA, NSA, and FBI have issued a joint advisory warning that Volt Typhoon is actively pre-positioning within US critical infrastructure networks including water, energy, and transportation sectors. The campaign uses living-off-the-land techniques to evade detection. Emergency Directive 25-01 requires immediate mitigation actions.",
        "severity": "CRITICAL",
        "tags": json.dumps(["APT", "critical-infra", "network"]),
        "threat_actors": json.dumps(["Volt Typhoon"]),
        "cve_refs": json.dumps([]),
        "published_at": datetime.utcnow() - timedelta(hours=10),
    },
    {
        "title": "Patch Tuesday April 2025: Microsoft Fixes 147 Vulnerabilities Including 3 Zero-Days",
        "url": "https://msrc.microsoft.com/update-guide/releaseNote/2025-Apr",
        "source": "SecurityWeek",
        "summary": "Microsoft's April 2025 Patch Tuesday addresses 147 CVEs across Windows, Office, Azure, and Exchange. Three zero-day vulnerabilities are being actively exploited: CVE-2025-21333 (Hyper-V RCE), CVE-2025-21334 (NTLM hash disclosure), and CVE-2025-21335 (Windows Task Scheduler EoP). Immediate patching is strongly recommended.",
        "severity": "CRITICAL",
        "tags": json.dumps(["zero-day", "patch", "windows", "vulnerability", "exploitation"]),
        "threat_actors": json.dumps([]),
        "cve_refs": json.dumps(["CVE-2025-21333", "CVE-2025-21334", "CVE-2025-21335"]),
        "published_at": datetime.utcnow() - timedelta(hours=14),
    },
    {
        "title": "Scattered Spider Targets Financial Sector Using Advanced Vishing and SIM Swapping",
        "url": "https://www.crowdstrike.com/blog/scattered-spider-financial-sector/",
        "source": "CrowdStrike Blog",
        "summary": "CrowdStrike Intelligence has observed Scattered Spider (UNC3944) pivoting to financial institutions after previous attacks on hospitality and gaming. The group combines social engineering, SIM swapping, and MFA fatigue attacks to bypass multi-factor authentication and establish persistence in cloud environments.",
        "severity": "HIGH",
        "tags": json.dumps(["APT", "phishing", "cloud", "data-breach"]),
        "threat_actors": json.dumps(["Scattered Spider"]),
        "cve_refs": json.dumps([]),
        "published_at": datetime.utcnow() - timedelta(hours=18),
    },
    {
        "title": "ALPHV/BlackCat Ransomware Claims MGM Successor Attack — New Encryptor Bypasses EDR",
        "url": "https://www.darkreading.com/threat-intelligence/alphv-blackcat-new-encryptor",
        "source": "Dark Reading",
        "summary": "ALPHV/BlackCat has claimed responsibility for a series of attacks using a redesigned encryptor that uses kernel-level drivers to disable EDR solutions before deployment. The group has shifted to targeting healthcare and critical infrastructure following law enforcement pressure.",
        "severity": "HIGH",
        "tags": json.dumps(["ransomware", "malware", "critical-infra"]),
        "threat_actors": json.dumps(["ALPHV/BlackCat"]),
        "cve_refs": json.dumps([]),
        "published_at": datetime.utcnow() - timedelta(hours=22),
    },
    {
        "title": "PyPI Supply Chain Attack: 15 Malicious Packages Steal AWS Credentials via Typosquatting",
        "url": "https://blog.talosintelligence.com/pypi-supply-chain-aws-credentials/",
        "source": "Talos Intelligence",
        "summary": "Cisco Talos has discovered 15 malicious Python packages on PyPI designed to steal AWS credentials, environment variables, and SSH keys. The packages use typosquatting to impersonate popular libraries including boto3, requests, and cryptography. The campaign has been active for 6 weeks with over 3,000 installations.",
        "severity": "HIGH",
        "tags": json.dumps(["supply-chain", "malware", "cloud"]),
        "threat_actors": json.dumps([]),
        "cve_refs": json.dumps([]),
        "published_at": datetime.utcnow() - timedelta(hours=26),
    },
    {
        "title": "Kimsuky Deploys GoldDragon Backdoor Against South Korean Government Targets",
        "url": "https://blog.malwarebytes.com/threat-intelligence/2025/kimsuky-golddragon/",
        "source": "Malwarebytes Labs",
        "summary": "Malwarebytes Threat Intelligence has identified a new Kimsuky campaign deploying the GoldDragon backdoor family against South Korean government agencies, think tanks, and academic institutions. The campaign uses spear-phishing with weaponized Word documents exploiting CVE-2024-38200.",
        "severity": "HIGH",
        "tags": json.dumps(["APT", "malware", "phishing"]),
        "threat_actors": json.dumps(["Kimsuky"]),
        "cve_refs": json.dumps(["CVE-2024-38200"]),
        "published_at": datetime.utcnow() - timedelta(hours=30),
    },
    {
        "title": "NIST NVD Processing Backlog Crisis: 17,000+ CVEs Await Analysis",
        "url": "https://www.darkreading.com/vulnerabilities-threats/nist-nvd-backlog-17000-cves",
        "source": "Dark Reading",
        "summary": "NIST's National Vulnerability Database continues to struggle with a massive processing backlog, with over 17,000 CVEs from 2024 still awaiting enrichment analysis. The backlog, which began in February 2024, is hampering the security community's ability to assess and prioritize vulnerabilities effectively.",
        "severity": "MEDIUM",
        "tags": json.dumps(["vulnerability", "patch"]),
        "threat_actors": json.dumps([]),
        "cve_refs": json.dumps([]),
        "published_at": datetime.utcnow() - timedelta(hours=36),
    },
    {
        "title": "Fortinet FortiGate Mass Exploitation: 87,000 Devices Compromised via CVE-2024-55591",
        "url": "https://www.bleepingcomputer.com/news/security/fortinet-fortigate-mass-exploitation/",
        "source": "BleepingComputer",
        "summary": "Arctic Wolf has confirmed that CVE-2024-55591, an authentication bypass in Fortinet FortiOS, is being mass-exploited to gain super-admin privileges on FortiGate devices. Shodan scans indicate at least 87,000 internet-exposed devices remain unpatched. The attackers create rogue admin accounts and modify SSL VPN configurations.",
        "severity": "CRITICAL",
        "tags": json.dumps(["exploitation", "vulnerability", "network", "CISA"]),
        "threat_actors": json.dumps([]),
        "cve_refs": json.dumps(["CVE-2024-55591"]),
        "published_at": datetime.utcnow() - timedelta(hours=40),
    },
    {
        "title": "New GhostSec Hacktivist Campaign Targets OT/ICS Systems in Middle East",
        "url": "https://www.securityweek.com/ghostsec-ot-ics-middle-east/",
        "source": "SecurityWeek",
        "summary": "Hacktivist group GhostSec has claimed attacks against operational technology and industrial control systems in several Middle Eastern countries. The group, which has ties to Anonymous, claims to have disrupted SCADA systems at water treatment facilities and energy infrastructure.",
        "severity": "HIGH",
        "tags": json.dumps(["critical-infra", "DDoS", "APT"]),
        "threat_actors": json.dumps([]),
        "cve_refs": json.dumps([]),
        "published_at": datetime.utcnow() - timedelta(hours=48),
    },
    {
        "title": "Turla Group Refreshes Arsenal With TinyTurla-NG Targeting European NGOs",
        "url": "https://blog.talosintelligence.com/turla-tinyturla-ng-ngos/",
        "source": "Talos Intelligence",
        "summary": "Cisco Talos has documented a Turla campaign deploying TinyTurla-Next Generation backdoor against European non-governmental organizations and embassies. The backdoor uses encrypted HTTPS communications with legitimate cloud services as C2 infrastructure to blend in with normal traffic.",
        "severity": "HIGH",
        "tags": json.dumps(["APT", "malware"]),
        "threat_actors": json.dumps(["Turla"]),
        "cve_refs": json.dumps([]),
        "published_at": datetime.utcnow() - timedelta(hours=52),
    },
    {
        "title": "GitHub Actions Supply Chain Attack Compromises 23,000 Repositories via tj-actions",
        "url": "https://www.bleepingcomputer.com/news/security/github-actions-supply-chain-attack-tj-actions/",
        "source": "BleepingComputer",
        "summary": "A supply chain attack targeting the popular tj-actions/changed-files GitHub Action has affected over 23,000 repositories. The attacker modified the action to dump CI/CD secrets, environment variables, and tokens directly to workflow logs. Organizations using this action should rotate all secrets immediately.",
        "severity": "CRITICAL",
        "tags": json.dumps(["supply-chain", "cloud", "data-breach"]),
        "threat_actors": json.dumps([]),
        "cve_refs": json.dumps([]),
        "published_at": datetime.utcnow() - timedelta(hours=56),
    },
    {
        "title": "FBI Issues Alert on Akira Ransomware: $42M in Ransom Paid Since 2023",
        "url": "https://www.ic3.gov/Media/News/2025/akira-ransomware-alert",
        "source": "US-CERT CISA",
        "summary": "The FBI, CISA, Europol, and NCSC-NL have released a joint advisory on Akira ransomware, which has extorted over $42 million from more than 250 victims globally. The group primarily exploits Cisco ASA/FTD vulnerabilities and compromised VPN credentials for initial access.",
        "severity": "HIGH",
        "tags": json.dumps(["ransomware", "vulnerability", "network"]),
        "threat_actors": json.dumps([]),
        "cve_refs": json.dumps(["CVE-2020-3259", "CVE-2023-20269"]),
        "published_at": datetime.utcnow() - timedelta(hours=60),
    },
    {
        "title": "Google Patches Chrome Zero-Day CVE-2025-2783 Used in APT Campaign Against Russia",
        "url": "https://chromereleases.googleblog.com/2025/03/stable-channel-update-for-desktop.html",
        "source": "Krebs on Security",
        "summary": "Google has released an emergency patch for CVE-2025-2783, a Chrome zero-day that was used in targeted attacks against Russian organizations in an espionage campaign. The vulnerability involves an incorrect handle in Mojo IPC component allowing sandbox escape.",
        "severity": "CRITICAL",
        "tags": json.dumps(["zero-day", "exploitation", "patch"]),
        "threat_actors": json.dumps([]),
        "cve_refs": json.dumps(["CVE-2025-2783"]),
        "published_at": datetime.utcnow() - timedelta(hours=70),
    },
    {
        "title": "MuddyWater Targets Middle East via Trojanized Remote Admin Tools",
        "url": "https://www.mandiant.com/resources/blog/muddywater-remote-admin-tools",
        "source": "Mandiant Blog",
        "summary": "Mandiant has tracked MuddyWater (UNC3313) deploying trojanized versions of legitimate remote administration tools including Atera Agent and Screen Connect to establish persistence in Middle Eastern government networks. The campaign shows significant operational overlap with APT34 infrastructure.",
        "severity": "HIGH",
        "tags": json.dumps(["APT", "malware"]),
        "threat_actors": json.dumps(["MuddyWater"]),
        "cve_refs": json.dumps([]),
        "published_at": datetime.utcnow() - timedelta(hours=72),
    },
    {
        "title": "Sandworm Deploys FrostyGoop ICS Malware Against Ukrainian Energy Infrastructure",
        "url": "https://www.dragos.com/blog/frostygoop-ics-malware/",
        "source": "SecurityWeek",
        "summary": "Dragos and Claroty have analyzed FrostyGoop, a new ICS-specific malware attributed to Sandworm that caused heating outages in Lviv, Ukraine. The malware communicates via Modbus TCP to directly interact with ICS controllers, representing a growing trend of OT-targeting capabilities.",
        "severity": "CRITICAL",
        "tags": json.dumps(["APT", "critical-infra", "malware"]),
        "threat_actors": json.dumps(["Sandworm"]),
        "cve_refs": json.dumps([]),
        "published_at": datetime.utcnow() - timedelta(hours=80),
    },
    {
        "title": "Cl0p MOVEit Campaign Victims Reach 2,773 Organizations, 95 Million Individuals",
        "url": "https://www.bleepingcomputer.com/news/security/clop-moveit-victims-reach-2773/",
        "source": "BleepingComputer",
        "summary": "The Cl0p ransomware group's exploitation of CVE-2023-34362 in Progress Software MOVEit Transfer has now impacted 2,773 organizations and approximately 95 million individuals. New victims continue to be disclosed 18 months after the initial exploitation wave. Total estimated damages exceed $12 billion.",
        "severity": "HIGH",
        "tags": json.dumps(["ransomware", "exploitation", "data-breach"]),
        "threat_actors": json.dumps(["Cl0p"]),
        "cve_refs": json.dumps(["CVE-2023-34362"]),
        "published_at": datetime.utcnow() - timedelta(hours=88),
    },
]

# ── Mock CVE items ─────────────────────────────────────────────────────────────
DEMO_CVES = [
    {
        "cve_id": "CVE-2025-0282",
        "description": "A stack-based buffer overflow in Ivanti Connect Secure before 22.7R2.5, Ivanti Policy Secure before 22.7R1.2, and Ivanti Neurons for ZTA gateways before 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.",
        "cvss_score": 9.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL", "in_kev": True, "epss_score": 0.9432,
        "published_at": datetime.utcnow() - timedelta(days=90),
        "affected_products": json.dumps(["ivanti connect secure", "ivanti policy secure", "ivanti neurons"]),
        "tags": json.dumps(["zero-day", "exploitation", "network", "CISA"]),
        "threat_actors": json.dumps([]),
    },
    {
        "cve_id": "CVE-2024-55591",
        "description": "An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS version 7.0.0 through 7.0.16 and FortiProxy version 7.0.0 through 7.0.19 allows a remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.",
        "cvss_score": 9.6, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "CRITICAL", "in_kev": True, "epss_score": 0.9718,
        "published_at": datetime.utcnow() - timedelta(days=85),
        "affected_products": json.dumps(["fortios", "fortiproxy", "fortigate"]),
        "tags": json.dumps(["exploitation", "vulnerability", "network", "CISA"]),
        "threat_actors": json.dumps([]),
    },
    {
        "cve_id": "CVE-2025-21333",
        "description": "Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege Vulnerability. An attacker who successfully exploited this vulnerability could gain SYSTEM privileges on the underlying host from a guest VM.",
        "cvss_score": 7.8, "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "severity": "HIGH", "in_kev": True, "epss_score": 0.6812,
        "published_at": datetime.utcnow() - timedelta(days=14),
        "affected_products": json.dumps(["windows server 2019", "windows server 2022", "windows 11"]),
        "tags": json.dumps(["zero-day", "exploitation", "windows"]),
        "threat_actors": json.dumps([]),
    },
    {
        "cve_id": "CVE-2025-2783",
        "description": "Incorrect handle provided in unspecified circumstances in Mojo in Google Chrome on Windows prior to 134.0.6998.177 allowed a remote attacker to perform a sandbox escape via a malicious file.",
        "cvss_score": 8.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "severity": "HIGH", "in_kev": True, "epss_score": 0.8923,
        "published_at": datetime.utcnow() - timedelta(days=20),
        "affected_products": json.dumps(["chrome", "chromium"]),
        "tags": json.dumps(["zero-day", "exploitation"]),
        "threat_actors": json.dumps([]),
    },
    {
        "cve_id": "CVE-2024-23113",
        "description": "A use of externally-controlled format string vulnerability [CWE-134] in FortiOS fgfmd daemon may allow a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted requests.",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL", "in_kev": True, "epss_score": 0.9621,
        "published_at": datetime.utcnow() - timedelta(days=60),
        "affected_products": json.dumps(["fortios", "fortiproxy", "fortimanager"]),
        "tags": json.dumps(["exploitation", "vulnerability", "network", "CISA"]),
        "threat_actors": json.dumps([]),
    },
    {
        "cve_id": "CVE-2023-34362",
        "description": "In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application.",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL", "in_kev": True, "epss_score": 0.9744,
        "published_at": datetime.utcnow() - timedelta(days=300),
        "affected_products": json.dumps(["moveit transfer", "progress software"]),
        "tags": json.dumps(["exploitation", "vulnerability", "data-breach", "CISA"]),
        "threat_actors": json.dumps(["Cl0p"]),
    },
    {
        "cve_id": "CVE-2024-38200",
        "description": "Microsoft Office Spoofing Vulnerability allows an attacker to coerce the client to send NTLM hashes to an attacker-controlled server.",
        "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "severity": "HIGH", "in_kev": False, "epss_score": 0.2341,
        "published_at": datetime.utcnow() - timedelta(days=180),
        "affected_products": json.dumps(["microsoft office", "microsoft 365"]),
        "tags": json.dumps(["exploitation", "windows", "vulnerability"]),
        "threat_actors": json.dumps(["Kimsuky"]),
    },
    {
        "cve_id": "CVE-2020-3259",
        "description": "A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to retrieve memory contents.",
        "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "HIGH", "in_kev": True, "epss_score": 0.8912,
        "published_at": datetime.utcnow() - timedelta(days=1800),
        "affected_products": json.dumps(["cisco asa", "cisco ftd", "cisco firepower"]),
        "tags": json.dumps(["exploitation", "vulnerability", "network", "CISA"]),
        "threat_actors": json.dumps([]),
    },
    {
        "cve_id": "CVE-2025-21334",
        "description": "Windows Hyper-V NT Kernel Integration VSP Information Disclosure Vulnerability enables NTLM hash theft via crafted SMB requests.",
        "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "HIGH", "in_kev": True, "epss_score": 0.4231,
        "published_at": datetime.utcnow() - timedelta(days=14),
        "affected_products": json.dumps(["windows 10", "windows 11", "windows server 2022"]),
        "tags": json.dumps(["zero-day", "exploitation", "windows"]),
        "threat_actors": json.dumps([]),
    },
    {
        "cve_id": "CVE-2025-21335",
        "description": "Windows Task Scheduler Elevation of Privilege Vulnerability allows a local attacker to gain SYSTEM privileges through a race condition in the Task Scheduler service.",
        "cvss_score": 7.8, "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "severity": "HIGH", "in_kev": True, "epss_score": 0.3891,
        "published_at": datetime.utcnow() - timedelta(days=14),
        "affected_products": json.dumps(["windows 10", "windows 11", "windows server"]),
        "tags": json.dumps(["zero-day", "exploitation", "windows"]),
        "threat_actors": json.dumps([]),
    },
    {
        "cve_id": "CVE-2023-20269",
        "description": "A vulnerability in the remote access VPN feature of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct a brute force attack to identify valid username and password combinations.",
        "cvss_score": 5.0, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM", "in_kev": True, "epss_score": 0.9234,
        "published_at": datetime.utcnow() - timedelta(days=400),
        "affected_products": json.dumps(["cisco asa", "cisco ftd"]),
        "tags": json.dumps(["vulnerability", "network", "exploitation"]),
        "threat_actors": json.dumps([]),
    },
    {
        "cve_id": "CVE-2024-3400",
        "description": "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
        "cvss_score": 10.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "CRITICAL", "in_kev": True, "epss_score": 0.9812,
        "published_at": datetime.utcnow() - timedelta(days=180),
        "affected_products": json.dumps(["palo alto pan-os", "globalprotect"]),
        "tags": json.dumps(["zero-day", "exploitation", "network", "CISA"]),
        "threat_actors": json.dumps([]),
    },
]


async def seed_demo_data():
    await init_db()

    async with SessionLocal() as db:
        # Seed news
        news_seeded = 0
        for item_data in DEMO_NEWS:
            existing = await db.scalar(select(NewsItem).where(NewsItem.url == item_data["url"]))
            if not existing:
                db.add(NewsItem(**item_data))
                news_seeded += 1

        # Seed CVEs
        cve_seeded = 0
        for cve_data in DEMO_CVES:
            existing = await db.scalar(select(CVEItem).where(CVEItem.cve_id == cve_data["cve_id"]))
            if not existing:
                db.add(CVEItem(**cve_data))
                cve_seeded += 1

        await db.commit()

    print(f"Demo seed: +{news_seeded} news items, +{cve_seeded} CVEs")
    return news_seeded, cve_seeded


if __name__ == "__main__":
    asyncio.run(seed_demo_data())
