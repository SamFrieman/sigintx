import { useEffect, useRef, useState, useCallback, lazy, Suspense, useMemo } from 'react'
import { Globe, X, AlertTriangle, MapPin, Clock, Shield, Crosshair } from 'lucide-react'
import type { NewsItem } from '@/types'

// ── Static attack dataset (real documented incidents) ─────────────────────────

interface Attack {
  id: string
  lat: number
  lng: number
  label: string
  target: string
  targetLat: number
  targetLng: number
  actor: string
  actorCountry: string
  type: 'ransomware' | 'espionage' | 'ddos' | 'supply-chain' | 'wiper' | 'phishing'
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'
  date: string
  description: string
  color: string
}

const TYPE_COLOR: Record<string, string> = {
  ransomware:    '#ff4444',
  espionage:     '#aa44ff',
  ddos:          '#f7931a',
  'supply-chain':'#ff6600',
  wiper:         '#ff0066',
  phishing:      '#00d4ff',
}

const ACTOR_COUNTRY_COLOR: Record<string, string> = {
  'Russia':         '#ff4444',
  'China':          '#ff6600',
  'North Korea':    '#aa44ff',
  'Iran':           '#00d4ff',
  'Ukraine/Russia': '#f7931a',
}

const ATTACKS: Attack[] = [
  // ── APT / Nation-state espionage — 2023–2025 ──────────────────────────────
  {
    id: 'volt-typhoon-2024', lat: 39.91, lng: 116.39, label: 'Volt Typhoon — US Infrastructure',
    target: 'US Telecoms & Utilities', targetLat: 38.90, targetLng: -77.04,
    actor: 'Volt Typhoon', actorCountry: 'China',
    type: 'espionage', severity: 'CRITICAL', date: 'Jan 2024',
    description: 'CISA confirmed Volt Typhoon pre-positioned inside US critical infrastructure — power grids, water, telecoms — for potential sabotage during a Taiwan conflict. 5-year persistent access in some networks.',
    color: '#aa44ff',
  },
  {
    id: 'salt-typhoon', lat: 39.91, lng: 116.39, label: 'Salt Typhoon — US Telecoms',
    target: 'AT&T, Verizon, T-Mobile, USA', targetLat: 40.71, targetLng: -74.01,
    actor: 'Salt Typhoon', actorCountry: 'China',
    type: 'espionage', severity: 'CRITICAL', date: 'Oct 2024',
    description: 'China\'s Salt Typhoon breached all major US carriers including AT&T, Verizon, and T-Mobile. Accessed wiretap systems and intercepted calls of senior government officials and Trump/Harris campaign staff.',
    color: '#aa44ff',
  },
  {
    id: 'midnight-blizzard-msft', lat: 55.75, lng: 37.62, label: 'Midnight Blizzard → Microsoft',
    target: 'Microsoft Corporate, USA', targetLat: 47.64, targetLng: -122.13,
    actor: 'Midnight Blizzard / APT29', actorCountry: 'Russia',
    type: 'espionage', severity: 'CRITICAL', date: 'Jan 2024',
    description: 'SVR-linked APT29 accessed Microsoft senior leadership email accounts and source code repositories for months. Used password spray then OAuth token abuse. Multiple US agencies notified.',
    color: '#aa44ff',
  },
  {
    id: 'apt28-nato-2024', lat: 55.75, lng: 37.62, label: 'APT28 — NATO Phishing Wave',
    target: 'NATO Members, Europe', targetLat: 50.85, targetLng: 4.35,
    actor: 'APT28 / Fancy Bear', actorCountry: 'Russia',
    type: 'phishing', severity: 'HIGH', date: 'Mar 2024',
    description: 'GRU\'s APT28 ran sustained spear-phishing against German, Polish, Czech, and Slovak government ministries. Exploited Outlook zero-day CVE-2023-23397 to steal NTLM hashes without user interaction.',
    color: '#00d4ff',
  },
  {
    id: 'lazarus-jobsploit-2024', lat: 39.02, lng: 125.75, label: 'Lazarus — DEV#POPPER',
    target: 'Software Developers, Global', targetLat: 37.77, targetLng: -122.42,
    actor: 'Lazarus Group', actorCountry: 'North Korea',
    type: 'phishing', severity: 'HIGH', date: 'Apr 2024',
    description: 'Lazarus lured developers via fake LinkedIn job interviews, delivering Python-based RATs during coding assessments. Targeted crypto, fintech, and defence contractors globally.',
    color: '#aa44ff',
  },
  {
    id: 'volt-typhoon-guam', lat: 39.91, lng: 116.39, label: 'Volt Typhoon — Guam Telecom',
    target: 'Guam Critical Infrastructure', targetLat: 13.45, targetLng: 144.80,
    actor: 'Volt Typhoon', actorCountry: 'China',
    type: 'espionage', severity: 'CRITICAL', date: 'May 2023',
    description: 'Pre-positioning in Guam communications infrastructure using living-off-the-land techniques. Attributed to pre-conflict preparation targeting US military logistics hub in the Pacific.',
    color: '#aa44ff',
  },
  {
    id: 'charming-kitten-2024', lat: 35.69, lng: 51.39, label: 'Charming Kitten — Election Interference',
    target: 'US Presidential Campaign Staff', targetLat: 38.90, targetLng: -77.04,
    actor: 'Charming Kitten / APT42', actorCountry: 'Iran',
    type: 'phishing', severity: 'CRITICAL', date: 'Jun 2024',
    description: 'Iran\'s APT42 compromised Trump campaign staffer accounts and attempted to infiltrate Biden-Harris campaign. Google TAG and FBI confirmed Iranian government involvement in US election interference.',
    color: '#00d4ff',
  },
  // ── Ransomware — 2023–2025 ────────────────────────────────────────────────
  {
    id: 'blackcat-change-health', lat: 55.75, lng: 37.62, label: 'BlackCat → Change Healthcare',
    target: 'Change Healthcare, USA', targetLat: 36.17, targetLng: -86.78,
    actor: 'ALPHV/BlackCat', actorCountry: 'Russia',
    type: 'ransomware', severity: 'CRITICAL', date: 'Feb 2024',
    description: '$22M ransom paid; US healthcare payment processing disrupted for 3 months. 190M patient records stolen — largest medical data breach in US history. UnitedHealth Group affected.',
    color: '#ff4444',
  },
  {
    id: 'scattered-spider-mgm', lat: 33.74, lng: -84.39, label: 'Scattered Spider → MGM Resorts',
    target: 'MGM Resorts, Las Vegas', targetLat: 36.17, targetLng: -115.14,
    actor: 'Scattered Spider', actorCountry: 'Russia',
    type: 'ransomware', severity: 'CRITICAL', date: 'Sep 2023',
    description: '$100M+ losses after social-engineering MGM\'s IT helpdesk via LinkedIn. BlackCat deployed; slot machines, hotel check-in, and digital key systems offline for 10 days.',
    color: '#ff4444',
  },
  {
    id: 'cdk-global', lat: 55.75, lng: 37.62, label: 'BlackSuit → CDK Global',
    target: '15,000 US Auto Dealerships', targetLat: 41.88, targetLng: -87.63,
    actor: 'BlackSuit', actorCountry: 'Russia',
    type: 'ransomware', severity: 'CRITICAL', date: 'Jun 2024',
    description: '$25M ransom reportedly paid. CDK Global software outage paralysed 15,000+ US car dealerships for weeks, halting sales and service operations across major brands.',
    color: '#ff4444',
  },
  {
    id: 'synnovis-nhs', lat: 55.75, lng: 37.62, label: 'Qilin → Synnovis / NHS',
    target: 'NHS London, UK', targetLat: 51.51, targetLng: -0.13,
    actor: 'Qilin', actorCountry: 'Russia',
    type: 'ransomware', severity: 'CRITICAL', date: 'Jun 2024',
    description: 'Ransomware on pathology lab Synnovis caused NHS London to declare critical incident. Blood transfusions postponed, 1,500+ operations cancelled. 400GB patient data leaked.',
    color: '#ff4444',
  },
  {
    id: 'clop-moveit', lat: 55.75, lng: 37.62, label: 'Cl0p — MOVEit Campaign',
    target: 'Global (2,600+ organisations)', targetLat: 40.71, targetLng: -74.01,
    actor: 'Cl0p', actorCountry: 'Russia',
    type: 'ransomware', severity: 'CRITICAL', date: 'Jun 2023',
    description: 'Zero-day in MOVEit Transfer exploited en-masse, compromising 2,600+ organisations and 77M+ individuals including US federal agencies, BBC, British Airways, and Shell.',
    color: '#ff4444',
  },
  {
    id: 'akira-2024', lat: 55.75, lng: 37.62, label: 'Akira Ransomware — Global Campaign',
    target: 'Global SMBs & Healthcare', targetLat: 52.52, targetLng: 13.41,
    actor: 'Akira', actorCountry: 'Russia',
    type: 'ransomware', severity: 'HIGH', date: '2024',
    description: 'Akira extorted $42M from 250+ victims across North America and Europe in 15 months. Primarily exploited Cisco VPN vulnerabilities lacking MFA.',
    color: '#ff4444',
  },
  // ── Supply Chain ──────────────────────────────────────────────────────────
  {
    id: 'xz-backdoor', lat: 39.91, lng: 116.39, label: 'XZ Utils Backdoor',
    target: 'Linux Distributions, Global', targetLat: 60.17, targetLng: 24.93,
    actor: 'Jia Tan (suspected state)', actorCountry: 'China',
    type: 'supply-chain', severity: 'CRITICAL', date: 'Mar 2024',
    description: 'Two-year supply-chain attack embedded SSH backdoor in XZ Utils across major Linux distros. Discovered by accident by a Microsoft engineer. Would have granted root access to millions of servers.',
    color: '#ff6600',
  },
  {
    id: 'polyfill-supply', lat: 39.91, lng: 116.39, label: 'Polyfill.io Hijack',
    target: '100,000+ Websites, Global', targetLat: 37.77, targetLng: -122.42,
    actor: 'Unknown (China-linked)', actorCountry: 'China',
    type: 'supply-chain', severity: 'HIGH', date: 'Jun 2024',
    description: 'Polyfill.io domain acquired and weaponised to inject malicious JavaScript into 100,000+ websites including JSTOR, Intuit, and Warner Bros. Redirected mobile users to scam sites.',
    color: '#ff6600',
  },
  {
    id: 'snowflake-breach', lat: 33.74, lng: -84.39, label: 'ShinyHunters — Snowflake Clients',
    target: '165 Companies incl. Ticketmaster', targetLat: 34.05, targetLng: -118.24,
    actor: 'ShinyHunters', actorCountry: 'Russia',
    type: 'supply-chain', severity: 'CRITICAL', date: 'Jun 2024',
    description: 'Stolen credentials used to exfiltrate data from 165 Snowflake customers. Ticketmaster (560M records), AT&T (110M), Advance Auto Parts, and Santander among victims. No MFA required on accounts.',
    color: '#ff6600',
  },
  // ── DDoS / Disruption ─────────────────────────────────────────────────────
  {
    id: 'russia-ukraine-wiper-2024', lat: 55.75, lng: 37.62, label: 'Sandworm — Ukraine Wipers',
    target: 'Ukraine Telecom & Energy', targetLat: 50.45, targetLng: 30.52,
    actor: 'Sandworm', actorCountry: 'Russia',
    type: 'wiper', severity: 'CRITICAL', date: '2024',
    description: 'Ongoing Sandworm wiper campaigns targeting Ukrainian telecoms (Kyivstar — 24M users offline Dec 2023) and energy infrastructure. AcidPour wiper deployed against Linux-based systems.',
    color: '#ff0066',
  },
  {
    id: 'noname-ddos-2024', lat: 55.75, lng: 37.62, label: 'NoName057(16) — EU DDoS',
    target: 'EU Elections Infrastructure', targetLat: 50.85, targetLng: 4.35,
    actor: 'NoName057(16)', actorCountry: 'Russia',
    type: 'ddos', severity: 'HIGH', date: 'Jun 2024',
    description: 'Pro-Russian NoName057(16) disrupted EU parliamentary election websites across France, Germany, Italy, and Poland on election day. Coordinated DDoS via DDoSIA crowdsourcing platform.',
    color: '#f7931a',
  },
  // ── Crypto theft ─────────────────────────────────────────────────────────
  {
    id: 'bybit-hack', lat: 39.02, lng: 125.75, label: 'Lazarus — Bybit Heist',
    target: 'Bybit Exchange, Dubai', targetLat: 25.20, targetLng: 55.27,
    actor: 'Lazarus Group', actorCountry: 'North Korea',
    type: 'espionage', severity: 'CRITICAL', date: 'Feb 2025',
    description: '$1.5B stolen from Bybit cold wallets — largest crypto heist in history. TraderTraitor compromised Safe{Wallet} developer machines to inject malicious JavaScript into the signing UI.',
    color: '#aa44ff',
  },
  {
    id: 'radiant-capital', lat: 39.02, lng: 125.75, label: 'Lazarus — Radiant Capital',
    target: 'Radiant Capital DeFi', targetLat: 37.77, targetLng: -122.42,
    actor: 'Lazarus Group', actorCountry: 'North Korea',
    type: 'espionage', severity: 'CRITICAL', date: 'Oct 2024',
    description: '$50M stolen from Radiant Capital DeFi protocol. Lazarus used a Telegram malware-laced PDF to compromise developer machines, then manipulated hardware wallet signing sessions.',
    color: '#aa44ff',
  },
  // ── Data breaches ─────────────────────────────────────────────────────────
  {
    id: 'npd-breach', lat: 33.74, lng: -84.39, label: 'National Public Data Breach',
    target: '2.9 Billion Records, USA', targetLat: 38.90, targetLng: -77.04,
    actor: 'USDoD (threat actor)', actorCountry: 'Russia',
    type: 'espionage', severity: 'CRITICAL', date: 'Aug 2024',
    description: '2.9 billion SSNs, names, and addresses of US, UK, and Canadian citizens leaked from data broker National Public Data. Largest personal data exposure ever recorded.',
    color: '#aa44ff',
  },
  {
    id: 'telecom-namibia', lat: 39.02, lng: 125.75, label: 'Hunters International — Telecom Namibia',
    target: 'Telecom Namibia', targetLat: -22.56, targetLng: 17.07,
    actor: 'Hunters International', actorCountry: 'Russia',
    type: 'ransomware', severity: 'HIGH', date: 'Dec 2024',
    description: '626K customer records including government officials\' data published after ransom refusal. Part of a broader Hunters International campaign targeting African telecoms and government.',
    color: '#ff4444',
  },
]

// ── Dynamic attacks from live news ───────────────────────────────────────────

const ACTOR_ORIGINS: Record<string, { lat: number; lng: number; country: string }> = {
  'apt28': { lat: 55.75, lng: 37.62, country: 'Russia' },
  'apt29': { lat: 55.75, lng: 37.62, country: 'Russia' },
  'sandworm': { lat: 55.75, lng: 37.62, country: 'Russia' },
  'lazarus': { lat: 39.02, lng: 125.75, country: 'North Korea' },
  'apt41': { lat: 39.91, lng: 116.39, country: 'China' },
  'volt typhoon': { lat: 39.91, lng: 116.39, country: 'China' },
  'charming kitten': { lat: 35.69, lng: 51.39, country: 'Iran' },
  'muddywater': { lat: 35.69, lng: 51.39, country: 'Iran' },
  'lockbit': { lat: 55.75, lng: 37.62, country: 'Russia' },
  'blackcat': { lat: 55.75, lng: 37.62, country: 'Russia' },
  'cl0p': { lat: 50.45, lng: 30.52, country: 'Ukraine/Russia' },
}

const TARGET_NODES: { lat: number; lng: number; city: string }[] = [
  { lat: 37.77, lng: -122.42, city: 'San Francisco' },
  { lat: 40.71, lng: -74.01, city: 'New York' },
  { lat: 51.51, lng: -0.13, city: 'London' },
  { lat: 48.86, lng: 2.35, city: 'Paris' },
  { lat: 35.68, lng: 139.69, city: 'Tokyo' },
  { lat: 1.35, lng: 103.82, city: 'Singapore' },
  { lat: 52.52, lng: 13.41, city: 'Berlin' },
  { lat: 50.45, lng: 30.52, city: 'Kyiv' },
  { lat: 25.20, lng: 55.27, city: 'Dubai' },
]

// ── Map point types ───────────────────────────────────────────────────────────

interface ActorPoint {
  nodeType: 'actor'
  actor: string
  actorCountry: string
  lat: number
  lng: number
  color: string
  attacks: Attack[]
}

interface TargetPoint {
  nodeType: 'target'
  attack: Attack
  lat: number
  lng: number
}

type MapPoint = ActorPoint | TargetPoint

type Selected =
  | { kind: 'actor'; data: ActorPoint }
  | { kind: 'attack'; data: Attack }
  | null

// ── Node HTML factories ───────────────────────────────────────────────────────

function makeActorNode(point: ActorPoint, onClick: (p: ActorPoint) => void): HTMLElement {
  // Outer wrapper is slightly taller to accommodate the label below
  const wrapper = document.createElement('div')
  wrapper.style.cssText = [
    'position:relative',
    'width:40px',
    'height:48px',
    'cursor:pointer',
    'transform:translate(-50%,-50%)',
    'pointer-events:auto',
  ].join(';')

  // Outer pulsing diamond ring (uses diamond-pulse so rotation is preserved)
  const ring2 = document.createElement('div')
  ring2.style.cssText = `
    position:absolute;top:18px;left:50%;
    width:28px;height:28px;
    transform:translate(-50%,-50%) rotate(45deg);
    border:1px solid ${point.color}44;
    animation:diamond-pulse 3s ease-out infinite;
    animation-delay:0.6s;
  `

  const ring1 = document.createElement('div')
  ring1.style.cssText = `
    position:absolute;top:18px;left:50%;
    width:20px;height:20px;
    transform:translate(-50%,-50%) rotate(45deg);
    border:1px solid ${point.color}77;
    animation:diamond-pulse 3s ease-out infinite;
  `

  // Solid diamond core
  const diamond = document.createElement('div')
  diamond.style.cssText = `
    position:absolute;top:18px;left:50%;
    width:13px;height:13px;
    transform:translate(-50%,-50%) rotate(45deg);
    background:${point.color};
    box-shadow:0 0 8px ${point.color}, 0 0 18px ${point.color}88;
    animation:diamond-throb 3s ease-in-out infinite;
    animation-delay:${Math.random() * 2}s;
  `

  // Country label beneath
  const label = document.createElement('div')
  label.style.cssText = `
    position:absolute;bottom:0;left:50%;
    transform:translateX(-50%);
    font-family:monospace;
    font-size:5.5px;
    font-weight:bold;
    letter-spacing:0.5px;
    color:${point.color};
    white-space:nowrap;
    text-shadow:0 0 6px ${point.color}99, 0 1px 2px #000;
    pointer-events:none;
  `
  label.textContent = point.actorCountry.toUpperCase()

  wrapper.appendChild(ring2)
  wrapper.appendChild(ring1)
  wrapper.appendChild(diamond)
  wrapper.appendChild(label)

  // Propagate clicks — stopPropagation prevents the globe from capturing the event
  wrapper.addEventListener('click', (e) => { e.stopPropagation(); onClick(point) })
  return wrapper
}

function makeTargetNode(point: TargetPoint, onClick: (a: Attack) => void): HTMLElement {
  const attack = point.attack
  const size  = attack.severity === 'CRITICAL' ? 16 : attack.severity === 'HIGH' ? 11 : 8
  const color = attack.color

  const wrapper = document.createElement('div')
  wrapper.style.cssText = [
    'position:relative',
    'width:36px',
    'height:44px',
    'cursor:pointer',
    'transform:translate(-50%,-50%)',
    'pointer-events:auto',
  ].join(';')

  // Outer ring (CRITICAL gets two)
  if (attack.severity === 'CRITICAL') {
    const ring2 = document.createElement('div')
    ring2.style.cssText = `
      position:absolute;top:16px;left:50%;
      width:${size + 14}px;height:${size + 14}px;
      transform:translate(-50%,-50%);
      border-radius:50%;
      border:1px solid ${color}33;
      animation:threat-pulse 2s ease-out infinite;
      animation-delay:${0.5 + Math.random() * 0.8}s;
    `
    wrapper.appendChild(ring2)
  }

  const ring = document.createElement('div')
  ring.style.cssText = `
    position:absolute;top:16px;left:50%;
    width:${size + 8}px;height:${size + 8}px;
    transform:translate(-50%,-50%);
    border-radius:50%;
    border:1px solid ${color}77;
    animation:threat-pulse 2s ease-out infinite;
    animation-delay:${Math.random() * 1.5}s;
  `

  // Core dot
  const dot = document.createElement('div')
  dot.style.cssText = `
    position:absolute;top:16px;left:50%;
    width:${size}px;height:${size}px;
    transform:translate(-50%,-50%);
    border-radius:50%;
    background:${color};
    box-shadow:0 0 ${size * 1.4}px ${color}, 0 0 ${size * 2.8}px ${color}55;
  `

  // Target city label beneath
  const label = document.createElement('div')
  const shortName = attack.target.split(',')[0]
  label.style.cssText = `
    position:absolute;bottom:0;left:50%;
    transform:translateX(-50%);
    font-family:monospace;
    font-size:5px;
    color:${color}cc;
    white-space:nowrap;
    text-shadow:0 1px 3px #000;
    pointer-events:none;
  `
  label.textContent = shortName.length > 14 ? shortName.slice(0, 13) + '…' : shortName

  wrapper.appendChild(ring)
  wrapper.appendChild(dot)
  wrapper.appendChild(label)

  wrapper.addEventListener('click', (e) => { e.stopPropagation(); onClick(attack) })
  return wrapper
}

// Lazy-load the Globe to avoid SSR issues
const GlobeGL = lazy(() => import('react-globe.gl'))

interface Props {
  news: NewsItem[]
  refreshTrigger: number
}

export function ThreatMap({ news, refreshTrigger }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [size, setSize] = useState({ w: 0, h: 0 })
  const [selected, setSelected] = useState<Selected>(null)
  const [dynamicArcs, setDynamicArcs] = useState<object[]>([])

  // Measure container
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const ro = new ResizeObserver(entries => {
      const { width, height } = entries[0].contentRect
      if (width > 10 && height > 10) setSize({ w: Math.round(width), h: Math.round(height) })
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  // Build dynamic arcs from news feed actor mentions
  useEffect(() => {
    const arcs: object[] = []
    const seen = new Set<string>()
    news.slice(0, 100).forEach(item => {
      item.threat_actors.forEach(actor => {
        const key = actor.toLowerCase()
        const origin = Object.entries(ACTOR_ORIGINS).find(([k]) => key.includes(k))?.[1]
        if (!origin) return
        const target = TARGET_NODES[Math.floor(Math.random() * TARGET_NODES.length)]
        const arcKey = `${origin.lat},${origin.lng}→${target.city}`
        if (seen.has(arcKey)) return
        seen.add(arcKey)
        arcs.push({
          startLat: origin.lat, startLng: origin.lng,
          endLat: target.lat, endLng: target.lng,
          color: ['rgba(255,68,68,0.85)', 'rgba(255,68,68,0.0)'],
          arcAlt: 0.25 + Math.random() * 0.3,
        })
      })
    })
    setDynamicArcs(arcs)
  }, [news, refreshTrigger])

  // Inject keyframe animations once (two separate ones so diamond rotation is preserved)
  useEffect(() => {
    if (document.getElementById('threat-pulse-style')) return
    const style = document.createElement('style')
    style.id = 'threat-pulse-style'
    style.textContent = `
      /* Circle node rings */
      @keyframes threat-pulse {
        0%   { transform: translate(-50%,-50%) scale(1);   opacity: 0.8; }
        100% { transform: translate(-50%,-50%) scale(2.5); opacity: 0;   }
      }
      /* Diamond node rings — keeps rotate(45deg) so halo stays diamond-shaped */
      @keyframes diamond-pulse {
        0%   { transform: translate(-50%,-50%) rotate(45deg) scale(1);   opacity: 0.8; }
        100% { transform: translate(-50%,-50%) rotate(45deg) scale(2.5); opacity: 0;   }
      }
      /* Subtle brightness throb on the diamond core */
      @keyframes diamond-throb {
        0%, 100% { filter: brightness(1); }
        50%       { filter: brightness(1.6) drop-shadow(0 0 4px currentColor); }
      }
    `
    document.head.appendChild(style)
  }, [])

  // Derive unique actor origin nodes
  const actorPoints = useMemo<ActorPoint[]>(() => {
    const map = new Map<string, ActorPoint>()
    for (const attack of ATTACKS) {
      if (!map.has(attack.actor)) {
        map.set(attack.actor, {
          nodeType: 'actor',
          actor: attack.actor,
          actorCountry: attack.actorCountry,
          lat: attack.lat,
          lng: attack.lng,
          color: ACTOR_COUNTRY_COLOR[attack.actorCountry] ?? '#aaaaaa',
          attacks: [],
        })
      }
      map.get(attack.actor)!.attacks.push(attack)
    }
    return Array.from(map.values())
  }, [])

  // One target node per attack at target coordinates
  const targetPoints = useMemo<TargetPoint[]>(() =>
    ATTACKS.map(a => ({ nodeType: 'target' as const, attack: a, lat: a.targetLat, lng: a.targetLng })),
  [])

  const allPoints = useMemo<MapPoint[]>(() => [...actorPoints, ...targetPoints], [actorPoints, targetPoints])

  const handleActorClick = useCallback((p: ActorPoint) => setSelected({ kind: 'actor', data: p }), [])
  const handleAttackClick = useCallback((a: Attack) => setSelected({ kind: 'attack', data: a }), [])

  // Build static attack arcs
  const staticArcs = ATTACKS.map(a => ({
    startLat: a.lat, startLng: a.lng,
    endLat: a.targetLat, endLng: a.targetLng,
    color: [a.color + 'cc', a.color + '00'],
    arcAlt: 0.2 + (a.severity === 'CRITICAL' ? 0.25 : 0.12),
  }))

  const allArcs = [...staticArcs, ...dynamicArcs]

  // Selected data helpers
  const selActor  = selected?.kind === 'actor'  ? selected.data : null
  const selAttack = selected?.kind === 'attack' ? selected.data : null

  return (
    <div className="panel flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <Globe size={11} className="text-[var(--color-primary)]" />
          <span className="panel-title">GLOBAL THREAT MAP</span>
          <span className="live-dot" />
          <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-wider">
            {ATTACKS.length} ATTACKS · {actorPoints.length} ACTORS
          </span>
        </div>
        <span className="font-mono text-[0.44rem] text-[var(--text-ghost)] tracking-widest">
          DIAMOND=ORIGIN · CIRCLE=TARGET
        </span>
      </div>

      {/* Globe + detail panel */}
      <div className="flex-1 relative overflow-hidden min-h-0 flex">
        {/* Globe */}
        <div ref={containerRef} className="flex-1 bg-[#030609] min-h-0">
          {size.w > 10 && (
            <Suspense fallback={
              <div className="w-full h-full flex items-center justify-center">
                <span className="font-mono text-[0.55rem] text-[var(--text-ghost)] tracking-widest animate-pulse">
                  LOADING GLOBE...
                </span>
              </div>
            }>
              <GlobeGL
                width={size.w}
                height={size.h}
                globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
                backgroundImageUrl="//unpkg.com/three-globe/example/img/night-sky.png"
                atmosphereColor="#00d4ff"
                atmosphereAltitude={0.25}
                htmlElementsData={allPoints}
                htmlLat={(d: object) => (d as MapPoint).lat}
                htmlLng={(d: object) => (d as MapPoint).lng}
                htmlAltitude={(d: object) => {
                  const pt = d as MapPoint
                  if (pt.nodeType === 'actor') return 0.02
                  const sev = pt.attack.severity
                  return sev === 'CRITICAL' ? 0.03 : 0.015
                }}
                htmlElement={(d: object) => {
                  const pt = d as MapPoint
                  if (pt.nodeType === 'actor') return makeActorNode(pt, handleActorClick)
                  return makeTargetNode(pt, handleAttackClick)
                }}
                ringsData={TARGET_NODES}
                ringLat="lat"
                ringLng="lng"
                ringColor={() => 'rgba(0, 212, 255, 0.5)'}
                ringMaxRadius={3}
                ringPropagationSpeed={1.5}
                ringRepeatPeriod={600}
                arcsData={allArcs}
                arcStartLat="startLat"
                arcStartLng="startLng"
                arcEndLat="endLat"
                arcEndLng="endLng"
                arcColor="color"
                arcAltitude="arcAlt"
                arcStroke={1.2}
                arcDashLength={0.6}
                arcDashGap={0.15}
                arcDashAnimateTime={1400}
              />
            </Suspense>
          )}
        </div>

        {/* Actor detail panel */}
        {selActor && (
          <div
            className="absolute right-0 top-0 h-full w-64 bg-[var(--bg-surface)]/95 backdrop-blur-sm border-l border-[var(--border-base)] flex flex-col overflow-hidden"
            style={{ borderLeft: `2px solid ${selActor.color}44` }}
          >
            <div
              className="flex items-center justify-between px-3 py-2 border-b border-[var(--border-base)] shrink-0"
              style={{ background: `${selActor.color}12` }}
            >
              <div className="flex items-center gap-2">
                <div
                  className="w-2.5 h-2.5 shrink-0"
                  style={{
                    background: selActor.color,
                    transform: 'rotate(45deg)',
                    boxShadow: `0 0 6px ${selActor.color}`,
                  }}
                />
                <span
                  className="font-mono text-[0.5rem] tracking-widest font-semibold truncate"
                  style={{ color: selActor.color }}
                >
                  THREAT ACTOR
                </span>
              </div>
              <button
                onClick={() => setSelected(null)}
                className="text-[var(--text-ghost)] hover:text-[var(--text-base)] transition-colors shrink-0"
              >
                <X size={12} />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-3 space-y-3">
              <div className="space-y-0.5">
                <div className="font-mono text-[0.65rem] font-bold text-[var(--text-base)]">
                  {selActor.actor}
                </div>
                <div className="flex items-center gap-1">
                  <MapPin size={8} className="text-[var(--text-ghost)]" />
                  <span className="font-mono text-[0.5rem] text-[var(--text-dim)]">{selActor.actorCountry}</span>
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="font-mono text-[0.42rem] text-[var(--text-ghost)] tracking-widest">
                  DOCUMENTED ATTACKS ({selActor.attacks.length})
                </div>
                {selActor.attacks.map(a => (
                  <button
                    key={a.id}
                    className="w-full text-left p-2 border transition-colors hover:bg-[rgba(255,255,255,0.03)]"
                    style={{ borderColor: `${a.color}33`, background: `${a.color}08` }}
                    onClick={() => setSelected({ kind: 'attack', data: a })}
                  >
                    <div className="flex items-center gap-1.5 mb-0.5">
                      <span
                        className="font-mono text-[0.38rem] tracking-widest px-1 border"
                        style={{ color: a.color, borderColor: `${a.color}55` }}
                      >
                        {a.severity}
                      </span>
                      <span className="font-mono text-[0.4rem] text-[var(--text-ghost)]">{a.date}</span>
                    </div>
                    <div className="font-mono text-[0.5rem] text-[var(--text-base)] leading-tight">{a.target}</div>
                  </button>
                ))}
              </div>
            </div>

            <div className="px-3 py-2 border-t border-[var(--border-base)] shrink-0">
              <div className="flex items-center gap-1.5">
                <Shield size={8} className="text-[var(--text-ghost)]" />
                <span className="font-mono text-[0.42rem] text-[var(--text-ghost)] tracking-widest">
                  CLICK ATTACK TO SEE DETAILS
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Attack detail panel */}
        {selAttack && (
          <div
            className="absolute right-0 top-0 h-full w-64 bg-[var(--bg-surface)]/95 backdrop-blur-sm border-l border-[var(--border-base)] flex flex-col overflow-hidden"
            style={{ borderLeft: `2px solid ${selAttack.color}44` }}
          >
            <div
              className="flex items-center justify-between px-3 py-2 border-b border-[var(--border-base)] shrink-0"
              style={{ background: `${selAttack.color}12` }}
            >
              <div className="flex items-center gap-2">
                <div
                  className="w-2 h-2 rounded-full shrink-0"
                  style={{ background: selAttack.color, boxShadow: `0 0 6px ${selAttack.color}` }}
                />
                <span
                  className="font-mono text-[0.5rem] tracking-widest font-semibold truncate"
                  style={{ color: selAttack.color }}
                >
                  {selAttack.label.toUpperCase()}
                </span>
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <button
                  onClick={() => setSelected({ kind: 'actor', data: actorPoints.find(p => p.actor === selAttack.actor)! })}
                  className="text-[var(--text-ghost)] hover:text-[var(--text-base)] transition-colors"
                  title="Back to actor"
                >
                  <Shield size={10} />
                </button>
                <button
                  onClick={() => setSelected(null)}
                  className="text-[var(--text-ghost)] hover:text-[var(--text-base)] transition-colors"
                >
                  <X size={12} />
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-3 space-y-3">
              <div className="flex items-center gap-2">
                <span
                  className="font-mono text-[0.42rem] tracking-widest px-1.5 py-0.5 border"
                  style={{ color: selAttack.color, borderColor: `${selAttack.color}55`, background: `${selAttack.color}10` }}
                >
                  {selAttack.severity}
                </span>
                <span className="font-mono text-[0.42rem] tracking-widest text-[var(--text-dim)] uppercase">
                  {selAttack.type.replace('-', ' ')}
                </span>
              </div>

              <div className="space-y-0.5">
                <div className="font-mono text-[0.42rem] text-[var(--text-ghost)] tracking-widest">THREAT ACTOR</div>
                <div className="font-mono text-[0.58rem] text-[var(--text-base)]">{selAttack.actor}</div>
                <div className="flex items-center gap-1">
                  <MapPin size={8} className="text-[var(--text-ghost)]" />
                  <span className="font-mono text-[0.5rem] text-[var(--text-dim)]">{selAttack.actorCountry}</span>
                </div>
              </div>

              <div className="space-y-0.5">
                <div className="font-mono text-[0.42rem] text-[var(--text-ghost)] tracking-widest">TARGET</div>
                <div className="flex items-center gap-1">
                  <Crosshair size={8} className="text-[var(--text-ghost)]" />
                  <span className="font-mono text-[0.55rem] text-[var(--text-base)]">{selAttack.target}</span>
                </div>
              </div>

              <div className="flex items-center gap-1.5">
                <Clock size={8} className="text-[var(--text-ghost)]" />
                <span className="font-mono text-[0.5rem] text-[var(--text-dim)]">{selAttack.date}</span>
              </div>

              <div className="space-y-1">
                <div className="font-mono text-[0.42rem] text-[var(--text-ghost)] tracking-widest">DETAILS</div>
                <p className="text-[0.62rem] text-[var(--text-secondary)] leading-relaxed">
                  {selAttack.description}
                </p>
              </div>
            </div>

            <div className="px-3 py-2 border-t border-[var(--border-base)] shrink-0">
              <div className="flex items-center gap-1.5">
                <Shield size={8} className="text-[var(--text-ghost)]" />
                <span className="font-mono text-[0.42rem] text-[var(--text-ghost)] tracking-widest">
                  DOCUMENTED INCIDENT · SIGINTX
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Legend overlay */}
        {!selected && (
          <div className="absolute bottom-3 left-3 pointer-events-none space-y-2">
            <div className="bg-[var(--bg-surface)]/80 backdrop-blur-sm border border-[var(--border-base)] px-2.5 py-2 space-y-1">
              <div className="font-mono text-[0.38rem] text-[var(--text-ghost)] tracking-widest mb-1">ATTACK TYPE</div>
              {Object.entries(TYPE_COLOR).map(([type, color]) => (
                <div key={type} className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full shrink-0" style={{ background: color }} />
                  <span className="font-mono text-[0.42rem] text-[var(--text-dim)] uppercase tracking-wider">
                    {type.replace('-', ' ')}
                  </span>
                </div>
              ))}
            </div>
            <div className="bg-[var(--bg-surface)]/80 backdrop-blur-sm border border-[var(--border-base)] px-2.5 py-2 space-y-1">
              <div className="font-mono text-[0.38rem] text-[var(--text-ghost)] tracking-widest mb-1">NODE TYPE</div>
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 shrink-0" style={{ background: '#ff4444', transform: 'rotate(45deg)' }} />
                <span className="font-mono text-[0.42rem] text-[var(--text-dim)] tracking-wider">ACTOR ORIGIN</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: '#00d4ff' }} />
                <span className="font-mono text-[0.42rem] text-[var(--text-dim)] tracking-wider">ATTACK TARGET</span>
              </div>
            </div>
          </div>
        )}

        {/* Live indicator */}
        {dynamicArcs.length > 0 && (
          <div className="absolute top-3 right-3 pointer-events-none flex items-center gap-1.5 bg-[var(--bg-surface)]/80 backdrop-blur-sm border border-[var(--border-base)] px-2 py-1">
            <AlertTriangle size={9} className="text-[var(--color-warning)]" />
            <span className="font-mono text-[0.44rem] text-[var(--color-warning)] tracking-widest">
              {dynamicArcs.length} LIVE VECTORS
            </span>
          </div>
        )}
      </div>
    </div>
  )
}
