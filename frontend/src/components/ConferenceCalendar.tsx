import { useState } from 'react'
import { motion } from 'framer-motion'
import { Calendar, MapPin, ExternalLink, Globe2, Search } from 'lucide-react'

interface Conference {
  name: string
  abbr?: string
  dates: string
  location: string
  country: string
  category: 'security' | 'tech' | 'crypto' | 'ai'
  url: string
  description: string
}

const CONFERENCES: Conference[] = [
  // ── Security ──────────────────────────────────────────────────────────────
  {
    name: 'RSA Conference',
    abbr: 'RSAC',
    dates: 'Apr 28 – May 1, 2025',
    location: 'San Francisco, CA',
    country: 'USA',
    category: 'security',
    url: 'https://www.rsaconference.com',
    description: 'Largest cybersecurity conference globally — enterprise security, threat intel, vendor showcase.',
  },
  {
    name: 'Black Hat USA',
    abbr: 'BH USA',
    dates: 'Aug 2–7, 2025',
    location: 'Las Vegas, NV',
    country: 'USA',
    category: 'security',
    url: 'https://www.blackhat.com/us-25/',
    description: 'Premier technical security conference — cutting-edge research, briefings, and trainings.',
  },
  {
    name: 'DEF CON 33',
    abbr: 'DEF CON',
    dates: 'Aug 7–10, 2025',
    location: 'Las Vegas, NV',
    country: 'USA',
    category: 'security',
    url: 'https://defcon.org',
    description: 'Iconic hacker convention — CTFs, villages, social engineering, hardware hacking.',
  },
  {
    name: 'CyberWarCon',
    dates: 'Nov 2025',
    location: 'Arlington, VA',
    country: 'USA',
    category: 'security',
    url: 'https://cyberwarcon.com',
    description: 'Nation-state cyber operations, threat actor research, geopolitical cyber analysis.',
  },
  {
    name: 'SANS ICS Security Summit',
    dates: 'Feb 2026',
    location: 'Orlando, FL',
    country: 'USA',
    category: 'security',
    url: 'https://www.sans.org/cyber-security-training-events/',
    description: 'Industrial control systems and OT/ICS security focus.',
  },
  {
    name: 'S4 Conference',
    dates: 'Jan 13–16, 2026',
    location: 'Tampa, FL',
    country: 'USA',
    category: 'security',
    url: 'https://s4xevents.com',
    description: 'ICS/SCADA security — critical infrastructure protection.',
  },
  {
    name: 'ShmooCon',
    dates: 'Jan 2026',
    location: 'Washington, D.C.',
    country: 'USA',
    category: 'security',
    url: 'https://www.shmoocon.org',
    description: 'Annual hacker convention on the east coast — research, community, workshops.',
  },
  {
    name: 'Hack In The Box (HITB)',
    abbr: 'HITB',
    dates: 'May 2026',
    location: 'Amsterdam',
    country: 'Netherlands',
    category: 'security',
    url: 'https://conference.hitb.org',
    description: 'Deep-knowledge security research — cryptography, reverse engineering, exploitation.',
  },
  {
    name: 'Black Hat Europe',
    abbr: 'BH EU',
    dates: 'Dec 9–12, 2025',
    location: 'London',
    country: 'UK',
    category: 'security',
    url: 'https://www.blackhat.com/eu-25/',
    description: 'European edition of Black Hat — technical briefings, Arsenal tool demos.',
  },
  {
    name: 'Troopers',
    dates: 'Mar 2026',
    location: 'Heidelberg',
    country: 'Germany',
    category: 'security',
    url: 'https://troopers.de',
    description: 'Deep technical security research — networking, enterprise attacks, adversary simulation.',
  },
  {
    name: 'OffensiveCon',
    dates: 'Feb 2026',
    location: 'Berlin',
    country: 'Germany',
    category: 'security',
    url: 'https://www.offensivecon.org',
    description: 'Exploit development, vulnerability research, offensive security techniques.',
  },
  {
    name: 'BSides Las Vegas',
    abbr: 'BSidesLV',
    dates: 'Aug 5–6, 2025',
    location: 'Las Vegas, NV',
    country: 'USA',
    category: 'security',
    url: 'https://www.bsideslv.org',
    description: 'Community-driven security conference co-located with DEF CON and Black Hat.',
  },
  {
    name: 'Nullcon',
    dates: 'Mar 2026',
    location: 'Goa',
    country: 'India',
    category: 'security',
    url: 'https://nullcon.net',
    description: 'Security research, vulnerability disclosure, appsec — Asia-Pacific focus.',
  },
  {
    name: 'Hardwear.io',
    dates: 'Oct 2025',
    location: 'The Hague',
    country: 'Netherlands',
    category: 'security',
    url: 'https://hardwear.io',
    description: 'Hardware security — embedded systems, IoT, firmware analysis, side-channel attacks.',
  },
  // ── Tech ──────────────────────────────────────────────────────────────────
  {
    name: 'Google I/O',
    dates: 'May 2026',
    location: 'Mountain View, CA',
    country: 'USA',
    category: 'tech',
    url: 'https://io.google',
    description: "Google's annual developer conference — AI, Android, cloud, web platform.",
  },
  {
    name: 'Apple WWDC',
    abbr: 'WWDC',
    dates: 'Jun 2026',
    location: 'Cupertino, CA',
    country: 'USA',
    category: 'tech',
    url: 'https://developer.apple.com/wwdc/',
    description: "Apple's Worldwide Developers Conference — iOS, macOS, visionOS announcements.",
  },
  {
    name: 'Microsoft Build',
    dates: 'May 2026',
    location: 'Seattle, WA',
    country: 'USA',
    category: 'tech',
    url: 'https://build.microsoft.com',
    description: 'Microsoft developer conference — Azure, AI, Windows, developer tools.',
  },
  {
    name: 'AWS re:Invent',
    abbr: 're:Invent',
    dates: 'Dec 1–5, 2025',
    location: 'Las Vegas, NV',
    country: 'USA',
    category: 'tech',
    url: 'https://reinvent.awsevents.com',
    description: "Amazon's cloud computing conference — AWS services, security, infrastructure.",
  },
  {
    name: 'CES',
    dates: 'Jan 6–9, 2026',
    location: 'Las Vegas, NV',
    country: 'USA',
    category: 'tech',
    url: 'https://www.ces.tech',
    description: "World's largest consumer electronics show — hardware, smart home, vehicles, AI gadgets.",
  },
  {
    name: 'Mobile World Congress',
    abbr: 'MWC',
    dates: 'Mar 2–5, 2026',
    location: 'Barcelona',
    country: 'Spain',
    category: 'tech',
    url: 'https://www.mwcbarcelona.com',
    description: 'Global mobile industry — 5G/6G, telecom security, connected devices.',
  },
  {
    name: 'KubeCon + CloudNativeCon',
    abbr: 'KubeCon',
    dates: 'Nov 10–13, 2025',
    location: 'Atlanta, GA',
    country: 'USA',
    category: 'tech',
    url: 'https://events.linuxfoundation.org/kubecon-cloudnativecon-north-america/',
    description: 'Kubernetes, cloud-native security, container security, DevSecOps.',
  },
  {
    name: 'GitHub Universe',
    dates: 'Oct 2025',
    location: 'San Francisco, CA',
    country: 'USA',
    category: 'tech',
    url: 'https://githubuniverse.com',
    description: 'GitHub platform, DevOps, developer AI tools, open-source security.',
  },
  {
    name: 'Web Summit',
    dates: 'Nov 10–13, 2025',
    location: 'Lisbon',
    country: 'Portugal',
    category: 'tech',
    url: 'https://websummit.com',
    description: "One of Europe's largest tech conferences — startups, enterprise, geopolitics of tech.",
  },
  // ── Crypto ────────────────────────────────────────────────────────────────
  {
    name: 'Consensus',
    dates: 'May 14–16, 2026',
    location: 'Austin, TX',
    country: 'USA',
    category: 'crypto',
    url: 'https://consensus2025.coindesk.com',
    description: "CoinDesk's flagship crypto & blockchain conference — DeFi, regulation, institutional adoption.",
  },
  {
    name: 'ETHDenver',
    abbr: 'ETHDenver',
    dates: 'Feb–Mar 2026',
    location: 'Denver, CO',
    country: 'USA',
    category: 'crypto',
    url: 'https://www.ethdenver.com',
    description: "World's largest Ethereum hackathon and conference — DeFi, Web3, smart contract security.",
  },
  {
    name: 'Token2049',
    dates: 'Sep 2026',
    location: 'Singapore',
    country: 'Singapore',
    category: 'crypto',
    url: 'https://www.token2049.com',
    description: 'Asia-Pacific crypto conference — institutional investors, Web3, blockchain protocols.',
  },
  {
    name: 'Bitcoin Amsterdam',
    dates: 'Oct 2025',
    location: 'Amsterdam',
    country: 'Netherlands',
    category: 'crypto',
    url: 'https://b.tc/conference',
    description: 'Bitcoin-focused conference — Lightning Network, layer-2, self-custody, privacy.',
  },
  {
    name: 'Permissionless',
    dates: 'Sep 2025',
    location: 'Salt Lake City, UT',
    country: 'USA',
    category: 'crypto',
    url: 'https://blockworks.co/event/permissionless',
    description: 'DeFi-native conference — protocols, on-chain finance, crypto infrastructure.',
  },
  {
    name: 'DevCon',
    dates: 'Nov 2025',
    location: 'Bangkok',
    country: 'Thailand',
    category: 'crypto',
    url: 'https://devcon.org',
    description: "Ethereum Foundation's developer conference — protocol R&D, smart contract security, ZK.",
  },
  // ── AI ────────────────────────────────────────────────────────────────────
  {
    name: 'NeurIPS',
    dates: 'Dec 2025',
    location: 'Vancouver',
    country: 'Canada',
    category: 'ai',
    url: 'https://neurips.cc',
    description: 'Neural Information Processing Systems — foundational AI/ML research, adversarial ML.',
  },
  {
    name: 'ICML',
    dates: 'Jul 2026',
    location: 'TBD',
    country: 'International',
    category: 'ai',
    url: 'https://icml.cc',
    description: 'International Conference on Machine Learning — adversarial robustness, AI safety.',
  },
  {
    name: 'AI Summit',
    dates: 'Jun 2026',
    location: 'New York, NY',
    country: 'USA',
    category: 'ai',
    url: 'https://theaisummit.com',
    description: 'Enterprise AI deployment — AI governance, risk, and cybersecurity applications.',
  },
]

const CATEGORY_CONFIG: Record<string, { label: string; color: string }> = {
  security: { label: 'SECURITY', color: '#ff4444' },
  tech:     { label: 'TECH',     color: '#00d4ff' },
  crypto:   { label: 'CRYPTO',   color: '#f7931a' },
  ai:       { label: 'AI',       color: '#a855f7' },
}

type FilterCat = 'all' | 'security' | 'tech' | 'crypto' | 'ai'

export function ConferenceCalendar() {
  const [activeFilter, setActiveFilter] = useState<FilterCat>('all')
  const [search, setSearch] = useState('')

  const filtered = CONFERENCES.filter(c => {
    if (activeFilter !== 'all' && c.category !== activeFilter) return false
    if (search) {
      const q = search.toLowerCase()
      return (
        c.name.toLowerCase().includes(q) ||
        c.location.toLowerCase().includes(q) ||
        c.country.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q)
      )
    }
    return true
  })

  return (
    <div className="panel flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <Calendar size={11} className="text-[var(--color-primary)]" />
          <span className="panel-title">CONFERENCE CALENDAR</span>
          <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-wider">
            {filtered.length} EVENTS
          </span>
        </div>
      </div>

      {/* Filters */}
      <div className="px-3 py-2 border-b border-[var(--border-base)] shrink-0 flex flex-col gap-2">
        {/* Category tabs */}
        <div className="flex gap-1 overflow-x-auto scrollbar-none">
          {(['all', 'security', 'tech', 'crypto', 'ai'] as FilterCat[]).map(cat => {
            const cfg   = cat === 'all' ? null : CATEGORY_CONFIG[cat]
            const color = cfg?.color ?? 'var(--color-primary)'
            const isActive = activeFilter === cat
            const count = cat === 'all'
              ? CONFERENCES.length
              : CONFERENCES.filter(c => c.category === cat).length
            return (
              <button
                key={cat}
                onClick={() => setActiveFilter(cat)}
                className="relative px-2.5 py-1 font-mono text-[0.5rem] tracking-widest shrink-0 transition-colors"
                style={{
                  color:      isActive ? color : 'var(--text-dim)',
                  background: isActive ? `${color}10` : 'transparent',
                  border:     `1px solid ${isActive ? color : 'var(--border-base)'}`,
                }}
              >
                {cat === 'all' ? 'ALL' : CATEGORY_CONFIG[cat].label}
                <span className="ml-1 opacity-60">({count})</span>
              </button>
            )
          })}
        </div>
        {/* Search */}
        <div className="relative">
          <Search size={9} className="absolute left-2 top-1/2 -translate-y-1/2 text-[var(--text-ghost)]" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search conferences..."
            className="w-full bg-[var(--bg-elevated)] border border-[var(--border-base)] pl-6 pr-3 py-1 font-mono text-[0.58rem] text-[var(--text-base)] placeholder:text-[var(--text-ghost)] focus:outline-none focus:border-[var(--color-primary)] transition-colors"
          />
        </div>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 && (
          <div className="flex items-center justify-center h-24">
            <span className="font-mono text-[0.55rem] text-[var(--text-ghost)] tracking-widest">
              NO CONFERENCES FOUND
            </span>
          </div>
        )}

        {activeFilter === 'all' && !search ? (
          // Grouped view: section headers per category
          (['security', 'tech', 'crypto', 'ai'] as Exclude<FilterCat, 'all'>[]).map(cat => {
            const group = filtered.filter(c => c.category === cat)
            if (group.length === 0) return null
            const cfg = CATEGORY_CONFIG[cat]
            return (
              <div key={cat}>
                {/* Section header */}
                <div className="px-3 py-1.5 bg-[var(--bg-elevated)] border-b border-[var(--border-base)] sticky top-0 z-10 flex items-center gap-2">
                  <div className="w-1.5 h-1.5 rounded-full" style={{ background: cfg.color }} />
                  <span className="font-mono text-[0.48rem] tracking-widest" style={{ color: cfg.color }}>
                    {cfg.label}
                  </span>
                  <span className="font-mono text-[0.42rem] text-[var(--text-ghost)]">
                    {group.length} EVENTS
                  </span>
                </div>
                {/* Items in this category */}
                <div className="divide-y divide-[var(--border-base)]">
                  {group.map((conf, i) => {
                    const ccfg = CATEGORY_CONFIG[conf.category]
                    return (
                      <motion.div
                        key={conf.name}
                        initial={{ opacity: 0, x: -8 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.03, duration: 0.2 }}
                        className="px-3 py-2.5 hover:bg-[var(--bg-elevated)] transition-colors group"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                              <span className="font-mono text-[0.65rem] font-semibold text-[var(--text-base)] truncate">
                                {conf.name}
                                {conf.abbr && (
                                  <span className="ml-1 text-[var(--text-dim)]">({conf.abbr})</span>
                                )}
                              </span>
                            </div>
                            <div className="flex items-center gap-3 mb-1">
                              <div className="flex items-center gap-1">
                                <Calendar size={8} className="text-[var(--text-ghost)]" />
                                <span className="font-mono text-[0.52rem] text-[var(--text-dim)]">
                                  {conf.dates}
                                </span>
                              </div>
                              <div className="flex items-center gap-1">
                                <MapPin size={8} className="text-[var(--text-ghost)]" />
                                <span className="font-mono text-[0.52rem] text-[var(--text-dim)]">
                                  {conf.location}, {conf.country}
                                </span>
                              </div>
                            </div>
                            <p className="text-[0.62rem] text-[var(--text-secondary)] leading-snug">
                              {conf.description}
                            </p>
                          </div>
                          <a
                            href={conf.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="shrink-0 text-[var(--text-ghost)] hover:text-[var(--color-primary)] transition-colors mt-0.5"
                            title={`Visit ${conf.name}`}
                          >
                            <ExternalLink size={11} />
                          </a>
                        </div>
                      </motion.div>
                    )
                  })}
                </div>
              </div>
            )
          })
        ) : (
          // Flat list: single category filter OR search active
          <div className="divide-y divide-[var(--border-base)]">
            {filtered.map((conf, i) => {
              const cfg = CATEGORY_CONFIG[conf.category]
              return (
                <motion.div
                  key={conf.name}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.03, duration: 0.2 }}
                  className="px-3 py-2.5 hover:bg-[var(--bg-elevated)] transition-colors group"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      {/* Name + badge */}
                      <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                        <span className="font-mono text-[0.65rem] font-semibold text-[var(--text-base)] truncate">
                          {conf.name}
                          {conf.abbr && (
                            <span className="ml-1 text-[var(--text-dim)]">({conf.abbr})</span>
                          )}
                        </span>
                        <span
                          className="font-mono text-[0.42rem] tracking-widest px-1.5 py-0.5 shrink-0"
                          style={{
                            color:      cfg.color,
                            border:     `1px solid ${cfg.color}55`,
                            background: `${cfg.color}10`,
                          }}
                        >
                          {cfg.label}
                        </span>
                      </div>

                      {/* Date + location */}
                      <div className="flex items-center gap-3 mb-1">
                        <div className="flex items-center gap-1">
                          <Calendar size={8} className="text-[var(--text-ghost)]" />
                          <span className="font-mono text-[0.52rem] text-[var(--text-dim)]">
                            {conf.dates}
                          </span>
                        </div>
                        <div className="flex items-center gap-1">
                          <MapPin size={8} className="text-[var(--text-ghost)]" />
                          <span className="font-mono text-[0.52rem] text-[var(--text-dim)]">
                            {conf.location}, {conf.country}
                          </span>
                        </div>
                      </div>

                      {/* Description */}
                      <p className="text-[0.62rem] text-[var(--text-secondary)] leading-snug">
                        {conf.description}
                      </p>
                    </div>

                    {/* Link */}
                    <a
                      href={conf.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="shrink-0 text-[var(--text-ghost)] hover:text-[var(--color-primary)] transition-colors mt-0.5"
                      title={`Visit ${conf.name}`}
                    >
                      <ExternalLink size={11} />
                    </a>
                  </div>
                </motion.div>
              )
            })}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="px-3 py-1.5 border-t border-[var(--border-base)] shrink-0 flex items-center gap-2">
        <Globe2 size={9} className="text-[var(--text-ghost)]" />
        <span className="font-mono text-[0.44rem] text-[var(--text-ghost)] tracking-widest">
          {CONFERENCES.length} GLOBAL CONFERENCES · STATIC CALENDAR · DATES UPDATED QUARTERLY
        </span>
      </div>
    </div>
  )
}
