import { useEffect, useRef, useState, useCallback, lazy, Suspense, useMemo } from 'react'
import { Globe, X, Clock, ExternalLink, Shield, AlertTriangle, MapPin, Tag } from 'lucide-react'
import type { NewsItem, NewsCategory } from '@/types'

// ── Country coordinates ───────────────────────────────────────────────────────

const COUNTRY_COORDS: Record<string, { lat: number; lng: number }> = {
  'Russia':        { lat: 55.75,  lng: 37.62  },
  'China':         { lat: 39.91,  lng: 116.39 },
  'North Korea':   { lat: 39.02,  lng: 125.75 },
  'Iran':          { lat: 35.69,  lng: 51.39  },
  'USA':           { lat: 38.90,  lng: -77.04 },
  'UK':            { lat: 51.51,  lng: -0.13  },
  'Germany':       { lat: 52.52,  lng: 13.41  },
  'France':        { lat: 48.86,  lng: 2.35   },
  'Ukraine':       { lat: 50.45,  lng: 30.52  },
  'Israel':        { lat: 31.77,  lng: 35.22  },
  'India':         { lat: 28.61,  lng: 77.21  },
  'Japan':         { lat: 35.68,  lng: 139.69 },
  'Australia':     { lat: -33.87, lng: 151.21 },
  'Brazil':        { lat: -15.78, lng: -47.93 },
  'Canada':        { lat: 45.42,  lng: -75.69 },
  'Singapore':     { lat: 1.35,   lng: 103.82 },
  'Netherlands':   { lat: 52.37,  lng: 4.90   },
  'Taiwan':        { lat: 25.03,  lng: 121.56 },
  'South Korea':   { lat: 37.57,  lng: 126.98 },
  'Pakistan':      { lat: 33.72,  lng: 73.06  },
  'Switzerland':   { lat: 46.95,  lng: 7.45   },
  'Sweden':        { lat: 59.33,  lng: 18.07  },
  'Poland':        { lat: 52.23,  lng: 21.01  },
  'Europe':        { lat: 50.11,  lng: 8.68   },
  'Middle East':   { lat: 29.00,  lng: 45.00  },
  'Africa':        { lat: -1.29,  lng: 36.82  },
  'Southeast Asia':{ lat: 13.75,  lng: 100.50 },
}

// Several "global" anchor points so "Global" items spread across the world map
const GLOBAL_ANCHORS: { lat: number; lng: number }[] = [
  { lat: 40.71,  lng: -74.01 },  // New York
  { lat: 51.51,  lng: -0.13  },  // London
  { lat: 48.86,  lng: 2.35   },  // Paris
  { lat: 35.68,  lng: 139.69 },  // Tokyo
  { lat: -33.87, lng: 151.21 },  // Sydney
  { lat: 1.35,   lng: 103.82 },  // Singapore
  { lat: 28.61,  lng: 77.21  },  // New Delhi
  { lat: -23.55, lng: -46.63 },  // São Paulo
]

// ── Actor → country (primary geo signal) ─────────────────────────────────────

const ACTOR_COUNTRY: [string, string][] = [
  ['apt28',            'Russia'], ['apt29',        'Russia'], ['sandworm',     'Russia'],
  ['midnight blizzard','Russia'], ['cozy bear',    'Russia'], ['fancy bear',   'Russia'],
  ['gamaredon',        'Russia'], ['turla',        'Russia'], ['lockbit',      'Russia'],
  ['blackcat',         'Russia'], ['alphv',        'Russia'], ['cl0p',         'Russia'],
  ['noname057',        'Russia'], ['killnet',      'Russia'], ['blacksuit',    'Russia'],
  ['akira',            'Russia'], ['qilin',        'Russia'], ['hunters international','Russia'],
  ['apt41',            'China'],  ['volt typhoon', 'China'],  ['salt typhoon', 'China'],
  ['silk typhoon',     'China'],  ['mustang panda','China'],  ['hafnium',      'China'],
  ['lazarus',          'North Korea'], ['kimsuky', 'North Korea'], ['apt38',   'North Korea'],
  ['bluenoroff',       'North Korea'], ['tradertraitor','North Korea'],
  ['charming kitten',  'Iran'],   ['apt42',        'Iran'],   ['muddywater',   'Iran'],
  ['apt34',            'Iran'],   ['oilrig',       'Iran'],   ['phosphorus',   'Iran'],
  ['scattered spider', 'USA'],    ['shinyHunters', 'USA'],
  ['sidewind',         'India'],
  ['transparent tribe','Pakistan'],
]

// ── Keyword → country fallback ────────────────────────────────────────────────

const COUNTRY_KEYWORDS: [string, string[]][] = [
  ['Russia',       ['russia', 'russian', 'kremlin', 'moscow', 'fsb', 'gru', 'svr']],
  ['China',        ['china', 'chinese', 'beijing', 'prc', 'pla', 'mss', 'alibaba', 'huawei', 'tiktok', 'bytedance']],
  ['North Korea',  ['north korea', 'dprk', 'pyongyang']],
  ['Iran',         ['iran', 'iranian', 'tehran', 'irgc', 'mois']],
  ['USA',          ['united states', ' u.s.', ' usa ', 'american', 'washington', 'pentagon', 'nsa', 'cisa', 'fbi',
                    'white house', 'congress', 'senate', 'federal reserve', 'sec ', 'nasdaq', 'silicon valley']],
  ['UK',           ['united kingdom', ' uk ', 'british', 'london', 'ncsc', 'gchq', 'boe ', 'ftse']],
  ['Germany',      ['german', 'germany', 'berlin', 'bundesbank', 'bsi ', 'dax ']],
  ['France',       ['france', 'french', 'paris', 'anssi', 'cac40']],
  ['Ukraine',      ['ukraine', 'ukrainian', 'kyiv', 'zelenskyy']],
  ['Israel',       ['israel', 'israeli', 'mossad', 'tel aviv', 'idf']],
  ['Taiwan',       ['taiwan', 'taipei', 'tsmc', 'foxconn']],
  ['India',        ['india', 'indian', 'new delhi', 'cert-in', 'rbi ', 'bse ']],
  ['Japan',        ['japan', 'japanese', 'tokyo', 'softbank', 'ntt ', 'sony', 'toyota']],
  ['Australia',    ['australia', 'australian', 'sydney', 'asd ', 'canberra']],
  ['Canada',       ['canada', 'canadian', 'ottawa', 'toronto']],
  ['Singapore',    ['singapore', 'mas ', 'sgx']],
  ['Switzerland',  ['switzerland', 'swiss', 'zurich', 'bern', 'davos']],
  ['Europe',       ['european union', 'eu parliament', 'nato', 'brussels', 'ecb ', 'eurozone']],
  ['Middle East',  ['saudi arabia', 'uae', 'dubai', 'abu dhabi', 'qatar', 'riyadh']],
  ['Southeast Asia',['indonesia', 'malaysia', 'thailand', 'vietnam', 'philippines']],
]

function detectCountry(item: NewsItem): string {
  // 1. Threat actors — most precise signal
  for (const actor of item.threat_actors) {
    const lower = actor.toLowerCase()
    for (const [key, country] of ACTOR_COUNTRY) {
      if (lower.includes(key)) return country
    }
  }
  // 2. Title + tags keyword scan
  const text = `${item.title} ${item.tags.join(' ')}`.toLowerCase()
  for (const [country, kws] of COUNTRY_KEYWORDS) {
    if (kws.some(k => text.includes(k))) return country
  }
  return 'Global'
}

// ── Category palette ──────────────────────────────────────────────────────────

const CAT_COLOR: Record<NewsCategory, string> = {
  security: '#ff3333',
  tech:     '#00d4ff',
  crypto:   '#f7931a',
  politics: '#aa44ff',
  ai:       '#00e676',
}

const CAT_LABEL: Record<NewsCategory, string> = {
  security: 'SECURITY',
  tech:     'TECH',
  crypto:   'CRYPTO',
  politics: 'POLITICS',
  ai:       'AI',
}

// ── Severity sizes (severity still drives dot size) ───────────────────────────

const SEV_SIZE: Record<string, number> = {
  CRITICAL: 13,
  HIGH:     9,
  MEDIUM:   6,
  INFO:     4,
}

const SEV_SCORE: Record<string, number> = {
  CRITICAL: 4,
  HIGH:     3,
  MEDIUM:   2,
  INFO:     1,
}

// ── Globe point ───────────────────────────────────────────────────────────────

interface NewsPoint {
  id:       number
  lat:      number
  lng:      number
  country:  string
  item:     NewsItem
  color:    string   // category colour
  size:     number   // severity size
}

// ── HTML node factory ─────────────────────────────────────────────────────────

function makeNewsNode(pt: NewsPoint, onClick: (p: NewsPoint) => void): HTMLElement {
  const { color, size, item } = pt
  const isCrit = item.severity === 'CRITICAL'
  const dim    = size + 24

  const wrapper = document.createElement('div')
  wrapper.style.cssText = [
    'position:relative',
    `width:${dim}px`,
    `height:${dim}px`,
    'cursor:pointer',
    'transform:translate(-50%,-50%)',
    'pointer-events:auto',
  ].join(';')

  if (isCrit) {
    const r2 = document.createElement('div')
    r2.style.cssText = `
      position:absolute; top:50%; left:50%;
      width:${size + 18}px; height:${size + 18}px;
      transform:translate(-50%,-50%);
      border-radius:50%;
      border:1px solid ${color}22;
      animation:news-pulse 3s ease-out infinite;
      animation-delay:0.5s;
    `
    wrapper.appendChild(r2)
  }

  const ring = document.createElement('div')
  ring.style.cssText = `
    position:absolute; top:50%; left:50%;
    width:${size + 8}px; height:${size + 8}px;
    transform:translate(-50%,-50%);
    border-radius:50%;
    border:1.5px solid ${color}66;
    animation:news-pulse ${isCrit ? '2' : '3.5'}s ease-out infinite;
    animation-delay:${Math.random() * 2}s;
  `

  const dot = document.createElement('div')
  dot.style.cssText = `
    position:absolute; top:50%; left:50%;
    width:${size}px; height:${size}px;
    transform:translate(-50%,-50%);
    border-radius:50%;
    background:${color};
    box-shadow:0 0 ${size * 1.1}px ${color}, 0 0 ${size * 2}px ${color}33;
  `

  wrapper.appendChild(ring)
  wrapper.appendChild(dot)
  wrapper.addEventListener('click', e => { e.stopPropagation(); onClick(pt) })
  return wrapper
}

// ── Lazy globe ────────────────────────────────────────────────────────────────

const GlobeGL = lazy(() => import('react-globe.gl'))

// ── Component ─────────────────────────────────────────────────────────────────

interface Props {
  news:           NewsItem[]
  refreshTrigger: number
}

export function ThreatMap({ news, refreshTrigger }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [size, setSize]         = useState({ w: 0, h: 0 })
  const [selected, setSelected] = useState<NewsPoint | null>(null)
  const [activeFilter, setActiveFilter] = useState<NewsCategory | null>(null)

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

  useEffect(() => {
    if (document.getElementById('news-pulse-style')) return
    const style = document.createElement('style')
    style.id = 'news-pulse-style'
    style.textContent = `
      @keyframes news-pulse {
        0%   { transform:translate(-50%,-50%) scale(1);   opacity:0.85; }
        100% { transform:translate(-50%,-50%) scale(3.2); opacity:0;    }
      }
    `
    document.head.appendChild(style)
  }, [])

  // ── Select top-10 per category by importance, then geo-locate ───────────────
  const newsPoints = useMemo<NewsPoint[]>(() => {
    const CATEGORIES: NewsCategory[] = ['security', 'tech', 'crypto', 'politics', 'ai']
    const TOP_N = 10

    // Pick top-10 per category (sort by severity score desc, then recency desc)
    const selected: NewsItem[] = []
    for (const cat of CATEGORIES) {
      const catItems = news
        .filter(n => n.category === cat)
        .sort((a, b) => {
          const scoreDiff = (SEV_SCORE[b.severity] ?? 0) - (SEV_SCORE[a.severity] ?? 0)
          if (scoreDiff !== 0) return scoreDiff
          const ta = a.published_at ? new Date(a.published_at).getTime() : 0
          const tb = b.published_at ? new Date(b.published_at).getTime() : 0
          return tb - ta
        })
        .slice(0, TOP_N)
      selected.push(...catItems)
    }

    // Geo-locate all selected items
    const located = selected.map(item => {
      const raw = detectCountry(item)
      return { item, country: raw }
    })

    // Count total items per geo-key (for radius calculation)
    const totals: Record<string, number> = {}
    const globalIdx = { n: 0 }

    for (const { country } of located) {
      if (country === 'Global') continue
      totals[country] = (totals[country] ?? 0) + 1
    }
    totals['Global'] = located.filter(l => l.country === 'Global').length

    // Build final points with sunflower spiral spread
    const countryIdx: Record<string, number> = {}
    const pts: NewsPoint[] = []

    for (const { item, country } of located) {
      const cat = item.category as NewsCategory
      const color = CAT_COLOR[cat] ?? '#aaaaaa'
      const sz    = SEV_SIZE[item.severity] ?? 6

      if (country === 'Global') {
        // Cycle through world anchors so globals aren't piled up
        const anchor = GLOBAL_ANCHORS[globalIdx.n % GLOBAL_ANCHORS.length]
        globalIdx.n++
        const jLat = (Math.random() - 0.5) * 3
        const jLng = (Math.random() - 0.5) * 3
        pts.push({ id: item.id, lat: anchor.lat + jLat, lng: anchor.lng + jLng, country, item, color, size: sz })
        continue
      }

      const base  = COUNTRY_COORDS[country] ?? COUNTRY_COORDS['USA']!
      const total = totals[country] ?? 1
      const idx   = countryIdx[country] ?? 0
      countryIdx[country] = idx + 1

      // Sunflower (Fibonacci) spiral — fills space evenly without gaps
      const angle     = idx * 2.3999  // ≈ golden angle in radians
      const maxRadius = Math.min(5.5, 1.2 + Math.sqrt(total) * 1.0)
      const r         = total === 1 ? 0 : Math.sqrt((idx + 0.5) / total) * maxRadius

      pts.push({
        id:      item.id,
        lat:     base.lat + Math.cos(angle) * r,
        lng:     base.lng + Math.sin(angle) * r,
        country,
        item,
        color,
        size: sz,
      })
    }
    return pts
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [news, refreshTrigger])

  // Pulsing rings at countries with ≥3 items
  const ringData = useMemo(() => {
    const counts: Record<string, number> = {}
    newsPoints.forEach(p => { if (p.country !== 'Global') counts[p.country] = (counts[p.country] ?? 0) + 1 })
    return Object.entries(counts)
      .filter(([, c]) => c >= 3)
      .map(([country]) => COUNTRY_COORDS[country]!)
      .filter(Boolean)
  }, [newsPoints])

  // Visible points after category filter
  const visiblePoints = useMemo(
    () => activeFilter ? newsPoints.filter(p => p.item.category === activeFilter) : newsPoints,
    [newsPoints, activeFilter],
  )

  const handleClick = useCallback((p: NewsPoint) => setSelected(p), [])

  // Per-category counts for header badges
  const catCounts = useMemo(() => {
    const c: Partial<Record<NewsCategory, number>> = {}
    newsPoints.forEach(p => {
      c[p.item.category as NewsCategory] = (c[p.item.category as NewsCategory] ?? 0) + 1
    })
    return c
  }, [newsPoints])

  const fmtDate = (d: string | null) =>
    d ? new Date(d).toLocaleDateString('en-GB', {
      day: 'numeric', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    }) : '—'

  return (
    <div className="panel flex flex-col h-full overflow-hidden">

      {/* ── Header ── */}
      <div className="panel-header shrink-0 flex-wrap gap-y-1">
        <div className="flex items-center gap-2 flex-wrap">
          <Globe size={11} className="text-[var(--color-primary)]" />
          <span className="panel-title">GLOBAL NEWS MAP</span>
          <span className="live-dot" />
          <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-wider">
            {visiblePoints.length} ARTICLES
          </span>
        </div>

        {/* Category filter badges */}
        <div className="flex items-center gap-1 flex-wrap">
          {(Object.keys(CAT_COLOR) as NewsCategory[]).map(cat => {
            const count = catCounts[cat] ?? 0
            const active = activeFilter === cat
            return (
              <button
                key={cat}
                onClick={() => setActiveFilter(active ? null : cat)}
                className="font-mono text-[0.4rem] tracking-widest px-1.5 py-0.5 border transition-all"
                style={{
                  color:       active ? '#000'                              : CAT_COLOR[cat],
                  background:  active ? CAT_COLOR[cat]                     : `${CAT_COLOR[cat]}10`,
                  borderColor: active ? CAT_COLOR[cat]                     : `${CAT_COLOR[cat]}44`,
                  opacity:     count === 0                                  ? 0.35 : 1,
                }}
                disabled={count === 0}
                title={`Filter to ${CAT_LABEL[cat]} (${count} articles)`}
              >
                {CAT_LABEL[cat]} {count > 0 ? count : ''}
              </button>
            )
          })}
          {activeFilter && (
            <button
              onClick={() => setActiveFilter(null)}
              className="font-mono text-[0.4rem] tracking-widest px-1 py-0.5 border border-[var(--border-base)] text-[var(--text-ghost)] hover:text-[var(--text-base)] transition-colors"
            >
              ALL
            </button>
          )}
        </div>
      </div>

      {/* ── Globe + detail ── */}
      <div className="flex-1 relative overflow-hidden min-h-0 flex">

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
                htmlElementsData={visiblePoints}
                htmlLat={(d: object) => (d as NewsPoint).lat}
                htmlLng={(d: object) => (d as NewsPoint).lng}
                htmlAltitude={(d: object) => (d as NewsPoint).item.severity === 'CRITICAL' ? 0.04 : 0.018}
                htmlElement={(d: object) => makeNewsNode(d as NewsPoint, handleClick)}
                ringsData={ringData}
                ringLat="lat"
                ringLng="lng"
                ringColor={() => 'rgba(0,212,255,0.25)'}
                ringMaxRadius={5}
                ringPropagationSpeed={1.0}
                ringRepeatPeriod={1200}
              />
            </Suspense>
          )}
        </div>

        {/* ── Detail panel ── */}
        {selected && (
          <div
            className="absolute right-0 top-0 h-full w-72 bg-[var(--bg-surface)]/95 backdrop-blur-sm border-l border-[var(--border-base)] flex flex-col overflow-hidden"
            style={{ borderLeft: `2px solid ${selected.color}55` }}
          >
            <div
              className="flex items-center justify-between px-3 py-2 border-b border-[var(--border-base)] shrink-0"
              style={{ background: `${selected.color}0c` }}
            >
              <div className="flex items-center gap-2">
                <div
                  className="w-2 h-2 rounded-full shrink-0 animate-pulse"
                  style={{ background: selected.color, boxShadow: `0 0 6px ${selected.color}` }}
                />
                <span
                  className="font-mono text-[0.5rem] tracking-widest font-semibold"
                  style={{ color: selected.color }}
                >
                  {CAT_LABEL[selected.item.category as NewsCategory]}
                </span>
                <span
                  className="font-mono text-[0.4rem] tracking-widest px-1 border"
                  style={{
                    color:       selected.item.severity === 'CRITICAL' ? '#ff3333' : selected.item.severity === 'HIGH' ? '#ff8800' : 'var(--text-ghost)',
                    borderColor: selected.item.severity === 'CRITICAL' ? 'rgba(255,51,51,0.35)' : selected.item.severity === 'HIGH' ? 'rgba(255,136,0,0.35)' : 'var(--border-base)',
                    background:  selected.item.severity === 'CRITICAL' ? 'rgba(255,51,51,0.07)' : selected.item.severity === 'HIGH' ? 'rgba(255,136,0,0.07)' : 'transparent',
                  }}
                >
                  {selected.item.severity}
                </span>
              </div>
              <button
                onClick={() => setSelected(null)}
                className="text-[var(--text-ghost)] hover:text-[var(--text-base)] transition-colors"
              >
                <X size={12} />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-3 space-y-3">

              {/* Headline */}
              <div>
                <div className="font-mono text-[0.38rem] text-[var(--text-ghost)] tracking-widest mb-1">HEADLINE</div>
                <p className="text-[0.65rem] text-[var(--text-base)] leading-snug font-medium">
                  {selected.item.title}
                </p>
              </div>

              {/* Meta grid */}
              <div className="grid grid-cols-2 gap-x-3 gap-y-2">
                <div>
                  <div className="font-mono text-[0.36rem] text-[var(--text-ghost)] tracking-widest mb-0.5">SOURCE</div>
                  <div className="font-mono text-[0.48rem] text-[var(--text-dim)]">{selected.item.source}</div>
                </div>
                <div>
                  <div className="font-mono text-[0.36rem] text-[var(--text-ghost)] tracking-widest mb-0.5">ORIGIN</div>
                  <div className="flex items-center gap-1">
                    <MapPin size={7} style={{ color: selected.color }} />
                    <span className="font-mono text-[0.48rem] text-[var(--text-dim)]">{selected.country}</span>
                  </div>
                </div>
                <div className="col-span-2">
                  <div className="font-mono text-[0.36rem] text-[var(--text-ghost)] tracking-widest mb-0.5">PUBLISHED</div>
                  <div className="flex items-center gap-1">
                    <Clock size={7} className="text-[var(--text-ghost)]" />
                    <span className="font-mono text-[0.44rem] text-[var(--text-dim)]">
                      {fmtDate(selected.item.published_at)}
                    </span>
                  </div>
                </div>
              </div>

              {/* Summary */}
              {selected.item.summary && (
                <div>
                  <div className="font-mono text-[0.38rem] text-[var(--text-ghost)] tracking-widest mb-1">SUMMARY</div>
                  <p className="text-[0.6rem] text-[var(--text-secondary)] leading-relaxed">
                    {selected.item.summary}
                  </p>
                </div>
              )}

              {/* Threat actors */}
              {selected.item.threat_actors.length > 0 && (
                <div>
                  <div className="flex items-center gap-1 mb-1.5">
                    <Shield size={8} style={{ color: '#ff4444' }} />
                    <span className="font-mono text-[0.38rem] text-[var(--text-ghost)] tracking-widest">
                      THREAT ACTORS ({selected.item.threat_actors.length})
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {selected.item.threat_actors.map(a => (
                      <span
                        key={a}
                        className="font-mono text-[0.42rem] px-1.5 py-0.5 border"
                        style={{ color: '#ff4444', borderColor: 'rgba(255,68,68,0.35)', background: 'rgba(255,68,68,0.07)' }}
                      >
                        {a}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* CVE refs */}
              {selected.item.cve_refs.length > 0 && (
                <div>
                  <div className="flex items-center gap-1 mb-1.5">
                    <AlertTriangle size={8} style={{ color: '#f7931a' }} />
                    <span className="font-mono text-[0.38rem] text-[var(--text-ghost)] tracking-widest">
                      CVE REFERENCES
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {selected.item.cve_refs.map(c => (
                      <span
                        key={c}
                        className="font-mono text-[0.42rem] px-1.5 py-0.5 border"
                        style={{ color: '#f7931a', borderColor: 'rgba(247,147,26,0.35)', background: 'rgba(247,147,26,0.07)' }}
                      >
                        {c}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Tags */}
              {selected.item.tags.length > 0 && (
                <div>
                  <div className="flex items-center gap-1 mb-1.5">
                    <Tag size={8} className="text-[var(--text-ghost)]" />
                    <span className="font-mono text-[0.38rem] text-[var(--text-ghost)] tracking-widest">TAGS</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {selected.item.tags.slice(0, 10).map(t => (
                      <span
                        key={t}
                        className="font-mono text-[0.4rem] px-1 py-0.5 border border-[var(--border-base)] text-[var(--text-ghost)]"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

            </div>

            {/* Footer */}
            <div className="px-3 py-2 border-t border-[var(--border-base)] shrink-0">
              <a
                href={selected.item.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 hover:opacity-75 transition-opacity"
                style={{ color: selected.color }}
              >
                <ExternalLink size={9} />
                <span className="font-mono text-[0.42rem] tracking-widest">OPEN FULL ARTICLE</span>
              </a>
            </div>
          </div>
        )}

        {/* ── Legend ── */}
        {!selected && (
          <div className="absolute bottom-3 left-3 pointer-events-none space-y-1.5">
            <div className="bg-[var(--bg-surface)]/80 backdrop-blur-sm border border-[var(--border-base)] px-2.5 py-2 space-y-1">
              <div className="font-mono text-[0.37rem] text-[var(--text-ghost)] tracking-widest mb-1">CATEGORY</div>
              {(Object.keys(CAT_COLOR) as NewsCategory[]).map(cat => (
                <div key={cat} className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full shrink-0" style={{ background: CAT_COLOR[cat] }} />
                  <span className="font-mono text-[0.4rem] tracking-wider" style={{ color: CAT_COLOR[cat] }}>
                    {CAT_LABEL[cat]}
                  </span>
                </div>
              ))}
            </div>
            <div className="bg-[var(--bg-surface)]/80 backdrop-blur-sm border border-[var(--border-base)] px-2.5 py-2 space-y-1">
              <div className="font-mono text-[0.37rem] text-[var(--text-ghost)] tracking-widest mb-1">SIZE = SEVERITY</div>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'INFO'].map(s => (
                <div key={s} className="flex items-center gap-2">
                  <div
                    className="rounded-full shrink-0"
                    style={{ width: `${SEV_SIZE[s]}px`, height: `${SEV_SIZE[s]}px`, background: 'var(--text-ghost)' }}
                  />
                  <span className="font-mono text-[0.4rem] text-[var(--text-dim)] tracking-wider">{s}</span>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>
    </div>
  )
}
