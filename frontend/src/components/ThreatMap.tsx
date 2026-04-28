import { useEffect, useRef, useState, useCallback, lazy, Suspense, useMemo } from 'react'
import { Globe, X, Clock, ExternalLink, Shield, AlertTriangle, MapPin, Tag } from 'lucide-react'
import type { NewsItem } from '@/types'

// ── Country coordinates ───────────────────────────────────────────────────────

const COUNTRY_COORDS: Record<string, { lat: number; lng: number }> = {
  'Russia':       { lat: 55.75,  lng: 37.62  },
  'China':        { lat: 39.91,  lng: 116.39 },
  'North Korea':  { lat: 39.02,  lng: 125.75 },
  'Iran':         { lat: 35.69,  lng: 51.39  },
  'USA':          { lat: 38.90,  lng: -77.04 },
  'UK':           { lat: 51.51,  lng: -0.13  },
  'Germany':      { lat: 52.52,  lng: 13.41  },
  'France':       { lat: 48.86,  lng: 2.35   },
  'Ukraine':      { lat: 50.45,  lng: 30.52  },
  'Israel':       { lat: 31.77,  lng: 35.22  },
  'India':        { lat: 28.61,  lng: 77.21  },
  'Japan':        { lat: 35.68,  lng: 139.69 },
  'Australia':    { lat: -33.87, lng: 151.21 },
  'Brazil':       { lat: -15.78, lng: -47.93 },
  'Canada':       { lat: 45.42,  lng: -75.69 },
  'Singapore':    { lat: 1.35,   lng: 103.82 },
  'Netherlands':  { lat: 52.37,  lng: 4.90   },
  'Taiwan':       { lat: 25.03,  lng: 121.56 },
  'South Korea':  { lat: 37.57,  lng: 126.98 },
  'Pakistan':     { lat: 33.72,  lng: 73.06  },
  'Europe':       { lat: 50.11,  lng: 8.68   },
  'NATO':         { lat: 50.85,  lng: 4.35   },
  'Middle East':  { lat: 32.00,  lng: 39.00  },
  'Global':       { lat: 40.71,  lng: -74.01 },
}

// ── Actor → country (used as primary geo signal) ──────────────────────────────

const ACTOR_COUNTRY: [string, string][] = [
  ['apt28',         'Russia'], ['apt29',       'Russia'], ['sandworm',        'Russia'],
  ['midnight blizzard','Russia'], ['cozy bear', 'Russia'], ['fancy bear',     'Russia'],
  ['gamaredon',     'Russia'], ['turla',        'Russia'], ['lockbit',         'Russia'],
  ['blackcat',      'Russia'], ['alphv',        'Russia'], ['cl0p',            'Russia'],
  ['noname057',     'Russia'], ['killnet',      'Russia'], ['blacksuit',       'Russia'],
  ['akira',         'Russia'], ['qilin',        'Russia'], ['hunters international','Russia'],

  ['apt41',         'China'],  ['volt typhoon', 'China'],  ['salt typhoon',    'China'],
  ['silk typhoon',  'China'],  ['mustang panda','China'],  ['hafnium',         'China'],

  ['lazarus',       'North Korea'], ['kimsuky',  'North Korea'], ['apt38',     'North Korea'],
  ['bluenoroff',    'North Korea'], ['tradertraitor','North Korea'],

  ['charming kitten','Iran'],  ['apt42',        'Iran'],   ['muddywater',      'Iran'],
  ['apt34',         'Iran'],   ['oilrig',       'Iran'],   ['phosphorus',      'Iran'],

  ['scattered spider','USA'],  ['shinyHunters', 'USA'],

  ['sidewind',      'India'],
  ['transparent tribe','Pakistan'],
]

// ── Keyword → country fallback ────────────────────────────────────────────────

const COUNTRY_KEYWORDS: [string, string[]][] = [
  ['Russia',      ['russia', 'russian', 'kremlin', 'moscow', 'fsb', 'gru', 'svr']],
  ['China',       ['china', 'chinese', 'beijing', 'prc', 'pla', 'mss']],
  ['North Korea', ['north korea', 'dprk', 'pyongyang']],
  ['Iran',        ['iran', 'iranian', 'tehran', 'irgc', 'mois']],
  ['USA',         ['united states', ' u.s.', ' us ', 'american', 'washington', 'pentagon', 'nsa', 'cisa', 'fbi']],
  ['UK',          ['united kingdom', ' uk ', 'british', 'london', 'ncsc', 'gchq']],
  ['Germany',     ['german', 'germany', 'berlin', 'bsi ']],
  ['Ukraine',     ['ukraine', 'ukrainian', 'kyiv']],
  ['Israel',      ['israel', 'israeli', 'mossad', 'tel aviv', 'idf']],
  ['Taiwan',      ['taiwan', 'taipei', 'pla straits']],
  ['India',       ['india', 'indian', 'new delhi', 'cert-in']],
  ['Japan',       ['japan', 'japanese', 'tokyo']],
  ['Australia',   ['australia', 'australian', 'sydney', 'asd ']],
  ['Europe',      ['european union', 'eu parliament', 'nato', 'brussels']],
]

function detectCountry(item: NewsItem): string {
  // 1. Threat actors → most reliable signal
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

// ── Severity palette ──────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff2222',
  HIGH:     '#ff8800',
  MEDIUM:   '#ffcc00',
  INFO:     '#44aaff',
}

const SEV_SIZE: Record<string, number> = {
  CRITICAL: 14,
  HIGH:     10,
  MEDIUM:   7,
  INFO:     5,
}

// ── Globe point data ──────────────────────────────────────────────────────────

interface NewsPoint {
  id:      number
  lat:     number
  lng:     number
  country: string
  item:    NewsItem
  color:   string
  size:    number
}

// ── HTML node factory ─────────────────────────────────────────────────────────

function makeNewsNode(pt: NewsPoint, onClick: (p: NewsPoint) => void): HTMLElement {
  const { color, size, item } = pt
  const isCrit = item.severity === 'CRITICAL'
  const dim    = size + 22

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
      width:${size + 16}px; height:${size + 16}px;
      transform:translate(-50%,-50%);
      border-radius:50%;
      border:1px solid ${color}2a;
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
    border:1px solid ${color}55;
    animation:news-pulse ${isCrit ? '2' : '3'}s ease-out infinite;
    animation-delay:${Math.random() * 1.5}s;
  `

  const dot = document.createElement('div')
  dot.style.cssText = `
    position:absolute; top:50%; left:50%;
    width:${size}px; height:${size}px;
    transform:translate(-50%,-50%);
    border-radius:50%;
    background:${color};
    box-shadow:0 0 ${size * 1.2}px ${color}, 0 0 ${size * 2.2}px ${color}44;
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
  const [size, setSize]       = useState({ w: 0, h: 0 })
  const [selected, setSelected] = useState<NewsPoint | null>(null)

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

  // Inject CSS keyframes once
  useEffect(() => {
    if (document.getElementById('news-pulse-style')) return
    const style = document.createElement('style')
    style.id = 'news-pulse-style'
    style.textContent = `
      @keyframes news-pulse {
        0%   { transform:translate(-50%,-50%) scale(1);   opacity:0.9; }
        100% { transform:translate(-50%,-50%) scale(3);   opacity:0;   }
      }
    `
    document.head.appendChild(style)
  }, [])

  // Build globe points from news feed (CRITICAL + HIGH only, up to 80 items)
  const newsPoints = useMemo<NewsPoint[]>(() => {
    const shown = news.filter(n => n.severity === 'CRITICAL' || n.severity === 'HIGH')
    const countryIdx: Record<string, number> = {}
    const pts: NewsPoint[] = []

    for (const item of shown.slice(0, 80)) {
      const country = detectCountry(item)
      const base    = COUNTRY_COORDS[country] ?? COUNTRY_COORDS['Global']!
      const idx     = countryIdx[country] ?? 0
      countryIdx[country] = idx + 1

      // Spiral jitter so items at the same country don't overlap
      const angle   = idx * 2.399   // golden angle ≈ 137.5°
      const radius  = Math.sqrt(idx + 0.5) * 1.8
      pts.push({
        id:      item.id,
        lat:     base.lat + Math.cos(angle) * radius,
        lng:     base.lng + Math.sin(angle) * radius,
        country,
        item,
        color:   SEV_COLOR[item.severity] ?? '#aaaaaa',
        size:    SEV_SIZE[item.severity]  ?? 7,
      })
    }
    return pts
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [news, refreshTrigger])

  // Pulsing rings at countries with ≥2 items
  const ringData = useMemo(() => {
    const counts: Record<string, number> = {}
    newsPoints.forEach(p => { counts[p.country] = (counts[p.country] ?? 0) + 1 })
    return Object.entries(counts)
      .filter(([, c]) => c >= 2)
      .map(([country]) => COUNTRY_COORDS[country] ?? COUNTRY_COORDS['Global']!)
  }, [newsPoints])

  const handleClick = useCallback((p: NewsPoint) => setSelected(p), [])

  const critCount = newsPoints.filter(p => p.item.severity === 'CRITICAL').length
  const highCount = newsPoints.filter(p => p.item.severity === 'HIGH').length

  const fmtDate = (d: string | null) =>
    d ? new Date(d).toLocaleDateString('en-GB', {
      day: 'numeric', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    }) : '—'

  return (
    <div className="panel flex flex-col h-full overflow-hidden">

      {/* ── Header ── */}
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <Globe size={11} className="text-[var(--color-primary)]" />
          <span className="panel-title">GLOBAL THREAT MAP</span>
          <span className="live-dot" />
          <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-wider">
            {newsPoints.length} NEWS INCIDENTS
          </span>
          {critCount > 0 && (
            <span className="font-mono text-[0.42rem] tracking-widest px-1 border"
              style={{ color: '#ff2222', borderColor: 'rgba(255,34,34,0.35)', background: 'rgba(255,34,34,0.07)' }}>
              {critCount} CRITICAL
            </span>
          )}
          {highCount > 0 && (
            <span className="font-mono text-[0.42rem] tracking-widest px-1 border"
              style={{ color: '#ff8800', borderColor: 'rgba(255,136,0,0.35)', background: 'rgba(255,136,0,0.07)' }}>
              {highCount} HIGH
            </span>
          )}
        </div>
        <span className="font-mono text-[0.42rem] text-[var(--text-ghost)] tracking-widest">
          CLICK NODE · ORIGIN = NEWS SOURCE COUNTRY
        </span>
      </div>

      {/* ── Globe + detail ── */}
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
                htmlElementsData={newsPoints}
                htmlLat={(d: object) => (d as NewsPoint).lat}
                htmlLng={(d: object) => (d as NewsPoint).lng}
                htmlAltitude={(d: object) => (d as NewsPoint).item.severity === 'CRITICAL' ? 0.03 : 0.015}
                htmlElement={(d: object) => makeNewsNode(d as NewsPoint, handleClick)}
                ringsData={ringData}
                ringLat="lat"
                ringLng="lng"
                ringColor={() => 'rgba(0,212,255,0.3)'}
                ringMaxRadius={4}
                ringPropagationSpeed={1.2}
                ringRepeatPeriod={900}
              />
            </Suspense>
          )}
        </div>

        {/* ── Detail panel ── */}
        {selected && (
          <div
            className="absolute right-0 top-0 h-full w-72 bg-[var(--bg-surface)]/95 backdrop-blur-sm border-l border-[var(--border-base)] flex flex-col overflow-hidden"
            style={{ borderLeft: `2px solid ${selected.color}44` }}
          >
            {/* Panel header */}
            <div
              className="flex items-center justify-between px-3 py-2 border-b border-[var(--border-base)] shrink-0"
              style={{ background: `${selected.color}0d` }}
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
                  {selected.item.severity} INCIDENT
                </span>
              </div>
              <button
                onClick={() => setSelected(null)}
                className="text-[var(--text-ghost)] hover:text-[var(--text-base)] transition-colors"
              >
                <X size={12} />
              </button>
            </div>

            {/* Scrollable body */}
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
                <div>
                  <div className="font-mono text-[0.36rem] text-[var(--text-ghost)] tracking-widest mb-0.5">CATEGORY</div>
                  <div className="font-mono text-[0.48rem] text-[var(--text-dim)] uppercase">{selected.item.category}</div>
                </div>
                <div>
                  <div className="font-mono text-[0.36rem] text-[var(--text-ghost)] tracking-widest mb-0.5">DATE</div>
                  <div className="flex items-center gap-1">
                    <Clock size={7} className="text-[var(--text-ghost)]" />
                    <span className="font-mono text-[0.42rem] text-[var(--text-dim)]">
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
                      CVE REFERENCES ({selected.item.cve_refs.length})
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
                    {selected.item.tags.slice(0, 12).map(t => (
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

            {/* Footer link */}
            <div className="px-3 py-2 border-t border-[var(--border-base)] shrink-0">
              <a
                href={selected.item.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 text-[var(--color-primary)] hover:opacity-75 transition-opacity"
              >
                <ExternalLink size={9} />
                <span className="font-mono text-[0.42rem] tracking-widest">OPEN FULL ARTICLE</span>
              </a>
            </div>
          </div>
        )}

        {/* ── Legend ── */}
        {!selected && (
          <div className="absolute bottom-3 left-3 pointer-events-none">
            <div className="bg-[var(--bg-surface)]/80 backdrop-blur-sm border border-[var(--border-base)] px-2.5 py-2 space-y-1">
              <div className="font-mono text-[0.38rem] text-[var(--text-ghost)] tracking-widest mb-1">SEVERITY</div>
              {Object.entries(SEV_COLOR).map(([sev, color]) => (
                <div key={sev} className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full shrink-0" style={{ background: color }} />
                  <span className="font-mono text-[0.42rem] tracking-wider" style={{ color }}>{sev}</span>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>
    </div>
  )
}
