import { useState, useCallback, useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import {
  Rss, Users, Globe2, LayoutDashboard,
  GitFork, Clock, SlidersHorizontal, Bot, Bell,
  Bookmark, Sun, Moon, CalendarDays,
  type LucideIcon,
} from 'lucide-react'

import { useWebSocket }    from '@/hooks/useWebSocket'
import { useApi }          from '@/hooks/useApi'
import type { Stats, NewsItem, AnalyzeTarget } from '@/types'

import { ErrorBoundary }     from '@/components/ErrorBoundary'
import { StatusBar }         from '@/components/StatusBar'
import { ActivityPanel }     from '@/components/ActivityPanel'
import { NewsFeed }          from '@/components/NewsFeed'
import { ThreatActors }      from '@/components/ThreatActors'
import { ThreatMap }         from '@/components/ThreatMap'
import { CorrelationGraph }  from '@/components/CorrelationGraph'
import { OllamaPanel }       from '@/components/OllamaPanel'
import { CampaignTimeline }  from '@/components/CampaignTimeline'
import { AiAnalyst }         from '@/components/AiAnalyst'
import { AlertRules }        from '@/components/AlertRules'
import { Settings }          from '@/components/Settings'
import { Watchlists }        from '@/components/Watchlists'
import { Login }             from '@/components/Login'
import { KeyboardHelp }      from '@/components/KeyboardHelp'
import { CryptoPricePanel }     from '@/components/CryptoPricePanel'
import { WorldClocks }           from '@/components/WorldClocks'
import { DefconIndicator }       from '@/components/DefconIndicator'
import { ConferenceCalendar }    from '@/components/ConferenceCalendar'

type TabId =
  | 'dashboard' | 'news' | 'actors'
  | 'graph' | 'campaigns' | 'map' | 'analyst' | 'alertrules' | 'watchlists' | 'conferences' | 'settings'

const TABS: { id: TabId; label: string; icon: LucideIcon; accent?: boolean }[] = [
  { id: 'dashboard',   label: 'DASHBOARD',    icon: LayoutDashboard },
  { id: 'news',        label: 'NEWS FEED',    icon: Rss },
  { id: 'actors',      label: 'THREAT ACTORS',icon: Users },
  { id: 'graph',       label: 'CORRELATION',  icon: GitFork },
  { id: 'campaigns',   label: 'CAMPAIGNS',    icon: Clock },
  { id: 'map',         label: 'GLOBAL MAP',   icon: Globe2 },
  { id: 'conferences', label: 'CONFERENCES',  icon: CalendarDays },
  { id: 'analyst',     label: 'AI ANALYST',   icon: Bot, accent: true },
  { id: 'alertrules',  label: 'ALERT RULES',  icon: Bell },
  { id: 'watchlists',  label: 'WATCHLISTS',   icon: Bookmark },
  { id: 'settings',    label: 'SETTINGS',     icon: SlidersHorizontal },
]

// Keyboard shortcut map: second key → tab id
const KEY_TAB_MAP: Record<string, TabId> = {
  d: 'dashboard',
  n: 'news',
  a: 'actors',
  r: 'graph',
  t: 'campaigns',
  m: 'map',
  c: 'conferences',
  x: 'analyst',
  u: 'alertrules',
  w: 'watchlists',
  s: 'settings',
}

// When deployed with a separate backend (e.g. Render), set VITE_API_URL to the
// backend origin (e.g. https://sigintx-api.onrender.com). The WS and API hooks
// will use it automatically. Leave unset for local dev (Vite proxy handles it).
const _apiOrigin = import.meta.env.VITE_API_URL?.replace(/\/$/, '') ?? ''
const WS_URL = _apiOrigin
  ? _apiOrigin.replace(/^https/, 'wss').replace(/^http/, 'ws') + '/ws'
  : `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws`

const FULL_H = 'calc(100vh - 200px)'
const MAP_H  = '42vh'
const FEED_H = '360px'

export default function App() {
  const [activeTab, setActiveTab]           = useState<TabId>('dashboard')
  const [refreshCounter, setRefreshCounter] = useState(0)
  const [analyzeTarget, setAnalyzeTarget]   = useState<AnalyzeTarget | null>(null)
  // Skip login when VITE_AUTH_DISABLED=true (demo / public deployments)
  const [authed, setAuthed]                 = useState(
    import.meta.env.VITE_AUTH_DISABLED === 'true'
  )
  const [showKeyHelp, setShowKeyHelp]       = useState(false)
  const [theme, setTheme]                   = useState<'dark' | 'light'>(() => {
    return (localStorage.getItem('sigintx-theme') as 'dark' | 'light') ?? 'dark'
  })

  // Apply theme to <html> element
  useEffect(() => {
    const root = document.documentElement
    if (theme === 'light') root.setAttribute('data-theme', 'light')
    else root.removeAttribute('data-theme')
    localStorage.setItem('sigintx-theme', theme)
  }, [theme])

  const toggleTheme = useCallback(() => setTheme(t => t === 'dark' ? 'light' : 'dark'), [])

  // Leader-key state: 'g' pressed, waiting for second key
  const leaderActive   = useRef(false)
  const leaderTimer    = useRef<ReturnType<typeof setTimeout> | null>(null)

  const { isConnected, lastMessage } = useWebSocket(WS_URL)

  const { refetch: refetchStats } =
    useApi<Stats>('/stats', undefined, refreshCounter, 30_000)

  const { data: recentNews } =
    useApi<NewsItem[]>('/news', { limit: 60 }, refreshCounter, 60_000)

  const handleRefresh = useCallback(() => {
    setRefreshCounter(c => c + 1)
    refetchStats()
  }, [refetchStats])

  // WebSocket-driven refresh: bump counter on any data-update message
  // so news panels immediately pick up new items without waiting for their polling interval.
  useEffect(() => {
    if (!lastMessage) return
    const type = (lastMessage as { type?: string }).type
    if (type === 'rss_update') {
      setRefreshCounter(c => c + 1)
    }
  }, [lastMessage])

  // Navigate from GlobalSearch — switch tab
  const handleNavigate = useCallback((tab: string) => {
    if (TABS.some(t => t.id === tab)) setActiveTab(tab as TabId)
  }, [])

  // Keyboard shortcuts
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName
      // Skip when user is typing in an input
      if (tag === 'INPUT' || tag === 'TEXTAREA' || (e.target as HTMLElement).isContentEditable) return

      const key = e.key

      // '?' — toggle keyboard help
      if (key === '?') { setShowKeyHelp(v => !v); return }

      // Escape — close overlays
      if (key === 'Escape') { setShowKeyHelp(false); return }

      // '/' — focus search (handled by StatusBar but clear leader)
      if (key === '/') { leaderActive.current = false; return }

      // 'g' leader key
      if (key === 'g') {
        leaderActive.current = true
        if (leaderTimer.current) clearTimeout(leaderTimer.current)
        leaderTimer.current = setTimeout(() => { leaderActive.current = false }, 1000)
        return
      }

      // Second key after 'g'
      if (leaderActive.current) {
        leaderActive.current = false
        if (leaderTimer.current) clearTimeout(leaderTimer.current)
        const dest = KEY_TAB_MAP[key]
        if (dest) { e.preventDefault(); setActiveTab(dest) }
        return
      }

      // 'r' — refresh
      if (key === 'r') { handleRefresh(); return }
    }

    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [handleRefresh])

  // Show Login screen until authenticated
  if (!authed) {
    return <Login onLogin={(_token, _username) => setAuthed(true)} />
  }

  return (
    <div className="flex flex-col min-h-screen">

      {/* ── Sticky header ──────────────────────────────── */}
      <StatusBar
        isConnected={isConnected}
        lastMessage={lastMessage}
        onRefresh={handleRefresh}
        onNavigate={handleNavigate}
      />

      {/* ── Desktop tab navigation ──────────────────────── */}
      <div className="border-b border-[var(--border-base)] bg-[var(--bg-surface)] shrink-0 desktop-tabs">
        <div className="flex overflow-x-auto scrollbar-none max-w-[1800px] mx-auto">
          {TABS.map(tab => {
            const Icon     = tab.icon
            const isActive = activeTab === tab.id
            const accentColor = tab.accent ? 'var(--color-info)' : 'var(--color-primary)'
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className="relative flex items-center gap-1.5 px-3 py-2.5 font-mono text-[0.55rem] tracking-widest whitespace-nowrap transition-colors shrink-0"
                style={{
                  color:      isActive ? accentColor : tab.accent ? 'rgba(170,68,255,0.6)' : 'var(--text-dim)',
                  background: isActive ? (tab.accent ? 'rgba(170,68,255,0.06)' : 'rgba(0,212,255,0.04)') : 'transparent',
                }}
              >
                <Icon size={10} />
                <span className="hidden sm:block">{tab.label}</span>
                {tab.accent && !isActive && (
                  <span className="w-1 h-1 rounded-full bg-[var(--color-info)] opacity-60" />
                )}
                {isActive && (
                  <motion.div
                    layoutId="tab-indicator"
                    className="absolute bottom-0 left-0 right-0 h-[2px]"
                    style={{ background: accentColor }}
                    transition={{ type: 'spring', stiffness: 400, damping: 35 }}
                  />
                )}
              </button>
            )
          })}
        </div>
      </div>

      {/* ── Main content ───────────────────────────────── */}
      <main className="flex-1 max-w-[1800px] mx-auto w-full px-2 py-2 min-h-0 mobile-main-pad">
        <div>

            {/* ══════════════ DASHBOARD ══════════════ */}
            {activeTab === 'dashboard' && (
              <div className="flex flex-col gap-2">
                {/* Hero: Globe + DEFCON + Activity */}
                <div
                  className="grid grid-cols-1 lg:grid-cols-6 gap-2"
                  style={{ height: MAP_H, minHeight: 260 }}
                >
                  <div className="lg:col-span-3 min-h-0">
                    <ErrorBoundary label="THREAT MAP">
                      <ThreatMap news={recentNews ?? []} refreshTrigger={refreshCounter} />
                    </ErrorBoundary>
                  </div>
                  <div className="lg:col-span-2 min-h-0">
                    <ErrorBoundary label="THREAT LEVEL">
                      <DefconIndicator />
                    </ErrorBoundary>
                  </div>
                  <div className="lg:col-span-1 min-h-0">
                    <ErrorBoundary label="ACTIVITY FEED">
                      <ActivityPanel
                        news={recentNews ?? []}
                        onAnalyze={t => setAnalyzeTarget(t)}
                      />
                    </ErrorBoundary>
                  </div>
                </div>

                {/* News panel full-width below the hero row */}
                <div style={{ height: FEED_H }}>
                  <ErrorBoundary label="NEWS FEED">
                    <NewsFeed refreshTrigger={refreshCounter} onAnalyze={t => setAnalyzeTarget(t)} />
                  </ErrorBoundary>
                </div>

                {/* Compact Markets + Clocks row */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-2" style={{ height: '200px' }}>
                  <div className="lg:col-span-2 min-h-0 overflow-hidden">
                    <ErrorBoundary label="MARKETS">
                      <CryptoPricePanel compact />
                    </ErrorBoundary>
                  </div>
                  <div className="min-h-0 overflow-hidden">
                    <ErrorBoundary label="CLOCKS">
                      <WorldClocks compact />
                    </ErrorBoundary>
                  </div>
                </div>
              </div>
            )}

            {/* ══════════════ NEWS FEED ══════════════ */}
            {activeTab === 'news' && (
              <div style={{ height: FULL_H }}>
                <ErrorBoundary label="NEWS FEED">
                  <NewsFeed refreshTrigger={refreshCounter} onAnalyze={t => setAnalyzeTarget(t)} />
                </ErrorBoundary>
              </div>
            )}

            {/* ══════════════ THREAT ACTORS ══════════ */}
            {activeTab === 'actors' && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-2" style={{ height: FULL_H }}>
                <ErrorBoundary label="THREAT ACTORS">
                  <ThreatActors refreshTrigger={refreshCounter} />
                </ErrorBoundary>
                <div className="panel flex flex-col">
                  <div className="panel-header shrink-0">
                    <span className="panel-title">MITRE ATT&amp;CK Reference</span>
                  </div>
                  <div className="flex-1 flex items-center justify-center flex-col gap-4 p-6 text-center">
                    <p className="font-mono text-[0.6rem] text-[var(--text-dim)] tracking-widest leading-relaxed max-w-xs">
                      ACTOR PROFILES SEEDED FROM MITRE ATT&amp;CK STIX BUNDLE.<br />
                      TECHNIQUE CHIPS LINK DIRECTLY TO ATTACK.MITRE.ORG.
                    </p>
                    <p className="text-[var(--text-muted)] text-sm max-w-xs leading-relaxed">
                      Use the Correlation tab to see the AI-generated Actor ↔ Campaign ↔ News linkage graph.
                    </p>
                    <a
                      href="https://attack.mitre.org/groups/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-[0.6rem] tracking-wider px-3 py-1.5 border border-[var(--border-accent)] text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.06)] transition-colors"
                    >
                      VIEW MITRE ATT&amp;CK GROUPS →
                    </a>
                  </div>
                </div>
              </div>
            )}

            {/* ══════════════ CORRELATION ════════════ */}
            {activeTab === 'graph' && (
              <div style={{ height: FULL_H }}>
                <ErrorBoundary label="CORRELATION GRAPH">
                  <CorrelationGraph refreshTrigger={refreshCounter} />
                </ErrorBoundary>
              </div>
            )}

            {/* ══════════════ CAMPAIGNS ══════════════ */}
            {activeTab === 'campaigns' && (
              <div style={{ height: FULL_H }}>
                <ErrorBoundary label="CAMPAIGN TIMELINES">
                  <CampaignTimeline refreshTrigger={refreshCounter} />
                </ErrorBoundary>
              </div>
            )}

            {/* ══════════════ GLOBAL MAP ═════════════ */}
            {activeTab === 'map' && (
              <div style={{ height: FULL_H }}>
                <ErrorBoundary label="GLOBAL MAP">
                  <ThreatMap news={recentNews ?? []} refreshTrigger={refreshCounter} />
                </ErrorBoundary>
              </div>
            )}

            {/* ══════════════ AI ANALYST ════════════ */}
            {activeTab === 'analyst' && (
              <div style={{ height: FULL_H }}>
                <ErrorBoundary label="AI ANALYST">
                  <AiAnalyst refreshTrigger={refreshCounter} />
                </ErrorBoundary>
              </div>
            )}

            {/* ══════════════ ALERT RULES ════════════ */}
            {activeTab === 'alertrules' && (
              <div className="overflow-y-auto" style={{ height: FULL_H }}>
                <ErrorBoundary label="ALERT RULES">
                  <AlertRules />
                </ErrorBoundary>
              </div>
            )}

            {/* ══════════════ WATCHLISTS ═════════════ */}
            {activeTab === 'watchlists' && (
              <div className="overflow-y-auto" style={{ height: FULL_H }}>
                <ErrorBoundary label="WATCHLISTS">
                  <Watchlists />
                </ErrorBoundary>
              </div>
            )}

            {/* ══════════════ CONFERENCES ════════════ */}
            {activeTab === 'conferences' && (
              <div style={{ height: FULL_H }}>
                <ErrorBoundary label="CONFERENCE CALENDAR">
                  <ConferenceCalendar />
                </ErrorBoundary>
              </div>
            )}

            {/* ══════════════ SETTINGS ═══════════════ */}
            {activeTab === 'settings' && (
              <div className="overflow-y-auto" style={{ height: FULL_H }}>
                <ErrorBoundary label="SETTINGS">
                  <Settings theme={theme} onThemeToggle={toggleTheme} />
                </ErrorBoundary>
              </div>
            )}

          </div>
      </main>

      {/* ── Footer ─────────────────────────────────────── */}
      <footer className="border-t border-[var(--border-base)] bg-[var(--bg-surface)] hidden md:block">
        <div className="max-w-[1800px] mx-auto px-4 py-2 flex items-center justify-between gap-4 flex-wrap">
          <span className="font-mono text-[0.46rem] text-[var(--text-ghost)] tracking-widest">
            SIGINTX v3.5.0 // TELEGRAM ALERTS // POLITICS INTEL // CRYPTO MARKETS // DEFCON INDICATOR // AUTO-AI // MIT LICENSE
          </span>
          <div className="flex items-center gap-3">
            <span className="font-mono text-[0.46rem] text-[var(--text-ghost)] tracking-wider hidden sm:block">
              MITRE ATT&CK · BLEEPINGCOMPUTER · KREBS · COINGECKO · 50+ RSS FEEDS
            </span>
            <button
              onClick={toggleTheme}
              className="flex items-center gap-1 font-mono text-[0.46rem] text-[var(--text-ghost)] tracking-wider hover:text-[var(--color-primary)] transition-colors"
              title="Toggle dark / light mode"
            >
              {theme === 'light' ? <Moon size={8} /> : <Sun size={8} />}
              {theme === 'light' ? 'DARK' : 'LIGHT'}
            </button>
            <button
              onClick={() => setShowKeyHelp(true)}
              className="font-mono text-[0.46rem] text-[var(--text-ghost)] tracking-wider hover:text-[var(--color-primary)] transition-colors"
              title="Keyboard shortcuts (?)"
            >
              [?] SHORTCUTS
            </button>
          </div>
        </div>
      </footer>

      {/* ── Ollama analysis panel (global — all tabs) ── */}
      <ErrorBoundary label="OLLAMA PANEL">
        <OllamaPanel target={analyzeTarget} onClose={() => setAnalyzeTarget(null)} />
      </ErrorBoundary>

      {/* ── Keyboard shortcuts overlay ──────────────── */}
      {showKeyHelp && <KeyboardHelp onClose={() => setShowKeyHelp(false)} />}

      {/* ── Mobile bottom navigation ────────────────── */}
      <nav className="mobile-nav">
        {TABS.map(tab => {
          const Icon     = tab.icon
          const isActive = activeTab === tab.id
          const accentColor = tab.accent ? 'var(--color-info)' : 'var(--color-primary)'
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className="flex flex-col items-center justify-center gap-0.5 px-3 py-2 min-w-[52px] font-mono text-[0.38rem] tracking-widest transition-colors shrink-0"
              style={{
                color:      isActive ? accentColor : 'var(--text-ghost)',
                background: isActive ? (tab.accent ? 'rgba(170,68,255,0.08)' : 'rgba(0,212,255,0.06)') : 'transparent',
                borderTop:  isActive ? `2px solid ${accentColor}` : '2px solid transparent',
              }}
            >
              <Icon size={14} />
              <span className="leading-none">{tab.label.split(' ')[0]}</span>
            </button>
          )
        })}
        {/* Theme toggle in mobile nav */}
        <button
          onClick={toggleTheme}
          className="flex flex-col items-center justify-center gap-0.5 px-3 py-2 min-w-[52px] font-mono text-[0.38rem] tracking-widest text-[var(--text-ghost)] hover:text-[var(--color-primary)] transition-colors shrink-0 border-t-2 border-transparent"
        >
          {theme === 'light' ? <Moon size={14} /> : <Sun size={14} />}
          <span>{theme === 'light' ? 'DARK' : 'LIGHT'}</span>
        </button>
      </nav>
    </div>
  )
}
