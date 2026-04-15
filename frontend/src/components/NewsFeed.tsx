import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ExternalLink, ChevronDown, ChevronUp, Search, Filter, Cpu } from 'lucide-react'
import type { NewsItem, SeverityLevel, AnalyzeTarget, NewsCategory } from '@/types'
import { useApi } from '@/hooks/useApi'
import { sevColor, sevBg, sevBorder, timeAgo } from '@/lib/utils'

const SEV_LEVELS: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']

type CategoryTab = 'all' | NewsCategory

interface CategoryConfig {
  id: CategoryTab
  label: string
  color: string
}

const CATEGORY_TABS: CategoryConfig[] = [
  { id: 'all',      label: 'ALL',      color: 'var(--color-primary)' },
  { id: 'security', label: 'SECURITY', color: '#ff4444' },
  { id: 'tech',     label: 'TECH',     color: '#00d4ff' },
  { id: 'crypto',   label: 'CRYPTO',   color: '#f7931a' },
  { id: 'politics', label: 'POLITICS', color: '#a855f7' },
  { id: 'ai',       label: 'AI',       color: '#22d3a5' },
]

const CATEGORY_BADGE: Record<string, { label: string; color: string }> = {
  security: { label: 'SEC',   color: '#ff4444' },
  tech:     { label: 'TECH',  color: '#00d4ff' },
  crypto:   { label: 'CRYPTO',color: '#f7931a' },
  politics: { label: 'POL',   color: '#a855f7' },
  ai:       { label: 'AI',    color: '#22d3a5' },
}

interface Props {
  refreshTrigger: number
  onAnalyze?: (target: AnalyzeTarget) => void
}

function SeverityBar({ sev }: { sev: SeverityLevel }) {
  return (
    <div
      className="sev-bar"
      style={{
        background: sevColor(sev),
        boxShadow: sev === 'CRITICAL' ? `0 0 8px ${sevColor(sev)}90` : undefined,
      }}
    />
  )
}

function SeverityBadge({ sev }: { sev: SeverityLevel }) {
  return (
    <span
      className="font-mono text-[0.55rem] tracking-widest px-1.5 py-0.5 border uppercase shrink-0"
      style={{
        color: sevColor(sev),
        background: sevBg(sev),
        borderColor: sevBorder(sev),
      }}
    >
      {sev}
    </span>
  )
}

function CategoryBadge({ category }: { category: string }) {
  const cfg = CATEGORY_BADGE[category]
  if (!cfg) return null
  return (
    <span
      className="font-mono text-[0.48rem] tracking-widest px-1 py-0.5 border shrink-0"
      style={{ color: cfg.color, borderColor: `${cfg.color}44`, background: `${cfg.color}11` }}
    >
      {cfg.label}
    </span>
  )
}

function NewsCard({ item, isNew, onAnalyze }: { item: NewsItem; isNew: boolean; onAnalyze?: (t: AnalyzeTarget) => void }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <motion.div
      layout
      initial={isNew ? { opacity: 0, y: -10 } : false}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.22 }}
      className="flex gap-3 px-4 py-3 border-b border-[var(--border-base)] hover:bg-[var(--bg-card-hover)] cursor-pointer group"
      onClick={() => item.summary && setExpanded(e => !e)}
    >
      <SeverityBar sev={item.severity} />

      <div className="flex-1 min-w-0">
        {/* Meta row */}
        <div className="flex items-center gap-2 mb-1 flex-wrap">
          <span className="font-mono text-[0.58rem] text-[var(--text-dim)] tracking-wider shrink-0">
            {item.source}
          </span>
          <span className="font-mono text-[0.52rem] text-[var(--text-ghost)]">
            {timeAgo(item.published_at)}
          </span>
          <CategoryBadge category={item.category} />
          {item.cve_refs.slice(0, 2).map(cve => (
            <span key={cve} className="cve-chip">{cve}</span>
          ))}
        </div>

        {/* Headline */}
        <a
          href={item.url}
          target="_blank"
          rel="noopener noreferrer"
          onClick={e => e.stopPropagation()}
          className="block font-heading font-semibold text-[0.92rem] text-[var(--text-base)] hover:text-[var(--color-primary)] leading-snug mb-1.5 group-hover:text-[var(--text-base)]"
        >
          {item.title}
          <ExternalLink size={11} className="inline ml-1.5 opacity-0 group-hover:opacity-60" />
        </a>

        {/* Tags + actors + analyze */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <SeverityBadge sev={item.severity} />
          {item.tags.slice(0, 4).map(t => (
            <span key={t} className="tag-chip">{t}</span>
          ))}
          {item.threat_actors.slice(0, 2).map(a => (
            <span key={a} className="actor-chip">{a}</span>
          ))}
          {onAnalyze && item.category === 'security' && (
            <button
              onClick={e => { e.stopPropagation(); onAnalyze({ type: 'news', item }) }}
              className="font-mono text-[0.5rem] tracking-widest px-1.5 py-0.5 border opacity-0 group-hover:opacity-70 hover:!opacity-100 transition-opacity"
              style={{ color: 'var(--color-primary)', borderColor: 'var(--border-accent)' }}
              title="Analyze with AI"
            >
              <Cpu size={9} className="inline mr-0.5" />AI
            </button>
          )}
        </div>

        {/* Expanded summary */}
        <AnimatePresence>
          {expanded && item.summary && (
            <motion.p
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="mt-2 text-[0.82rem] text-[var(--text-secondary)] leading-relaxed overflow-hidden"
            >
              {item.summary}
            </motion.p>
          )}
        </AnimatePresence>
      </div>

      {item.summary && (
        <div className="shrink-0 mt-0.5 text-[var(--text-dim)] opacity-0 group-hover:opacity-60">
          {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        </div>
      )}
    </motion.div>
  )
}

export function NewsFeed({ refreshTrigger, onAnalyze }: Props) {
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | ''>('')
  const [activeCategory, setActiveCategory] = useState<CategoryTab>('all')
  const [limit, setLimit] = useState(50)
  const [seenIds, setSeenIds] = useState<Set<number>>(new Set())
  const prevDataRef = useRef<NewsItem[]>([])

  const params = {
    limit,
    ...(severityFilter && { severity: severityFilter }),
    ...(search && { search }),
    ...(activeCategory !== 'all' && { category: activeCategory }),
  }

  const { data: items, loading } = useApi<NewsItem[]>(
    '/news', params, refreshTrigger, 30_000
  )

  // Track new items for animation
  useEffect(() => {
    if (!items) return
    const newIds = new Set(items.map(i => i.id))
    const prevIds = new Set(prevDataRef.current.map(i => i.id))
    const fresh: Set<number> = new Set([...newIds].filter(id => !prevIds.has(id)))
    setSeenIds(fresh)
    prevDataRef.current = items
  }, [items])

  const activeTab = CATEGORY_TABS.find(t => t.id === activeCategory)!

  return (
    <div className="panel flex flex-col h-full">
      {/* Panel header */}
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <span className="live-dot" />
          <span className="panel-title">Live Intel Feed</span>
          {items && (
            <span className="font-mono text-[0.55rem] text-[var(--text-ghost)]">
              [{items.length}]
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5">
          {SEV_LEVELS.map(s => (
            <button
              key={s}
              onClick={() => setSeverityFilter(prev => prev === s ? '' : s)}
              className="font-mono text-[0.52rem] tracking-wider px-1.5 py-0.5 border transition-all"
              style={{
                color: severityFilter === s ? sevColor(s) : 'var(--text-ghost)',
                background: severityFilter === s ? sevBg(s) : 'transparent',
                borderColor: severityFilter === s ? sevBorder(s) : 'var(--border-base)',
              }}
            >
              {s[0]}
            </button>
          ))}
        </div>
      </div>

      {/* Category tabs */}
      <div className="flex items-center gap-0 border-b border-[var(--border-base)] overflow-x-auto scrollbar-none shrink-0">
        {CATEGORY_TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => { setActiveCategory(tab.id); setLimit(50) }}
            className="relative font-mono text-[0.52rem] tracking-widest px-3 py-2 whitespace-nowrap shrink-0 transition-colors"
            style={{
              color: activeCategory === tab.id ? tab.color : 'var(--text-ghost)',
              background: activeCategory === tab.id ? `${tab.color}0d` : 'transparent',
            }}
          >
            {tab.label}
            {activeCategory === tab.id && (
              <motion.div
                layoutId="news-cat-indicator"
                className="absolute bottom-0 left-0 right-0 h-[2px]"
                style={{ background: tab.color }}
                transition={{ type: 'spring', stiffness: 400, damping: 35 }}
              />
            )}
          </button>
        ))}
      </div>

      {/* Search bar */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-[var(--border-base)] bg-[var(--bg-surface)] shrink-0">
        <Search size={12} className="text-[var(--text-dim)] shrink-0" />
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder={`Search ${activeCategory === 'all' ? 'all feeds' : activeCategory} headlines...`}
          className="flex-1 bg-transparent font-mono text-[0.72rem] text-[var(--text-secondary)] placeholder-[var(--text-ghost)] outline-none tracking-wide"
        />
        {search && (
          <button onClick={() => setSearch('')} className="text-[var(--text-dim)] hover:text-[var(--text-base)]">
            <Filter size={11} />
          </button>
        )}
      </div>

      {/* Feed items */}
      <div className="flex-1 overflow-y-auto min-h-0">
        {loading && !items && (
          <div className="flex flex-col gap-0">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="flex gap-3 px-4 py-3 border-b border-[var(--border-base)] animate-pulse">
                <div className="w-[3px] rounded bg-[var(--border-base)] self-stretch" />
                <div className="flex-1 space-y-1.5">
                  <div className="h-2 bg-[var(--bg-elevated)] rounded w-24" />
                  <div className="h-3.5 bg-[var(--bg-elevated)] rounded w-3/4" />
                  <div className="h-2 bg-[var(--bg-elevated)] rounded w-1/2" />
                </div>
              </div>
            ))}
          </div>
        )}

        {items && items.length === 0 && (
          <div className="flex items-center justify-center h-32 font-mono text-[0.65rem] text-[var(--text-ghost)] tracking-widest">
            NO ITEMS — COLLECTING...
          </div>
        )}

        {items && (
          <AnimatePresence initial={false}>
            {items.map(item => (
              <NewsCard key={item.id} item={item} isNew={seenIds.has(item.id)} onAnalyze={onAnalyze} />
            ))}
          </AnimatePresence>
        )}

        {/* Load more */}
        {items && items.length >= limit && (
          <button
            onClick={() => setLimit(l => l + 50)}
            className="w-full py-2.5 font-mono text-[0.6rem] tracking-widest text-[var(--text-dim)] hover:text-[var(--color-primary)] hover:bg-[var(--bg-elevated)] border-t border-[var(--border-base)] transition-colors"
          >
            LOAD MORE ↓
          </button>
        )}
      </div>
    </div>
  )
}
