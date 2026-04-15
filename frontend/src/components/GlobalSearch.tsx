/**
 * GlobalSearch — Cmd+K / Ctrl+K overlay search across news and CVEs.
 */
import { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Search, X, ExternalLink, Shield, Rss } from 'lucide-react'
import type { NewsItem, CVEItem } from '@/types'
import { sevColor, timeAgo } from '@/lib/utils'

interface Props {
  onNavigate: (tab: string) => void
}

interface SearchResults {
  news: NewsItem[]
  cves: CVEItem[]
}

async function searchAll(query: string): Promise<SearchResults> {
  if (!query.trim()) return { news: [], cves: [] }
  const [newsRes, cvesRes] = await Promise.all([
    fetch(`/api/v1/news?search=${encodeURIComponent(query)}&limit=8`).then(r => r.json()),
    fetch(`/api/v1/cves?search=${encodeURIComponent(query)}&limit=6`).then(r => r.json()),
  ])
  return { news: newsRes, cves: cvesRes }
}

export function GlobalSearch({ onNavigate }: Props) {
  const [open, setOpen]           = useState(false)
  const [query, setQuery]         = useState('')
  const [results, setResults]     = useState<SearchResults | null>(null)
  const [loading, setLoading]     = useState(false)
  const [selected, setSelected]   = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Keyboard shortcut to open
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setOpen(o => !o)
      }
      if (e.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  // Focus input when opened
  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 50)
      setQuery('')
      setResults(null)
      setSelected(0)
    }
  }, [open])

  // Debounced search
  useEffect(() => {
    if (!query.trim()) { setResults(null); return }
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(async () => {
      setLoading(true)
      try {
        const r = await searchAll(query)
        setResults(r)
        setSelected(0)
      } finally {
        setLoading(false)
      }
    }, 280)
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
  }, [query])

  const allResults = [
    ...(results?.news ?? []).map(n => ({ type: 'news' as const, item: n })),
    ...(results?.cves ?? []).map(c => ({ type: 'cve'  as const, item: c })),
  ]

  // Arrow key navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown')  { e.preventDefault(); setSelected(s => Math.min(s + 1, allResults.length - 1)) }
    if (e.key === 'ArrowUp')    { e.preventDefault(); setSelected(s => Math.max(s - 1, 0)) }
    if (e.key === 'Enter' && allResults[selected]) {
      const r = allResults[selected]
      if (r.type === 'news') { onNavigate('news'); setOpen(false) }
      else { onNavigate('cves'); setOpen(false) }
    }
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="hidden sm:flex items-center gap-2 px-3 py-1 border border-[var(--border-base)] bg-[var(--bg-card)] hover:border-[var(--border-accent)] text-[var(--text-dim)] hover:text-[var(--text-secondary)] transition-colors"
        title="Global search (Ctrl+K)"
      >
        <Search size={10} />
        <span className="font-mono text-[0.52rem] tracking-widest">SEARCH</span>
        <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] border border-[var(--border-base)] px-1 py-0.5">⌘K</span>
      </button>
    )
  }

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-[9000] flex items-start justify-center pt-[12vh]"
        style={{ background: 'rgba(3,6,9,0.85)', backdropFilter: 'blur(4px)' }}
        onClick={() => setOpen(false)}
      >
        <motion.div
          initial={{ opacity: 0, y: -16, scale: 0.97 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.15 }}
          className="w-full max-w-2xl mx-4"
          onClick={e => e.stopPropagation()}
        >
          {/* Search input */}
          <div className="border border-[var(--border-accent)] bg-[var(--bg-card)] flex items-center gap-3 px-4 py-3">
            <Search size={14} className="text-[var(--color-primary)] shrink-0" />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Search news, CVEs, threat actors…"
              className="flex-1 bg-transparent font-mono text-[0.82rem] text-[var(--text-base)] placeholder-[var(--text-ghost)] outline-none"
            />
            {loading && (
              <div className="w-3 h-3 border border-[var(--color-primary)] border-t-transparent rounded-full animate-spin shrink-0" />
            )}
            <button onClick={() => setOpen(false)} className="text-[var(--text-dim)] hover:text-[var(--text-base)] shrink-0">
              <X size={13} />
            </button>
          </div>

          {/* Results */}
          {results && (
            <div className="border border-t-0 border-[var(--border-base)] bg-[var(--bg-surface)] max-h-[60vh] overflow-y-auto">
              {allResults.length === 0 && (
                <div className="py-8 text-center font-mono text-[0.62rem] text-[var(--text-ghost)] tracking-widest">
                  NO RESULTS FOR "{query}"
                </div>
              )}

              {/* News results */}
              {results.news.length > 0 && (
                <>
                  <div className="px-4 py-2 border-b border-[var(--border-base)] flex items-center gap-1.5">
                    <Rss size={9} className="text-[var(--text-dim)]" />
                    <span className="font-mono text-[0.48rem] text-[var(--text-dim)] tracking-widest uppercase">News</span>
                  </div>
                  {results.news.map((item, i) => {
                    const idx = i
                    return (
                      <div
                        key={item.id}
                        className="flex items-start gap-3 px-4 py-2.5 border-b border-[var(--border-base)] cursor-pointer transition-colors"
                        style={{ background: selected === idx ? 'var(--bg-elevated)' : 'transparent' }}
                        onMouseEnter={() => setSelected(idx)}
                        onClick={() => { onNavigate('news'); setOpen(false) }}
                      >
                        <div
                          className="w-[2px] self-stretch shrink-0 rounded"
                          style={{ background: sevColor(item.severity) }}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <span className="font-mono text-[0.48rem] tracking-wide text-[var(--text-dim)]">{item.source}</span>
                            <span className="font-mono text-[0.45rem] text-[var(--text-ghost)]">{timeAgo(item.published_at)}</span>
                            <span className="font-mono text-[0.46rem] tracking-widest ml-auto" style={{ color: sevColor(item.severity) }}>
                              {item.severity}
                            </span>
                          </div>
                          <p className="font-heading text-[0.78rem] text-[var(--text-secondary)] line-clamp-1">{item.title}</p>
                        </div>
                        <a href={item.url} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}>
                          <ExternalLink size={9} className="text-[var(--text-ghost)] hover:text-[var(--color-primary)] mt-1" />
                        </a>
                      </div>
                    )
                  })}
                </>
              )}

              {/* CVE results */}
              {results.cves.length > 0 && (
                <>
                  <div className="px-4 py-2 border-b border-[var(--border-base)] flex items-center gap-1.5">
                    <Shield size={9} className="text-[var(--text-dim)]" />
                    <span className="font-mono text-[0.48rem] text-[var(--text-dim)] tracking-widest uppercase">CVEs</span>
                  </div>
                  {results.cves.map((cve, i) => {
                    const idx = (results?.news.length ?? 0) + i
                    return (
                      <div
                        key={cve.id}
                        className="flex items-center gap-3 px-4 py-2.5 border-b border-[var(--border-base)] cursor-pointer transition-colors"
                        style={{ background: selected === idx ? 'var(--bg-elevated)' : 'transparent' }}
                        onMouseEnter={() => setSelected(idx)}
                        onClick={() => { onNavigate('cves'); setOpen(false) }}
                      >
                        <div
                          className="w-[2px] self-stretch shrink-0 rounded"
                          style={{ background: sevColor(cve.severity) }}
                        />
                        <div className="flex items-center gap-2 flex-1 min-w-0">
                          <span className="font-code text-[0.72rem] text-[var(--color-primary)] shrink-0">{cve.cve_id}</span>
                          {cve.in_kev && <span className="kev-badge shrink-0">KEV</span>}
                          <p className="font-heading text-[0.75rem] text-[var(--text-secondary)] truncate">
                            {cve.description ?? 'No description'}
                          </p>
                        </div>
                        {cve.cvss_score !== null && (
                          <span className="font-mono text-[0.65rem] shrink-0" style={{ color: sevColor(cve.severity) }}>
                            {cve.cvss_score.toFixed(1)}
                          </span>
                        )}
                      </div>
                    )
                  })}
                </>
              )}

              {/* Footer hint */}
              <div className="px-4 py-2 flex items-center gap-3 border-t border-[var(--border-base)]">
                <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-wider">↑↓ navigate</span>
                <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-wider">↵ go to tab</span>
                <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-wider">Esc close</span>
              </div>
            </div>
          )}

          {!results && !loading && query.length > 0 && (
            <div className="border border-t-0 border-[var(--border-base)] bg-[var(--bg-surface)] py-6 text-center font-mono text-[0.6rem] text-[var(--text-ghost)] tracking-widest">
              SEARCHING…
            </div>
          )}

          {!query && (
            <div className="border border-t-0 border-[var(--border-base)] bg-[var(--bg-surface)] px-4 py-4">
              <p className="font-mono text-[0.55rem] text-[var(--text-dim)] tracking-widest mb-3">SEARCH ACROSS</p>
              <div className="flex gap-2 flex-wrap">
                {['NEWS HEADLINES', 'CVE IDs', 'CVE DESCRIPTIONS', 'THREAT ACTORS'].map(h => (
                  <span key={h} className="font-mono text-[0.5rem] tracking-wider px-2 py-1 border border-[var(--border-base)] text-[var(--text-ghost)]">{h}</span>
                ))}
              </div>
            </div>
          )}
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
}
