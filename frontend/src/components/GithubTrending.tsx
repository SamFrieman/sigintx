import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Github, Star, GitFork, Shield, RefreshCw,
  ExternalLink, AlertTriangle, Clock,
} from 'lucide-react'
import { API_BASE } from '@/hooks/useApi'
import { timeAgo } from '@/lib/utils'

interface TrendingRepo {
  full_name:   string
  owner:       string
  name:        string
  url:         string
  description: string
  language:    string
  total_stars: number
  forks:       number
  stars_week:  number
  security:    boolean
}

interface TrendingData {
  repos:      TrendingRepo[]
  fetched_at: string | null
  error:      string | null
}

// Language → color (covers the most common ones)
const LANG_COLORS: Record<string, string> = {
  Python:     '#3572A5', TypeScript: '#2b7489', JavaScript: '#f1e05a',
  Go:         '#00ADD8', Rust:       '#dea584', C:          '#555555',
  'C++':      '#f34b7d', 'C#':       '#178600', Java:       '#b07219',
  Kotlin:     '#A97BFF', Swift:      '#ffac45', Ruby:       '#701516',
  PHP:        '#4F5D95', Shell:      '#89e051', PowerShell: '#012456',
  Dockerfile: '#384d54', HTML:       '#e34c26', CSS:        '#563d7c',
  Lua:        '#000080', Nim:        '#ffc200', Zig:        '#ec915c',
}

function fmt(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`
  return String(n)
}

export function GithubTrending() {
  const [data, setData]         = useState<TrendingData | null>(null)
  const [loading, setLoading]   = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [hovered, setHovered]   = useState<string | null>(null)

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const r = await fetch(`${API_BASE}/github/trending`)
      if (r.ok) setData(await r.json())
    } catch { /* ignore */ } finally {
      setLoading(false)
    }
  }, [])

  // Initial load + auto-refresh every 20 min
  // Also retry after 10s in case the backend cache was still warming on first call
  useEffect(() => {
    load()
    const retryId = setTimeout(() => load(true), 10_000)
    const id      = setInterval(() => load(true), 20 * 60 * 1000)
    return () => {
      clearTimeout(retryId)
      clearInterval(id)
    }
  }, [load])

  const manualRefresh = async () => {
    setRefreshing(true)
    try {
      await fetch(`${API_BASE}/github/trending/refresh`, { method: 'POST' })
      await load(true)
    } catch { /* ignore */ } finally {
      setRefreshing(false)
    }
  }

  const repos     = data?.repos      ?? []
  const fetchedAt = data?.fetched_at ?? null
  const hasError  = !!data?.error && repos.length === 0
  const secCount  = repos.filter(r => r.security).length

  return (
    <div className="panel flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <Github size={11} className="text-[var(--color-primary)]" />
          <span className="panel-title">GITHUB TRENDING</span>
          <span className="font-mono text-[0.44rem] text-[var(--text-ghost)] tracking-widest">WEEKLY</span>
          {secCount > 0 && (
            <span
              className="font-mono text-[0.42rem] tracking-widest px-1.5 py-0.5 border"
              style={{
                color:       'var(--color-warning)',
                borderColor: 'rgba(255,170,0,0.35)',
                background:  'rgba(255,170,0,0.06)',
              }}
            >
              {secCount} SECURITY
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {fetchedAt && (
            <span className="font-mono text-[0.42rem] text-[var(--text-ghost)] flex items-center gap-1">
              <Clock size={7} />
              {timeAgo(fetchedAt)}
            </span>
          )}
          <button
            onClick={manualRefresh}
            disabled={refreshing || loading}
            className="flex items-center gap-1 px-2 py-1 border border-[var(--border-base)] font-mono text-[0.44rem] tracking-widest text-[var(--text-dim)] hover:text-[var(--color-primary)] hover:border-[var(--border-accent)] transition-colors disabled:opacity-40"
            title="Refresh GitHub trending"
          >
            <RefreshCw size={7} className={(refreshing || loading) ? 'animate-spin' : ''} />
            REFRESH
          </button>
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto min-h-0">
        {loading && repos.length === 0 && (
          <div className="py-8 flex flex-col items-center gap-2">
            <Github size={20} className="text-[var(--text-ghost)] animate-pulse" />
            <p className="font-mono text-[0.55rem] text-[var(--text-ghost)] tracking-widest animate-pulse">
              FETCHING TRENDING REPOS…
            </p>
          </div>
        )}

        {hasError && (
          <div className="py-8 flex flex-col items-center gap-2 px-4 text-center">
            <AlertTriangle size={18} className="text-[var(--color-warning)]" />
            <p className="font-mono text-[0.55rem] text-[var(--color-warning)] tracking-widest">
              FETCH FAILED
            </p>
            <p className="font-mono text-[0.5rem] text-[var(--text-ghost)] max-w-xs leading-relaxed">
              {data?.error}
            </p>
          </div>
        )}

        <AnimatePresence initial={false}>
          {repos.map((repo, i) => (
            <motion.a
              key={repo.full_name}
              href={repo.url}
              target="_blank"
              rel="noopener noreferrer"
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.02 }}
              onMouseEnter={() => setHovered(repo.full_name)}
              onMouseLeave={() => setHovered(null)}
              className="flex items-start gap-2 px-3 py-2 border-b border-[var(--border-base)] transition-colors cursor-pointer block"
              style={{
                background: hovered === repo.full_name
                  ? 'var(--bg-card-hover)'
                  : repo.security
                    ? 'rgba(255,170,0,0.02)'
                    : 'transparent',
              }}
            >
              {/* Rank */}
              <span className="font-mono text-[0.44rem] text-[var(--text-ghost)] w-4 shrink-0 mt-0.5 text-right">
                {i + 1}
              </span>

              {/* Main content */}
              <div className="flex-1 min-w-0">
                {/* Name row */}
                <div className="flex items-center gap-1.5 flex-wrap">
                  {repo.security && (
                    <span title="Security-related">
                      <Shield size={9} className="shrink-0" style={{ color: 'var(--color-warning)' }} />
                    </span>
                  )}
                  <span
                    className="font-mono text-[0.6rem] font-medium truncate"
                    style={{
                      color: repo.security
                        ? 'var(--color-warning)'
                        : hovered === repo.full_name
                          ? 'var(--color-primary)'
                          : 'var(--text-secondary)',
                    }}
                  >
                    {repo.owner}
                    <span className="text-[var(--text-ghost)]">/</span>
                    {repo.name}
                  </span>
                  <ExternalLink size={7} className="text-[var(--text-ghost)] shrink-0 opacity-0 group-hover:opacity-100" />
                </div>

                {/* Description */}
                {repo.description && (
                  <p className="font-mono text-[0.5rem] text-[var(--text-muted)] leading-relaxed mt-0.5 line-clamp-1">
                    {repo.description}
                  </p>
                )}

                {/* Meta row */}
                <div className="flex items-center gap-3 mt-1 flex-wrap">
                  {/* Language dot */}
                  {repo.language && (
                    <span className="flex items-center gap-1">
                      <span
                        className="w-2 h-2 rounded-full shrink-0"
                        style={{ background: LANG_COLORS[repo.language] ?? 'var(--text-ghost)' }}
                      />
                      <span className="font-mono text-[0.44rem] text-[var(--text-ghost)]">
                        {repo.language}
                      </span>
                    </span>
                  )}

                  {/* Total stars */}
                  <span className="flex items-center gap-0.5 text-[var(--text-ghost)]">
                    <Star size={7} />
                    <span className="font-mono text-[0.44rem]">{fmt(repo.total_stars)}</span>
                  </span>

                  {/* Forks */}
                  {repo.forks > 0 && (
                    <span className="flex items-center gap-0.5 text-[var(--text-ghost)]">
                      <GitFork size={7} />
                      <span className="font-mono text-[0.44rem]">{fmt(repo.forks)}</span>
                    </span>
                  )}
                </div>
              </div>

              {/* Stars this week — right column */}
              <div className="shrink-0 flex flex-col items-end gap-0.5 ml-1">
                <span
                  className="font-mono text-[0.6rem] font-semibold tabular-nums"
                  style={{ color: repo.security ? 'var(--color-warning)' : 'var(--color-primary)' }}
                >
                  +{fmt(repo.stars_week)}
                </span>
                <span className="font-mono text-[0.38rem] text-[var(--text-ghost)] whitespace-nowrap">
                  this week
                </span>
              </div>
            </motion.a>
          ))}
        </AnimatePresence>

        {!loading && repos.length === 0 && !hasError && (
          <div className="py-8 text-center">
            <p className="font-mono text-[0.55rem] text-[var(--text-ghost)] tracking-widest">
              NO DATA — CLICK REFRESH
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
