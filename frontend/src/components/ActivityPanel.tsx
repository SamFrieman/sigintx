/**
 * ActivityPanel — Compact critical/high threat feed for the dashboard hero row.
 * Receives pre-fetched news so no extra API call is made.
 */
import { motion } from 'framer-motion'
import { Zap, ExternalLink } from 'lucide-react'
import type { NewsItem, AnalyzeTarget } from '@/types'
import { sevColor, timeAgo } from '@/lib/utils'

interface Props {
  news: NewsItem[]
  onAnalyze?: (target: AnalyzeTarget) => void
}

export function ActivityPanel({ news, onAnalyze }: Props) {
  const items = news
    .filter(n => n.severity === 'CRITICAL' || n.severity === 'HIGH')
    .slice(0, 30)

  return (
    <div className="panel flex flex-col h-full">
      {/* Header */}
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <Zap size={11} className="text-[var(--color-danger)]" />
          <span className="panel-title">CRITICAL ACTIVITY</span>
          <span className="live-dot" />
        </div>
        <span
          className="font-mono text-[0.48rem] tracking-widest px-2 py-0.5 border"
          style={{ color: 'var(--color-danger)', borderColor: 'rgba(255,34,85,0.3)', background: 'rgba(255,34,85,0.07)' }}
        >
          {items.length} ACTIVE
        </span>
      </div>

      {/* Feed */}
      <div className="flex-1 overflow-y-auto min-h-0">
        {items.length === 0 && (
          <div className="flex items-center justify-center h-full">
            <span className="font-mono text-[0.58rem] text-[var(--text-dim)] tracking-widest">
              NO CRITICAL ACTIVITY DETECTED
            </span>
          </div>
        )}

        {items.map((item, i) => (
          <motion.div
            key={item.id}
            initial={{ opacity: 0, x: -6 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.018, duration: 0.2 }}
            className="flex gap-2 px-3 py-2 border-b border-[var(--border-base)] hover:bg-[var(--bg-card-hover)] group"
          >
            {/* Severity bar */}
            <div
              className="w-[2px] self-stretch shrink-0 rounded-full mt-0.5"
              style={{
                background: sevColor(item.severity),
                boxShadow: item.severity === 'CRITICAL' ? `0 0 6px ${sevColor(item.severity)}80` : 'none',
              }}
            />

            <div className="flex-1 min-w-0">
              {/* Meta row */}
              <div className="flex items-center gap-1.5 mb-0.5 flex-wrap">
                <span
                  className="font-mono text-[0.48rem] tracking-widest uppercase"
                  style={{ color: sevColor(item.severity) }}
                >
                  {item.severity}
                </span>
                <span className="font-mono text-[0.45rem] text-[var(--text-ghost)]">·</span>
                <span className="font-mono text-[0.48rem] text-[var(--text-dim)] uppercase tracking-wide">
                  {item.source}
                </span>
                <span className="ml-auto font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-wider shrink-0">
                  {timeAgo(item.published_at)}
                </span>
              </div>

              {/* Title */}
              <p className="font-heading text-[0.72rem] text-[var(--text-secondary)] leading-snug line-clamp-2 group-hover:text-[var(--text-base)] transition-colors">
                {item.title}
              </p>

              {/* CVE refs + actions */}
              <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                {item.cve_refs.slice(0, 2).map(cve => (
                  <span
                    key={cve}
                    className="font-mono text-[0.46rem] px-1 py-0.5 border shrink-0"
                    style={{ color: '#00d4ff', background: 'rgba(0,212,255,0.07)', borderColor: 'rgba(0,212,255,0.2)' }}
                  >
                    {cve}
                  </span>
                ))}
                {item.threat_actors.slice(0, 1).map(actor => (
                  <span
                    key={actor}
                    className="font-mono text-[0.46rem] px-1 py-0.5 border shrink-0"
                    style={{ color: '#aa44ff', background: 'rgba(170,68,255,0.07)', borderColor: 'rgba(170,68,255,0.2)' }}
                  >
                    {actor}
                  </span>
                ))}
                <div className="ml-auto flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                  {onAnalyze && (
                    <button
                      onClick={() => onAnalyze({ type: 'news', item })}
                      className="font-mono text-[0.45rem] tracking-widest px-1.5 py-0.5 border border-[var(--border-accent)] text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.08)] transition-colors"
                    >
                      AI
                    </button>
                  )}
                  <a
                    href={item.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={e => e.stopPropagation()}
                    className="text-[var(--text-dim)] hover:text-[var(--color-primary)] transition-colors"
                  >
                    <ExternalLink size={9} />
                  </a>
                </div>
              </div>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  )
}
