import { useEffect, useState } from 'react'
import { AlertOctagon, RefreshCw } from 'lucide-react'
import type { ThreatLevel } from '@/types'
import { API_BASE } from '@/hooks/useApi'

const LEVEL_CONFIG: Record<number, { color: string; bg: string; border: string; glow: string }> = {
  1: { color: '#ff1a1a', bg: 'rgba(255,26,26,0.12)',  border: 'rgba(255,26,26,0.5)',  glow: '0 0 24px rgba(255,26,26,0.4)' },
  2: { color: '#ff6600', bg: 'rgba(255,102,0,0.1)',   border: 'rgba(255,102,0,0.45)', glow: '0 0 16px rgba(255,102,0,0.3)' },
  3: { color: '#ffcc00', bg: 'rgba(255,204,0,0.08)',  border: 'rgba(255,204,0,0.4)',  glow: '0 0 12px rgba(255,204,0,0.2)' },
  4: { color: '#00aaff', bg: 'rgba(0,170,255,0.07)',  border: 'rgba(0,170,255,0.35)', glow: 'none' },
  5: { color: '#22c55e', bg: 'rgba(34,197,94,0.06)',  border: 'rgba(34,197,94,0.3)',  glow: 'none' },
}

export function DefconIndicator() {
  const [data, setData]       = useState<ThreatLevel | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchLevel = async () => {
    try {
      const r = await fetch(`${API_BASE}/threat-level`)
      if (r.ok) setData(await r.json())
    } catch { /* silently ignore */ }
    finally { setLoading(false) }
  }

  useEffect(() => {
    fetchLevel()
    const id = setInterval(fetchLevel, 120_000)  // refresh every 2 minutes
    return () => clearInterval(id)
  }, [])

  if (loading) {
    return (
      <div className="panel flex items-center justify-center h-full">
        <div className="font-mono text-[0.6rem] text-[var(--text-ghost)] tracking-widest animate-pulse">
          LOADING THREAT LEVEL...
        </div>
      </div>
    )
  }

  if (!data) return null

  const cfg    = LEVEL_CONFIG[data.level]
  const levels = [1, 2, 3, 4, 5]

  return (
    <div className="panel flex flex-col h-full overflow-hidden" style={{ isolation: 'isolate', contain: 'layout paint' }}>
      {/* Header */}
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <AlertOctagon size={11} style={{ color: cfg.color }} />
          <span className="panel-title">CYBER THREAT LEVEL</span>
        </div>
        <button onClick={fetchLevel} className="text-[var(--text-dim)] hover:text-[var(--color-primary)] transition-colors">
          <RefreshCw size={10} />
        </button>
      </div>

      {/* Main indicator */}
      <div className="flex-1 flex flex-col items-center justify-center gap-4 p-4">
        {/* Level display */}
        <div
          className="flex items-center justify-center w-24 h-24 border-2 rounded-sm"
          style={{
            borderColor: cfg.border,
            background: cfg.bg,
            boxShadow: cfg.glow,
          }}
        >
          <div className="text-center">
            <div
              className="font-mono text-[2.4rem] font-bold leading-none tabular-nums"
              style={{ color: cfg.color }}
            >
              {data.level}
            </div>
            <div
              className="font-mono text-[0.45rem] tracking-widest mt-0.5"
              style={{ color: cfg.color }}
            >
              DEFCON
            </div>
          </div>
        </div>

        {/* Level bars */}
        <div className="flex items-end gap-2 overflow-hidden" style={{ height: 56 }}>
          {levels.map(l => {
            const lCfg   = LEVEL_CONFIG[l]
            const active = l >= data.level    // levels ≥ current are "lit"
            const maxH   = (6 - l) * 10       // l=1→50px, l=2→40px … l=5→10px
            const barH   = active ? maxH : Math.max(3, Math.round(maxH * 0.25))
            return (
              <div
                key={l}
                className="w-5 rounded-sm transition-all duration-700 shrink-0"
                style={{
                  height:     barH,
                  background: active ? lCfg.color : `${lCfg.color}33`,
                  opacity:    active ? 1 : 0.45,
                  boxShadow:  active && l === data.level
                    ? `0 0 10px ${lCfg.color}88` : 'none',
                }}
              />
            )
          })}
        </div>

        {/* Label + description */}
        <div className="text-center max-w-[180px]">
          <div
            className="font-mono text-[0.8rem] tracking-widest font-semibold mb-1"
            style={{ color: cfg.color }}
          >
            {data.label}
          </div>
          <p className="text-[0.75rem] text-[var(--text-secondary)] leading-snug">
            {data.description}
          </p>
        </div>

        {/* Stats grid */}
        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 w-full max-w-[280px]">
          {[
            { label: 'CRITICAL/24H', value: data.critical_news_24h },
            { label: 'HIGH/24H',     value: data.high_news_24h },
            { label: 'ACTORS/7D',    value: data.active_actors_7d },
            { label: 'SCORE',        value: data.score },
          ].map(({ label, value }) => (
            <div key={label} className="flex justify-between items-center">
              <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-wider">{label}</span>
              <span className="font-mono text-[0.55rem]" style={{ color: cfg.color }}>{value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Footer */}
      <div className="px-4 py-1.5 border-t border-[var(--border-base)] shrink-0 text-center">
        <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-widest">
          UPDATES EVERY 2 MIN · BASED ON LIVE THREAT DATA
        </span>
      </div>
    </div>
  )
}
