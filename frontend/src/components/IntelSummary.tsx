import { motion } from 'framer-motion'
import { Activity, Users, type LucideIcon } from 'lucide-react'
import type { Stats } from '@/types'

interface Props {
  stats: Stats | null
  loading: boolean
}

interface MetricDef {
  label: string
  value: (s: Stats) => number
  color: string
  accentBorder?: boolean
  icon: LucideIcon
  sub: (s: Stats) => string
}

const METRICS: MetricDef[] = [
  {
    label: 'NEWS ITEMS',
    value: s => s.news_total,
    color: 'var(--color-primary)',
    icon: Activity,
    sub: s => `${s.critical_news} critical`,
  },
  {
    label: 'THREAT ACTORS',
    value: s => s.threat_actors,
    color: 'var(--color-info)',
    icon: Users,
    sub: () => 'MITRE mapped',
  },
]

function Skeleton() {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-2 gap-1.5">
      {Array.from({ length: 2 }).map((_, i) => (
        <div key={i} className="border border-[var(--border-base)] bg-[var(--bg-card)] px-3 py-2.5 animate-pulse">
          <div className="h-1.5 w-16 bg-[var(--bg-elevated)] rounded mb-2" />
          <div className="h-5 w-10 bg-[var(--bg-elevated)] rounded mb-1.5" />
          <div className="h-1.5 w-12 bg-[var(--bg-elevated)] rounded opacity-50" />
        </div>
      ))}
    </div>
  )
}

export function IntelSummary({ stats, loading }: Props) {
  if (loading || !stats) return <Skeleton />

  return (
    <div className="grid grid-cols-2 sm:grid-cols-2 gap-1.5">
      {METRICS.map((m, i) => {
        const Icon = m.icon
        const val  = m.value(stats)
        return (
          <motion.div
            key={m.label}
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.04, duration: 0.22 }}
            className="border border-[var(--border-base)] bg-[var(--bg-card)] px-3 py-2.5 relative overflow-hidden"
            style={m.accentBorder ? { borderLeft: `2px solid ${m.color}` } : {}}
          >
            {/* Ambient glow */}
            <div
              className="absolute -top-4 -right-4 w-12 h-12 rounded-full opacity-10 blur-xl pointer-events-none"
              style={{ background: m.color }}
            />

            {/* Label + icon */}
            <div className="flex items-center justify-between mb-1.5">
              <span className="font-mono text-[0.48rem] tracking-widest text-[var(--text-dim)] uppercase">
                {m.label}
              </span>
              <Icon size={9} color={m.color} className="opacity-50" />
            </div>

            {/* Value */}
            <div className="font-mono font-bold text-xl leading-none" style={{ color: m.color }}>
              {val.toLocaleString()}
            </div>

            {/* Sub-label */}
            <div className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-wider mt-1 truncate">
              {m.sub(stats)}
            </div>
          </motion.div>
        )
      })}
    </div>
  )
}
