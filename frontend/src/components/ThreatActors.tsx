import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Users, ExternalLink, ChevronDown, ChevronUp, Search } from 'lucide-react'
import type { ThreatActor, ActivityStatus } from '@/types'
import { useApi } from '@/hooks/useApi'
import { countryFlag } from '@/lib/utils'

interface Props { refreshTrigger: number }

const COUNTRIES = ['Russia', 'China', 'North Korea', 'Iran', 'United States', 'Unknown']

function ActorCard({ actor }: { actor: ThreatActor }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <motion.div
      layout
      className="border-b border-[var(--border-base)] hover:bg-[var(--bg-card-hover)] cursor-pointer"
      onClick={() => setExpanded(e => !e)}
    >
      <div className="flex items-start gap-3 px-4 py-3">
        {/* Left accent bar colored by country group */}
        <div className="w-[3px] self-stretch rounded shrink-0"
          style={{ background: countryColor(actor.country) }} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className="font-heading font-semibold text-[0.92rem] text-[var(--text-base)]">
              {actor.name}
            </span>
            {actor.mitre_id && (
              <a
                href={`https://attack.mitre.org/groups/${actor.mitre_id}/`}
                target="_blank"
                rel="noopener noreferrer"
                onClick={e => e.stopPropagation()}
                className="font-code text-[0.6rem] px-1.5 py-0.5 border hover:border-[var(--color-primary)]"
                style={{ color: '#00d4ff', background: 'rgba(0,212,255,0.07)', borderColor: 'rgba(0,212,255,0.2)' }}
              >
                {actor.mitre_id} <ExternalLink size={8} className="inline" />
              </a>
            )}
          </div>

          <div className="flex items-center gap-2 flex-wrap mb-1.5">
            {actor.country && (
              <span className="font-mono text-[0.62rem] text-[var(--text-muted)]">
                {countryFlag(actor.country)} {actor.country}
              </span>
            )}
            {actor.motivation && (
              <span className="font-mono text-[0.58rem] px-1.5 py-0.5 border"
                style={{ color: '#ffaa00', background: 'rgba(255,170,0,0.08)', borderColor: 'rgba(255,170,0,0.2)' }}>
                {actor.motivation}
              </span>
            )}
            <ActivityBadge status={actor.activity_status} />
          </div>

          {actor.aliases.length > 0 && (
            <div className="flex gap-1 flex-wrap">
              {actor.aliases.slice(0, 4).map(a => (
                <span key={a} className="tag-chip">{a}</span>
              ))}
              {actor.aliases.length > 4 && (
                <span className="tag-chip">+{actor.aliases.length - 4}</span>
              )}
            </div>
          )}
        </div>

        <div className="shrink-0 mt-1 text-[var(--text-dim)] opacity-0 group-hover:opacity-60">
          {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        </div>
      </div>

      {/* Expanded */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="px-6 pb-4 flex flex-col gap-3">
              {/* Description */}
              {actor.description ? (
                <p className="text-[0.8rem] text-[var(--text-secondary)] leading-relaxed">{actor.description}</p>
              ) : (
                <p className="text-[var(--text-ghost)] font-mono text-[0.65rem]">
                  NO DESCRIPTION AVAILABLE — SEE MITRE ATT&amp;CK
                </p>
              )}

              {/* All aliases */}
              {actor.aliases.length > 4 && (
                <div>
                  <span className="font-mono text-[0.52rem] text-[var(--text-dim)] tracking-widest block mb-1">ALL ALIASES</span>
                  <div className="flex flex-wrap gap-1">
                    {actor.aliases.map(a => (
                      <span key={a} className="tag-chip">{a}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* MITRE ATT&CK Techniques drill-down */}
              {actor.techniques.length > 0 && (
                <div>
                  <span className="font-mono text-[0.52rem] text-[var(--text-dim)] tracking-widest block mb-1.5">
                    MITRE ATT&amp;CK TECHNIQUES ({actor.techniques.length})
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {actor.techniques.slice(0, 20).map(tid => (
                      <a
                        key={tid}
                        href={`https://attack.mitre.org/techniques/${tid.replace('.', '/')}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={e => e.stopPropagation()}
                        className="font-code text-[0.58rem] px-1.5 py-0.5 border hover:opacity-80 transition-opacity"
                        style={{ color: '#00d4ff', background: 'rgba(0,212,255,0.06)', borderColor: 'rgba(0,212,255,0.2)' }}
                        title={`View ${tid} on MITRE ATT&CK`}
                      >
                        {tid} ↗
                      </a>
                    ))}
                    {actor.techniques.length > 20 && (
                      <span className="font-mono text-[0.55rem] text-[var(--text-ghost)] px-1 py-0.5">
                        +{actor.techniques.length - 20} more
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Quick link */}
              {actor.mitre_id && (
                <a
                  href={`https://attack.mitre.org/groups/${actor.mitre_id}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={e => e.stopPropagation()}
                  className="self-start font-mono text-[0.58rem] tracking-wider px-2.5 py-1 border border-[var(--border-accent)] text-[var(--color-primary)] hover:bg-[var(--bg-elevated)] transition-colors flex items-center gap-1"
                >
                  <ExternalLink size={9} />
                  FULL PROFILE ON MITRE ATT&amp;CK
                </a>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

function ActivityBadge({ status }: { status: ActivityStatus | null }) {
  if (!status) return null
  const map: Record<ActivityStatus, { label: string; color: string; bg: string; border: string }> = {
    active:   { label: 'ACTIVE',   color: '#00d4ff', bg: 'rgba(0,212,255,0.10)',   border: 'rgba(0,212,255,0.35)' },
    resurged: { label: 'RESURGED', color: '#ffaa00', bg: 'rgba(255,170,0,0.10)',   border: 'rgba(255,170,0,0.35)' },
    dormant:  { label: 'DORMANT',  color: '#667a8a', bg: 'rgba(102,122,138,0.08)', border: 'rgba(102,122,138,0.25)' },
  }
  const s = map[status]
  return (
    <span
      className="font-mono text-[0.52rem] tracking-widest px-1.5 py-0.5 border"
      style={{ color: s.color, background: s.bg, borderColor: s.border }}
    >
      {s.label}
    </span>
  )
}

function countryColor(country: string | null): string {
  const map: Record<string, string> = {
    'Russia':        '#ff5577',
    'China':         '#ff2255',
    'North Korea':   '#aa44ff',
    'Iran':          '#ffaa00',
    'United States': '#00d4ff',
    'Unknown':       '#304860',
  }
  return country ? (map[country] ?? '#304860') : '#304860'
}

export function ThreatActors({ refreshTrigger }: Props) {
  const [search, setSearch] = useState('')
  const [countryFilter, setCountryFilter] = useState('')

  const params = {
    limit: 100,
    ...(search && { search }),
    ...(countryFilter && { country: countryFilter }),
  }

  const { data: actors, loading } = useApi<ThreatActor[]>('/actors', params, refreshTrigger)

  return (
    <div className="panel flex flex-col h-full">
      {/* Header */}
      <div className="panel-header shrink-0 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <Users size={13} className="text-[var(--color-primary)]" />
          <span className="panel-title">Threat Actors</span>
          {actors && <span className="font-mono text-[0.55rem] text-[var(--text-ghost)]">[{actors.length}]</span>}
        </div>
      </div>

      {/* Filters */}
      <div className="px-4 py-2 border-b border-[var(--border-base)] bg-[var(--bg-surface)] shrink-0 space-y-2">
        <div className="flex items-center gap-2">
          <Search size={12} className="text-[var(--text-dim)] shrink-0" />
          <input type="text" value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search actors..."
            className="flex-1 bg-transparent font-mono text-[0.72rem] text-[var(--text-secondary)] placeholder-[var(--text-ghost)] outline-none" />
        </div>
        <div className="flex gap-1.5 flex-wrap">
          {COUNTRIES.map(c => (
            <button key={c}
              onClick={() => setCountryFilter(f => f === c ? '' : c)}
              className="font-mono text-[0.52rem] tracking-wide px-1.5 py-0.5 border transition-all"
              style={{
                color: countryFilter === c ? countryColor(c) : 'var(--text-ghost)',
                background: countryFilter === c ? `${countryColor(c)}18` : 'transparent',
                borderColor: countryFilter === c ? `${countryColor(c)}50` : 'var(--border-base)',
              }}>
              {countryFlag(c)} {c}
            </button>
          ))}
        </div>
      </div>

      {/* Actor list */}
      <div className="flex-1 overflow-y-auto min-h-0">
        {loading && !actors &&
          Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="flex gap-3 px-4 py-3 border-b border-[var(--border-base)] animate-pulse">
              <div className="w-[3px] h-12 bg-[var(--bg-elevated)] rounded" />
              <div className="flex-1 space-y-1.5">
                <div className="h-3.5 bg-[var(--bg-elevated)] rounded w-32" />
                <div className="h-2.5 bg-[var(--bg-elevated)] rounded w-20" />
              </div>
            </div>
          ))}
        {actors?.map(actor => <ActorCard key={actor.id} actor={actor} />)}
        {actors?.length === 0 && (
          <div className="flex items-center justify-center h-24 font-mono text-[0.65rem] text-[var(--text-ghost)] tracking-widest">
            NO ACTORS FOUND
          </div>
        )}
      </div>
    </div>
  )
}
