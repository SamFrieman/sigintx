import { useState, useCallback } from 'react'
import { motion } from 'framer-motion'
import { Shield, ShieldAlert, ExternalLink, Search, ChevronDown, ChevronUp, Cpu, ArrowUpDown } from 'lucide-react'
import type { CVEItem, CVEStatusValue, SeverityLevel, AnalyzeTarget } from '@/types'
import { useApi, API_BASE } from '@/hooks/useApi'
import { sevColor, sevBg, sevBorder, cvssColor, timeAgo } from '@/lib/utils'

interface Props { refreshTrigger: number; onAnalyze?: (target: AnalyzeTarget) => void }

type SortBy = 'priority' | 'cvss' | 'date'

const STATUS_OPTIONS: { value: CVEStatusValue; label: string; color: string }[] = [
  { value: 'open',          label: 'OPEN',          color: '#667a8a' },
  { value: 'investigating', label: 'INVESTIGATING',  color: '#ffaa00' },
  { value: 'patched',       label: 'PATCHED',        color: '#00cc88' },
  { value: 'accepted',      label: 'ACCEPTED RISK',  color: '#8855ff' },
]

function statusColor(status: CVEStatusValue): string {
  return STATUS_OPTIONS.find(o => o.value === status)?.color ?? '#667a8a'
}

function PriorityBar({ score }: { score: number | null }) {
  if (score === null) return <span className="font-mono text-[0.58rem] text-[var(--text-ghost)]">—</span>
  const pct = score * 100
  const color = pct >= 70 ? 'var(--color-danger)' : pct >= 40 ? 'var(--color-warning)' : 'var(--color-primary)'
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-10 h-1.5 bg-[var(--bg-elevated)] rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="font-mono text-[0.62rem]" style={{ color }}>{score.toFixed(2)}</span>
    </div>
  )
}

function CvssGauge({ score }: { score: number | null }) {
  if (score === null) return <span className="font-mono text-[0.65rem] text-[var(--text-ghost)]">N/A</span>
  const pct = (score / 10) * 100
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-12 h-1 bg-[var(--bg-elevated)] rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${pct}%`, background: cvssColor(score) }}
        />
      </div>
      <span className="font-mono text-[0.68rem]" style={{ color: cvssColor(score) }}>
        {score.toFixed(1)}
      </span>
    </div>
  )
}

function EpssBar({ score }: { score: number | null }) {
  if (score === null) return <span className="font-mono text-[0.58rem] text-[var(--text-ghost)]">—</span>
  const pct = score * 100
  const color = pct > 10 ? 'var(--color-danger)' : pct > 1 ? 'var(--color-warning)' : 'var(--color-primary)'
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-10 h-1 bg-[var(--bg-elevated)] rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${Math.min(pct * 3, 100)}%`, background: color }} />
      </div>
      <span className="font-mono text-[0.62rem]" style={{ color }}>
        {pct.toFixed(2)}%
      </span>
    </div>
  )
}

function CveStatusDropdown({ cveId }: { cveId: string }) {
  const [status, setStatus] = useState<CVEStatusValue>('open')
  const [saving, setSaving] = useState(false)

  const handleChange = useCallback(async (next: CVEStatusValue) => {
    setSaving(true)
    try {
      await fetch(`${API_BASE}/cves/${cveId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: next }),
      })
      setStatus(next)
    } catch {
      // best-effort
    } finally {
      setSaving(false)
    }
  }, [cveId])

  return (
    <div className="flex items-center gap-2">
      <span className="font-mono text-[0.52rem] text-[var(--text-dim)] tracking-widest">STATUS</span>
      <div className="flex gap-1 flex-wrap">
        {STATUS_OPTIONS.map(opt => (
          <button
            key={opt.value}
            disabled={saving}
            onClick={() => handleChange(opt.value)}
            className="font-mono text-[0.5rem] tracking-widest px-1.5 py-0.5 border transition-all disabled:opacity-40"
            style={{
              color: status === opt.value ? opt.color : 'var(--text-ghost)',
              background: status === opt.value ? `${opt.color}18` : 'transparent',
              borderColor: status === opt.value ? `${opt.color}50` : 'var(--border-base)',
            }}
          >
            {opt.label}
          </button>
        ))}
      </div>
    </div>
  )
}

function CveRow({ item, onAnalyze }: { item: CVEItem; onAnalyze?: (t: AnalyzeTarget) => void }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <>
      <motion.tr
        layout
        className="border-b border-[var(--border-base)] hover:bg-[var(--bg-card-hover)] cursor-pointer"
        onClick={() => setExpanded(e => !e)}
      >
        {/* Severity indicator */}
        <td className="py-2.5 pl-4 pr-2 w-1">
          <div className="w-1 h-full min-h-[32px] rounded"
               style={{ background: sevColor(item.severity), boxShadow: item.severity === 'CRITICAL' ? `0 0 6px ${sevColor(item.severity)}70` : undefined }} />
        </td>

        {/* CVE ID */}
        <td className="py-2.5 px-2">
          <div className="flex items-center gap-1.5">
            <a
              href={`https://nvd.nist.gov/vuln/detail/${item.cve_id}`}
              target="_blank"
              rel="noopener noreferrer"
              onClick={e => e.stopPropagation()}
              className="font-code text-[0.75rem] text-[var(--color-primary)] hover:text-[var(--prim-cyan-300)] flex items-center gap-0.5"
            >
              {item.cve_id}
              <ExternalLink size={9} />
            </a>
            {item.in_kev && <span className="kev-badge">KEV</span>}
          </div>
        </td>

        {/* Priority */}
        <td className="py-2.5 px-2 hidden sm:table-cell">
          <PriorityBar score={item.priority_score} />
        </td>

        {/* CVSS */}
        <td className="py-2.5 px-2 hidden sm:table-cell">
          <CvssGauge score={item.cvss_score} />
        </td>

        {/* EPSS */}
        <td className="py-2.5 px-2 hidden md:table-cell">
          <EpssBar score={item.epss_score} />
        </td>

        {/* Description (truncated) */}
        <td className="py-2.5 px-2">
          <p className="text-[0.82rem] text-[var(--text-secondary)] line-clamp-2 max-w-md">
            {item.description ?? 'No description available.'}
          </p>
        </td>

        {/* Severity badge */}
        <td className="py-2.5 px-2 hidden lg:table-cell">
          <span className="font-mono text-[0.55rem] tracking-widest px-1.5 py-0.5 border"
                style={{ color: sevColor(item.severity), background: sevBg(item.severity), borderColor: sevBorder(item.severity) }}>
            {item.severity}
          </span>
        </td>

        {/* Date */}
        <td className="py-2.5 px-3 text-right hidden lg:table-cell">
          <span className="font-mono text-[0.58rem] text-[var(--text-dim)]">{timeAgo(item.published_at)}</span>
        </td>

        <td className="py-2.5 px-3 w-5">
          <div className="flex items-center gap-1.5">
            {onAnalyze && (
              <button
                onClick={e => { e.stopPropagation(); onAnalyze({ type: 'cve', item }) }}
                className="font-mono text-[0.5rem] tracking-widest px-1 py-0.5 border opacity-0 group-hover:opacity-70 hover:!opacity-100 transition-opacity"
                style={{ color: 'var(--color-primary)', borderColor: 'var(--border-accent)' }}
                title="Analyze with Ollama"
              >
                <Cpu size={9} />
              </button>
            )}
            {expanded ? <ChevronUp size={12} className="text-[var(--text-dim)]" /> : <ChevronDown size={12} className="text-[var(--text-dim)]" />}
          </div>
        </td>
      </motion.tr>

      {/* Expanded row */}
      {expanded && (
        <motion.tr
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="bg-[var(--bg-elevated)]/30 border-b border-[var(--border-base)]"
        >
          <td colSpan={9} className="px-6 py-3">
            <div className="flex flex-wrap gap-4 text-[0.8rem]">
              <div>
                <span className="font-mono text-[0.55rem] text-[var(--text-dim)] tracking-widest block mb-1">DESCRIPTION</span>
                <p className="text-[var(--text-secondary)] max-w-xl leading-relaxed">{item.description ?? '—'}</p>
              </div>
              {item.affected_products.length > 0 && (
                <div>
                  <span className="font-mono text-[0.55rem] text-[var(--text-dim)] tracking-widest block mb-1">AFFECTED</span>
                  <div className="flex flex-wrap gap-1">
                    {item.affected_products.slice(0, 10).map((p, i) => (
                      <span key={i} className="tag-chip">{p}</span>
                    ))}
                  </div>
                </div>
              )}
              {item.tags.length > 0 && (
                <div>
                  <span className="font-mono text-[0.55rem] text-[var(--text-dim)] tracking-widest block mb-1">TAGS</span>
                  <div className="flex flex-wrap gap-1">
                    {item.tags.map(t => <span key={t} className="tag-chip">{t}</span>)}
                  </div>
                </div>
              )}
              {item.cvss_vector && (
                <div>
                  <span className="font-mono text-[0.55rem] text-[var(--text-dim)] tracking-widest block mb-1">VECTOR</span>
                  <span className="font-code text-[0.65rem] text-[var(--text-muted)]">{item.cvss_vector}</span>
                </div>
              )}
              <div className="w-full pt-1 border-t border-[var(--border-base)]" onClick={e => e.stopPropagation()}>
                <CveStatusDropdown cveId={item.cve_id} />
              </div>
            </div>
          </td>
        </motion.tr>
      )}
    </>
  )
}

export function CveExplorer({ refreshTrigger, onAnalyze }: Props) {
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | ''>('')
  const [kevOnly, setKevOnly] = useState(false)
  const [minCvss, setMinCvss] = useState<number | ''>('')
  const [sortBy, setSortBy] = useState<SortBy>('priority')
  const [limit, setLimit] = useState(50)

  const params = {
    limit,
    sort_by: sortBy,
    ...(severityFilter && { severity: severityFilter }),
    ...(kevOnly && { in_kev: true }),
    ...(search && { search }),
    ...(minCvss !== '' && { min_cvss: minCvss }),
  }

  const { data: cves, loading } = useApi<CVEItem[]>('/cves', params, refreshTrigger, 120_000)

  const sevLevels: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']

  const sortLabels: Record<SortBy, string> = {
    priority: 'PRIORITY',
    cvss: 'CVSS',
    date: 'DATE',
  }
  const sortCycle: SortBy[] = ['priority', 'cvss', 'date']

  return (
    <div className="panel flex flex-col h-full">
      {/* Header */}
      <div className="panel-header shrink-0 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlert size={13} className="text-[var(--color-primary)]" />
          <span className="panel-title">CVE Explorer</span>
          {cves && <span className="font-mono text-[0.55rem] text-[var(--text-ghost)]">[{cves.length}]</span>}
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          {/* Sort toggle */}
          <button
            onClick={() => setSortBy(s => sortCycle[(sortCycle.indexOf(s) + 1) % sortCycle.length])}
            className="flex items-center gap-1 font-mono text-[0.52rem] tracking-wider px-1.5 py-0.5 border transition-all"
            style={{ color: 'var(--color-primary)', borderColor: 'var(--border-accent)', background: 'rgba(0,212,255,0.07)' }}
          >
            <ArrowUpDown size={9} />
            {sortLabels[sortBy]}
          </button>

          {sevLevels.map(s => (
            <button key={s} onClick={() => setSeverityFilter(p => p === s ? '' : s)}
              className="font-mono text-[0.52rem] tracking-wider px-1.5 py-0.5 border transition-all"
              style={{
                color: severityFilter === s ? sevColor(s) : 'var(--text-ghost)',
                background: severityFilter === s ? sevBg(s) : 'transparent',
                borderColor: severityFilter === s ? sevBorder(s) : 'var(--border-base)',
              }}>
              {s}
            </button>
          ))}

          <button onClick={() => setKevOnly(k => !k)}
            className="font-mono text-[0.52rem] tracking-wider px-1.5 py-0.5 border transition-all"
            style={{
              color: kevOnly ? 'var(--color-danger)' : 'var(--text-ghost)',
              background: kevOnly ? 'rgba(255,34,85,0.12)' : 'transparent',
              borderColor: kevOnly ? 'rgba(255,34,85,0.35)' : 'var(--border-base)',
            }}>
            KEV ONLY
          </button>
        </div>
      </div>

      {/* Search / filters */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-[var(--border-base)] bg-[var(--bg-surface)] shrink-0">
        <Search size={12} className="text-[var(--text-dim)] shrink-0" />
        <input type="text" value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search CVE ID or description..."
          className="flex-1 bg-transparent font-mono text-[0.72rem] text-[var(--text-secondary)] placeholder-[var(--text-ghost)] outline-none" />
        <div className="flex items-center gap-1 shrink-0">
          <Shield size={10} className="text-[var(--text-dim)]" />
          <input type="number" value={minCvss} onChange={e => setMinCvss(e.target.value ? parseFloat(e.target.value) : '')}
            placeholder="Min CVSS" min={0} max={10} step={0.1}
            className="w-20 bg-transparent font-mono text-[0.65rem] text-[var(--text-secondary)] placeholder-[var(--text-ghost)] outline-none border border-[var(--border-base)] px-2 py-0.5" />
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-left border-collapse">
          <thead className="sticky top-0 bg-[var(--bg-base)] z-10">
            <tr className="border-b border-[var(--color-primary)]/30">
              <th className="py-2 pl-4 w-1" />
              <th className="py-2 px-2 font-mono text-[0.55rem] tracking-widest text-[var(--text-dim)] uppercase">CVE ID</th>
              <th className="py-2 px-2 font-mono text-[0.55rem] tracking-widest text-[var(--text-dim)] uppercase hidden sm:table-cell">PRIORITY</th>
              <th className="py-2 px-2 font-mono text-[0.55rem] tracking-widest text-[var(--text-dim)] uppercase hidden sm:table-cell">CVSS</th>
              <th className="py-2 px-2 font-mono text-[0.55rem] tracking-widest text-[var(--text-dim)] uppercase hidden md:table-cell">EPSS</th>
              <th className="py-2 px-2 font-mono text-[0.55rem] tracking-widest text-[var(--text-dim)] uppercase">Description</th>
              <th className="py-2 px-2 font-mono text-[0.55rem] tracking-widest text-[var(--text-dim)] uppercase hidden lg:table-cell">SEV</th>
              <th className="py-2 px-3 font-mono text-[0.55rem] tracking-widest text-[var(--text-dim)] uppercase text-right hidden lg:table-cell">Published</th>
              <th className="w-5" />
            </tr>
          </thead>
          <tbody>
            {loading && !cves &&
              Array.from({ length: 8 }).map((_, i) => (
                <tr key={i} className="border-b border-[var(--border-base)] animate-pulse">
                  <td className="py-2.5 pl-4"><div className="w-1 h-8 bg-[var(--bg-elevated)] rounded" /></td>
                  <td className="py-2.5 px-2"><div className="h-3 w-24 bg-[var(--bg-elevated)] rounded" /></td>
                  <td className="py-2.5 px-2 hidden sm:table-cell"><div className="h-2 w-14 bg-[var(--bg-elevated)] rounded" /></td>
                  <td className="py-2.5 px-2 hidden sm:table-cell"><div className="h-2 w-16 bg-[var(--bg-elevated)] rounded" /></td>
                  <td className="py-2.5 px-2 hidden md:table-cell"><div className="h-2 w-12 bg-[var(--bg-elevated)] rounded" /></td>
                  <td className="py-2.5 px-2"><div className="h-3 w-48 bg-[var(--bg-elevated)] rounded" /></td>
                  <td className="py-2.5 px-2 hidden lg:table-cell"><div className="h-3 w-14 bg-[var(--bg-elevated)] rounded" /></td>
                  <td /><td />
                </tr>
              ))
            }
            {cves?.map(cve => <CveRow key={cve.id} item={cve} onAnalyze={onAnalyze} />)}
          </tbody>
        </table>

        {cves?.length === 0 && (
          <div className="flex items-center justify-center h-24 font-mono text-[0.65rem] text-[var(--text-ghost)] tracking-widest">
            NO CVEs FOUND — COLLECTING FROM NVD...
          </div>
        )}

        {cves && cves.length >= limit && (
          <button onClick={() => setLimit(l => l + 50)}
            className="w-full py-2.5 font-mono text-[0.6rem] tracking-widest text-[var(--text-dim)] hover:text-[var(--color-primary)] hover:bg-[var(--bg-elevated)] border-t border-[var(--border-base)]">
            LOAD MORE ↓
          </button>
        )}
      </div>
    </div>
  )
}
