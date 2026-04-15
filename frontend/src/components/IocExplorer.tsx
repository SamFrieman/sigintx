/**
 * IocExplorer — Indicators of Compromise browser (Sprint 4)
 * Added: expandable row with enrichment data from Shodan/MalwareBazaar/URLhaus.
 */
import { useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Database, Copy, CheckCheck, Search, Download,
  ChevronDown, ChevronUp, Zap, RefreshCw,
} from 'lucide-react'
import { useApi } from '@/hooks/useApi'
import type { IOCItem } from '@/types'
import { timeAgo } from '@/lib/utils'

interface Props { refreshTrigger: number }

const SOURCES   = ['MalwareBazaar', 'URLhaus', 'ThreatFox', 'OTX']
const IOC_TYPES = ['hash_sha256', 'hash_md5', 'url', 'ip', 'domain', 'email']

const TYPE_COLOR: Record<string, string> = {
  hash_sha256: 'var(--color-warning)',
  hash_md5:    'var(--color-warning)',
  url:         'var(--color-danger)',
  ip:          'var(--color-primary)',
  domain:      'var(--color-primary)',
  email:       'var(--color-info)',
}

const SOURCE_COLOR: Record<string, string> = {
  MalwareBazaar: 'var(--color-danger)',
  URLhaus:       'var(--color-warning)',
  ThreatFox:     'var(--color-info)',
  OTX:           'var(--color-success)',
}

// ── Enrichment data types ─────────────────────────────────────────────────────
interface EnrichmentData {
  source: string
  not_found?: boolean
  // IP (Shodan)
  open_ports?: number[]
  cpes?: string[]
  vulns?: string[]
  tags?: string[]
  hostnames?: string[]
  // Hash (MalwareBazaar)
  file_type?: string
  file_size?: number
  signature?: string
  reporter?: string
  first_seen?: string
  yara_rules?: string[]
  delivery_method?: string
  // URL (URLhaus)
  url_status?: string
  threat?: string
  date_added?: string
  payloads?: { file_type?: string; sha256?: string; signature?: string }[]
}

interface EnrichmentResponse {
  ioc_id: number
  source: string
  fetched_at: string
  data: EnrichmentData
}

// ── Sub-components ────────────────────────────────────────────────────────────
function ConfidenceBar({ score }: { score: number | null }) {
  if (score === null || !isFinite(score)) {
    return <span className="font-mono text-[0.58rem] text-[var(--text-ghost)]">—</span>
  }
  const pct   = Math.min(100, Math.max(0, score * 100))
  const color = pct >= 75 ? 'var(--color-danger)' : pct >= 40 ? 'var(--color-warning)' : 'var(--color-primary)'
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-10 h-1 bg-[var(--bg-elevated)] rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="font-mono text-[0.6rem]" style={{ color }}>{pct.toFixed(0)}%</span>
    </div>
  )
}

function CopyValue({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  const copy = (e: React.MouseEvent) => {
    e.stopPropagation()
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }
  return (
    <button onClick={copy} className="flex items-center gap-1 group/copy max-w-[220px] text-left" title={value}>
      <span className="font-code text-[0.65rem] text-[var(--text-secondary)] truncate group-hover/copy:text-[var(--color-primary)] transition-colors">
        {value.length > 36 ? value.slice(0, 18) + '…' + value.slice(-10) : value}
      </span>
      <span className="opacity-0 group-hover/copy:opacity-60 transition-opacity shrink-0">
        {copied ? <CheckCheck size={9} className="text-[var(--color-success)]" /> : <Copy size={9} />}
      </span>
    </button>
  )
}

function EnrichmentPanel({ iocId, iocType }: { iocId: number; iocType: string }) {
  const [triggered, setTriggered] = useState(false)
  const { data, loading, error, refetch } = useApi<EnrichmentResponse>(
    `/iocs/${iocId}/enrichment`,
    undefined,
    triggered ? 1 : 0,
  )

  const enrich = async () => {
    setTriggered(true)
    refetch()
  }

  if (!triggered && !data && !error) {
    return (
      <button
        onClick={enrich}
        className="flex items-center gap-1.5 font-mono text-[0.5rem] tracking-widest px-2 py-1 border border-[var(--border-base)] text-[var(--text-dim)] hover:text-[var(--color-primary)] hover:border-[var(--border-accent)] transition-colors"
      >
        <Zap size={8} />
        LOAD ENRICHMENT
      </button>
    )
  }

  if (loading) {
    return (
      <div className="flex items-center gap-1.5 font-mono text-[0.5rem] text-[var(--text-ghost)] tracking-widest">
        <RefreshCw size={8} className="animate-spin" />
        FETCHING…
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="flex items-center gap-2">
        <span className="font-mono text-[0.5rem] text-[var(--text-ghost)] tracking-widest">
          {error?.includes('404') ? 'NOT YET ENRICHED' : 'ENRICHMENT ERROR'}
        </span>
        {iocType !== 'domain' && iocType !== 'email' && (
          <button
            onClick={refetch}
            className="font-mono text-[0.48rem] text-[var(--color-primary)] hover:underline tracking-widest"
          >
            RETRY
          </button>
        )}
      </div>
    )
  }

  const d = data.data

  if (d.not_found) {
    return (
      <span className="font-mono text-[0.5rem] text-[var(--text-ghost)] tracking-widest">
        NOT FOUND IN {d.source?.toUpperCase().replace('_', ' ')}
      </span>
    )
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="font-mono text-[0.46rem] tracking-widest px-1.5 py-0.5 border"
          style={{ color: 'var(--color-primary)', borderColor: 'rgba(0,212,255,0.3)', background: 'rgba(0,212,255,0.07)' }}>
          {d.source?.toUpperCase().replace('_', ' ')}
        </span>
        <span className="font-mono text-[0.44rem] text-[var(--text-ghost)]">
          as of {timeAgo(data.fetched_at)}
        </span>
        <button onClick={refetch} className="text-[var(--text-ghost)] hover:text-[var(--color-primary)]" title="Refresh">
          <RefreshCw size={8} />
        </button>
      </div>

      {/* IP / Shodan */}
      {d.open_ports !== undefined && (
        <div className="grid grid-cols-2 gap-3 font-mono text-[0.58rem]">
          {d.open_ports.length > 0 && (
            <div>
              <span className="text-[var(--text-dim)] tracking-widest block mb-1">OPEN PORTS</span>
              <div className="flex flex-wrap gap-1">
                {d.open_ports.slice(0, 15).map(p => (
                  <span key={p} className="px-1 py-0.5 border border-[var(--border-base)] text-[var(--color-primary)] text-[0.52rem]">{p}</span>
                ))}
              </div>
            </div>
          )}
          {d.vulns && d.vulns.length > 0 && (
            <div>
              <span className="text-[var(--color-danger)] tracking-widest block mb-1">VULNS ({d.vulns.length})</span>
              <div className="flex flex-wrap gap-1">
                {d.vulns.slice(0, 8).map(v => (
                  <span key={v} className="font-code text-[0.5rem] text-[var(--color-danger)] px-1 border border-[rgba(255,34,85,0.3)]">{v}</span>
                ))}
              </div>
            </div>
          )}
          {d.hostnames && d.hostnames.length > 0 && (
            <div className="col-span-2">
              <span className="text-[var(--text-dim)] tracking-widest block mb-1">HOSTNAMES</span>
              <span className="text-[var(--text-secondary)]">{d.hostnames.join(', ')}</span>
            </div>
          )}
          {d.tags && d.tags.length > 0 && (
            <div>
              <span className="text-[var(--text-dim)] tracking-widest block mb-1">TAGS</span>
              <div className="flex flex-wrap gap-1">
                {d.tags.map(t => <span key={t} className="tag-chip text-[0.46rem]">{t}</span>)}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Hash / MalwareBazaar */}
      {d.file_type !== undefined && (
        <div className="grid grid-cols-3 gap-2 font-mono text-[0.55rem]">
          {d.file_type && <KV label="TYPE"   value={d.file_type} />}
          {d.file_size && <KV label="SIZE"   value={`${(d.file_size / 1024).toFixed(1)} KB`} />}
          {d.signature && <KV label="FAMILY" value={d.signature} color="var(--color-warning)" />}
          {d.reporter  && <KV label="REPORTER" value={d.reporter} />}
          {d.first_seen && <KV label="FIRST SEEN" value={d.first_seen.slice(0, 10)} />}
          {d.delivery_method && <KV label="DELIVERY" value={d.delivery_method} />}
          {d.yara_rules && d.yara_rules.length > 0 && (
            <div className="col-span-3">
              <span className="text-[var(--text-dim)] tracking-widest block mb-1">YARA RULES</span>
              <div className="flex flex-wrap gap-1">
                {d.yara_rules.map(r => <span key={r} className="tag-chip text-[0.44rem]">{r}</span>)}
              </div>
            </div>
          )}
        </div>
      )}

      {/* URL / URLhaus */}
      {d.url_status !== undefined && (
        <div className="grid grid-cols-3 gap-2 font-mono text-[0.55rem]">
          <KV
            label="STATUS"
            value={d.url_status ?? '?'}
            color={d.url_status === 'online' ? 'var(--color-danger)' : '#00cc88'}
          />
          {d.threat    && <KV label="THREAT"  value={d.threat} color="var(--color-warning)" />}
          {d.reporter  && <KV label="REPORTER" value={d.reporter} />}
          {d.date_added && <KV label="ADDED"   value={d.date_added.slice(0, 10)} />}
          {d.payloads && d.payloads.length > 0 && (
            <div className="col-span-3">
              <span className="text-[var(--text-dim)] tracking-widest block mb-1">PAYLOADS ({d.payloads.length})</span>
              {d.payloads.map((p, i) => (
                <div key={i} className="font-code text-[0.48rem] text-[var(--text-secondary)] pl-1">
                  {p.signature ?? p.file_type ?? '?'}{p.sha256 ? ` — ${p.sha256.slice(0, 16)}…` : ''}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function KV({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div>
      <span className="font-mono text-[0.44rem] text-[var(--text-dim)] tracking-widest block">{label}</span>
      <span className="font-mono text-[0.55rem]" style={{ color: color ?? 'var(--text-secondary)' }}>{value}</span>
    </div>
  )
}

// ── Row with expandable enrichment ────────────────────────────────────────────
function IocRow({ ioc }: { ioc: IOCItem }) {
  const [expanded, setExpanded] = useState(false)
  const supportsEnrich = ['ip', 'hash_sha256', 'hash_md5', 'url'].includes(ioc.ioc_type)

  return (
    <>
      <motion.tr
        key={ioc.id}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="border-b border-[var(--border-base)] hover:bg-[var(--bg-card-hover)] group cursor-pointer"
        onClick={() => supportsEnrich && setExpanded(e => !e)}
      >
        <td className="py-2 px-3">
          <div className="flex items-center gap-1.5">
            <span
              className="font-mono text-[0.55rem] tracking-wider uppercase px-1.5 py-0.5 border"
              style={{
                color:       TYPE_COLOR[ioc.ioc_type] ?? 'var(--color-primary)',
                borderColor: `${TYPE_COLOR[ioc.ioc_type] ?? 'var(--color-primary)'}4d`,
                background:  `${TYPE_COLOR[ioc.ioc_type] ?? 'var(--color-primary)'}14`,
              }}
            >
              {ioc.ioc_type.replace('hash_', '')}
            </span>
            {supportsEnrich && (
              <div className="opacity-0 group-hover:opacity-60 transition-opacity">
                {expanded ? <ChevronUp size={9} className="text-[var(--text-dim)]" /> : <ChevronDown size={9} className="text-[var(--text-dim)]" />}
              </div>
            )}
          </div>
        </td>
        <td className="py-2 px-3"><CopyValue value={ioc.value} /></td>
        <td className="py-2 px-3 hidden sm:table-cell">
          {ioc.malware_family
            ? <span className="font-mono text-[0.62rem] text-[var(--color-warning)]">{ioc.malware_family}</span>
            : <span className="font-mono text-[0.55rem] text-[var(--text-ghost)]">—</span>
          }
        </td>
        <td className="py-2 px-3 hidden md:table-cell">
          <span className="font-mono text-[0.55rem] tracking-wide" style={{ color: SOURCE_COLOR[ioc.source] ?? 'var(--text-muted)' }}>
            {ioc.source}
          </span>
        </td>
        <td className="py-2 px-3 hidden lg:table-cell">
          <ConfidenceBar score={ioc.confidence} />
        </td>
        <td className="py-2 px-3 hidden lg:table-cell text-right">
          <span className="font-mono text-[0.55rem] text-[var(--text-dim)]">{timeAgo(ioc.first_seen)}</span>
        </td>
      </motion.tr>

      {/* Enrichment expansion */}
      <AnimatePresence>
        {expanded && (
          <motion.tr
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="bg-[var(--bg-elevated)]/20 border-b border-[var(--border-base)]"
          >
            <td colSpan={6} className="px-5 py-3">
              <EnrichmentPanel iocId={ioc.id} iocType={ioc.ioc_type} />
            </td>
          </motion.tr>
        )}
      </AnimatePresence>
    </>
  )
}

// ── Main component ────────────────────────────────────────────────────────────
export function IocExplorer({ refreshTrigger }: Props) {
  const [sourceFilter, setSourceFilter] = useState('')
  const [typeFilter,   setTypeFilter]   = useState('')
  const [search,       setSearch]       = useState('')
  const [limit,        setLimit]        = useState(100)
  const [exporting,    setExporting]    = useState(false)

  const params = {
    limit,
    ...(sourceFilter && { source:         sourceFilter }),
    ...(typeFilter   && { ioc_type:        typeFilter }),
    ...(search       && { malware_family:  search }),
  }

  const { data: iocs, loading } = useApi<IOCItem[]>('/iocs', params, refreshTrigger, 120_000)

  const handleExport = useCallback(async (fmt: 'csv' | 'json') => {
    setExporting(true)
    try {
      const qp = new URLSearchParams()
      qp.set('format', fmt)
      qp.set('limit', '50000')
      if (sourceFilter)  qp.set('source', sourceFilter)
      if (typeFilter)    qp.set('ioc_type', typeFilter)
      if (search)        qp.set('malware_family', search)
      const res  = await fetch(`/api/v1/iocs/export?${qp.toString()}`)
      const blob = await res.blob()
      const a    = document.createElement('a')
      a.href     = URL.createObjectURL(blob)
      a.download = `sigintx_iocs.${fmt}`
      a.click()
      URL.revokeObjectURL(a.href)
    } catch (e) {
      console.error('IOC export failed', e)
    } finally {
      setExporting(false)
    }
  }, [sourceFilter, typeFilter, search])

  return (
    <div className="panel flex flex-col h-full">
      {/* Header */}
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <Database size={12} className="text-[var(--color-primary)]" />
          <span className="panel-title">IOC EXPLORER</span>
          <span className="live-dot" />
          {iocs && <span className="font-mono text-[0.48rem] text-[var(--text-ghost)]">[{iocs.length}]</span>}
        </div>
        <div className="flex items-center gap-2">
          {SOURCES.map(s => (
            <div key={s} className="flex items-center gap-1">
              <div className="w-1.5 h-1.5 rounded-full" style={{ background: SOURCE_COLOR[s] }} />
              <span className="font-mono text-[0.46rem] text-[var(--text-ghost)] tracking-wider hidden sm:block">{s}</span>
            </div>
          ))}
          <div className="relative group/export">
            <button
              disabled={exporting || !iocs?.length}
              className="flex items-center gap-1 px-1.5 py-0.5 border border-[var(--border-base)] font-mono text-[0.46rem] tracking-widest text-[var(--text-dim)] hover:text-[var(--color-primary)] hover:border-[var(--border-accent)] transition-colors disabled:opacity-40"
            >
              <Download size={9} />
              {exporting ? 'EXPORTING…' : 'EXPORT'}
            </button>
            <div className="absolute right-0 top-full mt-0.5 z-20 hidden group-hover/export:flex flex-col border border-[var(--border-base)] bg-[var(--bg-surface)] min-w-[80px]">
              {(['csv', 'json'] as const).map(fmt => (
                <button key={fmt} onClick={() => handleExport(fmt)}
                  className="px-3 py-1.5 font-mono text-[0.52rem] tracking-widest text-[var(--text-dim)] hover:text-[var(--color-primary)] hover:bg-[var(--bg-elevated)] text-left transition-colors">
                  {fmt.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="shrink-0 border-b border-[var(--border-base)] bg-[var(--bg-surface)] px-3 py-2 flex flex-col gap-2">
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="font-mono text-[0.46rem] text-[var(--text-dim)] tracking-widest uppercase mr-1">SOURCE</span>
          {SOURCES.map(s => (
            <button key={s} onClick={() => setSourceFilter(f => f === s ? '' : s)}
              className="font-mono text-[0.48rem] tracking-wide px-1.5 py-0.5 border transition-all"
              style={{
                color:       sourceFilter === s ? SOURCE_COLOR[s] : 'var(--text-ghost)',
                background:  sourceFilter === s ? `${SOURCE_COLOR[s]}1a` : 'transparent',
                borderColor: sourceFilter === s ? `${SOURCE_COLOR[s]}66` : 'var(--border-base)',
              }}>
              {s}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="font-mono text-[0.46rem] text-[var(--text-dim)] tracking-widest uppercase mr-1">TYPE</span>
          {IOC_TYPES.map(t => (
            <button key={t} onClick={() => setTypeFilter(f => f === t ? '' : t)}
              className="font-mono text-[0.46rem] tracking-wide px-1.5 py-0.5 border transition-all"
              style={{
                color:       typeFilter === t ? TYPE_COLOR[t] ?? 'var(--color-primary)' : 'var(--text-ghost)',
                background:  typeFilter === t ? 'rgba(0,212,255,0.07)' : 'transparent',
                borderColor: typeFilter === t ? 'var(--border-accent)' : 'var(--border-base)',
              }}>
              {t.replace('hash_', '')}
            </button>
          ))}
          <div className="ml-auto flex items-center gap-1.5 border border-[var(--border-base)] bg-[var(--bg-elevated)] px-2 py-0.5">
            <Search size={9} className="text-[var(--text-dim)] shrink-0" />
            <input type="text" value={search} onChange={e => setSearch(e.target.value)}
              placeholder="family / value…"
              className="bg-transparent font-mono text-[0.62rem] text-[var(--text-secondary)] placeholder-[var(--text-ghost)] outline-none w-28" />
          </div>
        </div>
      </div>

      {/* Enrichment hint */}
      <div className="shrink-0 px-3 py-1 border-b border-[var(--border-base)] bg-[var(--bg-elevated)]/20">
        <span className="font-mono text-[0.44rem] text-[var(--text-ghost)] tracking-widest">
          CLICK IP · HASH · URL ROWS TO VIEW ENRICHMENT DATA
        </span>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-left border-collapse">
          <thead className="sticky top-0 bg-[var(--bg-base)] z-10">
            <tr className="border-b border-[var(--color-primary)]/20">
              <th className="py-2 px-3 font-mono text-[0.52rem] tracking-widest text-[var(--text-dim)] uppercase">TYPE</th>
              <th className="py-2 px-3 font-mono text-[0.52rem] tracking-widest text-[var(--text-dim)] uppercase">VALUE</th>
              <th className="py-2 px-3 font-mono text-[0.52rem] tracking-widest text-[var(--text-dim)] uppercase hidden sm:table-cell">FAMILY</th>
              <th className="py-2 px-3 font-mono text-[0.52rem] tracking-widest text-[var(--text-dim)] uppercase hidden md:table-cell">SOURCE</th>
              <th className="py-2 px-3 font-mono text-[0.52rem] tracking-widest text-[var(--text-dim)] uppercase hidden lg:table-cell">CONFIDENCE</th>
              <th className="py-2 px-3 font-mono text-[0.52rem] tracking-widest text-[var(--text-dim)] uppercase hidden lg:table-cell text-right">SEEN</th>
            </tr>
          </thead>
          <tbody>
            {loading && !iocs && Array.from({ length: 10 }).map((_, i) => (
              <tr key={i} className="border-b border-[var(--border-base)] animate-pulse">
                <td className="py-2 px-3"><div className="h-3 w-16 bg-[var(--bg-elevated)] rounded" /></td>
                <td className="py-2 px-3"><div className="h-3 w-40 bg-[var(--bg-elevated)] rounded" /></td>
                <td className="py-2 px-3 hidden sm:table-cell"><div className="h-3 w-20 bg-[var(--bg-elevated)] rounded" /></td>
                <td className="py-2 px-3 hidden md:table-cell"><div className="h-3 w-24 bg-[var(--bg-elevated)] rounded" /></td>
                <td className="py-2 px-3 hidden lg:table-cell"><div className="h-2 w-16 bg-[var(--bg-elevated)] rounded" /></td>
                <td className="py-2 px-3 hidden lg:table-cell" />
              </tr>
            ))}

            {(iocs ?? []).map(ioc => <IocRow key={ioc.id} ioc={ioc} />)}
          </tbody>
        </table>

        {!loading && (iocs ?? []).length === 0 && (
          <div className="flex flex-col items-center justify-center h-32 gap-2">
            <Database size={20} className="text-[var(--text-ghost)]" />
            <p className="font-mono text-[0.6rem] text-[var(--text-ghost)] tracking-widest text-center">
              {sourceFilter || typeFilter || search
                ? 'NO IOCs MATCH CURRENT FILTERS'
                : 'NO IOCs YET — ABUSE.CH COLLECTS EVERY 15 MIN'
              }
            </p>
            {(sourceFilter || typeFilter || search) && (
              <button
                onClick={() => { setSourceFilter(''); setTypeFilter(''); setSearch('') }}
                className="font-mono text-[0.52rem] tracking-widest text-[var(--color-primary)] hover:underline">
                CLEAR FILTERS
              </button>
            )}
          </div>
        )}

        {iocs && iocs.length >= limit && (
          <button onClick={() => setLimit(l => l + 100)}
            className="w-full py-2.5 font-mono text-[0.58rem] tracking-widest text-[var(--text-dim)] hover:text-[var(--color-primary)] hover:bg-[var(--bg-elevated)] border-t border-[var(--border-base)] transition-colors">
            LOAD MORE ↓
          </button>
        )}
      </div>
    </div>
  )
}
