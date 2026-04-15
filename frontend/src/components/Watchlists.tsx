import { useState, useCallback, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Bookmark, Plus, Trash2, ToggleLeft, ToggleRight,
  ChevronDown, ChevronUp, Loader2, AlertTriangle,
  CheckCircle, Bell, BellOff, Clock, Target,
  FileJson, RefreshCw,
} from 'lucide-react'
import { timeAgo } from '@/lib/utils'

interface WatchlistItem {
  id: number
  name: string
  description: string | null
  conditions: Record<string, unknown>
  enabled: boolean
  notify_webhook: boolean
  created_at: string | null
  last_checked: string | null
  last_hit: string | null
  hit_count: number
}

const CONDITION_TEMPLATE = JSON.stringify(
  {
    operator: 'AND',
    conditions: [
      { field: 'severity', op: 'eq', value: 'CRITICAL' },
      { field: 'title', op: 'contains', value: 'ransomware' },
    ],
  },
  null,
  2,
)

const CONDITION_HELP = [
  { field: 'severity',  ops: 'eq',          example: 'CRITICAL | HIGH | MEDIUM | INFO' },
  { field: 'title',     ops: 'contains',     example: 'any keyword substring' },
  { field: 'source',    ops: 'eq|contains',  example: 'BleepingComputer' },
  { field: 'actor',     ops: 'eq|contains',  example: 'APT28' },
  { field: 'cve',       ops: 'contains',     example: 'CVE-2024-' },
  { field: 'tag',       ops: 'contains',     example: 'ransomware' },
]

function conditionSummary(conditions: Record<string, unknown>): string {
  try {
    const conds = (conditions.conditions as { field: string; op: string; value: string }[]) ?? []
    const op = (conditions.operator as string) ?? 'AND'
    return conds.map(c => `${c.field} ${c.op} "${c.value}"`).join(` ${op} `)
  } catch {
    return 'custom conditions'
  }
}

export function Watchlists() {
  const [items, setItems]           = useState<WatchlistItem[]>([])
  const [loading, setLoading]       = useState(true)
  const [expanded, setExpanded]     = useState<number | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [refreshing, setRefreshing] = useState(false)

  // Create form state
  const [newName, setNewName]               = useState('')
  const [newDesc, setNewDesc]               = useState('')
  const [newConditions, setNewConditions]   = useState(CONDITION_TEMPLATE)
  const [newWebhook, setNewWebhook]         = useState(true)
  const [creating, setCreating]             = useState(false)
  const [createError, setCreateError]       = useState('')
  const [condJsonError, setCondJsonError]   = useState('')

  const load = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true)
    else setRefreshing(true)
    try {
      const r = await fetch('/api/v1/watchlists')
      if (r.ok) setItems(await r.json())
    } catch { /* ignore */ } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const validateJson = (val: string): boolean => {
    try { JSON.parse(val); setCondJsonError(''); return true }
    catch (e: unknown) {
      setCondJsonError(e instanceof SyntaxError ? e.message : 'Invalid JSON')
      return false
    }
  }

  const create = async () => {
    if (!newName.trim()) { setCreateError('Name is required.'); return }
    if (!validateJson(newConditions)) return
    setCreating(true)
    setCreateError('')
    try {
      const r = await fetch('/api/v1/watchlists', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          name:           newName.trim(),
          description:    newDesc.trim() || null,
          conditions:     newConditions,
          notify_webhook: newWebhook,
        }),
      })
      if (!r.ok) {
        const d = await r.json()
        setCreateError(d.detail ?? 'Failed to create watchlist.')
        return
      }
      setNewName('')
      setNewDesc('')
      setNewConditions(CONDITION_TEMPLATE)
      setNewWebhook(true)
      setShowCreate(false)
      await load(true)
    } catch {
      setCreateError('Request failed.')
    } finally {
      setCreating(false)
    }
  }

  const toggle = async (item: WatchlistItem) => {
    setItems(prev => prev.map(w => w.id === item.id ? { ...w, enabled: !item.enabled } : w))
    try {
      await fetch(`/api/v1/watchlists/${item.id}`, {
        method:  'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ enabled: !item.enabled }),
      })
    } catch {
      setItems(prev => prev.map(w => w.id === item.id ? { ...w, enabled: item.enabled } : w))
    }
  }

  const toggleWebhook = async (item: WatchlistItem) => {
    setItems(prev => prev.map(w => w.id === item.id ? { ...w, notify_webhook: !item.notify_webhook } : w))
    try {
      await fetch(`/api/v1/watchlists/${item.id}`, {
        method:  'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ notify_webhook: !item.notify_webhook }),
      })
    } catch {
      setItems(prev => prev.map(w => w.id === item.id ? { ...w, notify_webhook: item.notify_webhook } : w))
    }
  }

  const remove = async (id: number) => {
    setItems(prev => prev.filter(w => w.id !== id))
    if (expanded === id) setExpanded(null)
    try {
      await fetch(`/api/v1/watchlists/${id}`, { method: 'DELETE' })
    } catch {
      await load(true)
    }
  }

  return (
    <div className="max-w-2xl mx-auto py-6 px-2 flex flex-col gap-4">

      {/* Header */}
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <Bookmark size={14} className="text-[var(--color-primary)]" />
          <span className="font-mono text-[0.68rem] tracking-widest text-[var(--color-primary)]">
            WATCHLISTS
          </span>
          {!loading && (
            <span className="font-mono text-[0.48rem] text-[var(--text-ghost)] tracking-widest">
              [{items.filter(w => w.enabled).length}/{items.length} active]
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => load(true)}
            disabled={refreshing}
            className="flex items-center gap-1 px-2 py-1 border border-[var(--border-base)] font-mono text-[0.46rem] tracking-widest text-[var(--text-dim)] hover:text-[var(--color-primary)] hover:border-[var(--border-accent)] transition-colors disabled:opacity-40"
          >
            <RefreshCw size={8} className={refreshing ? 'animate-spin' : ''} />
            REFRESH
          </button>
          <button
            onClick={() => { setShowCreate(v => !v); setCreateError('') }}
            className="flex items-center gap-1.5 px-3 py-1.5 border font-mono text-[0.52rem] tracking-widest transition-colors"
            style={{
              color:       showCreate ? 'var(--text-dim)' : 'var(--color-primary)',
              borderColor: showCreate ? 'var(--border-base)' : 'var(--border-accent)',
              background:  showCreate ? 'transparent' : 'rgba(0,212,255,0.05)',
            }}
          >
            <Plus size={9} />
            {showCreate ? 'CANCEL' : 'NEW WATCHLIST'}
          </button>
        </div>
      </div>

      {/* Create form */}
      <AnimatePresence>
        {showCreate && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.18 }}
            className="overflow-hidden"
          >
            <div className="panel">
              <div className="panel-header">
                <span className="panel-title">NEW WATCHLIST</span>
              </div>
              <div className="px-4 py-3 flex flex-col gap-3">

                {/* Name + description */}
                <div className="flex flex-col sm:flex-row gap-2">
                  <input
                    type="text"
                    value={newName}
                    onChange={e => setNewName(e.target.value)}
                    placeholder="Watchlist name (e.g. Ransomware Critical)"
                    className="flex-1 bg-[var(--bg-elevated)] border border-[var(--border-base)] font-mono text-[0.68rem] text-[var(--text-secondary)] px-2.5 py-1.5 outline-none focus:border-[var(--border-accent)] transition-colors placeholder:text-[var(--text-ghost)]"
                  />
                  <input
                    type="text"
                    value={newDesc}
                    onChange={e => setNewDesc(e.target.value)}
                    placeholder="Description (optional)"
                    className="flex-1 bg-[var(--bg-elevated)] border border-[var(--border-base)] font-mono text-[0.65rem] text-[var(--text-secondary)] px-2.5 py-1.5 outline-none focus:border-[var(--border-accent)] transition-colors placeholder:text-[var(--text-ghost)]"
                  />
                </div>

                {/* Conditions JSON editor */}
                <div className="flex flex-col gap-1.5">
                  <div className="flex items-center gap-1.5">
                    <FileJson size={9} className="text-[var(--color-primary)]" />
                    <span className="font-mono text-[0.5rem] text-[var(--text-dim)] tracking-widest">
                      CONDITIONS (JSON)
                    </span>
                  </div>
                  <textarea
                    value={newConditions}
                    onChange={e => { setNewConditions(e.target.value); if (condJsonError) validateJson(e.target.value) }}
                    onBlur={e => validateJson(e.target.value)}
                    rows={8}
                    spellCheck={false}
                    className="w-full bg-[var(--bg-base)] border font-mono text-[0.62rem] text-[var(--text-secondary)] px-3 py-2 outline-none resize-y transition-colors leading-relaxed"
                    style={{ borderColor: condJsonError ? 'rgba(255,34,85,0.5)' : 'var(--border-base)' }}
                  />
                  {condJsonError && (
                    <p className="font-mono text-[0.52rem] text-[var(--color-danger)]">✗ {condJsonError}</p>
                  )}
                </div>

                {/* Field reference */}
                <details className="group">
                  <summary className="font-mono text-[0.48rem] text-[var(--text-ghost)] tracking-widest cursor-pointer hover:text-[var(--text-dim)] transition-colors">
                    ▸ FIELD REFERENCE
                  </summary>
                  <div className="mt-2 border border-[var(--border-base)] overflow-hidden">
                    {CONDITION_HELP.map((row, i) => (
                      <div
                        key={row.field}
                        className="flex items-start gap-3 px-3 py-1.5"
                        style={{ borderTop: i > 0 ? '1px solid var(--border-base)' : undefined, background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)' }}
                      >
                        <span className="font-mono text-[0.52rem] text-[var(--color-primary)] w-16 shrink-0">{row.field}</span>
                        <span className="font-mono text-[0.48rem] text-[var(--text-dim)] w-20 shrink-0">{row.ops}</span>
                        <span className="font-mono text-[0.46rem] text-[var(--text-ghost)]">{row.example}</span>
                      </div>
                    ))}
                  </div>
                </details>

                {/* Options row */}
                <div className="flex items-center gap-4">
                  <button
                    onClick={() => setNewWebhook(v => !v)}
                    className="flex items-center gap-1.5 font-mono text-[0.52rem] text-[var(--text-dim)] hover:text-[var(--text-base)] transition-colors"
                  >
                    {newWebhook
                      ? <Bell size={11} className="text-[var(--color-primary)]" />
                      : <BellOff size={11} className="text-[var(--text-ghost)]" />
                    }
                    WEBHOOK {newWebhook ? 'ON' : 'OFF'}
                  </button>
                  <p className="font-mono text-[0.46rem] text-[var(--text-ghost)] leading-relaxed">
                    When triggered, posts to the webhook URL configured in Settings.
                  </p>
                </div>

                {createError && (
                  <p className="font-mono text-[0.55rem] text-[var(--color-danger)]">✗ {createError}</p>
                )}

                {/* Submit */}
                <div className="flex justify-end">
                  <button
                    onClick={create}
                    disabled={creating || !newName.trim()}
                    className="flex items-center gap-1.5 px-4 py-2 font-mono text-[0.56rem] tracking-widest border border-[var(--border-accent)] text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.07)] transition-colors disabled:opacity-40"
                  >
                    {creating ? <Loader2 size={9} className="animate-spin" /> : <CheckCircle size={9} />}
                    CREATE WATCHLIST
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Watchlist list */}
      {loading && (
        <div className="font-mono text-[0.65rem] text-[var(--text-ghost)] tracking-widest text-center py-10 animate-pulse">
          LOADING WATCHLISTS...
        </div>
      )}

      {!loading && items.length === 0 && (
        <div className="panel">
          <div className="flex flex-col items-center gap-3 py-12 text-center px-6">
            <Bookmark size={24} className="text-[var(--text-ghost)]" />
            <p className="font-mono text-[0.6rem] text-[var(--text-ghost)] tracking-widest">
              NO WATCHLISTS CONFIGURED
            </p>
            <p className="font-mono text-[0.52rem] text-[var(--text-ghost)] max-w-xs leading-relaxed">
              Watchlists continuously monitor threat intelligence feeds for matching items.
              Click <strong className="text-[var(--text-dim)]">NEW WATCHLIST</strong> to create one.
            </p>
          </div>
        </div>
      )}

      {items.map((item, idx) => {
        const isExpanded = expanded === item.id
        return (
          <motion.div
            key={item.id}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.03 }}
            className="panel"
          >
            {/* Row */}
            <div className="flex items-center gap-3 px-4 py-3">

              {/* Enable toggle */}
              <button
                onClick={() => toggle(item)}
                className="shrink-0 transition-colors"
                title={item.enabled ? 'Disable watchlist' : 'Enable watchlist'}
              >
                {item.enabled
                  ? <ToggleRight size={18} className="text-[var(--color-success)]" />
                  : <ToggleLeft  size={18} className="text-[var(--text-ghost)]" />
                }
              </button>

              {/* Info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className="font-mono text-[0.68rem] font-semibold"
                    style={{ color: item.enabled ? 'var(--text-base)' : 'var(--text-ghost)' }}
                  >
                    {item.name}
                  </span>
                  {item.hit_count > 0 && (
                    <span className="font-mono text-[0.46rem] px-1.5 py-0.5 border font-bold tracking-wider"
                      style={{
                        color: 'var(--color-warning)',
                        borderColor: 'rgba(255,170,0,0.3)',
                        background: 'rgba(255,170,0,0.06)',
                      }}
                    >
                      {item.hit_count} HIT{item.hit_count !== 1 ? 'S' : ''}
                    </span>
                  )}
                  {!item.notify_webhook && (
                    <BellOff size={9} className="text-[var(--text-ghost)]" />
                  )}
                </div>
                {item.description && (
                  <p className="font-mono text-[0.55rem] text-[var(--text-muted)] mt-0.5 truncate">{item.description}</p>
                )}
                <p className="font-mono text-[0.48rem] text-[var(--text-ghost)] mt-0.5 truncate">
                  {conditionSummary(item.conditions)}
                </p>
              </div>

              {/* Last hit */}
              {item.last_hit && (
                <div className="hidden sm:flex items-center gap-1 shrink-0">
                  <Target size={8} className="text-[var(--color-warning)]" />
                  <span className="font-mono text-[0.46rem] text-[var(--color-warning)]">
                    {timeAgo(item.last_hit)}
                  </span>
                </div>
              )}

              {/* Actions */}
              <div className="flex items-center gap-1 shrink-0">
                <button
                  onClick={() => toggleWebhook(item)}
                  className="p-1.5 transition-colors"
                  title={item.notify_webhook ? 'Disable webhook' : 'Enable webhook'}
                  style={{ color: item.notify_webhook ? 'var(--color-primary)' : 'var(--text-ghost)' }}
                >
                  {item.notify_webhook ? <Bell size={11} /> : <BellOff size={11} />}
                </button>
                <button
                  onClick={() => setExpanded(isExpanded ? null : item.id)}
                  className="p-1.5 text-[var(--text-dim)] hover:text-[var(--text-base)] transition-colors"
                  title="View details"
                >
                  {isExpanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                </button>
                <button
                  onClick={() => remove(item.id)}
                  className="p-1.5 text-[var(--text-ghost)] hover:text-[var(--color-danger)] transition-colors"
                  title="Delete watchlist"
                >
                  <Trash2 size={11} />
                </button>
              </div>
            </div>

            {/* Expanded detail */}
            <AnimatePresence>
              {isExpanded && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.15 }}
                  className="overflow-hidden"
                >
                  <div className="border-t border-[var(--border-base)] px-4 py-3 flex flex-col gap-3">

                    {/* Stats row */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                      {[
                        { label: 'TOTAL HITS',    value: item.hit_count.toString(), icon: <Target size={9} /> },
                        { label: 'LAST HIT',      value: item.last_hit     ? timeAgo(item.last_hit)     : 'never', icon: <AlertTriangle size={9} /> },
                        { label: 'LAST CHECKED',  value: item.last_checked ? timeAgo(item.last_checked) : 'never', icon: <Clock size={9} /> },
                        { label: 'CREATED',       value: item.created_at   ? timeAgo(item.created_at)   : '—',    icon: <Bookmark size={9} /> },
                      ].map(stat => (
                        <div key={stat.label} className="bg-[var(--bg-elevated)] px-3 py-2 flex flex-col gap-1">
                          <div className="flex items-center gap-1 text-[var(--text-ghost)]">
                            {stat.icon}
                            <span className="font-mono text-[0.42rem] tracking-widest">{stat.label}</span>
                          </div>
                          <span className="font-mono text-[0.62rem] text-[var(--text-secondary)]">{stat.value}</span>
                        </div>
                      ))}
                    </div>

                    {/* Conditions JSON */}
                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-1">
                        <FileJson size={9} className="text-[var(--color-primary)]" />
                        <span className="font-mono text-[0.46rem] text-[var(--text-ghost)] tracking-widest">CONDITIONS</span>
                      </div>
                      <pre className="bg-[var(--bg-base)] border border-[var(--border-base)] px-3 py-2 font-mono text-[0.58rem] text-[var(--text-muted)] overflow-x-auto leading-relaxed">
                        {JSON.stringify(item.conditions, null, 2)}
                      </pre>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        )
      })}

      {/* Info note */}
      {!loading && items.length > 0 && (
        <div className="flex items-start gap-2 px-3 py-2.5 border border-[rgba(0,212,255,0.15)] bg-[rgba(0,212,255,0.03)]">
          <Clock size={10} className="text-[var(--color-primary)] shrink-0 mt-0.5" />
          <p className="font-mono text-[0.55rem] text-[var(--text-muted)] leading-relaxed">
            Watchlists are evaluated every 15 minutes against newly ingested data.
            Hit counts persist across restarts. Webhook delivery uses the URL configured in Settings.
          </p>
        </div>
      )}
    </div>
  )
}
