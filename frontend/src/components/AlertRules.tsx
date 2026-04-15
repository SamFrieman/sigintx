/**
 * AlertRules — manage structured alert rules that trigger webhooks.
 */
import { useState, useCallback, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Bell, Plus, Trash2, ToggleLeft, ToggleRight,
  Loader2, AlertTriangle, ChevronDown, FlaskConical,
  CheckCircle, X,
} from 'lucide-react'
import { timeAgo } from '@/lib/utils'

interface AlertRule {
  id:                   number
  name:                 string
  description:          string | null
  conditions:           string   // JSON
  min_severity:         string
  enabled:              boolean
  hit_count:            number
  last_triggered:       string | null
  cooldown_minutes:     number
  notification_channel: string   // webhook | telegram | both
  telegram_chat_id:     string | null
}

interface Condition {
  field: string
  op:    string
  value: string | string[] | boolean | number
}

interface RuleConditions {
  operator:   'AND' | 'OR'
  conditions: Condition[]
}

// ─── Field / operator config ─────────────────────────────────────────────────

const FIELDS = [
  { value: 'severity',      label: 'Severity' },
  { value: 'source',        label: 'Source' },
  { value: 'threat_actors', label: 'Threat Actors' },
  { value: 'has_cve',       label: 'Has CVE' },
  { value: 'in_kev',        label: 'In KEV' },
  { value: 'cvss_score',    label: 'CVSS Score' },
]

const OPS_FOR_FIELD: Record<string, { value: string; label: string }[]> = {
  severity:      [{ value: 'equals', label: 'equals' }, { value: 'in', label: 'is one of' }],
  source:        [{ value: 'equals', label: 'equals' }, { value: 'contains', label: 'contains' }],
  threat_actors: [{ value: 'contains', label: 'contains' }],
  has_cve:       [{ value: 'equals', label: 'equals' }],
  in_kev:        [{ value: 'equals', label: 'equals' }],
  cvss_score:    [
    { value: 'gt', label: 'greater than' },
    { value: 'gte', label: 'greater than or equal' },
    { value: 'lt', label: 'less than' },
    { value: 'equals', label: 'equals' },
  ],
}

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']

function sevColor(s: string) {
  if (s === 'CRITICAL') return 'var(--color-danger)'
  if (s === 'HIGH')     return 'var(--color-warning)'
  if (s === 'MEDIUM')   return 'var(--color-primary)'
  return 'var(--color-success)'
}

// ─── Condition builder ────────────────────────────────────────────────────────

interface ConditionRowProps {
  cond:     Condition
  index:    number
  onChange: (i: number, c: Condition) => void
  onDelete: (i: number) => void
  isLast:   boolean
  operator: 'AND' | 'OR'
  onToggleOp: () => void
}

function ConditionRow({ cond, index, onChange, onDelete, isLast, operator, onToggleOp }: ConditionRowProps) {
  const ops  = OPS_FOR_FIELD[cond.field] ?? []
  const isBool = cond.field === 'has_cve' || cond.field === 'in_kev'

  const selectCls = `
    bg-[var(--bg-elevated)] border border-[var(--border-base)] font-mono text-[0.62rem]
    text-[var(--text-secondary)] px-2 py-1 outline-none focus:border-[var(--border-accent)]
    transition-colors appearance-none cursor-pointer
  `

  return (
    <div className="flex flex-col gap-0">
      <div className="flex items-center gap-2 py-1.5">
        <div className="w-4 flex items-center justify-center">
          <span className="font-mono text-[0.48rem]" style={{ color: 'var(--text-ghost)' }}>
            {(index + 1).toString().padStart(2, '0')}
          </span>
        </div>

        {/* Field */}
        <select
          value={cond.field}
          onChange={e => {
            const f = e.target.value
            const firstOp = (OPS_FOR_FIELD[f]?.[0]?.value) ?? 'equals'
            const defaultVal = (f === 'has_cve' || f === 'in_kev') ? 'true' : ''
            onChange(index, { field: f, op: firstOp, value: defaultVal })
          }}
          className={selectCls}
        >
          {FIELDS.map(f => (
            <option key={f.value} value={f.value}>{f.label}</option>
          ))}
        </select>

        {/* Op */}
        <select
          value={cond.op}
          onChange={e => onChange(index, { ...cond, op: e.target.value })}
          className={selectCls}
        >
          {ops.map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>

        {/* Value */}
        {isBool ? (
          <select
            value={String(cond.value)}
            onChange={e => onChange(index, { ...cond, value: e.target.value })}
            className={selectCls}
          >
            <option value="true">true</option>
            <option value="false">false</option>
          </select>
        ) : cond.field === 'severity' ? (
          <select
            value={String(cond.value)}
            onChange={e => onChange(index, { ...cond, value: e.target.value })}
            className={selectCls}
          >
            {SEVERITIES.map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        ) : (
          <input
            type={cond.field === 'cvss_score' ? 'number' : 'text'}
            value={String(cond.value)}
            onChange={e => onChange(index, { ...cond, value: e.target.value })}
            placeholder="value…"
            className="flex-1 bg-[var(--bg-elevated)] border border-[var(--border-base)] font-mono text-[0.62rem] text-[var(--text-secondary)] px-2 py-1 outline-none focus:border-[var(--border-accent)] transition-colors min-w-0"
            step={cond.field === 'cvss_score' ? '0.1' : undefined}
            min={cond.field === 'cvss_score' ? '0' : undefined}
            max={cond.field === 'cvss_score' ? '10' : undefined}
          />
        )}

        <button
          onClick={() => onDelete(index)}
          className="shrink-0 transition-colors"
          style={{ color: 'var(--text-ghost)' }}
          onMouseEnter={e => ((e.currentTarget as HTMLButtonElement).style.color = 'var(--color-danger)')}
          onMouseLeave={e => ((e.currentTarget as HTMLButtonElement).style.color = 'var(--text-ghost)')}
          title="Remove condition"
        >
          <X size={12} />
        </button>
      </div>

      {/* AND/OR toggle between rows */}
      {!isLast && (
        <div className="flex items-center gap-2 py-0.5 pl-6">
          <div className="w-px h-3 bg-[var(--border-base)]" />
          <button
            onClick={onToggleOp}
            className="font-mono text-[0.5rem] tracking-widest px-2 py-0.5 border transition-all"
            style={{
              color:       'var(--color-info)',
              borderColor: 'rgba(139,92,246,0.35)',
              background:  'rgba(139,92,246,0.07)',
            }}
          >
            {operator}
          </button>
        </div>
      )}
    </div>
  )
}

// ─── Rule builder form ────────────────────────────────────────────────────────

interface BuilderProps {
  onSave:   (rule: Partial<AlertRule>) => Promise<void>
  onCancel: () => void
  saving:   boolean
}

function RuleBuilder({ onSave, onCancel, saving }: BuilderProps) {
  const [name,        setName]        = useState('')
  const [description, setDescription] = useState('')
  const [minSev,      setMinSev]      = useState('HIGH')
  const [cooldown,    setCooldown]    = useState(60)
  const [operator,    setOperator]    = useState<'AND' | 'OR'>('AND')
  const [channel,     setChannel]     = useState('webhook')
  const [tgChatId,    setTgChatId]    = useState('')
  const [conditions,  setConditions]  = useState<Condition[]>([
    { field: 'severity', op: 'equals', value: 'CRITICAL' },
  ])

  const addCondition = () => {
    setConditions(prev => [...prev, { field: 'severity', op: 'equals', value: 'CRITICAL' }])
  }

  const updateCondition = (i: number, c: Condition) => {
    setConditions(prev => prev.map((x, idx) => idx === i ? c : x))
  }

  const deleteCondition = (i: number) => {
    setConditions(prev => prev.filter((_, idx) => idx !== i))
  }

  const handleSave = () => {
    if (!name.trim() || conditions.length === 0) return
    const condObj: RuleConditions = { operator, conditions }
    onSave({
      name:                 name.trim(),
      description:          description.trim() || null,
      conditions:           JSON.stringify(condObj),
      min_severity:         minSev,
      cooldown_minutes:     cooldown,
      enabled:              true,
      notification_channel: channel,
      telegram_chat_id:     tgChatId.trim() || null,
    })
  }

  const inputCls = `
    w-full bg-[var(--bg-elevated)] border border-[var(--border-base)] font-mono text-[0.7rem]
    text-[var(--text-secondary)] px-3 py-2 outline-none focus:border-[var(--border-accent)]
    transition-colors placeholder:text-[var(--text-ghost)]
  `

  return (
    <div
      className="border px-5 py-4 flex flex-col gap-4"
      style={{ borderColor: 'var(--border-accent)', background: 'rgba(0,212,255,0.03)' }}
    >
      <div className="flex items-center justify-between">
        <span className="font-mono text-[0.6rem] tracking-widest" style={{ color: 'var(--color-primary)' }}>
          NEW RULE
        </span>
        <button onClick={onCancel} style={{ color: 'var(--text-ghost)' }}
          onMouseEnter={e => ((e.currentTarget as HTMLButtonElement).style.color = 'var(--text-base)')}
          onMouseLeave={e => ((e.currentTarget as HTMLButtonElement).style.color = 'var(--text-ghost)')}
        >
          <X size={13} />
        </button>
      </div>

      {/* Name */}
      <div className="flex flex-col gap-1">
        <label className="font-mono text-[0.5rem] tracking-widest" style={{ color: 'var(--text-dim)' }}>RULE NAME</label>
        <input
          className={inputCls}
          value={name}
          onChange={e => setName(e.target.value)}
          placeholder="e.g. Critical CVEs in KEV"
        />
      </div>

      {/* Description */}
      <div className="flex flex-col gap-1">
        <label className="font-mono text-[0.5rem] tracking-widest" style={{ color: 'var(--text-dim)' }}>DESCRIPTION <span style={{ color: 'var(--text-ghost)' }}>(optional)</span></label>
        <input
          className={inputCls}
          value={description}
          onChange={e => setDescription(e.target.value)}
          placeholder="Short description of what this rule detects"
        />
      </div>

      {/* Conditions */}
      <div className="flex flex-col gap-1">
        <div className="flex items-center justify-between">
          <label className="font-mono text-[0.5rem] tracking-widest" style={{ color: 'var(--text-dim)' }}>CONDITIONS</label>
          <button
            onClick={addCondition}
            className="flex items-center gap-1 font-mono text-[0.5rem] tracking-widest transition-colors"
            style={{ color: 'var(--color-primary)' }}
          >
            <Plus size={9} /> ADD CONDITION
          </button>
        </div>

        <div
          className="border px-3 py-2"
          style={{ borderColor: 'var(--border-base)', background: 'var(--bg-elevated)' }}
        >
          {conditions.length === 0 ? (
            <p className="font-mono text-[0.58rem] py-2 text-center" style={{ color: 'var(--text-ghost)' }}>
              No conditions — rule will match everything
            </p>
          ) : (
            conditions.map((c, i) => (
              <ConditionRow
                key={i}
                cond={c}
                index={i}
                onChange={updateCondition}
                onDelete={deleteCondition}
                isLast={i === conditions.length - 1}
                operator={operator}
                onToggleOp={() => setOperator(o => o === 'AND' ? 'OR' : 'AND')}
              />
            ))
          )}
        </div>
      </div>

      {/* Min severity + cooldown */}
      <div className="flex items-center gap-4">
        <div className="flex flex-col gap-1 flex-1">
          <label className="font-mono text-[0.5rem] tracking-widest" style={{ color: 'var(--text-dim)' }}>MIN SEVERITY</label>
          <select
            value={minSev}
            onChange={e => setMinSev(e.target.value)}
            className="bg-[var(--bg-elevated)] border border-[var(--border-base)] font-mono text-[0.65rem] text-[var(--text-secondary)] px-2 py-1.5 outline-none focus:border-[var(--border-accent)] appearance-none"
          >
            {SEVERITIES.map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <div className="flex flex-col gap-1 flex-1">
          <label className="font-mono text-[0.5rem] tracking-widest" style={{ color: 'var(--text-dim)' }}>COOLDOWN (min)</label>
          <input
            type="number"
            value={cooldown}
            onChange={e => setCooldown(Number(e.target.value))}
            min={1}
            className="bg-[var(--bg-elevated)] border border-[var(--border-base)] font-mono text-[0.65rem] text-[var(--text-secondary)] px-2 py-1.5 outline-none focus:border-[var(--border-accent)]"
          />
        </div>
      </div>

      {/* Notification channel */}
      <div className="flex flex-col gap-1">
        <label className="font-mono text-[0.5rem] tracking-widest" style={{ color: 'var(--text-dim)' }}>
          NOTIFICATION CHANNEL
        </label>
        <div className="flex gap-2">
          {[
            { value: 'webhook',  label: 'WEBHOOK' },
            { value: 'telegram', label: 'TELEGRAM' },
            { value: 'both',     label: 'BOTH' },
          ].map(opt => (
            <button
              key={opt.value}
              onClick={() => setChannel(opt.value)}
              className="font-mono text-[0.52rem] tracking-widest px-2.5 py-1.5 border transition-all"
              style={{
                color:       channel === opt.value ? 'var(--color-primary)' : 'var(--text-ghost)',
                borderColor: channel === opt.value ? 'var(--border-accent)' : 'var(--border-base)',
                background:  channel === opt.value ? 'rgba(0,212,255,0.08)' : 'transparent',
              }}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* Telegram chat ID override */}
      {(channel === 'telegram' || channel === 'both') && (
        <div className="flex flex-col gap-1">
          <label className="font-mono text-[0.5rem] tracking-widest" style={{ color: 'var(--text-dim)' }}>
            TELEGRAM CHAT ID <span style={{ color: 'var(--text-ghost)' }}>(leave blank to use global from Settings)</span>
          </label>
          <input
            className={inputCls}
            value={tgChatId}
            onChange={e => setTgChatId(e.target.value)}
            placeholder="-1001234567890  or  @channelname"
          />
        </div>
      )}

      {/* Save */}
      <div className="flex items-center gap-2 justify-end">
        <button
          onClick={onCancel}
          className="font-mono text-[0.56rem] tracking-widest px-3 py-2 border transition-colors"
          style={{ color: 'var(--text-dim)', borderColor: 'var(--border-base)' }}
        >
          CANCEL
        </button>
        <button
          onClick={handleSave}
          disabled={saving || !name.trim()}
          className="flex items-center gap-1.5 font-mono text-[0.56rem] tracking-widest px-3 py-2 border transition-all disabled:opacity-40"
          style={{
            color:       'var(--color-primary)',
            borderColor: 'var(--border-accent)',
            background:  'rgba(0,212,255,0.06)',
          }}
        >
          {saving ? <Loader2 size={9} className="animate-spin" /> : <CheckCircle size={9} />}
          SAVE RULE
        </button>
      </div>
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export function AlertRules() {
  const [rules,       setRules]       = useState<AlertRule[]>([])
  const [loading,     setLoading]     = useState(true)
  const [showBuilder, setShowBuilder] = useState(false)
  const [saving,      setSaving]      = useState(false)
  const [testResults, setTestResults] = useState<Record<number, string>>({})
  const [testing,     setTesting]     = useState<Record<number, boolean>>({})

  const loadRules = useCallback(async () => {
    try {
      const r = await fetch('/api/v1/rules')
      if (r.ok) setRules(await r.json())
    } catch { /* ignore */ } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadRules() }, [loadRules])

  const toggleRule = async (id: number, enabled: boolean) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !enabled } : r))
    try {
      await fetch(`/api/v1/rules/${id}`, {
        method:  'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ enabled: !enabled }),
      })
    } catch {
      setRules(prev => prev.map(r => r.id === id ? { ...r, enabled } : r))
    }
  }

  const deleteRule = async (id: number) => {
    setRules(prev => prev.filter(r => r.id !== id))
    try {
      await fetch(`/api/v1/rules/${id}`, { method: 'DELETE' })
    } catch {
      await loadRules()
    }
  }

  const saveRule = async (data: Partial<AlertRule>) => {
    setSaving(true)
    try {
      const r = await fetch('/api/v1/rules', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(data),
      })
      if (r.ok) {
        await loadRules()
        setShowBuilder(false)
      }
    } catch { /* ignore */ } finally {
      setSaving(false)
    }
  }

  const testRule = async (id: number) => {
    setTesting(t => ({ ...t, [id]: true }))
    try {
      const r = await fetch(`/api/v1/rules/${id}/test`, { method: 'POST' })
      if (r.ok) {
        const data = await r.json() as { matches: number; message?: string }
        setTestResults(tr => ({ ...tr, [id]: `${data.matches} recent match${data.matches !== 1 ? 'es' : ''}` }))
      } else {
        setTestResults(tr => ({ ...tr, [id]: 'Test failed' }))
      }
    } catch {
      setTestResults(tr => ({ ...tr, [id]: 'Error' }))
    } finally {
      setTesting(t => ({ ...t, [id]: false }))
      setTimeout(() => setTestResults(tr => { const n = { ...tr }; delete n[id]; return n }), 4000)
    }
  }

  return (
    <div className="max-w-2xl mx-auto py-6 px-2 flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <Bell size={14} className="text-[var(--color-primary)]" />
          <span className="font-mono text-[0.68rem] tracking-widest text-[var(--color-primary)]">ALERT RULES</span>
          {!loading && (
            <span className="font-mono text-[0.48rem] text-[var(--text-ghost)] tracking-widest">
              [{rules.filter(r => r.enabled).length}/{rules.length} active]
            </span>
          )}
        </div>
        <button
          onClick={() => setShowBuilder(v => !v)}
          className="flex items-center gap-1.5 font-mono text-[0.56rem] tracking-widest px-3 py-1.5 border transition-all"
          style={{
            color:       'var(--color-primary)',
            borderColor: 'var(--border-accent)',
            background:  showBuilder ? 'rgba(0,212,255,0.1)' : 'transparent',
          }}
        >
          <Plus size={10} />
          NEW RULE
        </button>
      </div>

      {/* Builder */}
      <AnimatePresence>
        {showBuilder && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2 }}
            style={{ overflow: 'hidden' }}
          >
            <RuleBuilder
              onSave={saveRule}
              onCancel={() => setShowBuilder(false)}
              saving={saving}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Rules list */}
      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">CONFIGURED RULES</span>
        </div>

        {loading && (
          <div className="py-10 text-center font-mono text-[0.6rem] text-[var(--text-ghost)] tracking-widest animate-pulse">
            LOADING RULES...
          </div>
        )}

        {!loading && rules.length === 0 && !showBuilder && (
          <div className="py-10 flex flex-col items-center gap-2">
            <Bell size={22} className="text-[var(--text-ghost)]" />
            <p className="font-mono text-[0.6rem] text-[var(--text-ghost)] tracking-widest">NO RULES DEFINED</p>
            <button
              onClick={() => setShowBuilder(true)}
              className="font-mono text-[0.55rem] text-[var(--color-primary)] tracking-widest hover:underline"
            >
              CREATE YOUR FIRST RULE
            </button>
          </div>
        )}

        {rules.map((rule, i) => {
          let parsedConds: RuleConditions | null = null
          try { parsedConds = JSON.parse(rule.conditions) } catch { /* ignore */ }

          return (
            <motion.div
              key={rule.id}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.04 }}
              className="px-4 py-3 border-b"
              style={{ borderColor: 'var(--border-base)' }}
            >
              <div className="flex items-start gap-3">
                {/* Toggle */}
                <button
                  onClick={() => toggleRule(rule.id, rule.enabled)}
                  className="shrink-0 mt-0.5"
                  title={rule.enabled ? 'Disable' : 'Enable'}
                >
                  {rule.enabled
                    ? <ToggleRight size={18} className="text-[var(--color-success)]" />
                    : <ToggleLeft  size={18} className="text-[var(--text-ghost)]" />
                  }
                </button>

                {/* Rule info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className="font-mono text-[0.7rem]"
                      style={{ color: rule.enabled ? 'var(--text-secondary)' : 'var(--text-ghost)' }}
                    >
                      {rule.name}
                    </span>
                    <span
                      className="font-mono text-[0.48rem] tracking-wider px-1.5 py-0.5 border"
                      style={{
                        color:       sevColor(rule.min_severity),
                        borderColor: `${sevColor(rule.min_severity)}4d`,
                        background:  `${sevColor(rule.min_severity)}14`,
                      }}
                    >
                      {rule.min_severity}+
                    </span>
                    <span className="font-mono text-[0.48rem] text-[var(--text-ghost)]">
                      {rule.hit_count} hits
                    </span>
                    {/* Notification channel badge */}
                    {rule.notification_channel && rule.notification_channel !== 'webhook' && (
                      <span
                        className="font-mono text-[0.44rem] tracking-widest px-1.5 py-0.5 border"
                        style={{
                          color:       rule.notification_channel === 'telegram' ? '#26a5e4' : '#f7931a',
                          borderColor: rule.notification_channel === 'telegram' ? '#26a5e433' : '#f7931a33',
                          background:  rule.notification_channel === 'telegram' ? '#26a5e411' : '#f7931a11',
                        }}
                      >
                        {rule.notification_channel === 'telegram' ? '📨 TG' : '📨 TG+WH'}
                      </span>
                    )}
                    {rule.last_triggered && (
                      <span className="font-mono text-[0.48rem] text-[var(--text-ghost)]">
                        · last {timeAgo(rule.last_triggered)}
                      </span>
                    )}
                  </div>

                  {rule.description && (
                    <p className="font-mono text-[0.58rem] mt-0.5" style={{ color: 'var(--text-muted)' }}>
                      {rule.description}
                    </p>
                  )}

                  {/* Conditions summary */}
                  {parsedConds && (
                    <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
                      {parsedConds.conditions.slice(0, 4).map((c, ci) => (
                        <span key={ci} className="flex items-center gap-1">
                          {ci > 0 && (
                            <span className="font-mono text-[0.44rem]" style={{ color: 'var(--color-info)' }}>
                              {parsedConds!.operator}
                            </span>
                          )}
                          <span
                            className="font-mono text-[0.5rem] px-1.5 py-0.5 border"
                            style={{
                              color:       'var(--text-muted)',
                              borderColor: 'var(--border-base)',
                              background:  'var(--bg-elevated)',
                            }}
                          >
                            {c.field} {c.op} {String(c.value)}
                          </span>
                        </span>
                      ))}
                      {parsedConds.conditions.length > 4 && (
                        <span className="font-mono text-[0.48rem]" style={{ color: 'var(--text-ghost)' }}>
                          +{parsedConds.conditions.length - 4} more
                        </span>
                      )}
                    </div>
                  )}

                  {/* Test result */}
                  {testResults[rule.id] && (
                    <p className="font-mono text-[0.55rem] mt-1" style={{ color: 'var(--color-success)' }}>
                      ✓ {testResults[rule.id]}
                    </p>
                  )}
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => testRule(rule.id)}
                    disabled={testing[rule.id]}
                    className="flex items-center gap-1 font-mono text-[0.5rem] tracking-widest px-2 py-1 border transition-all disabled:opacity-40"
                    style={{
                      color:       'var(--text-dim)',
                      borderColor: 'var(--border-base)',
                    }}
                    title="Test against recent items"
                  >
                    {testing[rule.id]
                      ? <Loader2 size={8} className="animate-spin" />
                      : <FlaskConical size={8} />
                    }
                    TEST
                  </button>
                  <button
                    onClick={() => deleteRule(rule.id)}
                    className="transition-colors"
                    style={{ color: 'var(--text-ghost)' }}
                    onMouseEnter={e => ((e.currentTarget as HTMLButtonElement).style.color = 'var(--color-danger)')}
                    onMouseLeave={e => ((e.currentTarget as HTMLButtonElement).style.color = 'var(--text-ghost)')}
                    title="Delete rule"
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>

              {/* Cooldown info */}
              <div className="mt-1.5 pl-9">
                <span className="font-mono text-[0.48rem] text-[var(--text-ghost)]">
                  cooldown: {rule.cooldown_minutes}m
                </span>
              </div>
            </motion.div>
          )
        })}
      </div>

      {/* Info note */}
      <div
        className="flex items-start gap-2 px-3 py-2.5 border"
        style={{
          borderColor: 'rgba(255,170,0,0.2)',
          background:  'rgba(255,170,0,0.04)',
        }}
      >
        <AlertTriangle size={11} className="text-[var(--color-warning)] shrink-0 mt-0.5" />
        <p className="font-mono text-[0.55rem] text-[var(--text-muted)] leading-relaxed">
          Rules are evaluated against incoming items during each collection cycle.
          Webhook targets are configured in Settings. Cooldown prevents duplicate alerts.
        </p>
      </div>
    </div>
  )
}
