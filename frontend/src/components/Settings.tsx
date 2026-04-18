import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import {
  Settings2, Save, Eye, EyeOff, CheckCircle,
  AlertTriangle, FlaskConical, Loader2, Bell, Clock,
  Rss, Plus, Trash2, ToggleLeft, ToggleRight, RefreshCw,
  Bot, Sun, Moon, ScrollText, User, Filter, Lock, Activity,
  Cpu, Link, ExternalLink,
} from 'lucide-react'
import { timeAgo } from '@/lib/utils'
import { API_BASE } from '@/hooks/useApi'

interface SettingField {
  key: string
  label: string
  placeholder: string
  secret: boolean
  hint: string
  testable?: boolean
}

const FIELDS: SettingField[] = [
  {
    key:         'OLLAMA_HOST',
    label:       'Ollama Host URL',
    placeholder: 'https://your-tunnel.trycloudflare.com  or  http://localhost:11434',
    secret:      false,
    testable:    true,
    hint:        'Where your Ollama server is running. Use http://localhost:11434 for local, or a Cloudflare / ngrok tunnel URL (must be https://) for remote access from Render.',
  },
  {
    key:         'AI_MODEL',
    label:       'Ollama Model',
    placeholder: 'llama3.2:3b',
    secret:      false,
    hint:        'Ollama model to use for AI features. Default: llama3.2:3b (fast, runs on CPU). Other options: llama3.1:8b, mistral:7b, phi3:mini.',
  },
  {
    key:      'GROQ_API_KEY',
    label:    'Groq API Key',
    placeholder: 'gsk_…',
    secret:   true,
    hint:     'Free at console.groq.com — 6 000 req/day. Enables cloud AI without a local GPU. Provider chain falls back here if Ollama is not running.',
  },
  {
    key:      'OPENROUTER_API_KEY',
    label:    'OpenRouter API Key',
    placeholder: 'sk-or-…',
    secret:   true,
    hint:     'Pay-per-use cloud router at openrouter.ai — access to Gemini, Claude, Llama, and more. Used if Ollama and Groq are both unavailable.',
  },
  {
    key:      'LLM_API_URL',
    label:    'Generic LLM Endpoint (URL)',
    placeholder: 'https://api.example.com/v1/chat/completions',
    secret:   false,
    hint:     'Any OpenAI-compatible /v1/chat/completions endpoint (LM Studio, vLLM, etc.). Also set LLM API Key and LLM Model below.',
  },
  {
    key:      'LLM_API_KEY',
    label:    'Generic LLM API Key',
    placeholder: 'sk-…',
    secret:   true,
    hint:     'API key for the generic endpoint above.',
  },
  {
    key:      'LLM_MODEL',
    label:    'Generic LLM Model Name',
    placeholder: 'gpt-4o-mini',
    secret:   false,
    hint:     'Model ID to send to the generic endpoint (e.g. gpt-4o-mini, mistral-small).',
  },
  {
    key:      'TELEGRAM_BOT_TOKEN',
    label:    'Telegram Bot Token',
    placeholder: '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11',
    secret:   true,
    hint:     'Create a bot via @BotFather on Telegram and paste the token here. Used to send alert notifications.',
  },
  {
    key:      'TELEGRAM_CHAT_ID',
    label:    'Telegram Chat ID (Global)',
    placeholder: '-1001234567890  or  @channelname',
    secret:   false,
    hint:     'Default target chat or channel for Telegram alerts. Individual rules can override this. Use @BotFather or @userinfobot to find your chat ID.',
  },
  {
    key:      'WEBHOOK_URL',
    label:    'Alert Webhook URL',
    placeholder: 'https://hooks.slack.com/… or https://discord.com/api/webhooks/…',
    secret:   false,
    testable: true,
    hint:     'POST target for new alerts. Receives JSON payload with matching items.',
  },
  {
    key:      'WEBHOOK_MIN_SEVERITY',
    label:    'Webhook Minimum Severity',
    placeholder: 'CRITICAL',
    secret:   false,
    hint:     'Minimum severity to trigger webhook. One of: CRITICAL, HIGH, MEDIUM, INFO.',
  },
]

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'
type TestStatus = 'idle' | 'testing' | 'ok' | 'fail'

interface AuditLogEntry {
  id: number
  timestamp: string | null
  action: string
  actor: string
  entity_type: string | null
  entity_id: string | null
  details: Record<string, unknown> | null
  ip_address: string | null
}

interface AlertLogEntry {
  id: number
  fired_at: string | null
  item_type: string
  count: number
  top_severity: string
  webhook_url: string
  success: boolean
  sample_title: string | null
}

interface RssFeed {
  id: number
  name: string
  url: string
  enabled: boolean
  added_at: string
  last_fetch: string | null
  item_count: number
}

function actionColor(action: string) {
  if (action.startsWith('auth'))       return 'var(--color-info)'
  if (action.startsWith('collector') || action.startsWith('collect')) return 'var(--color-primary)'
  if (action.includes('delete') || action.includes('error')) return 'var(--color-danger)'
  if (action.includes('create') || action.includes('add')) return 'var(--color-success)'
  if (action.includes('update') || action.includes('patch')) return 'var(--color-warning)'
  return 'var(--text-dim)'
}

function severityColor(sev: string) {
  if (sev === 'CRITICAL') return 'var(--color-danger)'
  if (sev === 'HIGH')     return 'var(--color-warning)'
  if (sev === 'MEDIUM')   return 'var(--color-primary)'
  return 'var(--color-success)'
}

interface CollectorStatus {
  name: string
  last_run: string | null
  last_count: number | null
  error: string | null
  status: 'ok' | 'error'
}

interface SettingsProps {
  theme: 'dark' | 'light'
  onThemeToggle: () => void
}

export function Settings({ theme, onThemeToggle }: SettingsProps) {
  const [values, setValues]         = useState<Record<string, string>>({})
  const [showSecret, setShowSecret] = useState<Record<string, boolean>>({})
  const [saveStatus, setSaveStatus] = useState<Record<string, SaveStatus>>({})
  const [testStatus, setTestStatus] = useState<Record<string, TestStatus>>({})
  const [testMsg, setTestMsg]       = useState<Record<string, string>>({})
  const [loading, setLoading]       = useState(true)
  const [alertLog, setAlertLog]     = useState<AlertLogEntry[]>([])
  const [logLoading, setLogLoading] = useState(true)
  const [auditLog, setAuditLog]     = useState<AuditLogEntry[]>([])
  const [auditLoading, setAuditLoading] = useState(true)
  const [auditActionFilter, setAuditActionFilter] = useState('')

  // Password change state
  const [pwCurrent, setPwCurrent]   = useState('')
  const [pwNew, setPwNew]           = useState('')
  const [pwConfirm, setPwConfirm]   = useState('')
  const [pwStatus, setPwStatus]     = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [pwMsg, setPwMsg]           = useState('')
  const [showPwCurrent, setShowPwCurrent] = useState(false)
  const [showPwNew, setShowPwNew]   = useState(false)

  // Collector status
  const [collectorStatus, setCollectorStatus] = useState<CollectorStatus[]>([])
  const [collectorLoading, setCollectorLoading] = useState(true)

  // Ollama status
  const [ollamaStatus, setOllamaStatus] = useState<{
    stage: string; message: string; progress: number; model: string; error: string | null
  } | null>(null)
  const [ollamaLoading, setOllamaLoading] = useState(true)

  // RSS feed management state
  const [feeds, setFeeds]           = useState<RssFeed[]>([])
  const [feedsLoading, setFeedsLoading] = useState(true)
  const [newFeedName, setNewFeedName] = useState('')
  const [newFeedUrl, setNewFeedUrl]   = useState('')
  const [addingFeed, setAddingFeed]   = useState(false)
  const [feedError, setFeedError]     = useState('')
  const [resetting, setResetting]     = useState(false)

  const loadOllamaStatus = useCallback(async () => {
    setOllamaLoading(true)
    try {
      const r = await fetch(`${API_BASE}/ollama/setup-status`)
      if (r.ok) setOllamaStatus(await r.json())
    } catch { /* ignore */ } finally {
      setOllamaLoading(false)
    }
  }, [])

  useEffect(() => {
    fetch(`${API_BASE}/settings`)
      .then(r => r.json())
      .then(data => { setValues(data); setLoading(false) })
      .catch(() => setLoading(false))

    fetch(`${API_BASE}/alert-log?limit=20`)
      .then(r => r.json())
      .then(data => { setAlertLog(data); setLogLoading(false) })
      .catch(() => setLogLoading(false))

    loadFeeds()
    loadAuditLog()
    loadCollectorStatus()
    loadOllamaStatus()
  }, [])  // eslint-disable-line react-hooks/exhaustive-deps

  const loadCollectorStatus = useCallback(async () => {
    setCollectorLoading(true)
    try {
      const r = await fetch(`${API_BASE}/collect/status`)
      if (r.ok) setCollectorStatus(await r.json())
    } catch { /* ignore */ } finally {
      setCollectorLoading(false)
    }
  }, [])

  const changePassword = async () => {
    if (!pwCurrent || !pwNew) { setPwMsg('Fill in all fields.'); return }
    if (pwNew !== pwConfirm)  { setPwMsg('New passwords do not match.'); return }
    if (pwNew.length < 8)     { setPwMsg('New password must be at least 8 characters.'); return }
    setPwStatus('saving'); setPwMsg('')
    try {
      const r = await fetch(`${API_BASE}/auth/change-password`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ current_password: pwCurrent, new_password: pwNew }),
      })
      if (!r.ok) {
        const data = await r.json()
        setPwMsg(data.detail ?? 'Failed to change password.')
        setPwStatus('error')
      } else {
        setPwStatus('saved')
        setPwMsg('Password changed successfully.')
        setPwCurrent(''); setPwNew(''); setPwConfirm('')
        setTimeout(() => { setPwStatus('idle'); setPwMsg('') }, 3500)
      }
    } catch {
      setPwStatus('error')
      setPwMsg('Request failed.')
    }
  }

  const loadAuditLog = useCallback(async (action?: string) => {
    setAuditLoading(true)
    try {
      const qs = action ? `?limit=50&action=${encodeURIComponent(action)}` : '?limit=50'
      const r = await fetch(`${API_BASE}/audit-log${qs}`)
      if (r.ok) setAuditLog(await r.json())
    } catch { /* ignore */ } finally {
      setAuditLoading(false)
    }
  }, [])

  const loadFeeds = useCallback(async () => {
    setFeedsLoading(true)
    try {
      const r = await fetch(`${API_BASE}/feeds`)
      if (r.ok) setFeeds(await r.json())
    } catch { /* ignore */ } finally {
      setFeedsLoading(false)
    }
  }, [])

  const save = async (key: string) => {
    setSaveStatus(s => ({ ...s, [key]: 'saving' }))
    try {
      const resp = await fetch(`${API_BASE}/settings`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ key, value: values[key] ?? '' }),
      })
      if (!resp.ok) throw new Error()
      setSaveStatus(s => ({ ...s, [key]: 'saved' }))
      setTimeout(() => setSaveStatus(s => ({ ...s, [key]: 'idle' })), 2500)
    } catch {
      setSaveStatus(s => ({ ...s, [key]: 'error' }))
      setTimeout(() => setSaveStatus(s => ({ ...s, [key]: 'idle' })), 3000)
    }
  }

  const testConnection = async (key: string) => {
    setTestStatus(s => ({ ...s, [key]: 'testing' }))
    setTestMsg(m => ({ ...m, [key]: '' }))
    try {
      const resp = await fetch(`${API_BASE}/settings/test`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ key }),
      })
      const data = await resp.json()
      setTestStatus(s => ({ ...s, [key]: data.ok ? 'ok' : 'fail' }))
      setTestMsg(m => ({ ...m, [key]: data.message }))
      setTimeout(() => setTestStatus(s => ({ ...s, [key]: 'idle' })), 5000)
    } catch {
      setTestStatus(s => ({ ...s, [key]: 'fail' }))
      setTestMsg(m => ({ ...m, [key]: 'Request failed' }))
      setTimeout(() => setTestStatus(s => ({ ...s, [key]: 'idle' })), 4000)
    }
  }

  const addFeed = async () => {
    if (!newFeedName.trim() || !newFeedUrl.trim()) {
      setFeedError('Both name and URL are required.')
      return
    }
    setAddingFeed(true)
    setFeedError('')
    try {
      const r = await fetch(`${API_BASE}/feeds`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ name: newFeedName.trim(), url: newFeedUrl.trim() }),
      })
      if (!r.ok) {
        const data = await r.json()
        setFeedError(data.detail ?? 'Failed to add feed.')
        return
      }
      setNewFeedName('')
      setNewFeedUrl('')
      await loadFeeds()
    } catch {
      setFeedError('Request failed.')
    } finally {
      setAddingFeed(false)
    }
  }

  const toggleFeed = async (id: number, enabled: boolean) => {
    // Optimistic update
    setFeeds(prev => prev.map(f => f.id === id ? { ...f, enabled: !enabled } : f))
    try {
      await fetch(`${API_BASE}/feeds/${id}`, {
        method:  'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ enabled: !enabled }),
      })
    } catch {
      // Revert on failure
      setFeeds(prev => prev.map(f => f.id === id ? { ...f, enabled } : f))
    }
  }

  const deleteFeed = async (id: number) => {
    setFeeds(prev => prev.filter(f => f.id !== id))
    try {
      await fetch(`${API_BASE}/feeds/${id}`, { method: 'DELETE' })
    } catch {
      await loadFeeds()  // reload on failure
    }
  }

  const resetFeeds = async () => {
    setResetting(true)
    try {
      await fetch(`${API_BASE}/feeds/reset`, { method: 'POST' })
      await loadFeeds()
    } catch { /* ignore */ } finally {
      setResetting(false)
    }
  }

  return (
    <div className="max-w-2xl mx-auto py-6 px-2 flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <Settings2 size={14} className="text-[var(--color-primary)]" />
          <span className="font-mono text-[0.68rem] tracking-widest text-[var(--color-primary)]">SYSTEM SETTINGS</span>
        </div>
        {/* Theme toggle */}
        <button
          onClick={onThemeToggle}
          className="flex items-center gap-2 px-3 py-1.5 border font-mono text-[0.52rem] tracking-widest transition-all"
          style={{
            color:       theme === 'light' ? '#0077aa' : 'var(--color-primary)',
            borderColor: theme === 'light' ? 'rgba(0,119,170,0.35)' : 'var(--border-accent)',
            background:  theme === 'light' ? 'rgba(0,119,170,0.06)' : 'rgba(0,212,255,0.05)',
          }}
          title="Toggle dark / light mode"
        >
          {theme === 'light'
            ? <><Moon size={10} /> DARK MODE</>
            : <><Sun  size={10} /> LIGHT MODE</>
          }
        </button>
      </div>

      {loading && (
        <div className="font-mono text-[0.65rem] text-[var(--text-ghost)] tracking-widest text-center py-10 animate-pulse">
          LOADING SETTINGS...
        </div>
      )}

      {!loading && FIELDS.map((field, fi) => {
        const isSecret = field.secret
        const shown    = showSecret[field.key] ?? false
        const val      = values[field.key] ?? ''
        const isMasked = isSecret && val === '••••••••'
        const st       = saveStatus[field.key] ?? 'idle'
        const ts       = testStatus[field.key] ?? 'idle'
        const tm       = testMsg[field.key] ?? ''

        return (
          <motion.div
            key={field.key}
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: fi * 0.04 }}
            className="panel"
          >
            <div className="panel-header">
              <div className="flex items-center gap-1.5">
                {field.key === 'AI_MODEL' && <Bot size={10} className="text-[var(--color-info)]" />}
                <span className="panel-title text-[0.65rem]">{field.label}</span>
              </div>
              <span className="font-mono text-[0.48rem] text-[var(--text-ghost)] tracking-widest">{field.key}</span>
            </div>

            <div className="px-4 py-3 flex flex-col gap-2.5">
              <p className="font-mono text-[0.6rem] text-[var(--text-muted)] leading-relaxed">{field.hint}</p>

              {/* Input row */}
              <div className="flex items-center gap-2">
                <div className="flex-1 flex items-center border border-[var(--border-base)] bg-[var(--bg-elevated)] focus-within:border-[var(--border-accent)] transition-colors">
                  <input
                    type={isSecret && !shown ? 'password' : 'text'}
                    value={isMasked ? '' : val}
                    placeholder={isMasked ? '(saved — re-enter to change)' : field.placeholder}
                    onChange={e => setValues(v => ({ ...v, [field.key]: e.target.value }))}
                    className="flex-1 bg-transparent font-mono text-[0.72rem] text-[var(--text-secondary)] px-3 py-2 outline-none placeholder-[var(--text-ghost)] tracking-wide"
                  />
                  {isSecret && (
                    <button
                      onClick={() => setShowSecret(s => ({ ...s, [field.key]: !shown }))}
                      className="px-2 text-[var(--text-dim)] hover:text-[var(--text-base)] transition-colors"
                    >
                      {shown ? <EyeOff size={12} /> : <Eye size={12} />}
                    </button>
                  )}
                </div>

                {/* Save button */}
                <button
                  onClick={() => save(field.key)}
                  disabled={st === 'saving'}
                  className="flex items-center gap-1.5 font-mono text-[0.56rem] tracking-widest px-3 py-2 border transition-all disabled:opacity-40 shrink-0"
                  style={{
                    color:       st === 'error' ? 'var(--color-danger)' : st === 'saved' ? 'var(--color-success)' : 'var(--color-primary)',
                    borderColor: st === 'error' ? 'rgba(255,34,85,0.4)' : st === 'saved' ? 'rgba(0,255,136,0.4)' : 'var(--border-accent)',
                    background:  st === 'saved' ? 'rgba(0,255,136,0.07)' : 'transparent',
                  }}
                >
                  {st === 'saving' && <><Loader2 size={9} className="animate-spin" />SAVING</>}
                  {st === 'saved'  && <><CheckCircle size={9} />SAVED</>}
                  {st === 'error'  && <><AlertTriangle size={9} />ERROR</>}
                  {st === 'idle'   && <><Save size={9} />SAVE</>}
                </button>

                {/* Test connection button (only for testable fields) */}
                {field.testable && (
                  <button
                    onClick={() => testConnection(field.key)}
                    disabled={ts === 'testing'}
                    className="flex items-center gap-1.5 font-mono text-[0.56rem] tracking-widest px-3 py-2 border transition-all disabled:opacity-40 shrink-0"
                    style={{
                      color:       ts === 'ok' ? 'var(--color-success)' : ts === 'fail' ? 'var(--color-danger)' : 'var(--text-dim)',
                      borderColor: ts === 'ok' ? 'rgba(0,255,136,0.35)' : ts === 'fail' ? 'rgba(255,34,85,0.35)' : 'var(--border-base)',
                      background:  ts === 'ok' ? 'rgba(0,255,136,0.06)' : ts === 'fail' ? 'rgba(255,34,85,0.06)' : 'transparent',
                    }}
                    title="Test connection"
                  >
                    {ts === 'testing' ? <Loader2 size={9} className="animate-spin" /> : <FlaskConical size={9} />}
                    TEST
                  </button>
                )}
              </div>

              {/* Test result message */}
              {tm && (
                <motion.p
                  initial={{ opacity: 0, y: -3 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="font-mono text-[0.58rem] leading-relaxed"
                  style={{ color: testStatus[field.key] === 'ok' ? 'var(--color-success)' : 'var(--color-danger)' }}
                >
                  {testStatus[field.key] === 'ok' ? '✓' : '✗'} {tm}
                </motion.p>
              )}
            </div>
          </motion.div>
        )
      })}

      {/* ── Ollama AI Engine Status ─────────────────────────────────────── */}
      <div className="panel">
        <div className="panel-header">
          <div className="flex items-center gap-2">
            <Cpu size={11} className="text-[var(--color-primary)]" />
            <span className="panel-title">OLLAMA AI ENGINE</span>
          </div>
          <button
            onClick={loadOllamaStatus}
            disabled={ollamaLoading}
            className="flex items-center gap-1 px-2 py-1 border border-[var(--border-base)] font-mono text-[0.46rem] tracking-widest text-[var(--text-dim)] hover:text-[var(--color-primary)] hover:border-[var(--border-accent)] transition-colors disabled:opacity-40"
          >
            <RefreshCw size={8} className={ollamaLoading ? 'animate-spin' : ''} />
            REFRESH
          </button>
        </div>

        <div className="px-4 py-3 flex flex-col gap-3">
          {/* Status indicator */}
          {ollamaStatus && (
            <div className="flex flex-col gap-2">
              <div className="flex items-center gap-3">
                {/* Stage badge */}
                <span
                  className="font-mono text-[0.5rem] tracking-widest px-2 py-0.5 border shrink-0"
                  style={{
                    color:       ollamaStatus.stage === 'ready'  ? 'var(--color-success)'
                               : ollamaStatus.stage === 'error'  ? 'var(--color-danger)'
                               : 'var(--color-warning)',
                    borderColor: ollamaStatus.stage === 'ready'  ? 'rgba(0,255,136,0.35)'
                               : ollamaStatus.stage === 'error'  ? 'rgba(255,34,85,0.35)'
                               : 'rgba(255,170,0,0.35)',
                    background:  ollamaStatus.stage === 'ready'  ? 'rgba(0,255,136,0.06)'
                               : ollamaStatus.stage === 'error'  ? 'rgba(255,34,85,0.06)'
                               : 'rgba(255,170,0,0.06)',
                  }}
                >
                  {ollamaStatus.stage.toUpperCase()}
                </span>
                <span className="font-mono text-[0.62rem] text-[var(--text-secondary)]">{ollamaStatus.message}</span>
              </div>

              {/* Progress bar (hidden when ready/error) */}
              {ollamaStatus.stage !== 'ready' && ollamaStatus.stage !== 'error' && ollamaStatus.progress > 0 && (
                <div className="h-0.5 bg-[var(--bg-elevated)] w-full overflow-hidden">
                  <div
                    className="h-full transition-all duration-500"
                    style={{ width: `${ollamaStatus.progress}%`, background: 'var(--color-primary)' }}
                  />
                </div>
              )}

              {/* Model + error */}
              {ollamaStatus.model && (
                <span className="font-mono text-[0.52rem] text-[var(--text-ghost)]">
                  Model: <span className="text-[var(--text-dim)]">{ollamaStatus.model}</span>
                </span>
              )}
              {ollamaStatus.error && (
                <span className="font-mono text-[0.52rem] text-[var(--color-danger)]">✗ {ollamaStatus.error}</span>
              )}
            </div>
          )}

          {/* Setup guide for Cloudflare tunnel */}
          <div className="border border-[var(--border-base)] bg-[var(--bg-elevated)] px-3 py-2.5 flex flex-col gap-1.5">
            <div className="flex items-center gap-1.5">
              <Link size={9} className="text-[var(--color-info)] shrink-0" />
              <span className="font-mono text-[0.55rem] tracking-widest text-[var(--color-info)]">REMOTE TUNNEL SETUP (NO COMMANDS)</span>
            </div>
            <ol className="flex flex-col gap-1">
              {[
                { n: '1', text: 'Start Ollama on your local machine (system tray or ollama serve)' },
                { n: '2', text: 'Go to one.dash.cloudflare.com → Zero Trust → Networks → Tunnels → Create a tunnel' },
                { n: '3', text: 'Choose "Cloudflared" → name it (e.g. sigintx-ollama) → download & run the Windows connector (.exe installer, no commands needed)' },
                { n: '4', text: 'Add a public hostname: subdomain = ollama, domain = yourdomain.com, service = http://localhost:11434' },
                { n: '5', text: 'Paste the resulting https://ollama.yourdomain.com URL into the OLLAMA_HOST field above and click Save' },
                { n: '6', text: '(Optional) In Cloudflare Access, add a Service Auth policy so only your Render backend can call it' },
              ].map(s => (
                <li key={s.n} className="flex items-start gap-2">
                  <span className="font-mono text-[0.46rem] text-[var(--color-primary)] shrink-0 mt-0.5 w-3">{s.n}.</span>
                  <span className="font-mono text-[0.52rem] text-[var(--text-muted)] leading-relaxed">{s.text}</span>
                </li>
              ))}
            </ol>
            <a
              href="https://one.dash.cloudflare.com"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 font-mono text-[0.5rem] text-[var(--color-info)] hover:underline mt-0.5 w-fit"
            >
              <ExternalLink size={8} />
              Open Cloudflare Zero Trust Dashboard
            </a>
          </div>
        </div>
      </div>

      {/* ── RSS Feed Management ──────────────────────────────────────────── */}
      <div className="panel">
        <div className="panel-header">
          <div className="flex items-center gap-2">
            <Rss size={11} className="text-[var(--color-primary)]" />
            <span className="panel-title">RSS FEED SOURCES</span>
            {!feedsLoading && (
              <span className="font-mono text-[0.48rem] text-[var(--text-ghost)] tracking-widest">
                [{feeds.filter(f => f.enabled).length}/{feeds.length} active]
              </span>
            )}
          </div>
          <button
            onClick={resetFeeds}
            disabled={resetting}
            className="flex items-center gap-1 px-2 py-1 border border-[var(--border-base)] font-mono text-[0.46rem] tracking-widest text-[var(--text-dim)] hover:text-[var(--color-warning)] hover:border-[rgba(255,170,0,0.4)] transition-colors disabled:opacity-40"
            title="Reset to default feed list"
          >
            {resetting ? <Loader2 size={8} className="animate-spin" /> : <RefreshCw size={8} />}
            RESET TO DEFAULTS
          </button>
        </div>

        <div className="px-4 py-3 flex flex-col gap-3">
          {/* Add feed form */}
          <div className="flex flex-col gap-2">
            <p className="font-mono text-[0.55rem] text-[var(--text-dim)] tracking-widest">ADD CUSTOM FEED</p>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={newFeedName}
                onChange={e => setNewFeedName(e.target.value)}
                placeholder="Feed name (e.g. SANS ISC)"
                className="w-36 bg-[var(--bg-elevated)] border border-[var(--border-base)] font-mono text-[0.65rem] text-[var(--text-secondary)] px-2.5 py-1.5 outline-none focus:border-[var(--border-accent)] transition-colors placeholder:text-[var(--text-ghost)]"
              />
              <input
                type="text"
                value={newFeedUrl}
                onChange={e => setNewFeedUrl(e.target.value)}
                placeholder="https://… (RSS/Atom)"
                className="flex-1 bg-[var(--bg-elevated)] border border-[var(--border-base)] font-mono text-[0.65rem] text-[var(--text-secondary)] px-2.5 py-1.5 outline-none focus:border-[var(--border-accent)] transition-colors placeholder:text-[var(--text-ghost)]"
                onKeyDown={e => e.key === 'Enter' && addFeed()}
              />
              <button
                onClick={addFeed}
                disabled={addingFeed || !newFeedName.trim() || !newFeedUrl.trim()}
                className="flex items-center gap-1 px-2.5 py-1.5 border border-[var(--border-accent)] font-mono text-[0.52rem] tracking-widest text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.06)] transition-colors disabled:opacity-40 shrink-0"
              >
                {addingFeed ? <Loader2 size={9} className="animate-spin" /> : <Plus size={9} />}
                ADD
              </button>
            </div>
            {feedError && (
              <p className="font-mono text-[0.55rem] text-[var(--color-danger)]">✗ {feedError}</p>
            )}
          </div>

          {/* Feed list */}
          <div className="flex flex-col gap-0 border border-[var(--border-base)] overflow-hidden">
            {feedsLoading && (
              <div className="py-6 text-center font-mono text-[0.58rem] text-[var(--text-ghost)] tracking-widest animate-pulse">
                LOADING FEEDS...
              </div>
            )}

            {!feedsLoading && feeds.length === 0 && (
              <div className="py-6 text-center font-mono text-[0.58rem] text-[var(--text-ghost)] tracking-widest">
                NO FEEDS CONFIGURED
              </div>
            )}

            {feeds.map((feed, i) => (
              <div
                key={feed.id}
                className="flex items-center gap-3 px-3 py-2 transition-colors hover:bg-[var(--bg-card-hover)]"
                style={{ borderTop: i > 0 ? '1px solid var(--border-base)' : undefined }}
              >
                {/* Toggle */}
                <button
                  onClick={() => toggleFeed(feed.id, feed.enabled)}
                  className="shrink-0 transition-colors"
                  title={feed.enabled ? 'Disable feed' : 'Enable feed'}
                >
                  {feed.enabled
                    ? <ToggleRight size={16} className="text-[var(--color-success)]" />
                    : <ToggleLeft  size={16} className="text-[var(--text-ghost)]" />
                  }
                </button>

                {/* Feed info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span
                      className="font-mono text-[0.62rem] truncate"
                      style={{ color: feed.enabled ? 'var(--text-secondary)' : 'var(--text-ghost)' }}
                    >
                      {feed.name}
                    </span>
                    {feed.item_count > 0 && (
                      <span className="font-mono text-[0.46rem] text-[var(--text-ghost)] shrink-0">
                        {feed.item_count} items
                      </span>
                    )}
                  </div>
                  <p className="font-mono text-[0.5rem] text-[var(--text-ghost)] truncate">{feed.url}</p>
                </div>

                {/* Last fetch */}
                {feed.last_fetch && (
                  <span className="font-mono text-[0.46rem] text-[var(--text-ghost)] shrink-0 hidden sm:block">
                    {timeAgo(feed.last_fetch)}
                  </span>
                )}

                {/* Delete */}
                <button
                  onClick={() => deleteFeed(feed.id)}
                  className="shrink-0 text-[var(--text-ghost)] hover:text-[var(--color-danger)] transition-colors"
                  title="Remove feed"
                >
                  <Trash2 size={11} />
                </button>
              </div>
            ))}
          </div>

          <p className="font-mono text-[0.52rem] text-[var(--text-ghost)] leading-relaxed">
            Changes take effect on the next collection cycle (every 15 min).
            "Reset to defaults" restores the built-in feed list, removing any custom additions.
          </p>
        </div>
      </div>

      {/* Collector Status */}
      <div className="panel">
        <div className="panel-header">
          <div className="flex items-center gap-2">
            <Activity size={11} className="text-[var(--color-primary)]" />
            <span className="panel-title">COLLECTOR STATUS</span>
          </div>
          <button
            onClick={loadCollectorStatus}
            disabled={collectorLoading}
            className="flex items-center gap-1 px-2 py-1 border border-[var(--border-base)] font-mono text-[0.46rem] tracking-widest text-[var(--text-dim)] hover:text-[var(--color-primary)] hover:border-[var(--border-accent)] transition-colors disabled:opacity-40"
          >
            <RefreshCw size={8} className={collectorLoading ? 'animate-spin' : ''} />
            REFRESH
          </button>
        </div>

        <div className="overflow-x-auto">
          {collectorLoading && (
            <div className="py-6 text-center font-mono text-[0.58rem] text-[var(--text-ghost)] tracking-widest animate-pulse">
              LOADING...
            </div>
          )}
          {!collectorLoading && collectorStatus.length === 0 && (
            <div className="py-6 text-center font-mono text-[0.58rem] text-[var(--text-ghost)] tracking-widest">
              NO DATA YET — COLLECTORS HAVEN'T RUN
            </div>
          )}
          {!collectorLoading && collectorStatus.length > 0 && (
            <table className="w-full font-mono text-[0.56rem]" style={{ borderCollapse: 'collapse' }}>
              <thead>
                <tr className="border-b border-[var(--border-base)]">
                  {['SOURCE', 'STATUS', 'LAST RUN', 'ITEMS'].map(h => (
                    <th key={h} className="px-4 py-2 text-left text-[var(--text-ghost)] tracking-widest font-normal">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {collectorStatus.map((c, i) => (
                  <tr
                    key={c.name}
                    className="border-b border-[var(--border-base)] hover:bg-[var(--bg-card-hover)] transition-colors"
                    style={{ borderTop: i > 0 ? undefined : 'none' }}
                  >
                    <td className="px-4 py-2 text-[var(--text-secondary)] tracking-wide">{c.name}</td>
                    <td className="px-4 py-2">
                      <span
                        className="px-1.5 py-0.5 border tracking-widest"
                        style={{
                          color:       c.status === 'ok' ? 'var(--color-success)' : 'var(--color-danger)',
                          borderColor: c.status === 'ok' ? 'rgba(0,255,136,0.3)' : 'rgba(255,34,85,0.3)',
                          background:  c.status === 'ok' ? 'rgba(0,255,136,0.06)' : 'rgba(255,34,85,0.06)',
                        }}
                      >
                        {c.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-[var(--text-muted)]">
                      {c.last_run ? timeAgo(c.last_run) : '—'}
                    </td>
                    <td className="px-4 py-2 text-[var(--text-muted)]">
                      {c.last_count !== null ? (
                        <span style={{ color: c.last_count > 0 ? 'var(--color-success)' : 'var(--text-ghost)' }}>
                          +{c.last_count}
                        </span>
                      ) : '—'}
                      {c.error && (
                        <span className="block text-[0.48rem] text-[var(--color-danger)] mt-0.5 truncate max-w-[16rem]" title={c.error}>
                          {c.error}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Alert Log */}
      <div className="panel">
        <div className="panel-header">
          <div className="flex items-center gap-2">
            <Bell size={11} className="text-[var(--color-primary)]" />
            <span className="panel-title">WEBHOOK ALERT LOG</span>
          </div>
          <span className="font-mono text-[0.48rem] text-[var(--text-ghost)] tracking-widest">LAST 20 DISPATCHES</span>
        </div>

        <div className="overflow-y-auto max-h-72">
          {logLoading && (
            <div className="py-6 text-center font-mono text-[0.58rem] text-[var(--text-ghost)] tracking-widest animate-pulse">
              LOADING ALERT LOG...
            </div>
          )}

          {!logLoading && alertLog.length === 0 && (
            <div className="py-8 flex flex-col items-center gap-2 text-center">
              <Bell size={18} className="text-[var(--text-ghost)]" />
              <p className="font-mono text-[0.58rem] text-[var(--text-ghost)] tracking-widest">
                NO ALERTS DISPATCHED YET
              </p>
              <p className="font-mono text-[0.52rem] text-[var(--text-ghost)] max-w-xs leading-relaxed">
                Alerts fire when new items reach or exceed the configured minimum severity threshold.
              </p>
            </div>
          )}

          {alertLog.map(entry => (
            <div
              key={entry.id}
              className="flex items-start gap-3 px-4 py-2.5 border-b border-[var(--border-base)] hover:bg-[var(--bg-card-hover)]"
            >
              {/* Status indicator */}
              <div
                className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0"
                style={{ background: entry.success ? 'var(--color-success)' : 'var(--color-danger)' }}
              />

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                  <span
                    className="font-mono text-[0.5rem] tracking-widest uppercase"
                    style={{ color: severityColor(entry.top_severity) }}
                  >
                    {entry.top_severity}
                  </span>
                  <span className="font-mono text-[0.48rem] text-[var(--text-dim)] uppercase">{entry.item_type}</span>
                  <span className="font-mono text-[0.48rem] text-[var(--text-ghost)]">·</span>
                  <span className="font-mono text-[0.48rem] text-[var(--text-ghost)]">{entry.count} item{entry.count !== 1 ? 's' : ''}</span>
                  <span className="font-mono text-[0.46rem] text-[var(--text-ghost)] ml-auto flex items-center gap-1 shrink-0">
                    <Clock size={7} />
                    {timeAgo(entry.fired_at)}
                  </span>
                </div>
                {entry.sample_title && (
                  <p className="font-heading text-[0.72rem] text-[var(--text-secondary)] truncate">{entry.sample_title}</p>
                )}
                <p className="font-mono text-[0.46rem] text-[var(--text-ghost)] truncate mt-0.5">{entry.webhook_url}</p>
              </div>

              <span
                className="font-mono text-[0.48rem] tracking-widest shrink-0 mt-0.5"
                style={{ color: entry.success ? 'var(--color-success)' : 'var(--color-danger)' }}
              >
                {entry.success ? 'OK' : 'FAIL'}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Audit Log */}
      <div className="panel">
        <div className="panel-header">
          <div className="flex items-center gap-2">
            <ScrollText size={11} className="text-[var(--color-primary)]" />
            <span className="panel-title">AUDIT LOG</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1 border border-[var(--border-base)] bg-[var(--bg-elevated)] px-2 py-1">
              <Filter size={8} className="text-[var(--text-ghost)]" />
              <input
                type="text"
                value={auditActionFilter}
                onChange={e => { setAuditActionFilter(e.target.value); loadAuditLog(e.target.value || undefined) }}
                placeholder="filter by action…"
                className="bg-transparent font-mono text-[0.52rem] text-[var(--text-secondary)] outline-none w-28 placeholder:text-[var(--text-ghost)]"
              />
            </div>
            <span className="font-mono text-[0.48rem] text-[var(--text-ghost)] tracking-widest">LAST 50</span>
          </div>
        </div>

        <div className="overflow-y-auto max-h-72">
          {auditLoading && (
            <div className="py-6 text-center font-mono text-[0.58rem] text-[var(--text-ghost)] tracking-widest animate-pulse">
              LOADING AUDIT LOG...
            </div>
          )}

          {!auditLoading && auditLog.length === 0 && (
            <div className="py-8 flex flex-col items-center gap-2 text-center">
              <ScrollText size={18} className="text-[var(--text-ghost)]" />
              <p className="font-mono text-[0.58rem] text-[var(--text-ghost)] tracking-widest">
                NO AUDIT EVENTS YET
              </p>
            </div>
          )}

          {auditLog.map(entry => (
            <div
              key={entry.id}
              className="flex items-start gap-3 px-4 py-2 border-b border-[var(--border-base)] hover:bg-[var(--bg-card-hover)] group"
            >
              {/* Action badge */}
              <span
                className="font-mono text-[0.46rem] tracking-widest px-1.5 py-0.5 border shrink-0 mt-0.5"
                style={{
                  color:       actionColor(entry.action),
                  borderColor: `${actionColor(entry.action)}44`,
                  background:  `${actionColor(entry.action)}11`,
                }}
              >
                {entry.action}
              </span>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <div className="flex items-center gap-1 text-[var(--text-dim)]">
                    <User size={7} />
                    <span className="font-mono text-[0.48rem]">{entry.actor}</span>
                  </div>
                  {entry.entity_type && (
                    <span className="font-mono text-[0.44rem] text-[var(--text-ghost)]">
                      {entry.entity_type}{entry.entity_id ? ` #${entry.entity_id}` : ''}
                    </span>
                  )}
                  {entry.ip_address && (
                    <span className="font-mono text-[0.42rem] text-[var(--text-ghost)] hidden sm:block">
                      {entry.ip_address}
                    </span>
                  )}
                </div>
                {entry.details && (
                  <p className="font-mono text-[0.46rem] text-[var(--text-ghost)] truncate mt-0.5">
                    {JSON.stringify(entry.details)}
                  </p>
                )}
              </div>

              <span className="font-mono text-[0.44rem] text-[var(--text-ghost)] shrink-0 flex items-center gap-1 mt-0.5">
                <Clock size={7} />
                {timeAgo(entry.timestamp)}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Password Change */}
      <div className="panel">
        <div className="panel-header">
          <div className="flex items-center gap-2">
            <Lock size={11} className="text-[var(--color-primary)]" />
            <span className="panel-title">CHANGE PASSWORD</span>
          </div>
        </div>
        <div className="px-4 py-3 flex flex-col gap-2.5">
          <p className="font-mono text-[0.6rem] text-[var(--text-muted)] leading-relaxed">
            Update your account password. Minimum 8 characters. Has no effect when AUTH_DISABLED=true.
          </p>

          {/* Current password */}
          <div className="flex items-center border border-[var(--border-base)] bg-[var(--bg-elevated)] focus-within:border-[var(--border-accent)] transition-colors">
            <input
              type={showPwCurrent ? 'text' : 'password'}
              value={pwCurrent}
              onChange={e => setPwCurrent(e.target.value)}
              placeholder="Current password"
              className="flex-1 bg-transparent font-mono text-[0.72rem] text-[var(--text-secondary)] px-3 py-2 outline-none placeholder-[var(--text-ghost)] tracking-wide"
            />
            <button onClick={() => setShowPwCurrent(v => !v)} className="px-2 text-[var(--text-dim)] hover:text-[var(--text-base)] transition-colors">
              {showPwCurrent ? <EyeOff size={12} /> : <Eye size={12} />}
            </button>
          </div>

          {/* New password */}
          <div className="flex items-center border border-[var(--border-base)] bg-[var(--bg-elevated)] focus-within:border-[var(--border-accent)] transition-colors">
            <input
              type={showPwNew ? 'text' : 'password'}
              value={pwNew}
              onChange={e => setPwNew(e.target.value)}
              placeholder="New password (min. 8 chars)"
              className="flex-1 bg-transparent font-mono text-[0.72rem] text-[var(--text-secondary)] px-3 py-2 outline-none placeholder-[var(--text-ghost)] tracking-wide"
            />
            <button onClick={() => setShowPwNew(v => !v)} className="px-2 text-[var(--text-dim)] hover:text-[var(--text-base)] transition-colors">
              {showPwNew ? <EyeOff size={12} /> : <Eye size={12} />}
            </button>
          </div>

          {/* Confirm password */}
          <input
            type="password"
            value={pwConfirm}
            onChange={e => setPwConfirm(e.target.value)}
            placeholder="Confirm new password"
            className="bg-[var(--bg-elevated)] border border-[var(--border-base)] font-mono text-[0.72rem] text-[var(--text-secondary)] px-3 py-2 outline-none focus:border-[var(--border-accent)] transition-colors placeholder:text-[var(--text-ghost)]"
            onKeyDown={e => e.key === 'Enter' && changePassword()}
          />

          <div className="flex items-center gap-3">
            <button
              onClick={changePassword}
              disabled={pwStatus === 'saving'}
              className="flex items-center gap-1.5 font-mono text-[0.56rem] tracking-widest px-3 py-2 border transition-all disabled:opacity-40"
              style={{
                color:       pwStatus === 'error' ? 'var(--color-danger)' : pwStatus === 'saved' ? 'var(--color-success)' : 'var(--color-primary)',
                borderColor: pwStatus === 'error' ? 'rgba(255,34,85,0.4)' : pwStatus === 'saved' ? 'rgba(0,255,136,0.4)' : 'var(--border-accent)',
                background:  pwStatus === 'saved' ? 'rgba(0,255,136,0.07)' : 'transparent',
              }}
            >
              {pwStatus === 'saving' && <><Loader2 size={9} className="animate-spin" />SAVING</>}
              {pwStatus === 'saved'  && <><CheckCircle size={9} />CHANGED</>}
              {pwStatus === 'error'  && <><AlertTriangle size={9} />ERROR</>}
              {pwStatus === 'idle'   && <><Save size={9} />UPDATE PASSWORD</>}
            </button>
            {pwMsg && (
              <span
                className="font-mono text-[0.56rem] leading-relaxed"
                style={{ color: pwStatus === 'saved' ? 'var(--color-success)' : 'var(--color-danger)' }}
              >
                {pwMsg}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Security note */}
      <div className="flex items-start gap-2 px-3 py-2.5 border border-[rgba(255,170,0,0.2)] bg-[rgba(255,170,0,0.04)]">
        <AlertTriangle size={11} className="text-[var(--color-warning)] shrink-0 mt-0.5" />
        <p className="font-mono text-[0.58rem] text-[var(--text-muted)] leading-relaxed">
          Settings are stored unencrypted in the local SQLite database. Do not deploy this instance
          with public network exposure without placing an authenticated reverse proxy in front.
        </p>
      </div>
    </div>
  )
}
