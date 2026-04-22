import { useState, useRef, useEffect, useCallback, type ReactNode } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Bot, Send, Square, RefreshCw, Zap, Search,
  Users, AlertTriangle, FileText, ChevronDown, ChevronUp as ChevronUpIcon, Clock,
  Cpu, Activity, TrendingUp, TrendingDown, Trash2, Wrench,
} from 'lucide-react'
import type { AiBriefing, AiStatus, ChatMessage, AgentStep, SeverityLevel } from '@/types'
import { timeAgo } from '@/lib/utils'
import { useApi, API_BASE } from '@/hooks/useApi'
const QUICK_PROMPTS = [
  { icon: AlertTriangle, label: 'Critical Threats',   prompt: 'What are the most critical active threats right now? Give me specific CVEs, actors, and immediate actions.' },
  { icon: Users,         label: 'Active Actors',      prompt: 'Which threat actors are most active in the past 24 hours? Summarize their campaigns, TTPs, and targets.' },
  { icon: Search,        label: 'Threat Hunt',        prompt: 'Generate a threat hunting checklist based on the most active threat actors and IOC patterns in the current data.' },
  { icon: TrendingUp,    label: 'Trend Analysis',     prompt: 'What threat trends are emerging in the current intelligence? Any notable increases in attack patterns?' },
  { icon: FileText,      label: 'Morning Briefing',   prompt: 'Generate a concise morning threat briefing I can share with my security team. Include executive summary and action items.' },
  { icon: Zap,           label: 'Zero-Days',          prompt: 'Are there any zero-day or recently disclosed vulnerabilities in the current data that require emergency attention?' },
]

const SEV_COLOR: Record<SeverityLevel, string> = {
  CRITICAL: 'var(--color-danger)',
  HIGH:     'var(--color-warning)',
  MEDIUM:   'var(--color-primary)',
  INFO:     'var(--text-dim)',
}

/** Retrieve or create a stable session ID in localStorage */
function getSessionId(): string {
  const key = 'sigintx_chat_session'
  let sid = localStorage.getItem(key)
  if (!sid) {
    sid = crypto.randomUUID()
    localStorage.setItem(key, sid)
  }
  return sid
}

function SeverityBadge({ sev }: { sev: SeverityLevel }) {
  return (
    <span
      className="font-mono text-[0.46rem] tracking-widest px-1 py-0.5 border"
      style={{ color: SEV_COLOR[sev], borderColor: `${SEV_COLOR[sev]}44`, background: `${SEV_COLOR[sev]}0d` }}
    >
      {sev}
    </span>
  )
}

function AgentStepsList({ steps }: { steps: AgentStep[] }) {
  const [open, setOpen] = useState(false)
  if (!steps?.length) return null
  const callCount = steps.filter(s => s.type === 'tool_call').length
  return (
    <div className="mb-2">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-1.5 font-mono text-[0.49rem] tracking-widest opacity-60 hover:opacity-100 transition-opacity"
        style={{ color: 'var(--color-primary)' }}
      >
        <Wrench size={8} />
        {callCount} TOOL CALL{callCount !== 1 ? 'S' : ''}
        {open ? <ChevronUpIcon size={8} /> : <ChevronDown size={8} />}
      </button>
      {open && (
        <div className="mt-1.5 space-y-0.5 pl-2.5 border-l-2" style={{ borderColor: 'rgba(0,212,255,0.2)' }}>
          {steps.map((step, i) => (
            <div key={i} className="font-mono text-[0.51rem]">
              {step.type === 'tool_call' ? (
                <div className="flex items-start gap-1">
                  <span style={{ color: 'var(--color-primary)' }}>→</span>
                  <div>
                    <span style={{ color: 'var(--color-primary)' }}>{step.name}</span>
                    {step.args && Object.keys(step.args).length > 0 && (
                      <span className="text-[var(--text-ghost)] ml-1">
                        {JSON.stringify(step.args).slice(0, 80)}
                      </span>
                    )}
                  </div>
                </div>
              ) : (
                <div className="flex items-start gap-1">
                  <span style={{ color: '#00cc88' }}>←</span>
                  <span className="text-[var(--text-dim)] line-clamp-2 flex-1">{step.text}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

interface DeltaData {
  window_hours: number
  generated_at: string
  news:           { current: number; baseline: number; pct_change: number | null }
  critical_news:  { current: number; baseline: number; pct_change: number | null }
  cves:           { current: number; baseline: number; pct_change: number | null }
  kev:            { current: number; baseline: number; pct_change: number | null }
  new_actors:          string[]
  disappeared_actors:  string[]
  new_malware_families: string[]
}

function TrendBadge({ pct }: { pct: number | null }) {
  if (pct === null) return <span className="font-mono text-[0.48rem] text-[var(--text-ghost)]">—</span>
  const up    = pct > 0
  const color = up ? 'var(--color-danger)' : '#00cc88'
  const Icon  = up ? TrendingUp : TrendingDown
  return (
    <span className="flex items-center gap-0.5 font-mono text-[0.52rem]" style={{ color }}>
      <Icon size={8} />{pct > 0 ? '+' : ''}{pct}%
    </span>
  )
}

function DeltaPanel() {
  const [windowHours, setWindowHours] = useState(24)
  const { data: delta, loading, refetch } = useApi<DeltaData>('/ai/delta', { hours_back: windowHours })

  const windows = [
    { label: '24H', hours: 24 },
    { label: '48H', hours: 48 },
    { label: '7D',  hours: 168 },
  ]

  const metrics = delta ? [
    { label: 'NEWS',     ...delta.news,          color: 'var(--color-primary)' },
    { label: 'CRITICAL', ...delta.critical_news, color: 'var(--color-danger)'  },
    { label: 'CVEs',     ...delta.cves,          color: 'var(--color-warning)' },
    { label: 'KEV',      ...delta.kev,           color: '#aa44ff'               },
  ] : []

  return (
    <div className="p-3 space-y-4">
      {/* Window selector */}
      <div className="flex gap-1.5">
        {windows.map(w => (
          <button key={w.hours} onClick={() => setWindowHours(w.hours)}
            className="flex-1 font-mono text-[0.5rem] tracking-widest py-1 border transition-all"
            style={{
              color:       windowHours === w.hours ? 'var(--color-primary)' : 'var(--text-ghost)',
              background:  windowHours === w.hours ? 'rgba(0,212,255,0.08)' : 'transparent',
              borderColor: windowHours === w.hours ? 'var(--border-accent)'  : 'var(--border-base)',
            }}>
            {w.label}
          </button>
        ))}
        <button onClick={refetch}
          className="px-2 border border-[var(--border-base)] text-[var(--text-ghost)] hover:text-[var(--color-primary)] transition-colors">
          <RefreshCw size={8} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      {loading && !delta && (
        <div className="flex items-center justify-center h-20">
          <span className="font-mono text-[0.55rem] text-[var(--text-ghost)] animate-pulse tracking-widest">COMPUTING DELTA…</span>
        </div>
      )}

      {delta && (
        <>
          {/* Metric cards */}
          <div className="grid grid-cols-2 gap-1.5">
            {metrics.map(m => (
              <div key={m.label} className="border border-[var(--border-base)] p-2 bg-[var(--bg-elevated)]/40">
                <div className="font-mono text-[0.42rem] tracking-widest mb-1" style={{ color: m.color }}>{m.label}</div>
                <div className="font-mono text-[1.1rem] mb-0.5" style={{ color: m.color }}>{m.current}</div>
                <div className="flex items-center gap-1.5">
                  <span className="font-mono text-[0.42rem] text-[var(--text-ghost)]">vs {m.baseline}</span>
                  <TrendBadge pct={m.pct_change} />
                </div>
              </div>
            ))}
          </div>

          {/* New actors */}
          {delta.new_actors.length > 0 && (
            <div>
              <p className="font-mono text-[0.46rem] text-[var(--color-danger)] tracking-widest mb-1.5">
                NEW ACTORS ({delta.new_actors.length})
              </p>
              <div className="flex flex-wrap gap-1">
                {delta.new_actors.map(a => (
                  <span key={a} className="actor-chip text-[0.44rem]">{a}</span>
                ))}
              </div>
            </div>
          )}

          {/* Disappeared actors */}
          {delta.disappeared_actors.length > 0 && (
            <div>
              <p className="font-mono text-[0.46rem] text-[var(--text-ghost)] tracking-widest mb-1.5">
                WENT DARK ({delta.disappeared_actors.length})
              </p>
              <div className="flex flex-wrap gap-1">
                {delta.disappeared_actors.map(a => (
                  <span key={a} className="tag-chip text-[0.44rem] opacity-50">{a}</span>
                ))}
              </div>
            </div>
          )}

          {/* New malware families */}
          {delta.new_malware_families.length > 0 && (
            <div>
              <p className="font-mono text-[0.46rem] text-[var(--color-warning)] tracking-widest mb-1.5">
                NEW MALWARE FAMILIES ({delta.new_malware_families.length})
              </p>
              <div className="flex flex-wrap gap-1">
                {delta.new_malware_families.map(f => (
                  <span key={f} className="tag-chip text-[0.44rem]">{f}</span>
                ))}
              </div>
            </div>
          )}

          {delta.new_actors.length === 0 && delta.new_malware_families.length === 0 && (
            <div className="text-center py-4">
              <p className="font-mono text-[0.55rem] text-[var(--text-ghost)] tracking-widest">
                NO SIGNIFICANT CHANGES
              </p>
              <p className="text-[0.65rem] text-[var(--text-dim)] mt-1">
                Threat landscape stable vs. prior {windowHours}h window
              </p>
            </div>
          )}

          <p className="font-mono text-[0.42rem] text-[var(--text-ghost)] text-right">
            {delta.generated_at ? new Date(delta.generated_at).toLocaleTimeString() : ''}
          </p>
        </>
      )}
    </div>
  )
}

// ── Inline-span renderer: bold, italic, inline-code, CVE chips ────────────────
function InlineText({ text }: { text: string }) {
  // Split on **bold**, *italic*, `code`, CVE-XXXX-XXXXX
  const TOKEN_RE = /(\*\*(.+?)\*\*|\*(.+?)\*|`([^`]+)`|(CVE-\d{4}-\d+))/g
  const parts: ReactNode[] = []
  let last = 0
  let m: RegExpExecArray | null
  while ((m = TOKEN_RE.exec(text)) !== null) {
    if (m.index > last) parts.push(text.slice(last, m.index))
    if (m[2] !== undefined) {
      parts.push(<strong key={m.index} className="font-semibold text-[var(--text-primary)]">{m[2]}</strong>)
    } else if (m[3] !== undefined) {
      parts.push(<em key={m.index} className="italic text-[var(--text-secondary)]">{m[3]}</em>)
    } else if (m[4] !== undefined) {
      parts.push(<code key={m.index} className="font-mono text-[0.72rem] px-1 py-0.5 rounded bg-[rgba(0,212,255,0.08)] text-[var(--color-primary)] border border-[rgba(0,212,255,0.15)]">{m[4]}</code>)
    } else if (m[5] !== undefined) {
      parts.push(<code key={m.index} className="cve-chip">{m[5]}</code>)
    }
    last = m.index + m[0].length
  }
  if (last < text.length) parts.push(text.slice(last))
  return <>{parts}</>
}

// ── Block types produced by the parser ────────────────────────────────────────
type MdBlock =
  | { type: 'h2';        text: string }
  | { type: 'h3';        text: string }
  | { type: 'h4';        text: string }
  | { type: 'hr' }
  | { type: 'blockquote'; text: string }
  | { type: 'bullet';    text: string; depth: number }
  | { type: 'ordered';   text: string; n: number }
  | { type: 'code';      lang: string; lines: string[] }
  | { type: 'table';     head: string[]; align: ('left'|'right'|'center'|'none')[]; rows: string[][] }
  | { type: 'para';      text: string }
  | { type: 'blank' }

function parseMarkdown(raw: string): MdBlock[] {
  const lines = raw.split('\n')
  const blocks: MdBlock[] = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i]

    // ── Fenced code block ──────────────────────────────────────────────────────
    if (line.trimStart().startsWith('```')) {
      const lang = line.trimStart().slice(3).trim()
      const codeLines: string[] = []
      i++
      while (i < lines.length && !lines[i].trimStart().startsWith('```')) {
        codeLines.push(lines[i])
        i++
      }
      i++ // consume closing ```
      blocks.push({ type: 'code', lang, lines: codeLines })
      continue
    }

    // ── Headings ───────────────────────────────────────────────────────────────
    if (/^#{4}\s/.test(line)) { blocks.push({ type: 'h4', text: line.replace(/^#{4}\s+/, '') }); i++; continue }
    if (/^#{3}\s/.test(line)) { blocks.push({ type: 'h3', text: line.replace(/^#{3}\s+/, '') }); i++; continue }
    if (/^#{2}\s/.test(line)) { blocks.push({ type: 'h2', text: line.replace(/^#{2}\s+/, '') }); i++; continue }

    // ── Horizontal rule ────────────────────────────────────────────────────────
    if (/^[-*_]{3,}\s*$/.test(line.trim())) { blocks.push({ type: 'hr' }); i++; continue }

    // ── Blockquote ─────────────────────────────────────────────────────────────
    if (line.startsWith('> ')) { blocks.push({ type: 'blockquote', text: line.slice(2) }); i++; continue }

    // ── Bullet list ───────────────────────────────────────────────────────────
    const bulletM = line.match(/^(\s*)[-*•]\s+(.*)/)
    if (bulletM) {
      blocks.push({ type: 'bullet', depth: Math.floor(bulletM[1].length / 2), text: bulletM[2] })
      i++; continue
    }

    // ── Ordered list ──────────────────────────────────────────────────────────
    const ordM = line.match(/^(\d+)\.\s+(.*)/)
    if (ordM) {
      blocks.push({ type: 'ordered', n: parseInt(ordM[1], 10), text: ordM[2] })
      i++; continue
    }

    // ── Table (look-ahead: next line must be separator row) ────────────────────
    if (line.includes('|')) {
      const nextLine = lines[i + 1] ?? ''
      if (/^\|?[\s:|-]+\|/.test(nextLine) || /^[\s:|-]+\|[\s:|-|]+$/.test(nextLine)) {
        // Parse header
        const parseCells = (l: string) =>
          l.replace(/^\||\|$/g, '').split('|').map(c => c.trim())
        const head = parseCells(line)
        i++ // separator row
        const sepCells = parseCells(lines[i])
        const align = sepCells.map((s): 'left'|'right'|'center'|'none' => {
          if (s.startsWith(':') && s.endsWith(':')) return 'center'
          if (s.endsWith(':')) return 'right'
          if (s.startsWith(':')) return 'left'
          return 'none'
        })
        i++
        const rows: string[][] = []
        while (i < lines.length && lines[i].includes('|') && lines[i].trim() !== '') {
          rows.push(parseCells(lines[i]))
          i++
        }
        blocks.push({ type: 'table', head, align, rows })
        continue
      }
    }

    // ── Blank line ────────────────────────────────────────────────────────────
    if (line.trim() === '') { blocks.push({ type: 'blank' }); i++; continue }

    // ── Paragraph ─────────────────────────────────────────────────────────────
    blocks.push({ type: 'para', text: line })
    i++
  }
  return blocks
}

function MarkdownText({ text }: { text: string }) {
  const blocks = parseMarkdown(text)
  const nodes: ReactNode[] = []
  let blankCount = 0

  blocks.forEach((block, idx) => {
    if (block.type === 'blank') {
      blankCount++
      if (blankCount === 1) nodes.push(<div key={idx} className="h-1.5" />)
      return
    }
    blankCount = 0

    switch (block.type) {
      case 'h2':
        nodes.push(
          <p key={idx} className="font-mono text-[0.65rem] tracking-widest text-[var(--color-primary)] mt-4 mb-1.5 border-b border-[rgba(0,212,255,0.15)] pb-1">
            {block.text.toUpperCase()}
          </p>
        )
        break

      case 'h3':
        nodes.push(
          <p key={idx} className="font-mono text-[0.62rem] tracking-wider text-[var(--text-secondary)] mt-3 mb-1 uppercase">
            {block.text}
          </p>
        )
        break

      case 'h4':
        nodes.push(
          <p key={idx} className="text-[0.75rem] font-semibold text-[var(--text-primary)] mt-2 mb-0.5">
            <InlineText text={block.text} />
          </p>
        )
        break

      case 'hr':
        nodes.push(<hr key={idx} className="border-[var(--border-base)] my-3" />)
        break

      case 'blockquote':
        nodes.push(
          <div key={idx} className="border-l-2 border-[var(--color-primary)] pl-3 my-1.5 text-[0.78rem] text-[var(--text-dim)] italic leading-relaxed">
            <InlineText text={block.text} />
          </div>
        )
        break

      case 'bullet':
        nodes.push(
          <p
            key={idx}
            className="text-[0.78rem] text-[var(--text-secondary)] leading-relaxed flex gap-1.5"
            style={{ paddingLeft: `${block.depth * 1.25}rem` }}
          >
            <span className="text-[var(--color-primary)] shrink-0 mt-px">›</span>
            <span><InlineText text={block.text} /></span>
          </p>
        )
        break

      case 'ordered':
        nodes.push(
          <p key={idx} className="text-[0.78rem] text-[var(--text-secondary)] leading-relaxed flex gap-1.5">
            <span className="font-mono text-[0.68rem] text-[var(--color-primary)] shrink-0 mt-px w-4 text-right">{block.n}.</span>
            <span><InlineText text={block.text} /></span>
          </p>
        )
        break

      case 'code':
        nodes.push(
          <div key={idx} className="my-2 rounded border border-[rgba(0,212,255,0.15)] overflow-hidden">
            {block.lang && (
              <div className="font-mono text-[0.55rem] tracking-widest px-3 py-1 bg-[rgba(0,212,255,0.06)] text-[var(--color-primary)] border-b border-[rgba(0,212,255,0.12)]">
                {block.lang.toUpperCase()}
              </div>
            )}
            <pre className="font-mono text-[0.72rem] text-[var(--text-secondary)] bg-[rgba(0,0,0,0.25)] px-3 py-2 overflow-x-auto leading-relaxed whitespace-pre">
              {block.lines.join('\n')}
            </pre>
          </div>
        )
        break

      case 'table': {
        const alignClass = (a: string) =>
          a === 'right' ? 'text-right' : a === 'center' ? 'text-center' : 'text-left'
        nodes.push(
          <div key={idx} className="my-2 overflow-x-auto">
            <table className="w-full text-[0.73rem] border-collapse">
              <thead>
                <tr className="border-b border-[rgba(0,212,255,0.25)]">
                  {block.head.map((h, ci) => (
                    <th
                      key={ci}
                      className={`font-mono text-[0.62rem] tracking-wider text-[var(--color-primary)] px-2 py-1.5 ${alignClass(block.align[ci] ?? 'none')} whitespace-nowrap`}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {block.rows.map((row, ri) => (
                  <tr key={ri} className="border-b border-[rgba(255,255,255,0.04)] hover:bg-[rgba(0,212,255,0.03)] transition-colors">
                    {row.map((cell, ci) => (
                      <td
                        key={ci}
                        className={`text-[var(--text-secondary)] px-2 py-1.5 ${alignClass(block.align[ci] ?? 'none')}`}
                      >
                        <InlineText text={cell} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
        break
      }

      case 'para':
      default: {
        const t = (block as { type: string; text: string }).text
        nodes.push(
          <p key={idx} className="text-[0.78rem] text-[var(--text-secondary)] leading-relaxed">
            <InlineText text={t} />
          </p>
        )
        break
      }
    }
  })

  return <div className="space-y-0.5">{nodes}</div>
}

interface Props {
  refreshTrigger: number
}

export function AiAnalyst({ refreshTrigger }: Props) {
  const sessionId = useRef(getSessionId())

  const [messages, setMessages]         = useState<ChatMessage[]>([])
  const [input, setInput]               = useState('')
  const [availableModels, setAvailableModels] = useState<string[]>([])
  const [selectedModel, setSelectedModel]     = useState<string>('')
  const [streaming, setStreaming]       = useState(false)
  const [status, setStatus]             = useState<AiStatus | null>(null)
  const [statusLoading, setStatusLoading] = useState(true)
  const [historyLoading, setHistoryLoading] = useState(true)
  const [briefing, setBriefing]         = useState<AiBriefing | null>(null)
  const [briefingLoading, setBriefingLoading] = useState(false)
  const [briefingContent, setBriefingContent] = useState<string | null>(null)
  const [briefingStreaming, setBriefingStreaming] = useState(false)
  const [showBriefing, setShowBriefing] = useState(false)
  const [activePanel, setActivePanel]   = useState<'chat' | 'briefing' | 'delta'>('chat')
  const [clearingHistory, setClearingHistory] = useState(false)
  const [agentMode, setAgentMode]       = useState(false)

  const messagesEndRef    = useRef<HTMLDivElement>(null)
  const abortRef          = useRef<AbortController | null>(null)
  const briefingAbortRef  = useRef<AbortController | null>(null)
  const inputRef          = useRef<HTMLTextAreaElement>(null)
  const lastStatusFetchRef = useRef<number>(0)

  // Auto-scroll chat
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // Load AI status on mount / refresh
  const loadStatus = useCallback(async () => {
    setStatusLoading(true)
    try {
      const r = await fetch(`${API_BASE}/ai/status`)
      if (r.ok) {
        const data = await r.json()
        setStatus(data)
        // Populate model list from what's actually installed on Ollama
        if (data.available_models && data.available_models.length > 0) {
          setAvailableModels(data.available_models)
        } else {
          setAvailableModels([])
        }
      }
    } catch { /* ignore */ } finally {
      setStatusLoading(false)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const loadBriefing = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/ai/briefing`)
      if (r.ok) {
        const data = await r.json()
        if (data.briefing) setBriefing(data.briefing)
      }
    } catch { /* ignore */ }
  }, [])

  // Load persistent chat history on mount
  const loadHistory = useCallback(async () => {
    setHistoryLoading(true)
    try {
      const r = await fetch(`${API_BASE}/ai/chat/history?session_id=${sessionId.current}`)
      if (r.ok) {
        const rows: { id: number; role: string; content: string; created_at: string; model_used?: string }[] = await r.json()
        if (rows.length > 0) {
          setMessages(rows.map(row => ({
            id:        String(row.id),
            role:      row.role as 'user' | 'assistant',
            content:   row.content,
            timestamp: new Date(row.created_at),
          })))
        }
      }
    } catch { /* ignore */ } finally {
      setHistoryLoading(false)
    }
  }, [])

  useEffect(() => {
    // Throttle loadStatus to at most once every 15 s; briefing/history can refresh freely
    const now = Date.now()
    if (now - lastStatusFetchRef.current > 15_000) {
      lastStatusFetchRef.current = now
      loadStatus()
    }
    loadBriefing()
    loadHistory()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshTrigger])

  /** Persist a single message to the backend */
  const persistMessage = useCallback(async (role: 'user' | 'assistant', content: string) => {
    try {
      await fetch(`${API_BASE}/ai/chat/history`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          session_id: sessionId.current,
          role,
          content,
          model_used: null,
        }),
      })
    } catch { /* fire-and-forget */ }
  }, [])

  const sendMessage = useCallback(async (text?: string) => {
    const msg = (text ?? input).trim()
    if (!msg || streaming) return

    const userMsg: ChatMessage = {
      id:        crypto.randomUUID(),
      role:      'user',
      content:   msg,
      timestamp: new Date(),
    }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setStreaming(true)
    void persistMessage('user', msg)

    const assistantId = crypto.randomUUID()
    setMessages(prev => [...prev, {
      id: assistantId, role: 'assistant', content: '',
      streaming: true, timestamp: new Date(),
      steps: agentMode ? [] : undefined,
      agentMode,
    }])

    abortRef.current = new AbortController()
    let finalContent = ''
    let steps: AgentStep[] = []

    try {
      const endpoint = agentMode ? `${API_BASE}/ai/agent/chat` : `${API_BASE}/ai/chat`
      const resp = await fetch(endpoint, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          message: msg,
          ...(selectedModel ? { model: selectedModel } : {}),
        }),
        signal:  abortRef.current.signal,
      })

      if (!resp.ok || !resp.body) throw new Error(`HTTP ${resp.status}`)

      const reader  = resp.body.getReader()
      const decoder = new TextDecoder()
      let finished  = false

      while (!finished) {
        const { done, value } = await reader.read()
        if (done) break
        const raw = decoder.decode(value, { stream: true })
        for (const line of raw.split('\n')) {
          if (!line.startsWith('data: ')) continue
          try {
            const event = JSON.parse(line.slice(6))

            if (agentMode) {
              // Typed events from the agentic endpoint
              if (event.type === 'tool_call') {
                steps = [...steps, { type: 'tool_call', name: event.name, args: event.args }]
                setMessages(prev => prev.map(m => m.id === assistantId ? { ...m, steps } : m))
              } else if (event.type === 'tool_result') {
                steps = [...steps, { type: 'tool_result', name: event.name, text: event.text }]
                setMessages(prev => prev.map(m => m.id === assistantId ? { ...m, steps } : m))
              } else if (event.type === 'text') {
                finalContent += event.text ?? ''
                setMessages(prev => prev.map(m =>
                  m.id === assistantId ? { ...m, content: finalContent } : m
                ))
              } else if (event.type === 'done') {
                finished = true; break
              }
            } else {
              // Basic {"text": token, "done": bool} from standard endpoint
              finalContent += event.text ?? ''
              setMessages(prev => prev.map(m =>
                m.id === assistantId
                  ? { ...m, content: m.content + (event.text ?? ''), streaming: !event.done }
                  : m
              ))
              if (event.done) { finished = true; break }
            }
          } catch { /* skip malformed */ }
        }
      }
    } catch (e: unknown) {
      if ((e as Error).name !== 'AbortError') {
        const errMsg = '⚠️ Failed to reach AI analyst. Ensure Ollama is running.'
        finalContent = errMsg
        setMessages(prev => prev.map(m =>
          m.id === assistantId ? { ...m, content: m.content || errMsg, streaming: false } : m
        ))
      }
    } finally {
      setStreaming(false)
      setMessages(prev => prev.map(m => m.id === assistantId ? { ...m, streaming: false } : m))
      if (finalContent && abortRef.current && !abortRef.current.signal.aborted) {
        void persistMessage('assistant', finalContent)
      }
    }
  }, [input, streaming, agentMode, selectedModel, persistMessage])

  const stopStream = () => {
    abortRef.current?.abort()
    setStreaming(false)
    setMessages(prev => prev.map(m => ({ ...m, streaming: false })))
  }

  /** Generate briefing via SSE streaming endpoint */
  const generateBriefing = useCallback(async () => {
    if (briefingLoading || briefingStreaming) return
    setBriefingLoading(true)
    setBriefingStreaming(true)
    setBriefingContent('')
    setShowBriefing(true)
    setActivePanel('briefing')

    briefingAbortRef.current = new AbortController()
    let accumulated = ''

    try {
      const resp = await fetch(`${API_BASE}/ai/briefing/stream`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(selectedModel ? { model: selectedModel } : {}),
        signal:  briefingAbortRef.current.signal,
      })

      if (!resp.ok || !resp.body) throw new Error(`HTTP ${resp.status}`)

      const reader  = resp.body.getReader()
      const decoder = new TextDecoder()

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        const raw = decoder.decode(value, { stream: true })
        for (const line of raw.split('\n')) {
          if (!line.startsWith('data: ')) continue
          try {
            const chunk = JSON.parse(line.slice(6))
            if (chunk.done) {
              // Server sent final event — reload briefing metadata from DB
              setBriefingStreaming(false)
              setBriefingLoading(false)
              setBriefingContent(accumulated)
              await loadBriefing()
              return
            }
            accumulated += chunk.text ?? ''
            setBriefingContent(accumulated)
          } catch { /* skip malformed */ }
        }
      }
    } catch (e: unknown) {
      if ((e as Error).name !== 'AbortError') {
        setBriefingContent(accumulated || '⚠️ Briefing generation failed. Ensure Ollama is running.')
      }
    } finally {
      setBriefingStreaming(false)
      setBriefingLoading(false)
    }
  }, [briefingLoading, briefingStreaming, selectedModel, loadBriefing])

  const stopBriefing = () => {
    briefingAbortRef.current?.abort()
    setBriefingStreaming(false)
    setBriefingLoading(false)
  }

  const clearHistory = async () => {
    setClearingHistory(true)
    try {
      await fetch(`${API_BASE}/ai/chat/history/${sessionId.current}`, { method: 'DELETE' })
      setMessages([])
    } catch { /* ignore */ } finally {
      setClearingHistory(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  const isOnline = status?.ollama_reachable ?? false
  const ctx      = status?.context

  // ── Ollama bootstrap status (polled until ready) ─────────────────────────
  interface SetupStatus {
    stage: 'starting' | 'installing' | 'serving' | 'pulling' | 'ready' | 'error'
    message: string
    progress: number
    model: string
    error: string | null
  }

  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null)
  const setupPollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    const poll = async () => {
      try {
        const r = await fetch(`${API_BASE}/ollama/setup-status`)
        if (!r.ok) return
        const data: SetupStatus = await r.json()
        setSetupStatus(data)
        if (data.stage === 'ready' || data.stage === 'error') {
          if (setupPollRef.current) clearInterval(setupPollRef.current)
          if (data.stage === 'ready') loadStatus()   // refresh AI status once ready
        }
      } catch { /* ignore */ }
    }
    poll()
    setupPollRef.current = setInterval(poll, 2000)
    return () => { if (setupPollRef.current) clearInterval(setupPollRef.current) }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const setupStageColor: Record<string, string> = {
    starting:   'var(--color-primary)',
    installing: '#f7931a',
    serving:    '#a855f7',
    pulling:    'var(--color-info)',
    ready:      'var(--color-success)',
    error:      'var(--color-danger)',
  }

  // Show setup overlay when Ollama is still bootstrapping
  const showSetupOverlay = setupStatus && setupStatus.stage !== 'ready' && !isOnline

  return (
    <div className="flex h-full gap-2 min-h-0">

      {/* ── Left: Chat ──────────────────────────────────────────────── */}
      <div className="flex-1 panel flex flex-col min-h-0" style={{ minWidth: 0 }}>

        {/* Header */}
        <div className="panel-header shrink-0">
          <div className="flex items-center gap-2">
            <Bot size={13} className="text-[var(--color-primary)]" />
            <span className="panel-title">AI ANALYST</span>
            <span className="live-dot" />
            <span className="font-mono text-[0.46rem] text-[var(--text-ghost)] tracking-widest">
              SIGINT-X AGENT v3.0
            </span>
            {messages.length > 0 && (
              <span className="font-mono text-[0.44rem] text-[var(--text-ghost)] tracking-widest">
                [{messages.length} msgs · session]
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {/* Online/offline indicator */}
            <div className="flex items-center gap-1">
              <div
                className="w-1.5 h-1.5 rounded-full"
                style={{ background: isOnline ? 'var(--color-success)' : 'var(--color-danger)' }}
              />
              <span className="font-mono text-[0.46rem] tracking-widest" style={{ color: isOnline ? 'var(--color-success)' : setupStatus && setupStatus.stage !== 'ready' && setupStatus.stage !== 'error' ? '#f7931a' : 'var(--color-danger)' }}>
                {statusLoading
                  ? 'CHECKING'
                  : isOnline
                    ? 'AI READY'
                    : setupStatus && setupStatus.stage !== 'ready' && setupStatus.stage !== 'error'
                      ? `INITIALIZING — ${setupStatus.stage.toUpperCase()}`
                      : 'AI OFFLINE'
                }
              </span>
            </div>
            {/* Warn if online but no models pulled */}
            {isOnline && availableModels.length === 0 && !statusLoading && (
              <span className="font-mono text-[0.44rem] text-[var(--color-warning)] tracking-widest">
                NO MODELS PULLED
              </span>
            )}
            {/* Model selector — applies to both chat and briefing */}
            {availableModels.length > 0 && (
              <div className="flex items-center gap-0.5">
                <span className="font-mono text-[0.38rem] text-[var(--text-ghost)] tracking-widest mr-0.5">MODEL</span>
                <button
                  onClick={() => setSelectedModel('')}
                  title="Use default model (set in Settings → Ollama Model)"
                  className="font-mono text-[0.42rem] tracking-widest px-1.5 py-0.5 border transition-all"
                  style={{
                    color:       selectedModel === '' ? 'var(--color-primary)' : 'var(--text-ghost)',
                    borderColor: selectedModel === '' ? 'var(--border-accent)' : 'var(--border-base)',
                    background:  selectedModel === '' ? 'rgba(0,212,255,0.07)' : 'transparent',
                  }}
                >
                  AUTO
                </button>
                {availableModels.map(m => (
                  <button
                    key={m}
                    onClick={() => setSelectedModel(m)}
                    title={m}
                    className="font-mono text-[0.42rem] tracking-widest px-1.5 py-0.5 border transition-all max-w-[72px] truncate"
                    style={{
                      color:       selectedModel === m ? 'var(--color-primary)' : 'var(--text-ghost)',
                      borderColor: selectedModel === m ? 'var(--border-accent)' : 'var(--border-base)',
                      background:  selectedModel === m ? 'rgba(0,212,255,0.07)' : 'transparent',
                    }}
                  >
                    {m.split(':')[0]}
                  </button>
                ))}
              </div>
            )}
            {/* Agent mode toggle */}
            <button
              onClick={() => setAgentMode(m => !m)}
              title={agentMode ? 'Agent mode ON — uses tool-calling loop' : 'Agent mode OFF — switch to enable DB tool calls'}
              className="flex items-center gap-1 px-2 py-0.5 border font-mono text-[0.46rem] tracking-widest transition-all"
              style={{
                color:       agentMode ? '#00cc88' : 'var(--text-ghost)',
                background:  agentMode ? 'rgba(0,204,136,0.08)' : 'transparent',
                borderColor: agentMode ? 'rgba(0,204,136,0.35)' : 'var(--border-base)',
              }}
            >
              <Wrench size={8} />
              AGENT{agentMode ? ' ON' : ''}
            </button>

            {/* Clear history */}
            {messages.length > 0 && (
              <button
                onClick={clearHistory}
                disabled={clearingHistory || streaming}
                className="p-1 text-[var(--text-ghost)] hover:text-[var(--color-danger)] transition-colors"
                title="Clear chat history"
              >
                {clearingHistory
                  ? <RefreshCw size={10} className="animate-spin" />
                  : <Trash2 size={10} />
                }
              </button>
            )}
            <button
              onClick={loadStatus}
              className="p-1 text-[var(--text-dim)] hover:text-[var(--color-primary)] transition-colors"
              title="Refresh status"
            >
              <RefreshCw size={10} />
            </button>
          </div>
        </div>

        {/* Quick prompts */}
        <div className="shrink-0 px-3 py-2 border-b border-[var(--border-base)] flex gap-1.5 overflow-x-auto scrollbar-none">
          {QUICK_PROMPTS.map(({ icon: Icon, label, prompt }) => (
            <button
              key={label}
              onClick={() => sendMessage(prompt)}
              disabled={streaming}
              className="flex items-center gap-1 px-2 py-1 border border-[var(--border-base)] font-mono text-[0.48rem] tracking-widest text-[var(--text-dim)] hover:text-[var(--color-primary)] hover:border-[var(--border-accent)] transition-colors shrink-0 disabled:opacity-40"
            >
              <Icon size={8} />
              {label}
            </button>
          ))}
        </div>

        {/* ── Ollama bootstrap overlay ─────────────────────────────── */}
        {showSetupOverlay && setupStatus && (
          <div className="flex-1 flex flex-col items-center justify-center gap-5 px-6 py-8 min-h-0">
            {/* Animated icon */}
            <div className="relative">
              <Bot size={48} style={{ color: setupStageColor[setupStatus.stage] }} />
              {setupStatus.stage !== 'error' && (
                <div className="absolute -top-1 -right-1">
                  <div className="w-3 h-3 rounded-full animate-ping" style={{ background: setupStageColor[setupStatus.stage], opacity: 0.7 }} />
                </div>
              )}
            </div>

            {/* Stage label */}
            <div className="text-center space-y-1">
              <p
                className="font-mono text-[0.58rem] tracking-widest font-semibold uppercase"
                style={{ color: setupStageColor[setupStatus.stage] }}
              >
                {setupStatus.stage === 'starting'   && 'CHECKING AI ENGINE'}
                {setupStatus.stage === 'installing' && 'INSTALLING OLLAMA'}
                {setupStatus.stage === 'serving'    && 'STARTING AI SERVER'}
                {setupStatus.stage === 'pulling'    && `DOWNLOADING MODEL`}
                {setupStatus.stage === 'error'      && 'SETUP ERROR'}
              </p>
              <p className="font-mono text-[0.62rem] text-[var(--text-secondary)] max-w-sm leading-relaxed">
                {setupStatus.message}
              </p>
            </div>

            {/* Progress bar */}
            {setupStatus.stage !== 'error' && (
              <div className="w-full max-w-xs">
                <div className="h-1 bg-[var(--bg-elevated)] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${setupStatus.progress}%`,
                      background: setupStageColor[setupStatus.stage],
                      boxShadow: `0 0 8px ${setupStageColor[setupStatus.stage]}`,
                    }}
                  />
                </div>
                <div className="flex justify-between mt-1">
                  <span className="font-mono text-[0.42rem] text-[var(--text-ghost)]">
                    {setupStatus.model}
                  </span>
                  <span className="font-mono text-[0.42rem]" style={{ color: setupStageColor[setupStatus.stage] }}>
                    {setupStatus.progress}%
                  </span>
                </div>
              </div>
            )}

            {/* Steps visual */}
            <div className="flex items-center gap-2 font-mono text-[0.44rem] tracking-widest">
              {(['starting', 'installing', 'serving', 'pulling', 'ready'] as const).map((s, i, arr) => {
                const stages = ['starting', 'installing', 'serving', 'pulling', 'ready']
                const currentIdx = stages.indexOf(setupStatus.stage)
                const thisIdx    = stages.indexOf(s)
                const isDone     = thisIdx < currentIdx
                const isCurrent  = thisIdx === currentIdx
                const color = isDone ? 'var(--color-success)' : isCurrent ? setupStageColor[s] : 'var(--text-ghost)'
                const labels = ['CHECK', 'INSTALL', 'SERVE', 'PULL', 'READY']
                return (
                  <div key={s} className="flex items-center gap-2">
                    <div className="flex flex-col items-center gap-0.5">
                      <div
                        className="w-5 h-5 rounded-full flex items-center justify-center border"
                        style={{
                          borderColor: color,
                          background: isDone || isCurrent ? `${color}20` : 'transparent',
                        }}
                      >
                        {isDone
                          ? <span style={{ color }}>✓</span>
                          : <span style={{ color }}>{thisIdx + 1}</span>
                        }
                      </div>
                      <span style={{ color }}>{labels[i]}</span>
                    </div>
                    {i < arr.length - 1 && (
                      <div className="w-4 h-px" style={{ background: isDone ? 'var(--color-success)' : 'var(--border-base)' }} />
                    )}
                  </div>
                )
              })}
            </div>

            {setupStatus.stage === 'error' && setupStatus.error && (
              <div className="max-w-sm p-3 border border-[var(--color-danger)] bg-[rgba(255,26,26,0.06)] text-center">
                <p className="font-mono text-[0.55rem] text-[var(--color-danger)] leading-relaxed">
                  {setupStatus.error}
                </p>
                <p className="font-mono text-[0.48rem] text-[var(--text-ghost)] mt-1.5">
                  You can still use cloud AI (Groq / OpenRouter) by adding API keys in Settings.
                </p>
              </div>
            )}

            <p className="font-mono text-[0.42rem] text-[var(--text-ghost)] tracking-widest text-center">
              THIS HAPPENS ONCE — AI WILL BE READY FOR ALL FUTURE SESSIONS
            </p>
          </div>
        )}

        {/* Messages */}
        <div className={`flex-1 overflow-y-auto min-h-0 px-3 py-3 space-y-4 ${showSetupOverlay ? 'hidden' : ''}`}>
          {historyLoading && (
            <div className="flex items-center justify-center h-16">
              <span className="font-mono text-[0.55rem] text-[var(--text-ghost)] tracking-widest animate-pulse">
                LOADING HISTORY...
              </span>
            </div>
          )}

          {!historyLoading && messages.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-center">
              <div className="relative">
                <Bot size={40} className="text-[var(--text-ghost)]" />
                {isOnline && (
                  <div className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-[var(--color-success)]" />
                )}
              </div>
              <div>
                <p className="font-mono text-[0.65rem] tracking-widest text-[var(--color-primary)] mb-1">
                  SIGINT-X ANALYST READY
                </p>
                <p className="text-[0.75rem] text-[var(--text-muted)] max-w-sm leading-relaxed">
                  {isOnline && availableModels.length > 0
                    ? `Connected to Ollama · ${availableModels.length} model(s) available · Ask anything about current threats.`
                    : isOnline
                    ? 'Ollama is running but no models are pulled. Run: ollama pull llama3.2:3b'
                    : 'Ollama offline. Run ollama serve then ollama pull llama3.2:3b'
                  }
                </p>
              </div>
              {ctx && (
                <div className="grid grid-cols-2 gap-2 text-left max-w-sm w-full">
                  {[
                    { label: 'NEWS 24H', value: ctx.news_24h },
                    { label: 'CRITICAL', value: ctx.critical_24h },
                  ].map(s => (
                    <div key={s.label} className="border border-[var(--border-base)] p-2">
                      <div className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-widest">{s.label}</div>
                      <div className="font-mono text-[1.1rem] text-[var(--color-primary)]">{s.value.toLocaleString()}</div>
                    </div>
                  ))}
                </div>
              )}
              <p className="font-mono text-[0.46rem] text-[var(--text-ghost)] tracking-widest">
                USE QUICK PROMPTS ABOVE OR TYPE A QUESTION
              </p>
            </div>
          )}

          <AnimatePresence initial={false}>
            {messages.map(msg => (
              <motion.div
                key={msg.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.15 }}
                className={`flex gap-2.5 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                {msg.role === 'assistant' && (
                  <div className="shrink-0 w-6 h-6 border border-[var(--border-accent)] flex items-center justify-center bg-[var(--bg-elevated)] mt-0.5">
                    <Bot size={11} className="text-[var(--color-primary)]" />
                  </div>
                )}

                <div
                  className="max-w-[85%] rounded-sm px-3 py-2.5"
                  style={{
                    background:  msg.role === 'user' ? 'rgba(0,212,255,0.08)' : 'var(--bg-elevated)',
                    border:      `1px solid ${msg.role === 'user' ? 'rgba(0,212,255,0.2)' : 'var(--border-base)'}`,
                  }}
                >
                  {msg.role === 'user' ? (
                    <p className="text-[0.8rem] text-[var(--text-secondary)] leading-relaxed">{msg.content}</p>
                  ) : (
                    <>
                      {msg.steps && msg.steps.length > 0 && (
                        <AgentStepsList steps={msg.steps} />
                      )}
                      <MarkdownText text={msg.content} />
                    </>
                  )}
                  {msg.streaming && (
                    <span className="inline-block w-1.5 h-3.5 bg-[var(--color-primary)] ml-0.5 animate-pulse align-middle" />
                  )}
                  <div className="mt-1.5 font-mono text-[0.42rem] text-[var(--text-ghost)] tracking-widest">
                    {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </div>
                </div>

                {msg.role === 'user' && (
                  <div className="shrink-0 w-6 h-6 border border-[var(--border-base)] flex items-center justify-center bg-[var(--bg-elevated)] mt-0.5">
                    <Cpu size={11} className="text-[var(--text-dim)]" />
                  </div>
                )}
              </motion.div>
            ))}
          </AnimatePresence>
          <div ref={messagesEndRef} />
        </div>

        {/* Input bar */}
        <div className="shrink-0 border-t border-[var(--border-base)] p-2 flex gap-2">
          <textarea
            ref={inputRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={streaming}
            placeholder={
              setupStatus && setupStatus.stage !== 'ready' && !isOnline
                ? `AI engine ${setupStatus.stage}… ${setupStatus.progress}% — please wait`
                : isOnline
                  ? 'Ask about current threats, actors, campaigns, or geopolitics…'
                  : 'AI initializing — please wait…'
            }
            rows={2}
            className="flex-1 bg-[var(--bg-elevated)] border border-[var(--border-base)] text-[0.8rem] text-[var(--text-secondary)] px-3 py-2 outline-none resize-none placeholder:text-[var(--text-ghost)] focus:border-[var(--border-accent)] transition-colors disabled:opacity-50"
            style={{ fontFamily: 'inherit' }}
          />
          {streaming ? (
            <button
              onClick={stopStream}
              className="px-3 py-2 border border-[rgba(255,34,85,0.4)] text-[var(--color-danger)] hover:bg-[rgba(255,34,85,0.08)] transition-colors self-stretch font-mono text-[0.52rem] tracking-widest"
            >
              <Square size={12} />
            </button>
          ) : (
            <button
              onClick={() => sendMessage()}
              disabled={!input.trim() || !isOnline}
              className="px-3 py-2 border border-[var(--border-accent)] text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.08)] transition-colors self-stretch disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <Send size={12} />
            </button>
          )}
        </div>
      </div>

      {/* ── Right: Briefing + Context ────────────────────────────────── */}
      <div className="w-80 flex flex-col gap-2 min-h-0 shrink-0">

        {/* Panel toggle */}
        <div className="panel shrink-0">
          <div className="flex">
            {([
              { id: 'chat',     label: 'CONTEXT'  },
              { id: 'briefing', label: 'BRIEFS'   },
              { id: 'delta',    label: 'DELTA', icon: TrendingUp },
            ] as { id: 'chat' | 'briefing' | 'delta'; label: string; icon?: typeof TrendingUp }[]).map(p => (
              <button
                key={p.id}
                onClick={() => setActivePanel(p.id)}
                className="flex-1 py-2 font-mono text-[0.5rem] tracking-widest transition-colors flex items-center justify-center gap-1"
                style={{
                  color:        activePanel === p.id ? 'var(--color-primary)' : 'var(--text-dim)',
                  background:   activePanel === p.id ? 'rgba(0,212,255,0.06)' : 'transparent',
                  borderBottom: activePanel === p.id ? '1px solid var(--color-primary)' : '1px solid transparent',
                }}
              >
                {p.icon && <p.icon size={8} />}
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* Context panel */}
        {activePanel === 'chat' && (
          <div className="panel flex-1 flex flex-col min-h-0 overflow-y-auto">
            <div className="panel-header shrink-0">
              <div className="flex items-center gap-1.5">
                <Activity size={11} className="text-[var(--color-primary)]" />
                <span className="panel-title">THREAT CONTEXT</span>
              </div>
              <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-widest">LAST 24H</span>
            </div>

            <div className="flex-1 p-3 space-y-4 min-h-0">
              {ctx ? (
                <>
                  {/* Stats grid */}
                  <div className="grid grid-cols-2 gap-1.5">
                    {[
                      { icon: FileText,      label: 'NEWS',     value: ctx.news_24h,    color: 'var(--color-primary)' },
                      { icon: AlertTriangle, label: 'CRITICAL', value: ctx.critical_24h, color: 'var(--color-danger)' },
                    ].map(({ icon: Icon, label, value, color }) => (
                      <div key={label} className="border border-[var(--border-base)] p-2 bg-[var(--bg-elevated)]/40">
                        <div className="flex items-center gap-1 mb-1">
                          <Icon size={8} style={{ color }} />
                          <span className="font-mono text-[0.42rem] tracking-widest" style={{ color }}>{label}</span>
                        </div>
                        <div className="font-mono text-[1.1rem]" style={{ color }}>{value.toLocaleString()}</div>
                      </div>
                    ))}
                  </div>

                  {/* Active actors */}
                  {ctx.active_actors.length > 0 && (
                    <div>
                      <p className="font-mono text-[0.48rem] text-[var(--text-ghost)] tracking-widest mb-2">
                        DETECTED ACTORS ({ctx.active_actors.length})
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {ctx.active_actors.map(actor => (
                          <span key={actor} className="actor-chip text-[0.46rem]">{actor}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Context note */}
                  <div className="border border-[var(--border-base)] p-2.5 bg-[var(--bg-elevated)]/20">
                    <p className="font-mono text-[0.46rem] text-[var(--text-ghost)] tracking-widest mb-1">
                      AI CONTEXT WINDOW
                    </p>
                    <p className="text-[0.7rem] text-[var(--text-muted)] leading-relaxed">
                      The analyst has real-time access to all {ctx.news_24h} news items
                      and threat actor intelligence from the past 24 hours.
                    </p>
                  </div>
                </>
              ) : (
                <div className="flex items-center justify-center h-full">
                  <div className="flex items-center gap-2">
                    <RefreshCw size={12} className="text-[var(--text-ghost)] animate-spin" />
                    <span className="font-mono text-[0.55rem] text-[var(--text-ghost)] tracking-widest">LOADING CONTEXT</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Briefing panel */}
        {activePanel === 'briefing' && (
          <div className="panel flex-1 flex flex-col min-h-0">
            <div className="panel-header shrink-0">
              <div className="flex items-center gap-1.5">
                <FileText size={11} className="text-[var(--color-primary)]" />
                <span className="panel-title">THREAT BRIEFING</span>
              </div>
              {briefingStreaming ? (
                <button
                  onClick={stopBriefing}
                  className="flex items-center gap-1 px-2 py-1 border border-[rgba(255,34,85,0.4)] font-mono text-[0.48rem] tracking-widest text-[var(--color-danger)] hover:bg-[rgba(255,34,85,0.06)] transition-colors"
                >
                  <Square size={8} />
                  STOP
                </button>
              ) : (
                <button
                  onClick={generateBriefing}
                  disabled={briefingLoading || !isOnline}
                  className="flex items-center gap-1 px-2 py-1 border border-[var(--border-accent)] font-mono text-[0.48rem] tracking-widest text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.06)] transition-colors disabled:opacity-40"
                >
                  <Zap size={8} />
                  GENERATE
                </button>
              )}
            </div>

            <div className="flex-1 overflow-y-auto min-h-0 p-3">
              {/* Streaming: show live text as it arrives */}
              {briefingStreaming && (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 mb-2">
                    <RefreshCw size={9} className="text-[var(--color-primary)] animate-spin" />
                    <span className="font-mono text-[0.52rem] text-[var(--color-primary)] tracking-widest animate-pulse">
                      GENERATING BRIEFING
                    </span>
                  </div>
                  {briefingContent && (
                    <div className="border border-[var(--border-base)] p-3 bg-[var(--bg-elevated)]/20">
                      <MarkdownText text={briefingContent} />
                      <span className="inline-block w-1.5 h-3.5 bg-[var(--color-primary)] ml-0.5 animate-pulse align-middle" />
                    </div>
                  )}
                </div>
              )}

              {/* Done streaming — show meta + content */}
              {!briefingStreaming && briefing && (
                <div className="space-y-3">
                  {/* Briefing meta */}
                  <div className="border border-[var(--border-base)] p-2.5 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <SeverityBadge sev={briefing.top_severity} />
                      <span className="font-mono text-[0.46rem] text-[var(--text-ghost)] tracking-widest">
                        {briefing.model_used}
                      </span>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="flex items-center gap-1 font-mono text-[0.46rem] text-[var(--text-dim)]">
                        <Clock size={7} />
                        {timeAgo(briefing.generated_at)}
                      </div>
                      <span className="font-mono text-[0.46rem] text-[var(--text-ghost)]">
                        {briefing.news_count} news · {briefing.cve_count} CVEs
                      </span>
                    </div>
                    {briefing.threat_actors.length > 0 && (
                      <div className="flex flex-wrap gap-1 pt-0.5">
                        {briefing.threat_actors.slice(0, 4).map(a => (
                          <span key={a} className="actor-chip text-[0.42rem]">{a}</span>
                        ))}
                        {briefing.threat_actors.length > 4 && (
                          <span className="font-mono text-[0.42rem] text-[var(--text-ghost)]">
                            +{briefing.threat_actors.length - 4} more
                          </span>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Toggle content */}
                  <button
                    onClick={() => {
                      setShowBriefing(s => !s)
                      if (!briefingContent && briefing.content) setBriefingContent(briefing.content)
                    }}
                    className="w-full flex items-center justify-between px-2 py-1.5 border border-[var(--border-base)] font-mono text-[0.5rem] tracking-widest text-[var(--text-dim)] hover:text-[var(--color-primary)] hover:border-[var(--border-accent)] transition-colors"
                  >
                    <span>{showBriefing ? 'COLLAPSE BRIEFING' : 'VIEW FULL BRIEFING'}</span>
                    <ChevronDown
                      size={10}
                      className="transition-transform"
                      style={{ transform: showBriefing ? 'rotate(180deg)' : 'none' }}
                    />
                  </button>

                  {showBriefing && (briefingContent ?? briefing.content) && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      className="border border-[var(--border-base)] p-3 bg-[var(--bg-elevated)]/20 overflow-hidden"
                    >
                      <MarkdownText text={briefingContent ?? briefing.content ?? ''} />
                    </motion.div>
                  )}
                </div>
              )}

              {/* Empty state */}
              {!briefingStreaming && !briefing && (
                <div className="flex flex-col items-center justify-center h-full gap-4 text-center">
                  <FileText size={32} className="text-[var(--text-ghost)]" />
                  <div>
                    <p className="font-mono text-[0.58rem] text-[var(--text-dim)] tracking-widest mb-1">
                      NO BRIEFING YET
                    </p>
                    <p className="text-[0.72rem] text-[var(--text-muted)] max-w-[200px] leading-relaxed">
                      {isOnline
                        ? 'Click GENERATE to create an AI threat briefing from current data.'
                        : 'Start Ollama to enable automated briefing generation.'
                      }
                    </p>
                  </div>
                  {isOnline && (
                    <button
                      onClick={generateBriefing}
                      className="flex items-center gap-1.5 px-3 py-1.5 border border-[var(--border-accent)] font-mono text-[0.55rem] tracking-widest text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.06)] transition-colors"
                    >
                      <Zap size={10} />
                      GENERATE BRIEFING
                    </button>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Delta panel */}
        {activePanel === 'delta' && (
          <div className="panel flex-1 flex flex-col min-h-0">
            <div className="panel-header shrink-0">
              <div className="flex items-center gap-1.5">
                <TrendingUp size={11} className="text-[var(--color-primary)]" />
                <span className="panel-title">THREAT DELTA</span>
              </div>
              <span className="font-mono text-[0.44rem] text-[var(--text-ghost)] tracking-widest">
                CURRENT VS BASELINE
              </span>
            </div>
            <div className="flex-1 overflow-y-auto min-h-0">
              <DeltaPanel />
            </div>
          </div>
        )}

      </div>
    </div>
  )
}
