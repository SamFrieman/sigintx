import { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X, Cpu, AlertTriangle, ChevronDown, Zap } from 'lucide-react'
import type { AnalyzeTarget } from '@/types'

// Fallback model list shown when the backend hasn't discovered any models.
// Covers common Ollama, Groq, and OpenRouter models.
const FALLBACK_MODELS = [
  'llama3.2:3b',
  'llama3.2:1b',
  'llama3.1:8b',
  'mistral:7b',
  'gemma2:2b',
  'qwen2.5:3b',
  'llama-3.3-70b-versatile',
  'google/gemini-2.0-flash',
]

const PROVIDER_COLORS: Record<string, string> = {
  ollama:      '#00d4ff',
  groq:        '#f55036',
  openrouter:  '#a855f7',
  generic:     '#22c55e',
}

const PROVIDER_LABELS: Record<string, string> = {
  ollama:      'OLLAMA',
  groq:        'GROQ',
  openrouter:  'OPENROUTER',
  generic:     'CUSTOM LLM',
}

interface AiStatus {
  active_provider: string | null
  available_models: string[]
  providers: { name: string; available: boolean }[]
}

interface Props {
  target: AnalyzeTarget | null
  onClose: () => void
}

export function OllamaPanel({ target, onClose }: Props) {
  const [models, setModels]           = useState<string[]>(FALLBACK_MODELS)
  const [model, setModel]             = useState(FALLBACK_MODELS[0])
  const [activeProvider, setActiveProvider] = useState<string | null>(null)
  const [streamProvider, setStreamProvider] = useState<string | null>(null)
  const [streamModel, setStreamModel] = useState<string | null>(null)
  const [anyConfigured, setAnyConfigured] = useState(true)
  const [content, setContent]         = useState('')
  const [streaming, setStreaming]     = useState(false)
  const [done, setDone]               = useState(false)
  const [error, setError]             = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)
  const abortRef  = useRef<AbortController | null>(null)

  // Load AI status on mount
  useEffect(() => {
    fetch('/api/v1/ai/status')
      .then(r => r.ok ? r.json() as Promise<AiStatus> : null)
      .then(data => {
        if (!data) return
        const discovered = data.available_models ?? []
        if (discovered.length > 0) {
          setModels(discovered)
          setModel(discovered[0])
        }
        setActiveProvider(data.active_provider ?? null)
        const configured = data.providers?.some(p => p.available) ?? false
        setAnyConfigured(configured)
      })
      .catch(() => { /* keep fallback defaults */ })
  }, [])

  // Reset when target changes
  useEffect(() => {
    setContent('')
    setDone(false)
    setError(false)
    setStreaming(false)
    setStreamProvider(null)
    setStreamModel(null)
  }, [target])

  // Auto-scroll
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [content])

  const startAnalysis = async () => {
    if (!target || streaming) return
    setContent('')
    setDone(false)
    setError(false)
    setStreaming(true)
    setStreamProvider(null)
    setStreamModel(null)

    abortRef.current = new AbortController()

    try {
      const resp = await fetch('/api/v1/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          item_type: target.type,
          item_id: target.item.id,
          model,
        }),
        signal: abortRef.current.signal,
      })

      if (!resp.ok || !resp.body) {
        setError(true)
        setStreaming(false)
        return
      }

      const reader  = resp.body.getReader()
      const decoder = new TextDecoder()
      let firstChunk = true

      while (true) {
        const { done: rdDone, value } = await reader.read()
        if (rdDone) break
        const raw = decoder.decode(value, { stream: true })
        for (const line of raw.split('\n')) {
          if (!line.startsWith('data: ')) continue
          try {
            const chunk = JSON.parse(line.slice(6))
            // First chunk carries provider/model announcement
            if (firstChunk && chunk.provider) {
              setStreamProvider(chunk.provider)
              setStreamModel(chunk.model ?? null)
              firstChunk = false
              continue
            }
            firstChunk = false
            if (chunk.text) setContent(prev => prev + chunk.text)
            if (chunk.done) { setDone(true); break }
          } catch { /* skip malformed */ }
        }
      }
    } catch (e: unknown) {
      if ((e as Error).name !== 'AbortError') setError(true)
    } finally {
      setStreaming(false)
    }
  }

  const stopStream = () => {
    abortRef.current?.abort()
    setStreaming(false)
    setDone(true)
  }

  const itemLabel = target
    ? target.type === 'news'
      ? target.item.title.slice(0, 60) + (target.item.title.length > 60 ? '…' : '')
      : (target.item as import('@/types').CVEItem).cve_id
    : ''

  const displayProvider = streamProvider ?? activeProvider
  const providerColor   = displayProvider ? (PROVIDER_COLORS[displayProvider] ?? '#94a3b8') : 'var(--color-primary)'
  const providerLabel   = displayProvider ? (PROVIDER_LABELS[displayProvider] ?? displayProvider.toUpperCase()) : null

  return (
    <AnimatePresence>
      {target && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 z-40"
            onClick={onClose}
          />

          {/* Panel */}
          <motion.div
            initial={{ opacity: 0, x: 40 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 40 }}
            transition={{ type: 'spring', stiffness: 380, damping: 35 }}
            className="fixed right-0 top-0 h-full w-full max-w-[520px] z-50 flex flex-col"
            style={{
              background: 'var(--bg-surface)',
              borderLeft: '1px solid var(--border-accent)',
            }}
            onClick={e => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-base)] shrink-0">
              <div className="flex items-center gap-2">
                <Cpu size={13} className="text-[var(--color-primary)]" />
                <span className="font-mono text-[0.62rem] tracking-widest text-[var(--color-primary)]">
                  AI ANALYSIS
                </span>
                {providerLabel && (
                  <span
                    className="font-mono text-[0.52rem] tracking-widest px-1.5 py-0.5 border"
                    style={{ color: providerColor, borderColor: `${providerColor}55`, background: `${providerColor}12` }}
                  >
                    {providerLabel}
                  </span>
                )}
              </div>
              <button onClick={onClose} className="text-[var(--text-dim)] hover:text-[var(--text-base)] transition-colors">
                <X size={14} />
              </button>
            </div>

            {/* Target info */}
            <div className="px-4 py-2.5 border-b border-[var(--border-base)] shrink-0 bg-[var(--bg-elevated)]/30">
              <div className="font-mono text-[0.52rem] text-[var(--text-dim)] tracking-widest mb-0.5 uppercase">
                {target.type === 'news' ? 'News Item' : 'CVE'}
              </div>
              <p className="text-[0.8rem] text-[var(--text-secondary)] leading-snug">{itemLabel}</p>
            </div>

            {/* Model selector + run button */}
            <div className="px-4 py-2.5 border-b border-[var(--border-base)] flex items-center gap-2 shrink-0">
              <div className="relative flex-1">
                <select
                  value={model}
                  onChange={e => setModel(e.target.value)}
                  disabled={streaming}
                  className="w-full appearance-none bg-[var(--bg-elevated)] border border-[var(--border-base)] font-mono text-[0.65rem] text-[var(--text-secondary)] px-2 py-1.5 pr-6 outline-none tracking-wide disabled:opacity-50"
                >
                  {models.map(m => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
                <ChevronDown size={10} className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--text-dim)] pointer-events-none" />
              </div>

              {streaming ? (
                <button
                  onClick={stopStream}
                  className="font-mono text-[0.6rem] tracking-widest px-3 py-1.5 border border-[rgba(255,34,85,0.4)] text-[#ff2255] hover:bg-[rgba(255,34,85,0.1)] transition-colors shrink-0"
                >
                  STOP
                </button>
              ) : (
                <button
                  onClick={startAnalysis}
                  className="font-mono text-[0.6rem] tracking-widest px-3 py-1.5 border border-[var(--border-accent)] text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.08)] transition-colors shrink-0"
                >
                  {content ? 'RE-ANALYZE' : 'ANALYZE'}
                </button>
              )}
            </div>

            {/* Output area */}
            <div
              ref={scrollRef}
              className="flex-1 overflow-y-auto px-4 py-3 min-h-0"
            >
              {!content && !streaming && (
                <div className="flex flex-col items-center justify-center h-full gap-3 text-center">
                  <Cpu size={28} className="text-[var(--text-ghost)]" />
                  <p className="font-mono text-[0.62rem] text-[var(--text-ghost)] tracking-wider">
                    READY — CLICK ANALYZE TO START
                  </p>
                  {anyConfigured ? (
                    <div className="flex items-center gap-1.5">
                      <Zap size={10} style={{ color: providerColor }} />
                      <p className="text-[0.72rem]" style={{ color: providerColor }}>
                        {providerLabel
                          ? `Using ${providerLabel}`
                          : 'AI provider ready'}
                      </p>
                    </div>
                  ) : (
                    <p className="text-[0.72rem] text-[var(--text-muted)] max-w-xs">
                      No AI provider configured. Add a{' '}
                      <span className="text-[var(--color-primary)]">Groq</span> or{' '}
                      <span className="text-[var(--color-primary)]">OpenRouter</span> API key in{' '}
                      <span className="text-[var(--color-primary)]">Settings → AI Provider</span>,
                      or run <code className="font-code text-[var(--color-primary)]">ollama serve</code> locally.
                    </p>
                  )}
                </div>
              )}

              {error && (
                <div className="flex items-center gap-2 p-3 border border-[rgba(255,34,85,0.3)] bg-[rgba(255,34,85,0.06)] mb-3">
                  <AlertTriangle size={12} className="text-[#ff2255] shrink-0" />
                  <span className="font-mono text-[0.62rem] text-[#ff2255] tracking-wide">
                    No AI provider reachable. Check Settings → AI Provider.
                  </span>
                </div>
              )}

              {content && (
                <div className="prose-sm text-[0.82rem] text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap">
                  {content}
                  {streaming && (
                    <span className="inline-block w-1.5 h-3.5 bg-[var(--color-primary)] ml-0.5 animate-pulse" />
                  )}
                </div>
              )}

              {done && content && (
                <div className="mt-3 pt-2 border-t border-[var(--border-base)]">
                  <span className="font-mono text-[0.52rem] text-[var(--text-ghost)] tracking-widest">
                    ANALYSIS COMPLETE
                    {streamProvider && ` · VIA ${PROVIDER_LABELS[streamProvider] ?? streamProvider.toUpperCase()}`}
                    {streamModel && ` · ${streamModel}`}
                  </span>
                </div>
              )}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  )
}
