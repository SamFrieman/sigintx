/**
 * ModelManager — Ollama model library panel.
 * Browse recommended models, pull with live progress, delete installed models.
 * Embedded inside the AI Analyst tab.
 */
import { useState, useCallback, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Download, Trash2, CheckCircle, AlertTriangle,
  HardDrive, RefreshCw, Square, Cpu, ChevronDown, ChevronUp,
  ExternalLink,
} from 'lucide-react'
import { API_BASE } from '@/hooks/useApi'

interface InstalledModel {
  name: string
  size_gb: number
  modified_at: string
  digest: string
  details: {
    parameter_size?: string
    quantization_level?: string
    family?: string
  }
}

interface PullState {
  status: string
  completed: number
  total: number
  done: boolean
  error: boolean
}

interface Props {
  ollamaOnline: boolean
  onModelsChanged: () => void   // parent re-fetches status after pull/delete
}

// Curated catalogue — name, tag, size estimate, description
const CATALOGUE: {
  name: string
  tag: string
  size: string
  ctx: string
  desc: string
  recommended?: boolean
}[] = [
  { name: 'llama3.2',    tag: '3b',   size: '2.0 GB',  ctx: '128k', desc: 'Meta — best small model for everyday tasks',          recommended: true  },
  { name: 'llama3.2',    tag: '1b',   size: '1.3 GB',  ctx: '128k', desc: 'Meta — ultra-fast, low RAM footprint'                                    },
  { name: 'llama3.1',    tag: '8b',   size: '4.7 GB',  ctx: '128k', desc: 'Meta — strong reasoning, good for briefings',         recommended: true  },
  { name: 'mistral',     tag: '7b',   size: '4.1 GB',  ctx: '32k',  desc: 'Mistral AI — fast, precise instruction following'                        },
  { name: 'gemma2',      tag: '2b',   size: '1.6 GB',  ctx: '8k',   desc: 'Google — excellent small model',                      recommended: true  },
  { name: 'gemma2',      tag: '9b',   size: '5.4 GB',  ctx: '8k',   desc: 'Google — strong mid-range performance'                                   },
  { name: 'qwen2.5',     tag: '3b',   size: '2.0 GB',  ctx: '32k',  desc: 'Alibaba — multilingual, long context'                                    },
  { name: 'qwen2.5',     tag: '7b',   size: '4.7 GB',  ctx: '128k', desc: 'Alibaba — top coding and reasoning'                                      },
  { name: 'phi3',        tag: 'mini', size: '2.3 GB',  ctx: '128k', desc: 'Microsoft — fast reasoning, 3.8B params',             recommended: true  },
  { name: 'deepseek-r1', tag: '7b',   size: '4.7 GB',  ctx: '64k',  desc: 'DeepSeek — strong math/code reasoning'                                   },
  { name: 'codellama',   tag: '7b',   size: '3.8 GB',  ctx: '16k',  desc: 'Meta — optimised for code analysis and generation'                       },
  { name: 'nomic-embed-text', tag: 'latest', size: '274 MB', ctx: '8k', desc: 'Nomic — text embeddings, very small'                                 },
]

function formatBytes(completed: number, total: number): string {
  const fmt = (n: number) => {
    if (n >= 1_073_741_824) return `${(n / 1_073_741_824).toFixed(1)} GB`
    if (n >= 1_048_576)     return `${(n / 1_048_576).toFixed(0)} MB`
    return `${(n / 1024).toFixed(0)} KB`
  }
  if (!total) return fmt(completed)
  return `${fmt(completed)} / ${fmt(total)}`
}

function PullProgress({ pull }: { pull: PullState }) {
  const pct = pull.total > 0 ? Math.round((pull.completed / pull.total) * 100) : null

  const color = pull.error
    ? 'var(--color-danger)'
    : pull.done
    ? 'var(--color-success)'
    : 'var(--color-primary)'

  return (
    <div className="mt-1.5 space-y-1">
      <div className="flex items-center justify-between">
        <span className="font-mono text-[0.52rem] truncate max-w-[60%]" style={{ color }}>
          {pull.error ? '✗' : pull.done ? '✓' : '↓'} {pull.status}
        </span>
        {pct !== null && !pull.done && (
          <span className="font-mono text-[0.52rem] text-[var(--text-dim)]">{pct}%</span>
        )}
      </div>
      {pct !== null && !pull.done && !pull.error && (
        <div className="w-full h-1 bg-[var(--bg-elevated)] rounded-full overflow-hidden">
          <motion.div
            className="h-full rounded-full"
            style={{ background: 'var(--color-primary)' }}
            animate={{ width: `${pct}%` }}
            transition={{ duration: 0.3 }}
          />
        </div>
      )}
      {pull.total > 0 && !pull.done && !pull.error && (
        <span className="font-mono text-[0.46rem] text-[var(--text-ghost)]">
          {formatBytes(pull.completed, pull.total)}
        </span>
      )}
    </div>
  )
}

export function ModelManager({ ollamaOnline, onModelsChanged }: Props) {
  const [installed, setInstalled]   = useState<InstalledModel[]>([])
  const [loading, setLoading]       = useState(false)
  const [pulling, setPulling]       = useState<Record<string, PullState>>({})
  const [deleting, setDeleting]     = useState<Record<string, boolean>>({})
  const [showCatalogue, setShowCatalogue] = useState(true)
  const [customModel, setCustomModel] = useState('')
  const abortRefs = useRef<Record<string, AbortController>>({})

  const fetchInstalled = useCallback(async () => {
    if (!ollamaOnline) return
    setLoading(true)
    try {
      const r = await fetch(`${API_BASE}/ollama/models`)
      if (r.ok) setInstalled(await r.json())
    } catch { /* ignore */ } finally {
      setLoading(false)
    }
  }, [ollamaOnline])

  useEffect(() => {
    fetchInstalled()
  }, [fetchInstalled])

  const installedNames = new Set(installed.map(m => m.name))

  const pullModel = useCallback(async (modelName: string) => {
    if (pulling[modelName]) return

    // Abort any previous pull for this model
    abortRefs.current[modelName]?.abort()
    const abort = new AbortController()
    abortRefs.current[modelName] = abort

    setPulling(p => ({
      ...p,
      [modelName]: { status: 'Connecting…', completed: 0, total: 0, done: false, error: false },
    }))

    try {
      const resp = await fetch(`${API_BASE}/ollama/pull`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ model: modelName }),
        signal:  abort.signal,
      })

      if (!resp.ok || !resp.body) {
        const txt = await resp.text()
        setPulling(p => ({
          ...p,
          [modelName]: { status: txt.slice(0, 100) || `HTTP ${resp.status}`, completed: 0, total: 0, done: true, error: true },
        }))
        return
      }

      const reader  = resp.body.getReader()
      const decoder = new TextDecoder()

      while (true) {
        const { done: eof, value } = await reader.read()
        if (eof) break
        const raw = decoder.decode(value, { stream: true })
        for (const line of raw.split('\n')) {
          if (!line.startsWith('data: ')) continue
          try {
            const chunk: PullState = JSON.parse(line.slice(6))
            setPulling(p => ({ ...p, [modelName]: chunk }))
            if (chunk.done) {
              if (!chunk.error) {
                // Refresh installed list + bubble up
                await fetchInstalled()
                onModelsChanged()
                // Auto-clear success after 4s
                setTimeout(() => setPulling(p => {
                  const n = { ...p }
                  delete n[modelName]
                  return n
                }), 4000)
              }
              break
            }
          } catch { /* skip */ }
        }
      }
    } catch (e: unknown) {
      if ((e as Error).name !== 'AbortError') {
        setPulling(p => ({
          ...p,
          [modelName]: { status: 'Pull cancelled or failed', completed: 0, total: 0, done: true, error: true },
        }))
      } else {
        setPulling(p => {
          const n = { ...p }
          delete n[modelName]
          return n
        })
      }
    }
  }, [pulling, fetchInstalled, onModelsChanged])

  const cancelPull = useCallback((modelName: string) => {
    abortRefs.current[modelName]?.abort()
    setPulling(p => {
      const n = { ...p }
      delete n[modelName]
      return n
    })
  }, [])

  const deleteModel = useCallback(async (modelName: string) => {
    if (deleting[modelName]) return
    setDeleting(d => ({ ...d, [modelName]: true }))
    try {
      const r = await fetch(`${API_BASE}/ollama/models/${encodeURIComponent(modelName)}`, { method: 'DELETE' })
      if (r.ok) {
        setInstalled(prev => prev.filter(m => m.name !== modelName))
        onModelsChanged()
      }
    } catch { /* ignore */ } finally {
      setDeleting(d => ({ ...d, [modelName]: false }))
    }
  }, [deleting, onModelsChanged])

  return (
    <div className="flex flex-col gap-3 h-full overflow-y-auto">

      {/* Offline banner */}
      {!ollamaOnline && (
        <div className="flex items-center gap-2 px-3 py-2.5 border border-[rgba(255,34,85,0.25)] bg-[rgba(255,34,85,0.05)]">
          <AlertTriangle size={11} className="text-[var(--color-danger)] shrink-0" />
          <p className="font-mono text-[0.58rem] text-[var(--color-danger)] tracking-widest">
            OLLAMA OFFLINE — start with: <code className="text-[var(--color-warning)]">ollama serve</code>
          </p>
        </div>
      )}

      {/* ── Installed Models ─────────────────────────────────────────────── */}
      <div className="panel shrink-0">
        <div className="panel-header">
          <div className="flex items-center gap-2">
            <HardDrive size={11} className="text-[var(--color-primary)]" />
            <span className="panel-title">INSTALLED MODELS</span>
            {!loading && (
              <span className="font-mono text-[0.46rem] text-[var(--text-ghost)]">
                [{installed.length}]
              </span>
            )}
          </div>
          <button
            onClick={fetchInstalled}
            disabled={loading || !ollamaOnline}
            className="p-1 text-[var(--text-dim)] hover:text-[var(--color-primary)] transition-colors disabled:opacity-40"
            title="Refresh"
          >
            <RefreshCw size={10} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>

        <div className="divide-y divide-[var(--border-base)]">
          {loading && installed.length === 0 && (
            <div className="py-4 text-center font-mono text-[0.55rem] text-[var(--text-ghost)] tracking-widest animate-pulse">
              READING MODELS...
            </div>
          )}

          {!loading && installed.length === 0 && ollamaOnline && (
            <div className="py-5 flex flex-col items-center gap-2 text-center px-4">
              <Cpu size={22} className="text-[var(--text-ghost)]" />
              <p className="font-mono text-[0.58rem] text-[var(--text-ghost)] tracking-widest">
                NO MODELS INSTALLED
              </p>
              <p className="text-[0.7rem] text-[var(--text-muted)] leading-relaxed max-w-xs">
                Pull a model from the catalogue below to get started.
                Recommended: <code className="text-[var(--color-primary)]">llama3.2:3b</code>
              </p>
            </div>
          )}

          <AnimatePresence initial={false}>
            {installed.map(m => {
              const isPulling = !!pulling[m.name]
              const isDel     = deleting[m.name]
              const paramSize = m.details?.parameter_size ?? ''
              const quant     = m.details?.quantization_level ?? ''

              return (
                <motion.div
                  key={m.name}
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="flex items-center gap-3 px-3 py-2.5 hover:bg-[var(--bg-card-hover)] group"
                >
                  <CheckCircle size={11} className="text-[var(--color-success)] shrink-0" />

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-[0.68rem] text-[var(--text-secondary)] tracking-wide">
                        {m.name}
                      </span>
                      {paramSize && (
                        <span className="font-mono text-[0.46rem] text-[var(--color-primary)] border border-[var(--border-accent)] px-1 py-0.5">
                          {paramSize}
                        </span>
                      )}
                      {quant && (
                        <span className="font-mono text-[0.46rem] text-[var(--text-ghost)] border border-[var(--border-base)] px-1 py-0.5">
                          {quant}
                        </span>
                      )}
                    </div>
                    <span className="font-mono text-[0.5rem] text-[var(--text-ghost)]">
                      {m.size_gb} GB · {m.digest}
                    </span>
                  </div>

                  {/* Delete */}
                  <button
                    onClick={() => deleteModel(m.name)}
                    disabled={isDel}
                    className="opacity-0 group-hover:opacity-100 shrink-0 p-1 text-[var(--text-ghost)] hover:text-[var(--color-danger)] transition-all"
                    title={`Delete ${m.name}`}
                  >
                    {isDel
                      ? <RefreshCw size={11} className="animate-spin text-[var(--color-danger)]" />
                      : <Trash2 size={11} />
                    }
                  </button>
                </motion.div>
              )
            })}
          </AnimatePresence>
        </div>
      </div>

      {/* ── Model Catalogue ──────────────────────────────────────────────── */}
      <div className="panel shrink-0">
        <button
          className="panel-header w-full text-left hover:bg-[var(--bg-card-hover)] transition-colors"
          onClick={() => setShowCatalogue(s => !s)}
        >
          <div className="flex items-center gap-2">
            <Download size={11} className="text-[var(--color-primary)]" />
            <span className="panel-title">MODEL CATALOGUE</span>
            <span className="font-mono text-[0.46rem] text-[var(--text-ghost)] tracking-widest">
              [{CATALOGUE.length} models]
            </span>
          </div>
          {showCatalogue
            ? <ChevronUp size={11} className="text-[var(--text-dim)]" />
            : <ChevronDown size={11} className="text-[var(--text-dim)]" />
          }
        </button>

        <AnimatePresence>
          {showCatalogue && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="overflow-hidden"
            >
              {/* Custom model input */}
              <div className="flex items-center gap-2 px-3 py-2 border-b border-[var(--border-base)] bg-[var(--bg-elevated)]/40">
                <input
                  type="text"
                  value={customModel}
                  onChange={e => setCustomModel(e.target.value)}
                  placeholder="Custom model (e.g. llama3.1:70b)"
                  className="flex-1 bg-transparent font-mono text-[0.62rem] text-[var(--text-secondary)] placeholder-[var(--text-ghost)] outline-none"
                  onKeyDown={e => {
                    if (e.key === 'Enter' && customModel.trim()) {
                      pullModel(customModel.trim())
                      setCustomModel('')
                    }
                  }}
                />
                <button
                  onClick={() => {
                    if (customModel.trim()) {
                      pullModel(customModel.trim())
                      setCustomModel('')
                    }
                  }}
                  disabled={!customModel.trim() || !ollamaOnline}
                  className="flex items-center gap-1 px-2 py-1 border border-[var(--border-accent)] font-mono text-[0.48rem] tracking-widest text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.06)] transition-colors disabled:opacity-40 shrink-0"
                >
                  <Download size={8} />
                  PULL
                </button>
                <a
                  href="https://ollama.com/library"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="shrink-0 p-1 text-[var(--text-ghost)] hover:text-[var(--color-primary)] transition-colors"
                  title="Browse Ollama library"
                >
                  <ExternalLink size={10} />
                </a>
              </div>

              {/* Catalogue rows */}
              <div className="divide-y divide-[var(--border-base)]">
                {CATALOGUE.map(entry => {
                  const fullName   = `${entry.name}:${entry.tag}`
                  const isInstalled = installedNames.has(fullName)
                  const pullState  = pulling[fullName]
                  const inProgress = pullState && !pullState.done

                  return (
                    <div
                      key={fullName}
                      className="flex items-start gap-3 px-3 py-2.5 hover:bg-[var(--bg-card-hover)] transition-colors"
                    >
                      {/* Status dot */}
                      <div className="shrink-0 mt-1">
                        {isInstalled
                          ? <CheckCircle size={10} className="text-[var(--color-success)]" />
                          : inProgress
                          ? <RefreshCw size={10} className="text-[var(--color-primary)] animate-spin" />
                          : <div className="w-2.5 h-2.5 rounded-full border border-[var(--border-base)]" />
                        }
                      </div>

                      {/* Info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-[0.65rem] text-[var(--text-secondary)]">
                            {fullName}
                          </span>
                          {entry.recommended && (
                            <span className="font-mono text-[0.44rem] tracking-widest px-1 py-0.5 border border-[rgba(0,212,255,0.3)] text-[var(--color-primary)] bg-[rgba(0,212,255,0.06)]">
                              RECOMMENDED
                            </span>
                          )}
                          <span className="font-mono text-[0.5rem] text-[var(--text-ghost)]">
                            {entry.size}
                          </span>
                          <span className="font-mono text-[0.5rem] text-[var(--text-ghost)]">
                            ctx {entry.ctx}
                          </span>
                        </div>
                        <p className="text-[0.7rem] text-[var(--text-muted)] leading-snug mt-0.5">
                          {entry.desc}
                        </p>

                        {/* Pull progress */}
                        {pullState && (
                          <PullProgress pull={pullState} />
                        )}
                      </div>

                      {/* Pull / Cancel button */}
                      <div className="shrink-0">
                        {inProgress ? (
                          <button
                            onClick={() => cancelPull(fullName)}
                            className="flex items-center gap-1 px-2 py-1 border border-[rgba(255,34,85,0.35)] font-mono text-[0.46rem] tracking-widest text-[var(--color-danger)] hover:bg-[rgba(255,34,85,0.06)] transition-colors"
                            title="Cancel"
                          >
                            <Square size={7} />
                            STOP
                          </button>
                        ) : isInstalled ? (
                          <button
                            onClick={() => deleteModel(fullName)}
                            disabled={deleting[fullName]}
                            className="flex items-center gap-1 px-2 py-1 border border-[var(--border-base)] font-mono text-[0.46rem] tracking-widest text-[var(--text-ghost)] hover:text-[var(--color-danger)] hover:border-[rgba(255,34,85,0.35)] transition-colors disabled:opacity-40"
                            title="Delete"
                          >
                            {deleting[fullName]
                              ? <RefreshCw size={7} className="animate-spin" />
                              : <Trash2 size={7} />
                            }
                            DELETE
                          </button>
                        ) : (
                          <button
                            onClick={() => pullModel(fullName)}
                            disabled={!ollamaOnline || !!pullState}
                            className="flex items-center gap-1 px-2 py-1 border border-[var(--border-accent)] font-mono text-[0.46rem] tracking-widest text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.06)] transition-colors disabled:opacity-40"
                            title={`Pull ${fullName}`}
                          >
                            <Download size={7} />
                            PULL
                          </button>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>

              {/* Footer note */}
              <div className="px-3 py-2 border-t border-[var(--border-base)] bg-[var(--bg-elevated)]/30">
                <p className="font-mono text-[0.5rem] text-[var(--text-ghost)] leading-relaxed">
                  Models are downloaded from <span className="text-[var(--color-primary)]">ollama.com/library</span> and stored locally.
                  Sizes are approximate. Larger models require more RAM — 3B fits in 4 GB, 7B requires 8 GB.
                </p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}
