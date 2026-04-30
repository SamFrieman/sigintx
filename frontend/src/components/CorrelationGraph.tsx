/**
 * SIGINTX — Threat Correlation Graph  (v3)
 *
 * Graph is built in two layers:
 *   - Deterministic (verified=true):  news ↔ actors from DB, actor ↔ technique from DB
 *   - AI-enriched   (verified=false): campaign nodes added by LLM grouping
 *
 * Layout: gravity-based hierarchical — each row sorts its nodes by the
 * average x-position of their already-placed neighbours, so connected
 * nodes end up visually near each other across rows.
 *
 * Interaction:
 *   - Click a node → highlights its 1-hop neighbourhood, dims everything else
 *   - Click pane   → clears selection
 *   - Detail panel → shows full metadata, connected neighbours, and a verify button
 */

import {
  useState, useCallback, useEffect, useRef, useMemo,
} from 'react'
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  type Node,
  type Edge,
  type NodeProps,
} from 'reactflow'
import 'reactflow/dist/style.css'
import {
  GitFork, RefreshCw, CheckCircle, AlertTriangle,
  Shield, Newspaper, Target, Zap, X, Info, Lock,
} from 'lucide-react'
import { sevColor } from '@/lib/utils'
import { fetchJson } from '@/hooks/useApi'
import type { SeverityLevel } from '@/types'

// ── Types ─────────────────────────────────────────────────────────────────────

interface AiNode {
  id: string
  type: 'actor' | 'news' | 'campaign' | 'technique'
  label: string
  description: string
  severity?: string | null
  verified: boolean
  ai_generated: boolean
  confidence?: number | null
  country?: string | null
  last_seen?: string | null
  iocs?: string[]
  techniques?: string[]
  target_sectors?: string[]
  sources?: string[]
}

interface AiEdge {
  id: string
  source: string
  target: string
  label: string
  type: string
  strength?: number
  verified: boolean
  ai_generated: boolean
}

interface AiGraphData {
  nodes: AiNode[]
  edges: AiEdge[]
  provider: string
  hours_back: number
  generated_at: string
  ai_generated: boolean
}

// ── Visual config ─────────────────────────────────────────────────────────────

const NODE_W = 165
const NODE_H = 72

const NODE_CONFIG: Record<string, {
  color: string; bgColor: string; borderColor: string
  icon: typeof Shield; label: string
}> = {
  actor:     { color: '#cc55ff', bgColor: 'rgba(204,85,255,0.12)',  borderColor: 'rgba(204,85,255,0.5)',  icon: Shield,    label: 'ACTOR'     },
  campaign:  { color: '#f7931a', bgColor: 'rgba(247,147,26,0.12)',  borderColor: 'rgba(247,147,26,0.5)',  icon: Target,    label: 'CAMPAIGN'  },
  technique: { color: '#00ff88', bgColor: 'rgba(0,255,136,0.09)',   borderColor: 'rgba(0,255,136,0.42)', icon: Zap,       label: 'TECHNIQUE' },
  news:      { color: '#00d4ff', bgColor: 'rgba(0,212,255,0.09)',   borderColor: 'rgba(0,212,255,0.38)', icon: Newspaper, label: 'NEWS'      },
}

const EDGE_STYLE: Record<string, { stroke: string; strokeWidth: number }> = {
  linked_to:      { stroke: 'rgba(200,200,255,0.55)', strokeWidth: 1.5 },
  uses_technique: { stroke: 'rgba(0,255,136,0.70)',   strokeWidth: 2.0 },
  targets:        { stroke: 'rgba(255,68,68,0.70)',   strokeWidth: 2.0 },
  mentioned_in:   { stroke: 'rgba(0,212,255,0.55)',   strokeWidth: 1.5 },
}

// ── Layout: gravity-based hierarchical ───────────────────────────────────────
//
// Processes rows top-to-bottom.  For each row, nodes are sorted by the average
// x-coordinate of their already-placed neighbours, so nodes that share edges
// tend to land directly above/below one another.

function buildLayout(aiNodes: AiNode[], aiEdges: AiEdge[]): Node[] {
  const ROW_ORDER = ['actor', 'campaign', 'technique', 'news'] as const
  const ROW_Y     = [0, 180, 360, 540]
  const H_STEP    = NODE_W + 44   // min horizontal distance between node centres

  const layers: Record<string, AiNode[]> = { actor: [], campaign: [], technique: [], news: [] }
  for (const n of aiNodes) {
    const row = layers[n.type] ?? layers.news
    row.push(n)
  }

  // Build neighbour lists
  const neighbours: Record<string, string[]> = {}
  for (const e of aiEdges) {
    ;(neighbours[e.source] ??= []).push(e.target)
    ;(neighbours[e.target] ??= []).push(e.source)
  }

  const placedX: Record<string, number> = {}  // node_id → centre x
  const result:  Node[] = []

  ROW_ORDER.forEach((type, li) => {
    const rn = layers[type]
    if (!rn.length) return

    // Gravity: average x of already-placed neighbours
    const sorted = [...rn].sort((a, b) => {
      const grav = (id: string) => {
        const xs = (neighbours[id] ?? []).filter(nid => nid in placedX).map(nid => placedX[nid])
        return xs.length ? xs.reduce((s, v) => s + v, 0) / xs.length : 0
      }
      return grav(a.id) - grav(b.id)
    })

    const rowW   = sorted.length * H_STEP
    const startX = -(rowW / 2) + H_STEP / 2

    sorted.forEach((n, i) => {
      const x   = startX + i * H_STEP
      placedX[n.id] = x + NODE_W / 2

      const cfg  = NODE_CONFIG[n.type] ?? NODE_CONFIG.news
      const color = n.severity ? sevColor(n.severity as SeverityLevel) : cfg.color

      result.push({
        id:       n.id,
        type:     'correlationNode',
        position: { x, y: ROW_Y[li] },
        data: {
          nodeType:       n.type,
          label:          n.label,
          description:    n.description,
          severity:       n.severity as SeverityLevel | null | undefined,
          verified:       n.verified,
          ai_generated:   n.ai_generated,
          color,
          cfgColor:       cfg.color,
          confidence:     n.confidence,
          country:        n.country,
          last_seen:      n.last_seen,
          iocs:           n.iocs           ?? [],
          techniques:     n.techniques     ?? [],
          target_sectors: n.target_sectors ?? [],
          sources:        n.sources        ?? [],
          dimmed:         false,
        },
      })
    })
  })

  return result
}

// ── Custom node component ─────────────────────────────────────────────────────

function CorrelationNode({ data }: NodeProps) {
  const cfg   = NODE_CONFIG[data.nodeType] ?? NODE_CONFIG.news
  const Icon  = cfg.icon
  const color = data.color as string

  return (
    <div
      className="relative rounded-sm font-mono select-none transition-all duration-200"
      style={{
        width:      NODE_W,
        minHeight:  NODE_H,
        background: cfg.bgColor,
        border:     `1px solid ${data.verified ? color : cfg.borderColor}`,
        boxShadow:  data.verified
          ? `0 0 16px ${color}44, inset 0 0 6px ${color}0d`
          : `0 0 5px ${cfg.color}1a`,
        opacity:    data.dimmed ? 0.22 : 1,
        filter:     data.dimmed ? 'grayscale(0.6)' : 'none',
      }}
    >
      {/* Type bar */}
      <div
        className="flex items-center gap-1 px-2 py-1 border-b"
        style={{ borderColor: `${color}2a`, background: `${color}14` }}
      >
        <Icon size={8} style={{ color }} />
        <span className="tracking-widest text-[0.42rem] font-bold" style={{ color }}>
          {cfg.label}
          {data.severity && <span className="ml-1 opacity-60">· {data.severity}</span>}
        </span>
        <div className="ml-auto flex items-center gap-1">
          {data.confidence != null && (
            <span
              className="text-[0.37rem]"
              style={{
                color: data.confidence >= 75 ? 'var(--color-success)'
                  : data.confidence >= 50 ? 'var(--color-warning)'
                  : 'var(--color-danger)',
              }}
            >
              {data.confidence}%
            </span>
          )}
          {data.verified
            ? <CheckCircle size={9} style={{ color: 'var(--color-success)' }} />
            : data.ai_generated
              ? <AlertTriangle size={8} style={{ color: 'rgba(255,170,0,0.7)' }} />
              : <Lock size={8} style={{ color: 'var(--text-ghost)' }} />}
        </div>
      </div>

      {/* Label */}
      <div className="px-2 py-1.5 text-[0.6rem] leading-tight" style={{ color: 'var(--text-base)' }}>
        {data.label}
      </div>

      {/* Footer chips */}
      <div className="px-2 pb-1.5 flex items-center gap-1 flex-wrap">
        {data.country && (
          <span
            className="text-[0.37rem] px-1 py-0.5 border"
            style={{ color: cfg.color, borderColor: `${cfg.color}2a`, background: `${cfg.color}0a` }}
          >
            {data.country}
          </span>
        )}
        {data.iocs?.length > 0 && (
          <span
            className="text-[0.37rem] px-1 py-0.5 border"
            style={{ color: 'rgba(255,170,0,0.9)', borderColor: 'rgba(255,170,0,0.28)', background: 'rgba(255,170,0,0.05)' }}
          >
            {data.iocs.length} IOC{data.iocs.length > 1 ? 's' : ''}
          </span>
        )}
        {data.last_seen && (
          <span className="text-[0.37rem] text-[var(--text-ghost)]">{data.last_seen}</span>
        )}
      </div>
    </div>
  )
}

const NODE_TYPES = { correlationNode: CorrelationNode }

// ── Detail panel ──────────────────────────────────────────────────────────────

function DetailPanel({
  node, onClose, onVerify, rawData,
}: {
  node: AiNode
  onClose: () => void
  onVerify: (id: string) => void
  rawData: AiGraphData | null
}) {
  const cfg   = NODE_CONFIG[node.type] ?? NODE_CONFIG.news
  const color = node.severity ? sevColor(node.severity as SeverityLevel) : cfg.color

  const { incoming, outgoing } = useMemo(() => {
    const inc: { id: string; label: string; type: string; edgeLabel: string }[] = []
    const out: { id: string; label: string; type: string; edgeLabel: string }[] = []
    if (!rawData) return { incoming: inc, outgoing: out }
    for (const e of rawData.edges) {
      if (e.target === node.id) {
        const n = rawData.nodes.find(n => n.id === e.source)
        if (n) inc.push({ id: n.id, label: n.label, type: n.type, edgeLabel: e.label || e.type })
      } else if (e.source === node.id) {
        const n = rawData.nodes.find(n => n.id === e.target)
        if (n) out.push({ id: n.id, label: n.label, type: n.type, edgeLabel: e.label || e.type })
      }
    }
    const dedup = (arr: typeof inc) => arr.filter((v, i, a) => a.findIndex(x => x.id === v.id) === i)
    return { incoming: dedup(inc), outgoing: dedup(out) }
  }, [rawData, node.id])

  const NeighbourList = ({ items, title }: { items: typeof incoming; title: string }) =>
    items.length === 0 ? null : (
      <div>
        <p className="font-mono text-[0.44rem] tracking-widest text-[var(--text-ghost)] mb-1.5">{title}</p>
        <div className="space-y-0.5">
          {items.map(n => {
            const ncfg = NODE_CONFIG[n.type] ?? NODE_CONFIG.news
            return (
              <div key={n.id} className="flex items-center gap-1.5 font-mono text-[0.5rem]">
                <div className="w-1.5 h-1.5 rounded-sm shrink-0" style={{ background: ncfg.color }} />
                <span className="text-[var(--text-secondary)] truncate">{n.label}</span>
                <span className="ml-auto shrink-0 text-[0.38rem] text-[var(--text-ghost)]">{n.edgeLabel}</span>
              </div>
            )
          })}
        </div>
      </div>
    )

  return (
    <div
      className="absolute top-3 right-3 z-30 w-72 border bg-[var(--bg-surface)] shadow-2xl flex flex-col max-h-[calc(100%-24px)]"
      style={{ borderColor: `${color}50`, borderLeft: `2px solid ${color}` }}
    >
      {/* Sticky header */}
      <div
        className="flex items-center justify-between px-3 py-2 border-b shrink-0"
        style={{ borderColor: `${color}28`, background: `${color}0a` }}
      >
        <div className="flex items-center gap-1.5">
          <cfg.icon size={10} style={{ color }} />
          <span className="font-mono text-[0.48rem] tracking-widest" style={{ color }}>{cfg.label}</span>
          {node.severity && (
            <span
              className="font-mono text-[0.42rem] px-1 border"
              style={{ color, borderColor: `${color}44`, background: `${color}0d` }}
            >
              {node.severity}
            </span>
          )}
          {node.ai_generated && !node.verified && (
            <span className="font-mono text-[0.38rem] px-1 border border-[rgba(255,170,0,0.3)] text-[rgba(255,170,0,0.8)] bg-[rgba(255,170,0,0.05)]">
              AI
            </span>
          )}
        </div>
        <button onClick={onClose} className="text-[var(--text-ghost)] hover:text-[var(--text-base)] transition-colors shrink-0">
          <X size={11} />
        </button>
      </div>

      {/* Scrollable body */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {/* Title */}
        <p className="font-mono text-[0.65rem] text-[var(--text-base)] leading-snug font-semibold">
          {node.label}
        </p>

        {/* Confidence bar */}
        {node.confidence != null && (
          <div>
            <div className="flex justify-between mb-1">
              <span className="font-mono text-[0.44rem] text-[var(--text-dim)] tracking-widest">CONFIDENCE</span>
              <span
                className="font-mono text-[0.44rem]"
                style={{
                  color: node.confidence >= 75 ? 'var(--color-success)'
                    : node.confidence >= 50 ? 'var(--color-warning)' : 'var(--color-danger)',
                }}
              >
                {node.confidence}%
              </span>
            </div>
            <div className="h-1 bg-[var(--bg-elevated)] rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all"
                style={{
                  width: `${node.confidence}%`,
                  background: node.confidence >= 75 ? 'var(--color-success)'
                    : node.confidence >= 50 ? 'var(--color-warning)' : 'var(--color-danger)',
                }}
              />
            </div>
          </div>
        )}

        {/* Description */}
        {node.description && (
          <p className="text-[0.62rem] text-[var(--text-secondary)] leading-relaxed">{node.description}</p>
        )}

        {/* Meta grid */}
        <div className="grid grid-cols-2 gap-1 font-mono text-[0.5rem]">
          {node.country && (
            <div className="border border-[var(--border-base)] px-1.5 py-1">
              <span className="text-[var(--text-ghost)] block text-[0.38rem] tracking-widest mb-0.5">ORIGIN</span>
              <span style={{ color }}>{node.country}</span>
            </div>
          )}
          {node.last_seen && (
            <div className="border border-[var(--border-base)] px-1.5 py-1">
              <span className="text-[var(--text-ghost)] block text-[0.38rem] tracking-widest mb-0.5">LAST SEEN</span>
              <span className="text-[var(--text-secondary)]">{node.last_seen}</span>
            </div>
          )}
          <div className="border border-[var(--border-base)] px-1.5 py-1">
            <span className="text-[var(--text-ghost)] block text-[0.38rem] tracking-widest mb-0.5">CONNECTIONS</span>
            <span className="text-[var(--text-secondary)]">{incoming.length + outgoing.length} nodes</span>
          </div>
          <div className="border border-[var(--border-base)] px-1.5 py-1">
            <span className="text-[var(--text-ghost)] block text-[0.38rem] tracking-widest mb-0.5">SOURCE</span>
            <span style={{ color: node.verified ? 'var(--color-success)' : 'rgba(255,170,0,0.8)' }}>
              {node.ai_generated ? 'AI-GENERATED' : 'DATABASE'}
            </span>
          </div>
        </div>

        {/* Connections */}
        <NeighbourList items={incoming} title={`← FROM (${incoming.length})`} />
        <NeighbourList items={outgoing} title={`→ TO (${outgoing.length})`} />

        {/* Techniques */}
        {node.techniques && node.techniques.length > 0 && (
          <div>
            <p className="font-mono text-[0.44rem] tracking-widest text-[var(--text-ghost)] mb-1.5">TECHNIQUES / ALIASES</p>
            <div className="flex flex-wrap gap-1">
              {node.techniques.map((t, i) => (
                <span key={i}
                  className="font-mono text-[0.44rem] px-1.5 py-0.5 border border-[rgba(0,255,136,0.25)] text-[var(--color-success)] bg-[rgba(0,255,136,0.05)]">
                  {t}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Target sectors */}
        {node.target_sectors && node.target_sectors.length > 0 && (
          <div>
            <p className="font-mono text-[0.44rem] tracking-widest text-[var(--text-ghost)] mb-1.5">TARGET SECTORS</p>
            <div className="flex flex-wrap gap-1">
              {node.target_sectors.map((s, i) => (
                <span key={i}
                  className="font-mono text-[0.44rem] px-1.5 py-0.5 border border-[rgba(255,68,68,0.25)] text-[var(--color-danger)] bg-[rgba(255,68,68,0.05)]">
                  {s}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* IOCs / CVE refs */}
        {node.iocs && node.iocs.length > 0 && (
          <div>
            <p className="font-mono text-[0.44rem] tracking-widest text-[rgba(255,170,0,0.9)] mb-1.5">
              INDICATORS / CVEs ({node.iocs.length})
            </p>
            <div className="space-y-0.5 font-mono text-[0.5rem] text-[var(--text-dim)]">
              {node.iocs.map((ioc, i) => (
                <div key={i}
                  className="px-1.5 py-0.5 bg-[rgba(247,147,26,0.05)] border border-[rgba(247,147,26,0.15)] truncate">
                  {ioc}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Source intelligence */}
        {node.sources && node.sources.length > 0 && (
          <div>
            <p className="font-mono text-[0.44rem] tracking-widest text-[var(--text-ghost)] mb-1.5">
              SOURCE INTELLIGENCE
            </p>
            <div className="space-y-0.5">
              {node.sources.map((src, i) => (
                <div key={i} className="flex items-start gap-1 font-mono text-[0.48rem] text-[var(--text-dim)]">
                  <span style={{ color: 'var(--color-primary)' }} className="shrink-0">›</span>
                  <span className="leading-tight">{src}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Verify button */}
        {!node.verified ? (
          <button
            onClick={() => onVerify(node.id)}
            className="w-full flex items-center justify-center gap-2 px-3 py-1.5 border font-mono text-[0.5rem] tracking-widest transition-colors hover:bg-[rgba(0,255,136,0.08)]"
            style={{ borderColor: 'var(--color-success)', color: 'var(--color-success)' }}
          >
            <CheckCircle size={10} /> MARK AS VERIFIED
          </button>
        ) : (
          <div
            className="flex items-center justify-center gap-1.5 px-3 py-1.5 border font-mono text-[0.5rem] tracking-widest"
            style={{ borderColor: 'rgba(0,255,136,0.3)', color: 'var(--color-success)', background: 'rgba(0,255,136,0.06)' }}
          >
            <CheckCircle size={10} /> VERIFIED
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

interface Props { refreshTrigger: number }

export function CorrelationGraph({ refreshTrigger }: Props) {
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [rawData, setRawData]       = useState<AiGraphData | null>(null)
  const [loading, setLoading]       = useState(false)
  const [error, setError]           = useState<string | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [verified, setVerified]     = useState<Set<string>>(new Set())
  const [hoursBack, setHoursBack]   = useState(48)

  // Track whether we're mid-flight to avoid duplicate requests
  const inFlightRef = useRef(false)
  // Track the last hoursBack used so window changes re-fetch
  const lastHoursRef = useRef(-1)

  const fetchCorrelation = useCallback(async (force = false) => {
    if (inFlightRef.current && !force) return
    inFlightRef.current = true
    setLoading(true)
    setError(null)
    try {
      const data = await fetchJson<AiGraphData>(
        '/correlation/ai',
        { hours_back: hoursBack, ...(force ? { force_refresh: 'true' } : {}) },
      )
      setRawData(data)
      setSelectedId(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to fetch correlation data')
    } finally {
      setLoading(false)
      inFlightRef.current = false
    }
  }, [hoursBack])

  // Initial fetch
  useEffect(() => { fetchCorrelation() }, []) // eslint-disable-line

  // Manual refresh trigger (parent signals via refreshTrigger prop increment)
  const prevRefreshRef = useRef(refreshTrigger)
  useEffect(() => {
    if (refreshTrigger !== prevRefreshRef.current) {
      prevRefreshRef.current = refreshTrigger
      fetchCorrelation(true)
    }
  }, [refreshTrigger, fetchCorrelation])

  // Re-fetch when time window changes
  useEffect(() => {
    if (lastHoursRef.current !== -1 && lastHoursRef.current !== hoursBack) {
      fetchCorrelation()
    }
    lastHoursRef.current = hoursBack
  }, [hoursBack, fetchCorrelation])

  // ── Build React Flow graph from rawData ────────────────────────────────────
  useEffect(() => {
    if (!rawData?.nodes.length) return

    const aiNodes = rawData.nodes.map(n => ({ ...n, verified: n.verified || verified.has(n.id) }))
    const rfNodes = buildLayout(aiNodes, rawData.edges)
    setNodes(rfNodes)

    const rfEdges: Edge[] = rawData.edges.map(e => {
      const es     = EDGE_STYLE[e.type] ?? EDGE_STYLE.linked_to
      const str    = e.strength ?? 60
      const sw     = es.strokeWidth * (0.6 + (str / 100) * 0.9)
      const isVer  = verified.has(e.source) && verified.has(e.target)

      return {
        id:           e.id,
        source:       e.source,
        target:       e.target,
        label:        e.label || undefined,
        labelStyle:   { fill: 'rgba(180,200,220,0.75)', fontFamily: 'monospace', fontSize: 8 },
        labelBgStyle: { fill: 'rgba(6,13,24,0.88)', fillOpacity: 1 },
        style: {
          stroke:          isVer ? es.stroke.replace(/[\d.]+\)$/, '0.95)') : es.stroke,
          strokeWidth:     sw,
          strokeDasharray: e.verified ? undefined : '5 3',
          filter:          isVer ? `drop-shadow(0 0 3px ${es.stroke})` : undefined,
        },
        markerEnd: { type: MarkerType.ArrowClosed, color: es.stroke, width: 13, height: 13 },
        animated:  e.type === 'uses_technique' || e.type === 'targets',
        type:      'smoothstep',
        data:      { baseAnimated: e.type === 'uses_technique' || e.type === 'targets' },
      }
    })
    setEdges(rfEdges)
  }, [rawData, verified, setNodes, setEdges])

  // ── Node selection: dim non-neighbours ────────────────────────────────────
  useEffect(() => {
    if (!rawData) return

    if (!selectedId) {
      setNodes(prev => prev.map(n => ({ ...n, data: { ...n.data, dimmed: false } })))
      setEdges(prev => prev.map(e => ({
        ...e,
        style:    { ...e.style, opacity: 1 },
        animated: e.data?.baseAnimated ?? false,
      })))
      return
    }

    const hood = new Set<string>([selectedId])
    for (const e of rawData.edges) {
      if (e.source === selectedId) hood.add(e.target)
      if (e.target === selectedId) hood.add(e.source)
    }

    setNodes(prev => prev.map(n => ({
      ...n, data: { ...n.data, dimmed: !hood.has(n.id) },
    })))

    setEdges(prev => prev.map(e => {
      const connected = e.source === selectedId || e.target === selectedId
      return {
        ...e,
        style: {
          ...e.style,
          opacity:     connected ? 1 : 0.08,
          strokeWidth: connected ? ((Number(e.style?.strokeWidth) || 1.5) * 2) : e.style?.strokeWidth,
        },
        animated: connected,
      }
    }))
  }, [selectedId]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleVerify    = useCallback((id: string) => setVerified(p => new Set([...p, id])), [])
  const handleVerifyAll = useCallback(() => {
    if (rawData) setVerified(new Set(rawData.nodes.map(n => n.id)))
  }, [rawData])

  const selectedNode  = rawData?.nodes.find(n => n.id === selectedId) ?? null
  const verifiedCount = rawData?.nodes.filter(n => verified.has(n.id)).length ?? 0
  const totalCount    = rawData?.nodes.length ?? 0
  const edgeCount     = rawData?.edges.length ?? 0

  const typeCounts = useMemo(() => {
    const acc: Record<string, number> = {}
    rawData?.nodes.forEach(n => { acc[n.type] = (acc[n.type] ?? 0) + 1 })
    return acc
  }, [rawData])

  const isDetOnly = rawData?.provider === 'deterministic'

  return (
    <div className="panel flex flex-col h-full overflow-hidden">

      {/* ── Header ── */}
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2 flex-wrap">
          <GitFork size={11} className="text-[var(--color-primary)] shrink-0" />
          <span className="panel-title">THREAT CORRELATION</span>
          {rawData && (
            <>
              <span className="live-dot" />
              <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-widest">
                {totalCount} NODES · {edgeCount} EDGES
              </span>
              {Object.entries(typeCounts).map(([type, count]) => {
                const cfg = NODE_CONFIG[type]
                return cfg ? (
                  <span key={type}
                    className="font-mono text-[0.42rem] tracking-widest px-1.5 py-0.5 border"
                    style={{ color: cfg.color, borderColor: `${cfg.color}33`, background: `${cfg.color}0d` }}>
                    {type.toUpperCase()} ×{count}
                  </span>
                ) : null
              })}
              <span
                className="font-mono text-[0.42rem] tracking-widest px-1.5 py-0.5 border"
                style={{
                  color:       isDetOnly ? 'var(--color-success)' : 'var(--color-info)',
                  borderColor: isDetOnly ? 'rgba(0,255,136,0.3)' : 'rgba(170,68,255,0.3)',
                  background:  isDetOnly ? 'rgba(0,255,136,0.06)' : 'rgba(170,68,255,0.07)',
                }}
              >
                {isDetOnly ? 'DB' : `AI: ${rawData.provider.toUpperCase()}`}
              </span>
            </>
          )}
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          <div className="flex items-center gap-0.5">
            {[24, 48, 72].map(h => (
              <button key={h} onClick={() => setHoursBack(h)}
                className="font-mono text-[0.46rem] tracking-widest px-1.5 py-0.5 border transition-all"
                style={{
                  color:       hoursBack === h ? 'var(--color-primary)' : 'var(--text-ghost)',
                  borderColor: hoursBack === h ? 'var(--border-accent)' : 'var(--border-base)',
                  background:  hoursBack === h ? 'rgba(0,212,255,0.07)' : 'transparent',
                }}>
                {h}H
              </button>
            ))}
          </div>
          {rawData && verifiedCount < totalCount && (
            <button onClick={handleVerifyAll}
              className="flex items-center gap-1 px-2 py-0.5 border font-mono text-[0.46rem] tracking-widest transition-colors hover:bg-[rgba(0,255,136,0.08)]"
              style={{ borderColor: 'rgba(0,255,136,0.4)', color: 'var(--color-success)' }}>
              <CheckCircle size={8} /> VERIFY ALL
            </button>
          )}
          <button onClick={() => fetchCorrelation(true)} disabled={loading}
            className="flex items-center gap-1 px-2 py-0.5 border border-[var(--border-accent)] font-mono text-[0.46rem] tracking-widest text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.07)] disabled:opacity-40 transition-colors">
            <RefreshCw size={8} className={loading ? 'animate-spin' : ''} />
            {loading ? 'LOADING...' : 'REFRESH'}
          </button>
        </div>
      </div>

      {/* ── Verification bar ── */}
      {rawData && totalCount > 0 && (
        <div className="shrink-0 px-3 py-1.5 border-b border-[var(--border-base)] flex items-center gap-2">
          {verifiedCount === totalCount
            ? <CheckCircle size={9} className="text-[var(--color-success)]" />
            : <AlertTriangle size={9} className="text-[var(--color-warning)]" />}
          <span className="font-mono text-[0.46rem] tracking-widest"
            style={{ color: verifiedCount === totalCount ? 'var(--color-success)' : 'var(--color-warning)' }}>
            {verifiedCount === totalCount
              ? 'ALL NODES VERIFIED'
              : `${verifiedCount}/${totalCount} VERIFIED — ${totalCount - verifiedCount} PENDING`}
          </span>
          <div className="flex-1 h-1 bg-[var(--bg-elevated)] rounded-full overflow-hidden ml-2">
            <div className="h-full rounded-full transition-all duration-500"
              style={{
                width: `${totalCount > 0 ? (verifiedCount / totalCount) * 100 : 0}%`,
                background: verifiedCount === totalCount ? 'var(--color-success)' : 'var(--color-warning)',
              }}
            />
          </div>
        </div>
      )}

      {/* ── Canvas ── */}
      <div className="flex-1 relative min-h-0">

        {/* Loading */}
        {loading && nodes.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 z-10">
            <RefreshCw size={28} className="text-[var(--color-primary)] animate-spin" />
            <p className="font-mono text-[0.65rem] text-[var(--text-dim)] tracking-widest">
              BUILDING CORRELATION GRAPH...
            </p>
            <p className="font-mono text-[0.52rem] text-[var(--text-ghost)] tracking-widest">
              Extracting relationships from DB · AI enrichment optional
            </p>
          </div>
        )}

        {/* Error */}
        {error && !loading && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 z-10 px-8 text-center">
            <AlertTriangle size={28} className="text-[var(--color-warning)]" />
            <p className="font-mono text-[0.65rem] text-[var(--color-danger)] tracking-widest">CORRELATION FAILED</p>
            <p className="font-mono text-[0.58rem] text-[var(--text-muted)] max-w-sm leading-relaxed">{error}</p>
            <button onClick={() => fetchCorrelation(true)}
              className="font-mono text-[0.52rem] tracking-widest px-4 py-1.5 border border-[var(--border-accent)] text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.06)] transition-colors">
              RETRY
            </button>
          </div>
        )}

        {/* Empty */}
        {!loading && !error && rawData && nodes.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 z-10 px-8 text-center">
            <Info size={28} className="text-[var(--text-ghost)]" />
            <p className="font-mono text-[0.65rem] text-[var(--text-dim)] tracking-widest">
              NO CORRELATIONS IN {hoursBack}H WINDOW
            </p>
            <p className="text-[0.7rem] text-[var(--text-muted)] max-w-sm leading-relaxed">
              No news with linked threat actors found. Try a wider time window.
            </p>
          </div>
        )}

        {/* React Flow */}
        {nodes.length > 0 && (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={NODE_TYPES}
            onNodeClick={(_, node) => setSelectedId(id => id === node.id ? null : node.id)}
            onPaneClick={() => setSelectedId(null)}
            fitView
            fitViewOptions={{ padding: 0.18 }}
            minZoom={0.1}
            maxZoom={3}
            proOptions={{ hideAttribution: true }}
            defaultEdgeOptions={{ type: 'smoothstep' }}
          >
            <Background color="rgba(0,212,255,0.035)" gap={28} size={1} />
            <Controls className="border border-[var(--border-base)] bg-[var(--bg-surface)]" showInteractive={false} />
            <MiniMap
              nodeColor={n => (NODE_CONFIG[n.data?.nodeType as string] ?? NODE_CONFIG.news).color}
              className="border border-[var(--border-base)] bg-[var(--bg-card)]"
              maskColor="rgba(0,0,0,0.72)"
              style={{ width: 160, height: 100 }}
            />
          </ReactFlow>
        )}

        {/* Detail panel */}
        {selectedId && selectedNode && (
          <DetailPanel
            node={{ ...selectedNode, verified: selectedNode.verified || verified.has(selectedNode.id) }}
            onClose={() => setSelectedId(null)}
            onVerify={handleVerify}
            rawData={rawData}
          />
        )}

        {/* Legend */}
        {nodes.length > 0 && (
          <div className="absolute bottom-3 left-3 z-10 bg-[var(--bg-surface)]/90 backdrop-blur-sm border border-[var(--border-base)] px-2.5 py-2 space-y-1 pointer-events-none">
            {Object.entries(NODE_CONFIG).map(([type, cfg]) => (
              <div key={type} className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-sm shrink-0" style={{ background: cfg.color }} />
                <span className="font-mono text-[0.42rem] tracking-widest text-[var(--text-dim)]">{cfg.label}</span>
              </div>
            ))}
            <div className="pt-1 border-t border-[var(--border-base)] space-y-0.5 mt-0.5">
              <div className="flex items-center gap-1.5">
                <CheckCircle size={8} className="text-[var(--color-success)]" />
                <span className="font-mono text-[0.4rem] text-[var(--text-ghost)]">DB VERIFIED</span>
              </div>
              <div className="flex items-center gap-1.5">
                <AlertTriangle size={8} style={{ color: 'rgba(255,170,0,0.7)' }} />
                <span className="font-mono text-[0.4rem] text-[var(--text-ghost)]">AI ENRICHED</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Footer ── */}
      {rawData && (
        <div className="shrink-0 px-3 py-1.5 border-t border-[var(--border-base)] flex items-center gap-3 text-[var(--text-ghost)] flex-wrap">
          <span className="font-mono text-[0.42rem] tracking-widest">
            GENERATED: {new Date(rawData.generated_at).toLocaleTimeString()}
          </span>
          <span className="font-mono text-[0.42rem] tracking-widest">WINDOW: {rawData.hours_back}H</span>
          <span className="font-mono text-[0.42rem] tracking-widest">
            {isDetOnly ? 'SOURCE: DATABASE ONLY' : `ENRICHED BY: ${rawData.provider.toUpperCase()}`}
          </span>
          {!isDetOnly && (
            <span className="ml-auto font-mono text-[0.42rem] tracking-widest text-[var(--color-warning)]">
              ⚠ AI CAMPAIGN NODES UNVERIFIED
            </span>
          )}
        </div>
      )}
    </div>
  )
}
