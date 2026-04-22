/**
 * SIGINTX — AI-Driven Threat Correlation Graph  (v2)
 *
 * Replaces dagre (unreliable for sparse graphs) with a deterministic
 * type-grouped radial layout:
 *   • ACTOR nodes  — top row
 *   • CAMPAIGN     — second row, positioned near linked actors
 *   • TECHNIQUE    — third row
 *   • NEWS         — bottom row
 *
 * Edges are rendered as glowing SVG curves directly over the node canvas so
 * connections are always clearly visible.
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
  Shield, Newspaper, Target, Zap, X, Info,
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
  // Enrichment fields
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

// ── Node dimensions ───────────────────────────────────────────────────────────

const NODE_W = 170
const NODE_H = 68

// ── Node style config ─────────────────────────────────────────────────────────

const NODE_CONFIG: Record<string, {
  color: string; bgColor: string; borderColor: string
  icon: typeof Shield; label: string; rowOrder: number
}> = {
  actor:     { color: '#cc55ff', bgColor: 'rgba(204,85,255,0.13)',  borderColor: 'rgba(204,85,255,0.5)',  icon: Shield,    label: 'ACTOR',     rowOrder: 0 },
  campaign:  { color: '#f7931a', bgColor: 'rgba(247,147,26,0.13)',  borderColor: 'rgba(247,147,26,0.5)',  icon: Target,    label: 'CAMPAIGN',  rowOrder: 1 },
  technique: { color: '#00ff88', bgColor: 'rgba(0,255,136,0.10)',   borderColor: 'rgba(0,255,136,0.45)', icon: Zap,       label: 'TECHNIQUE', rowOrder: 2 },
  news:      { color: '#00d4ff', bgColor: 'rgba(0,212,255,0.10)',   borderColor: 'rgba(0,212,255,0.4)',  icon: Newspaper, label: 'NEWS',      rowOrder: 3 },
}

const EDGE_STYLE: Record<string, { stroke: string; strokeWidth: number }> = {
  linked_to:      { stroke: 'rgba(200,200,255,0.55)', strokeWidth: 1.5 },
  uses_technique: { stroke: 'rgba(0,255,136,0.65)',   strokeWidth: 2   },
  targets:        { stroke: 'rgba(255,68,68,0.65)',    strokeWidth: 2   },
  mentioned_in:   { stroke: 'rgba(0,212,255,0.55)',   strokeWidth: 1.5 },
}

// ── Custom layout: type-grouped rows with even spacing ────────────────────────

function buildLayout(nodes: AiNode[]): Node[] {
  const ROWS = ['actor', 'campaign', 'technique', 'news']
  const H_GAP = 60   // vertical gap between rows
  const W_GAP = 50   // horizontal gap between nodes in same row
  const rowNodes: Record<string, AiNode[]> = {
    actor: [], campaign: [], technique: [], news: [],
  }
  for (const n of nodes) {
    const row = rowNodes[n.type] ?? rowNodes.news
    row.push(n)
  }

  const result: Node[] = []
  let y = 20

  for (const rowType of ROWS) {
    const rn = rowNodes[rowType]
    if (!rn.length) continue
    const rowW = rn.length * NODE_W + (rn.length - 1) * W_GAP
    const startX = -rowW / 2
    for (let i = 0; i < rn.length; i++) {
      const n = rn[i]
      const cfg = NODE_CONFIG[n.type] ?? NODE_CONFIG.news
      result.push({
        id:       n.id,
        type:     'correlationNode',
        position: { x: startX + i * (NODE_W + W_GAP), y },
        data: {
          nodeType:      n.type,
          label:         n.label,
          description:   n.description,
          severity:      n.severity as SeverityLevel | null | undefined,
          verified:      n.verified,
          ai_generated:  n.ai_generated,
          color:         cfg.color,
          confidence:    n.confidence,
          country:       n.country,
          last_seen:     n.last_seen,
          iocs:          n.iocs ?? [],
          techniques:    n.techniques ?? [],
          target_sectors: n.target_sectors ?? [],
          sources:       n.sources ?? [],
          dimmed:        false,
        },
      })
    }
    y += NODE_H + H_GAP
  }

  return result
}

// ── Custom node component ─────────────────────────────────────────────────────

function CorrelationNode({ data }: NodeProps) {
  const cfg   = NODE_CONFIG[data.nodeType] ?? NODE_CONFIG.news
  const Icon  = cfg.icon
  const color = data.severity ? sevColor(data.severity as SeverityLevel) : cfg.color
  const dimmed = data.dimmed

  return (
    <div
      className="relative rounded-sm text-[0.55rem] font-mono select-none transition-all duration-200"
      style={{
        width:       NODE_W,
        minHeight:   NODE_H,
        background:  cfg.bgColor,
        border:      `1px solid ${data.verified ? color : cfg.borderColor}`,
        boxShadow:   data.verified
          ? `0 0 14px ${color}44, inset 0 0 6px ${color}11`
          : `0 0 6px ${cfg.color}22`,
        opacity: dimmed ? 0.25 : 1,
        filter:  dimmed ? 'grayscale(0.5)' : 'none',
      }}
    >
      {/* Type header */}
      <div
        className="flex items-center gap-1 px-2 py-1 border-b"
        style={{ borderColor: `${color}30`, background: `${color}18` }}
      >
        <Icon size={8} style={{ color }} />
        <span className="tracking-widest text-[0.42rem] font-bold" style={{ color }}>
          {cfg.label}
          {data.severity && <span className="ml-1 opacity-70">· {data.severity}</span>}
        </span>
        <div className="ml-auto flex items-center gap-1">
          {data.confidence != null && (
            <span
              className="font-mono text-[0.38rem]"
              style={{
                color: data.confidence >= 75
                  ? 'var(--color-success)'
                  : data.confidence >= 50
                    ? 'var(--color-warning)'
                    : 'var(--color-danger)',
              }}
            >
              {data.confidence}%
            </span>
          )}
          {data.verified
            ? <CheckCircle size={9} style={{ color: 'var(--color-success)' }} />
            : <AlertTriangle size={8} style={{ color: 'rgba(255,170,0,0.6)' }} />}
        </div>
      </div>
      {/* Label */}
      <div
        className="px-2 py-1.5 leading-tight text-[0.6rem]"
        style={{ color: 'var(--text-base)' }}
      >
        {data.label}
      </div>
      {/* Footer chips */}
      <div className="px-2 pb-1.5 flex items-center gap-1 flex-wrap">
        {data.country && (
          <span
            className="font-mono text-[0.38rem] px-1 py-0.5 border"
            style={{ color: cfg.color, borderColor: `${cfg.color}30`, background: `${cfg.color}0d` }}
          >
            {data.country}
          </span>
        )}
        {data.iocs?.length > 0 && (
          <span
            className="font-mono text-[0.38rem] px-1 py-0.5 border border-[rgba(255,170,0,0.3)] bg-[rgba(255,170,0,0.06)]"
            style={{ color: 'rgba(255,170,0,0.9)' }}
          >
            {data.iocs.length} IOC{data.iocs.length > 1 ? 's' : ''}
          </span>
        )}
        {data.last_seen && (
          <span className="font-mono text-[0.38rem] text-[var(--text-ghost)]">
            {data.last_seen}
          </span>
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

  // Find connected neighbors
  const neighbors = useMemo(() => {
    if (!rawData) return []
    const result: { id: string; label: string; type: string }[] = []
    rawData.edges.forEach(e => {
      if (e.source === node.id) {
        const n = rawData.nodes.find(n => n.id === e.target)
        if (n) result.push({ id: n.id, label: n.label, type: n.type })
      } else if (e.target === node.id) {
        const n = rawData.nodes.find(n => n.id === e.source)
        if (n) result.push({ id: n.id, label: n.label, type: n.type })
      }
    })
    // Deduplicate
    return result.filter((v, i, a) => a.findIndex(x => x.id === v.id) === i)
  }, [rawData, node.id])

  return (
    <div
      className="absolute top-3 right-3 z-30 w-72 border bg-[var(--bg-surface)] shadow-2xl overflow-y-auto max-h-[calc(100%-24px)]"
      style={{ borderColor: `${color}55`, borderLeft: `2px solid ${color}` }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-3 py-2 border-b sticky top-0 z-10"
        style={{ borderColor: `${color}33`, background: `var(--bg-surface)` }}
      >
        <div className="flex items-center gap-1.5">
          <cfg.icon size={10} style={{ color }} />
          <span className="font-mono text-[0.48rem] tracking-widest" style={{ color }}>
            {cfg.label}
          </span>
          {node.severity && (
            <span
              className="font-mono text-[0.42rem] px-1 border"
              style={{ color, borderColor: `${color}44`, background: `${color}0d` }}
            >
              {node.severity}
            </span>
          )}
        </div>
        <button onClick={onClose} className="text-[var(--text-ghost)] hover:text-[var(--text-base)] transition-colors">
          <X size={11} />
        </button>
      </div>

      <div className="p-3 space-y-3">
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
                  color: node.confidence >= 75
                    ? 'var(--color-success)'
                    : node.confidence >= 50
                      ? 'var(--color-warning)'
                      : 'var(--color-danger)',
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
                  background: node.confidence >= 75
                    ? 'var(--color-success)'
                    : node.confidence >= 50
                      ? 'var(--color-warning)'
                      : 'var(--color-danger)',
                }}
              />
            </div>
          </div>
        )}

        {/* Description */}
        {node.description && (
          <p className="text-[0.62rem] text-[var(--text-secondary)] leading-relaxed">
            {node.description}
          </p>
        )}

        {/* Meta row */}
        <div className="grid grid-cols-2 gap-1 font-mono text-[0.5rem]">
          {node.country && (
            <div className="border border-[var(--border-base)] px-1.5 py-1">
              <span className="text-[var(--text-ghost)] block text-[0.42rem] tracking-widest mb-0.5">ORIGIN</span>
              <span style={{ color }}>{node.country}</span>
            </div>
          )}
          {node.last_seen && (
            <div className="border border-[var(--border-base)] px-1.5 py-1">
              <span className="text-[var(--text-ghost)] block text-[0.42rem] tracking-widest mb-0.5">LAST SEEN</span>
              <span className="text-[var(--text-secondary)]">{node.last_seen}</span>
            </div>
          )}
          <div className="border border-[var(--border-base)] px-1.5 py-1">
            <span className="text-[var(--text-ghost)] block text-[0.42rem] tracking-widest mb-0.5">CONNECTIONS</span>
            <span className="text-[var(--text-secondary)]">{neighbors.length} nodes</span>
          </div>
          <div className="border border-[var(--border-base)] px-1.5 py-1">
            <span className="text-[var(--text-ghost)] block text-[0.42rem] tracking-widest mb-0.5">VERIFIED</span>
            <span style={{ color: node.verified ? 'var(--color-success)' : 'var(--color-warning)' }}>
              {node.verified ? 'YES' : 'PENDING'}
            </span>
          </div>
        </div>

        {/* Connected nodes */}
        {neighbors.length > 0 && (
          <div>
            <p className="font-mono text-[0.44rem] tracking-widest text-[var(--text-ghost)] mb-1.5">
              CONNECTED NODES ({neighbors.length})
            </p>
            <div className="space-y-0.5">
              {neighbors.map(n => {
                const ncfg = NODE_CONFIG[n.type] ?? NODE_CONFIG.news
                return (
                  <div key={n.id} className="flex items-center gap-1.5 font-mono text-[0.5rem]">
                    <div className="w-1.5 h-1.5 rounded-sm shrink-0" style={{ background: ncfg.color }} />
                    <span className="text-[var(--text-secondary)] truncate">{n.label}</span>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Techniques */}
        {node.techniques && node.techniques.length > 0 && (
          <div>
            <p className="font-mono text-[0.44rem] tracking-widest text-[var(--text-ghost)] mb-1.5">TECHNIQUES</p>
            <div className="flex flex-wrap gap-1">
              {node.techniques.map((t, i) => (
                <span
                  key={i}
                  className="font-mono text-[0.44rem] px-1.5 py-0.5 border border-[rgba(0,255,136,0.25)] text-[var(--color-success)] bg-[rgba(0,255,136,0.05)]"
                >
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
                <span
                  key={i}
                  className="font-mono text-[0.44rem] px-1.5 py-0.5 border border-[rgba(255,68,68,0.25)] text-[var(--color-danger)] bg-[rgba(255,68,68,0.05)]"
                >
                  {s}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* IOCs */}
        {node.iocs && node.iocs.length > 0 && (
          <div>
            <p className="font-mono text-[0.44rem] tracking-widest text-[var(--color-warning)] mb-1.5">
              INDICATORS OF COMPROMISE ({node.iocs.length})
            </p>
            <div className="space-y-0.5 font-mono text-[0.5rem] text-[var(--text-dim)]">
              {node.iocs.map((ioc, i) => (
                <div
                  key={i}
                  className="px-1.5 py-0.5 bg-[rgba(247,147,26,0.05)] border border-[rgba(247,147,26,0.15)] truncate"
                >
                  {ioc}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Source articles */}
        {node.sources && node.sources.length > 0 && (
          <div>
            <p className="font-mono text-[0.44rem] tracking-widest text-[var(--text-ghost)] mb-1.5">
              SOURCE INTELLIGENCE ({node.sources.length})
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
            <CheckCircle size={10} />MARK AS VERIFIED
          </button>
        ) : (
          <div
            className="flex items-center justify-center gap-1.5 px-3 py-1.5 border font-mono text-[0.5rem] tracking-widest"
            style={{ borderColor: 'rgba(0,255,136,0.3)', color: 'var(--color-success)', background: 'rgba(0,255,136,0.06)' }}
          >
            <CheckCircle size={10} />VERIFIED
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
  const [rawData, setRawData]         = useState<AiGraphData | null>(null)
  const [loading, setLoading]         = useState(false)
  const [error, setError]             = useState<string | null>(null)
  const [selectedId, setSelectedId]   = useState<string | null>(null)
  const [verified, setVerified]       = useState<Set<string>>(new Set())
  const [hoursBack, setHoursBack]   = useState(48)
  const fetchedRef  = useRef(false)
  const inFlightRef = useRef(false)

  const fetchAiCorrelation = useCallback(async (force = false) => {
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
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to fetch AI correlation')
    } finally {
      setLoading(false)
      inFlightRef.current = false
    }
  }, [hoursBack])

  // Fetch on mount (once)
  useEffect(() => {
    if (!fetchedRef.current) {
      fetchedRef.current = true
      fetchAiCorrelation()
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Re-fetch when refresh trigger changes (manual refresh)
  useEffect(() => {
    if (fetchedRef.current && refreshTrigger > 0) {
      fetchAiCorrelation(true)
    }
  }, [refreshTrigger]) // eslint-disable-line react-hooks/exhaustive-deps

  // Re-fetch when time window changes
  useEffect(() => {
    if (fetchedRef.current) fetchAiCorrelation()
  }, [hoursBack]) // eslint-disable-line react-hooks/exhaustive-deps

  // Build React Flow graph whenever data or verification state changes
  useEffect(() => {
    if (!rawData?.nodes.length) return

    const aiNodes = rawData.nodes.map(n => ({
      ...n,
      verified: verified.has(n.id),
    }))

    const rfNodes = buildLayout(aiNodes)
    setNodes(rfNodes)

    const rfEdges: Edge[] = rawData.edges.map(e => {
      const eStyle = EDGE_STYLE[e.type] ?? EDGE_STYLE.linked_to
      const isVerified = verified.has(e.source) && verified.has(e.target)
      return {
        id:           e.id,
        source:       e.source,
        target:       e.target,
        label:        e.label || undefined,
        labelStyle:   {
          fill: 'rgba(180,200,220,0.8)',
          fontFamily: '"Share Tech Mono", monospace',
          fontSize: 8,
        },
        labelBgStyle: { fill: 'rgba(6,13,24,0.85)', fillOpacity: 1 },
        style: {
          stroke:          isVerified
            ? eStyle.stroke.replace(/[\d.]+\)$/, '0.9)')
            : eStyle.stroke,
          strokeWidth:     isVerified ? eStyle.strokeWidth + 0.5 : eStyle.strokeWidth,
          strokeDasharray: e.type === 'uses_technique' ? undefined : (e.verified ? undefined : '6 3'),
          filter:          isVerified ? `drop-shadow(0 0 3px ${eStyle.stroke})` : undefined,
        },
        markerEnd: {
          type:   MarkerType.ArrowClosed,
          color:  eStyle.stroke,
          width:  14,
          height: 14,
        },
        animated: e.type === 'uses_technique' || e.type === 'targets',
        type: 'smoothstep',
      }
    })

    setEdges(rfEdges)
  }, [rawData, verified, setNodes, setEdges])

  // When selection changes, dim non-neighbor nodes and highlight connected edges
  useEffect(() => {
    if (!rawData || !selectedId) {
      // Clear all dimming/highlighting
      setNodes(prev => prev.map(n => ({ ...n, data: { ...n.data, dimmed: false, highlighted: false } })))
      setEdges(prev => prev.map(e => ({
        ...e,
        style: { ...e.style, opacity: 1 },
        animated: e.data?.baseAnimated ?? e.animated,
      })))
      return
    }

    // Find neighbor IDs
    const neighborIds = new Set<string>()
    neighborIds.add(selectedId)
    rawData.edges.forEach(e => {
      if (e.source === selectedId) neighborIds.add(e.target)
      if (e.target === selectedId) neighborIds.add(e.source)
    })

    // Dim non-neighbors
    setNodes(prev => prev.map(n => ({
      ...n,
      data: { ...n.data, dimmed: !neighborIds.has(n.id) },
    })))

    // Highlight connected edges, dim others
    setEdges(prev => prev.map(e => {
      const isConnected = e.source === selectedId || e.target === selectedId
      return {
        ...e,
        style: {
          ...e.style,
          opacity: isConnected ? 1 : 0.1,
          strokeWidth: isConnected ? (e.style?.strokeWidth ?? 1.5) * 1.8 : e.style?.strokeWidth,
        },
        animated: isConnected ? true : false,
      }
    }))
  }, [selectedId, rawData]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleVerify    = useCallback((id: string) => setVerified(p => new Set([...p, id])), [])
  const handleVerifyAll = useCallback(() => {
    if (rawData) setVerified(new Set(rawData.nodes.map(n => n.id)))
  }, [rawData])

  const selectedNode   = rawData?.nodes.find(n => n.id === selectedId) ?? null
  const verifiedCount  = rawData?.nodes.filter(n => verified.has(n.id)).length ?? 0
  const totalCount     = rawData?.nodes.length ?? 0
  const edgeCount      = rawData?.edges.length ?? 0

  // Node type summary counts
  const typeCounts = useMemo(() => {
    const acc: Record<string, number> = {}
    rawData?.nodes.forEach(n => { acc[n.type] = (acc[n.type] ?? 0) + 1 })
    return acc
  }, [rawData])

  return (
    <div className="panel flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2 flex-wrap">
          <GitFork size={11} className="text-[var(--color-primary)] shrink-0" />
          <span className="panel-title">AI CORRELATION GRAPH</span>
          {rawData && (
            <>
              <span className="live-dot" />
              <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-widest">
                {totalCount} NODES · {edgeCount} EDGES
              </span>
              {/* Type breakdown */}
              {Object.entries(typeCounts).map(([type, count]) => {
                const cfg = NODE_CONFIG[type]
                return cfg ? (
                  <span
                    key={type}
                    className="font-mono text-[0.42rem] tracking-widest px-1.5 py-0.5 border"
                    style={{ color: cfg.color, borderColor: `${cfg.color}33`, background: `${cfg.color}10` }}
                  >
                    {type.toUpperCase()} ×{count}
                  </span>
                ) : null
              })}
              <span
                className="font-mono text-[0.42rem] tracking-widest px-1.5 py-0.5 border"
                style={{ color: 'var(--color-info)', borderColor: 'rgba(170,68,255,0.3)', background: 'rgba(170,68,255,0.07)' }}
              >
                AI: {rawData.provider.toUpperCase()}
              </span>
            </>
          )}
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          <div className="flex items-center gap-0.5">
            {[24, 48, 72].map(h => (
              <button
                key={h}
                onClick={() => setHoursBack(h)}
                className="font-mono text-[0.46rem] tracking-widest px-1.5 py-0.5 border transition-all"
                style={{
                  color:       hoursBack === h ? 'var(--color-primary)' : 'var(--text-ghost)',
                  borderColor: hoursBack === h ? 'var(--border-accent)' : 'var(--border-base)',
                  background:  hoursBack === h ? 'rgba(0,212,255,0.07)' : 'transparent',
                }}
              >
                {h}H
              </button>
            ))}
          </div>
          {rawData && verifiedCount < totalCount && (
            <button
              onClick={handleVerifyAll}
              className="flex items-center gap-1 px-2 py-0.5 border font-mono text-[0.46rem] tracking-widest transition-colors hover:bg-[rgba(0,255,136,0.08)]"
              style={{ borderColor: 'rgba(0,255,136,0.4)', color: 'var(--color-success)' }}
            >
              <CheckCircle size={8} />
              VERIFY ALL ({totalCount - verifiedCount})
            </button>
          )}
          <button
            onClick={() => fetchAiCorrelation(true)}
            disabled={loading}
            className="flex items-center gap-1 px-2 py-0.5 border border-[var(--border-accent)] font-mono text-[0.46rem] tracking-widest text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.07)] disabled:opacity-40 transition-colors"
          >
            <RefreshCw size={8} className={loading ? 'animate-spin' : ''} />
            {loading ? 'GENERATING...' : 'AI REFRESH'}
          </button>
        </div>
      </div>

      {/* Verification progress */}
      {rawData && totalCount > 0 && (
        <div className="shrink-0 px-3 py-1.5 border-b border-[var(--border-base)] flex items-center gap-2">
          {verifiedCount === totalCount
            ? <CheckCircle size={9} className="text-[var(--color-success)]" />
            : <AlertTriangle size={9} className="text-[var(--color-warning)]" />}
          <span className="font-mono text-[0.46rem] tracking-widest"
            style={{ color: verifiedCount === totalCount ? 'var(--color-success)' : 'var(--color-warning)' }}>
            {verifiedCount === totalCount
              ? 'ALL NODES VERIFIED'
              : `${verifiedCount}/${totalCount} NODES VERIFIED — AI DATA UNCONFIRMED`}
          </span>
          <div className="flex-1 h-1 bg-[var(--bg-elevated)] rounded-full overflow-hidden ml-2">
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{
                width: `${totalCount > 0 ? (verifiedCount / totalCount) * 100 : 0}%`,
                background: verifiedCount === totalCount ? 'var(--color-success)' : 'var(--color-warning)',
              }}
            />
          </div>
          <span className="font-mono text-[0.42rem] text-[var(--text-ghost)] tracking-widest shrink-0">
            CLICK NODES TO VERIFY
          </span>
        </div>
      )}

      {/* Canvas */}
      <div className="flex-1 relative min-h-0">

        {/* Loading */}
        {loading && nodes.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 z-10">
            <div className="relative">
              <RefreshCw size={28} className="text-[var(--color-primary)] animate-spin" />
              <div className="absolute inset-0 animate-ping opacity-20">
                <RefreshCw size={28} className="text-[var(--color-primary)]" />
              </div>
            </div>
            <p className="font-mono text-[0.65rem] text-[var(--text-dim)] tracking-widest">
              AI IS ANALYSING THREAT INTELLIGENCE...
            </p>
            <p className="font-mono text-[0.52rem] text-[var(--text-ghost)] tracking-widest">
              First analysis may take 30–60 s · Results cached for 10 min
            </p>
          </div>
        )}

        {/* Error */}
        {error && !loading && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 z-10 px-8 text-center">
            <AlertTriangle size={28} className="text-[var(--color-warning)]" />
            <p className="font-mono text-[0.65rem] text-[var(--color-danger)] tracking-widest">
              AI CORRELATION FAILED
            </p>
            <p className="font-mono text-[0.58rem] text-[var(--text-muted)] max-w-sm leading-relaxed">
              {error}
            </p>
            <button
              onClick={() => fetchAiCorrelation(true)}
              className="font-mono text-[0.52rem] tracking-widest px-4 py-1.5 border border-[var(--border-accent)] text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.06)] transition-colors"
            >
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
              No high/critical news found. Try extending the time window.
            </p>
          </div>
        )}

        {/* React Flow graph */}
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
            fitViewOptions={{ padding: 0.15 }}
            minZoom={0.15}
            maxZoom={3}
            proOptions={{ hideAttribution: true }}
            defaultEdgeOptions={{ type: 'smoothstep' }}
          >
            <Background
              color="rgba(0,212,255,0.04)"
              gap={28}
              size={1}
            />
            <Controls
              className="border border-[var(--border-base)] bg-[var(--bg-surface)]"
              showInteractive={false}
            />
            <MiniMap
              nodeColor={n => (NODE_CONFIG[n.data?.nodeType as string] ?? NODE_CONFIG.news).color}
              className="border border-[var(--border-base)] bg-[var(--bg-card)]"
              maskColor="rgba(0,0,0,0.7)"
              style={{ width: 160, height: 100 }}
            />
          </ReactFlow>
        )}

        {/* Node detail panel */}
        {selectedId && selectedNode && (
          <DetailPanel
            node={{ ...selectedNode, verified: verified.has(selectedNode.id) }}
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
            <div className="pt-1 border-t border-[var(--border-base)] space-y-0.5">
              <div className="flex items-center gap-1.5">
                <div className="w-5 h-px" style={{ background: EDGE_STYLE.uses_technique.stroke }} />
                <span className="font-mono text-[0.42rem] text-[var(--text-ghost)]">TECHNIQUE</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="w-5 h-px" style={{ background: EDGE_STYLE.targets.stroke, borderTop: '1px dashed' }} />
                <span className="font-mono text-[0.42rem] text-[var(--text-ghost)]">TARGETS</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      {rawData && (
        <div className="shrink-0 px-3 py-1.5 border-t border-[var(--border-base)] flex items-center gap-3 text-[var(--text-ghost)] flex-wrap">
          <span className="font-mono text-[0.42rem] tracking-widest">
            GENERATED: {new Date(rawData.generated_at).toLocaleTimeString()}
          </span>
          <span className="font-mono text-[0.42rem] tracking-widest">
            WINDOW: {rawData.hours_back}H
          </span>
          <span className="font-mono text-[0.42rem] tracking-widest">
            PROVIDER: {rawData.provider.toUpperCase()}
          </span>
          <span className="ml-auto font-mono text-[0.42rem] tracking-widest text-[var(--color-warning)]">
            ⚠ AI-GENERATED DATA — VERIFY BEFORE ACTING
          </span>
        </div>
      )}
    </div>
  )
}
