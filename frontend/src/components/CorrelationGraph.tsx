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
}

interface AiEdge {
  id: string
  source: string
  target: string
  label: string
  type: string
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
          nodeType:    n.type,
          label:       n.label,
          description: n.description,
         severity:     n.severity as SeverityLevel | null | undefined,
          verified:    n.verified,
          ai_generated: n.ai_generated,
          color:       cfg.color,
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

  return (
    <div
      className="relative rounded-sm text-[0.55rem] font-mono select-none"
      style={{
        width:       NODE_W,
        minHeight:   NODE_H,
        background:  cfg.bgColor,
        border:      `1px solid ${data.verified ? color : cfg.borderColor}`,
        boxShadow:   data.verified
          ? `0 0 14px ${color}44, inset 0 0 6px ${color}11`
          : `0 0 6px ${cfg.color}22`,
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
        <div className="ml-auto">
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
    </div>
  )
}

const NODE_TYPES = { correlationNode: CorrelationNode }

// ── Detail panel ──────────────────────────────────────────────────────────────

function DetailPanel({
  node, onClose, onVerify,
}: { node: AiNode; onClose: () => void; onVerify: (id: string) => void }) {
  const cfg   = NODE_CONFIG[node.type] ?? NODE_CONFIG.news
  const color = node.severity ? sevColor(node.severity as SeverityLevel) : cfg.color

  return (
    <div
      className="absolute top-3 right-3 z-30 w-64 border bg-[var(--bg-surface)] shadow-2xl"
      style={{ borderColor: `${color}55`, borderLeft: `2px solid ${color}` }}
    >
      <div
        className="flex items-center justify-between px-3 py-2 border-b"
        style={{ borderColor: `${color}33`, background: `${color}10` }}
      >
        <div className="flex items-center gap-1.5">
          <cfg.icon size={10} style={{ color }} />
          <span className="font-mono text-[0.48rem] tracking-widest" style={{ color }}>
            {cfg.label}
          </span>
        </div>
        <button onClick={onClose} className="text-[var(--text-ghost)] hover:text-[var(--text-base)] transition-colors">
          <X size={11} />
        </button>
      </div>

      <div className="p-3 space-y-3">
        <p className="font-mono text-[0.65rem] text-[var(--text-base)] leading-snug font-semibold">
          {node.label}
        </p>
        {node.description && (
          <p className="text-[0.62rem] text-[var(--text-secondary)] leading-relaxed">
            {node.description}
          </p>
        )}
        <div className="space-y-1 font-mono text-[0.55rem]">
          {node.severity && (
            <div className="flex justify-between">
              <span className="text-[var(--text-dim)]">SEVERITY</span>
              <span style={{ color }}>{node.severity}</span>
            </div>
          )}
          <div className="flex justify-between">
            <span className="text-[var(--text-dim)]">VERIFIED</span>
            <span style={{ color: node.verified ? 'var(--color-success)' : 'var(--color-warning)' }}>
              {node.verified ? 'YES' : 'PENDING'}
            </span>
          </div>
        </div>
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
      const url = `/api/v1/correlation/ai?hours_back=${hoursBack}${force ? '&force_refresh=true' : ''}`
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${localStorage.getItem('sigintx_token') ?? ''}` },
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail ?? `HTTP ${res.status}`)
      }
      const data: AiGraphData = await res.json()
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
