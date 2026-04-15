export type NewsCategory = 'security' | 'tech' | 'crypto' | 'politics' | 'ai'

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO'

export type CVEStatusValue = 'open' | 'investigating' | 'patched' | 'accepted'

export interface CVEItem {
  id: number
  cve_id: string
  description: string | null
  cvss_score: number | null
  cvss_vector: string | null
  severity: SeverityLevel
  in_kev: boolean
  epss_score: number | null
  priority_score: number | null
  published_at: string | null
  affected_products: string[]
  tags: string[]
  threat_actors: string[]
}

export interface IOCItem {
  id: number
  ioc_type: string
  value: string
  malware_family: string | null
  source: string
  confidence: number | null
  first_seen: string | null
  fetched_at: string
  tags: string | null
}

export interface NewsItem {
  id: number
  title: string
  url: string
  source: string
  summary: string | null
  published_at: string | null
  severity: SeverityLevel
  tags: string[]
  threat_actors: string[]
  cve_refs: string[]
  category: NewsCategory
}

export interface ThreatLevel {
  level: 1 | 2 | 3 | 4 | 5
  label: 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'GUARDED' | 'LOW'
  description: string
  critical_news_24h: number
  high_news_24h: number
  active_actors_7d: number
  score: number
  updated_at: string
}

export type ActivityStatus = 'active' | 'resurged' | 'dormant'

export interface ThreatActor {
  id: number
  name: string
  aliases: string[]
  mitre_id: string | null
  country: string | null
  description: string | null
  motivation: string | null
  techniques: string[]
  last_activity: string | null
  activity_status: ActivityStatus | null
}

export interface Stats {
  news_total: number
  threat_actors: number
  critical_news: number
  ws_connections: number
}

export interface WSMessage {
  type: 'connected' | 'rss_update' | 'ping' | 'briefing_ready'
  new_items?: number
  message?: string
}

// ── Correlation Graph ────────────────────────────────────────────────────────
export interface GraphNode {
  id: string
  node_type: 'news' | 'actor' | 'campaign' | 'technique' | 'target'
  label: string
  severity?: SeverityLevel
  published_at?: string | null
  description?: string | null
  verified?: boolean
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  type: 'mentions_actor' | 'linked_to' | 'uses_technique' | 'targets'
  label?: string
  verified?: boolean
}

export interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

// ── Ollama ───────────────────────────────────────────────────────────────────
export interface OllamaChunk {
  text: string
  done: boolean
}

export type AnalyzeTarget =
  | { type: 'news'; item: NewsItem }
  | { type: 'cve'; item: CVEItem }

// ── AI Analyst ───────────────────────────────────────────────────────────────
export interface AiBriefing {
  id: number
  generated_at: string
  model_used: string
  news_count: number
  cve_count: number
  top_severity: SeverityLevel
  threat_actors: string[]
  content?: string
}

export interface AiStatus {
  ollama_reachable: boolean
  ollama_host: string
  available_models: string[]
  context: {
    news_24h: number
    critical_24h: number
    active_actors: string[]
  }
}

export interface AgentStep {
  type: 'tool_call' | 'tool_result'
  name: string
  args?: Record<string, unknown>
  text?: string
}

export interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  streaming?: boolean
  timestamp: Date
  steps?: AgentStep[]
  agentMode?: boolean
}
