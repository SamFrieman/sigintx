import { useState, useCallback, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ChevronDown, ChevronUp, ExternalLink, Clock, Sparkles, Target, Shield, AlertTriangle, RefreshCw } from 'lucide-react'
import { useApi } from '@/hooks/useApi'
import { sevColor, sevBg, sevBorder, timeAgo } from '@/lib/utils'
import type { SeverityLevel } from '@/types'

interface TimelineEvent {
  id: number
  title: string
  severity: SeverityLevel
  published_at: string | null
  source: string
  url: string
}

interface Campaign {
  actor: string
  top_severity: SeverityLevel
  news_count: number
  cve_count: number
  cves: string[]
  first_seen: string | null
  last_seen: string | null
  timeline: TimelineEvent[]
}

interface HiddenCampaign {
  name: string
  confidence: 'HIGH' | 'MEDIUM' | 'LOW'
  description: string
  suspected_actor: string | null
  techniques: string[]
  targeted_sectors: string[]
  key_indicators: string[]
  severity: SeverityLevel
  news_titles: string[]
}

interface AiDiscoverResult {
  campaigns: HiddenCampaign[]
  analysis_summary: string
  provider: string
  generated_at: string
  days_back: number
  news_analyzed: number
}

interface Props { refreshTrigger: number }

const EVENTS_PER_PAGE = 10

/** Format an ISO date string as a UTC local date, avoiding TZ shift. */
function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  try {
    const normalized = /[Z+\-]\d*$/.test(iso) ? iso : iso + 'Z'
    return new Date(normalized).toLocaleDateString(undefined, {
      year:  'numeric',
      month: 'short',
      day:   'numeric',
      timeZone: 'UTC',
    })
  } catch {
    return '—'
  }
}

function CampaignCard({ camp }: { camp: Campaign }) {
  const [expanded,     setExpanded]    = useState(false)
  const [visibleCount, setVisibleCount] = useState(EVENTS_PER_PAGE)

  const shownEvents = camp.timeline.slice(0, visibleCount)
  const hasMore     = visibleCount < camp.timeline.length

  return (
    <motion.div layout className="border border-[var(--border-base)] bg-[var(--bg-card)] mb-2">
      {/* Card header */}
      <button
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-[var(--bg-card-hover)] transition-colors text-left"
        onClick={() => setExpanded(e => !e)}
      >
        {/* Severity bar */}
        <div
          className="w-0.5 self-stretch rounded shrink-0"
          style={{ background: sevColor(camp.top_severity), minHeight: 32 }}
        />

        {/* Actor name */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className="font-mono text-[0.7rem] tracking-wide uppercase"
              style={{ color: 'var(--color-info)' }}
            >
              {camp.actor}
            </span>
            <span
              className="font-mono text-[0.52rem] tracking-widest px-1.5 py-0.5 border"
              style={{ color: sevColor(camp.top_severity), background: sevBg(camp.top_severity), borderColor: sevBorder(camp.top_severity) }}
            >
              {camp.top_severity}
            </span>
          </div>
          <div className="flex items-center gap-3 mt-0.5 flex-wrap">
            <span className="font-mono text-[0.58rem] text-[var(--text-dim)]">
              {camp.news_count} events
            </span>
            {camp.cve_count > 0 && (
              <span className="font-mono text-[0.58rem] text-[var(--color-primary)]">
                {camp.cve_count} CVEs
              </span>
            )}
            {camp.last_seen && (
              <span className="font-mono text-[0.55rem] text-[var(--text-ghost)]">
                last seen {timeAgo(camp.last_seen)}
              </span>
            )}
          </div>
        </div>

        {/* CVE pills */}
        <div className="hidden md:flex flex-wrap gap-1 max-w-[220px]">
          {camp.cves.slice(0, 3).map(cve => (
            <span key={cve} className="cve-chip text-[0.52rem]">{cve}</span>
          ))}
          {camp.cves.length > 3 && (
            <span className="font-mono text-[0.52rem] text-[var(--text-ghost)]">+{camp.cves.length - 3}</span>
          )}
        </div>

        <div className="shrink-0 text-[var(--text-dim)]">
          {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        </div>
      </button>

      {/* Timeline events */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="border-t border-[var(--border-base)] px-4 py-3">
              {/* Date range — UTC-normalised */}
              {camp.first_seen && camp.last_seen && (
                <div className="flex items-center gap-1.5 mb-3 text-[var(--text-dim)]">
                  <Clock size={10} />
                  <span className="font-mono text-[0.55rem] tracking-wide">
                    CAMPAIGN WINDOW: {fmtDate(camp.first_seen)} — {fmtDate(camp.last_seen)}
                  </span>
                </div>
              )}

              {/* CVEs */}
              {camp.cves.length > 0 && (
                <div className="flex flex-wrap gap-1 mb-3">
                  {camp.cves.map(cve => (
                    <a
                      key={cve}
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="cve-chip text-[0.55rem] hover:opacity-80 transition-opacity"
                    >
                      {cve} ↗
                    </a>
                  ))}
                </div>
              )}

              {/* Paginated events */}
              <div className="relative">
                <div className="absolute left-[7px] top-2 bottom-2 w-px bg-[var(--border-base)]" />
                <div className="flex flex-col gap-2 pl-5">
                  {shownEvents.map(ev => (
                    <div key={ev.id} className="relative">
                      <div
                        className="absolute -left-[18px] top-[5px] w-2 h-2 rounded-full border"
                        style={{ background: sevBg(ev.severity), borderColor: sevColor(ev.severity) }}
                      />
                      <div>
                        <a
                          href={ev.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-heading text-[0.82rem] text-[var(--text-base)] hover:text-[var(--color-primary)] leading-snug flex items-start gap-1"
                        >
                          {ev.title}
                          <ExternalLink size={9} className="shrink-0 mt-1 opacity-60" />
                        </a>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="font-mono text-[0.52rem] text-[var(--text-dim)]">{ev.source}</span>
                          <span className="font-mono text-[0.5rem] text-[var(--text-ghost)]">{timeAgo(ev.published_at)}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Show-more for long timelines */}
              {hasMore && (
                <button
                  onClick={e => { e.stopPropagation(); setVisibleCount(c => c + EVENTS_PER_PAGE) }}
                  className="mt-3 w-full py-1.5 font-mono text-[0.52rem] tracking-widest text-[var(--text-dim)] hover:text-[var(--color-primary)] border border-[var(--border-base)] hover:border-[var(--border-accent)] transition-colors"
                >
                  SHOW MORE ({camp.timeline.length - visibleCount} remaining)
                </button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

const CONFIDENCE_COLOR = { HIGH: 'var(--color-danger)', MEDIUM: 'var(--color-warning)', LOW: 'var(--color-primary)' }

function HiddenCampaignCard({ camp }: { camp: HiddenCampaign }) {
  const [expanded, setExpanded] = useState(false)
  const confColor = CONFIDENCE_COLOR[camp.confidence]

  return (
    <motion.div layout className="border border-[var(--border-base)] bg-[var(--bg-card)] mb-2">
      <button
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-[var(--bg-card-hover)] transition-colors text-left"
        onClick={() => setExpanded(e => !e)}
      >
        {/* Severity bar */}
        <div
          className="w-0.5 self-stretch rounded shrink-0"
          style={{ background: sevColor(camp.severity), minHeight: 32 }}
        />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-[0.68rem] tracking-wide" style={{ color: 'var(--color-warning)' }}>
              {camp.name}
            </span>
            <span
              className="font-mono text-[0.5rem] tracking-widest px-1.5 py-0.5 border"
              style={{ color: sevColor(camp.severity), background: sevBg(camp.severity), borderColor: sevBorder(camp.severity) }}
            >
              {camp.severity}
            </span>
            <span
              className="font-mono text-[0.48rem] tracking-widest px-1 py-0.5 border"
              style={{ color: confColor, borderColor: `${confColor}44`, background: `${confColor}10` }}
            >
              {camp.confidence} CONFIDENCE
            </span>
          </div>
          <div className="flex items-center gap-3 mt-0.5 flex-wrap">
            {camp.suspected_actor && camp.suspected_actor.toLowerCase() !== 'null' && (
              <span className="font-mono text-[0.56rem]" style={{ color: 'var(--color-info)' }}>
                suspect: {camp.suspected_actor}
              </span>
            )}
            {camp.targeted_sectors.length > 0 && (
              <span className="font-mono text-[0.54rem] text-[var(--text-dim)]">
                targets: {camp.targeted_sectors.slice(0, 3).join(', ')}
              </span>
            )}
          </div>
        </div>

        <div className="shrink-0 text-[var(--text-dim)]">
          {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        </div>
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="border-t border-[var(--border-base)] px-4 py-3 space-y-3">
              {/* Description */}
              <p className="text-[0.74rem] text-[var(--text-muted)] leading-relaxed">{camp.description}</p>

              {/* Techniques */}
              {camp.techniques.length > 0 && (
                <div>
                  <div className="flex items-center gap-1 mb-1.5">
                    <Shield size={9} className="text-[var(--color-primary)]" />
                    <span className="font-mono text-[0.5rem] tracking-widest text-[var(--text-ghost)]">TECHNIQUES</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {camp.techniques.map((t, i) => (
                      <span key={i} className="font-mono text-[0.52rem] px-1.5 py-0.5 border border-[var(--border-base)] text-[var(--text-dim)]">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Key indicators */}
              {camp.key_indicators.length > 0 && (
                <div>
                  <div className="flex items-center gap-1 mb-1.5">
                    <Target size={9} className="text-[var(--color-warning)]" />
                    <span className="font-mono text-[0.5rem] tracking-widest text-[var(--text-ghost)]">KEY INDICATORS</span>
                  </div>
                  <div className="flex flex-col gap-0.5">
                    {camp.key_indicators.map((ind, i) => (
                      <span key={i} className="font-mono text-[0.55rem] text-[var(--text-dim)]">• {ind}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* Supporting articles */}
              {camp.news_titles.length > 0 && (
                <div>
                  <div className="flex items-center gap-1 mb-1.5">
                    <AlertTriangle size={9} className="text-[var(--text-ghost)]" />
                    <span className="font-mono text-[0.5rem] tracking-widest text-[var(--text-ghost)]">SUPPORTING INTEL</span>
                  </div>
                  <div className="flex flex-col gap-0.5 pl-2 border-l border-[var(--border-base)]">
                    {camp.news_titles.map((t, i) => (
                      <span key={i} className="text-[0.67rem] text-[var(--text-muted)] leading-snug">{t}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

export function CampaignTimeline({ refreshTrigger }: Props) {
  const [daysBack, setDaysBack] = useState(30)
  const [activeView, setActiveView] = useState<'known' | 'hidden'>('known')
  const [aiResult, setAiResult] = useState<AiDiscoverResult | null>(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState<string | null>(null)

  const { data: campaigns, loading, error } = useApi<Campaign[]>(
    '/campaigns', { days_back: daysBack }, refreshTrigger, 300_000
  )

  const discoverHidden = useCallback(async () => {
    setAiLoading(true)
    setAiError(null)
    try {
      const res = await fetch(`/api/v1/campaigns/ai-discover?days_back=${daysBack}`, { method: 'POST' })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail ?? `HTTP ${res.status}`)
      }
      setAiResult(await res.json())
    } catch (e) {
      setAiError(e instanceof Error ? e.message : String(e))
    } finally {
      setAiLoading(false)
    }
  }, [daysBack])

  // When days window changes while on the AI view, invalidate and re-fetch
  useEffect(() => {
    if (activeView === 'hidden') {
      setAiResult(null)
      setAiError(null)
      discoverHidden()
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [daysBack])

  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-header shrink-0 flex-col gap-2">
        <div className="flex items-center justify-between w-full">
          <div className="flex items-center gap-2">
            <Clock size={13} className="text-[var(--color-primary)]" />
            <span className="panel-title">CAMPAIGN TIMELINES</span>
            {campaigns && (
              <span className="font-mono text-[0.55rem] text-[var(--text-ghost)]">[{campaigns.length} actors]</span>
            )}
          </div>
          <div className="flex items-center gap-1">
            {[7, 14, 30, 60].map(d => (
              <button key={d} onClick={() => setDaysBack(d)}
                className="font-mono text-[0.52rem] tracking-wider px-1.5 py-0.5 border transition-all"
                style={{
                  color:       daysBack === d ? 'var(--color-primary)' : 'var(--text-ghost)',
                  background:  daysBack === d ? 'rgba(0,212,255,0.08)' : 'transparent',
                  borderColor: daysBack === d ? 'var(--border-accent)' : 'var(--border-base)',
                }}
              >
                {d}D
              </button>
            ))}
          </div>
        </div>

        {/* View toggle */}
        <div className="flex items-center gap-1 w-full">
          <button
            onClick={() => setActiveView('known')}
            className="flex items-center gap-1 font-mono text-[0.52rem] tracking-wider px-2 py-1 border transition-all"
            style={{
              color:       activeView === 'known' ? 'var(--color-primary)' : 'var(--text-ghost)',
              background:  activeView === 'known' ? 'rgba(0,212,255,0.08)' : 'transparent',
              borderColor: activeView === 'known' ? 'var(--border-accent)' : 'var(--border-base)',
            }}
          >
            <Clock size={8} />
            KNOWN ACTORS
          </button>
          <button
            onClick={() => { setActiveView('hidden'); if (!aiResult && !aiLoading) discoverHidden() }}
            className="flex items-center gap-1 font-mono text-[0.52rem] tracking-wider px-2 py-1 border transition-all"
            style={{
              color:       activeView === 'hidden' ? 'var(--color-warning)' : 'var(--text-ghost)',
              background:  activeView === 'hidden' ? 'rgba(255,170,0,0.08)' : 'transparent',
              borderColor: activeView === 'hidden' ? 'rgba(255,170,0,0.4)' : 'var(--border-base)',
            }}
          >
            <Sparkles size={8} />
            AI DISCOVER
          </button>
          {activeView === 'hidden' && (aiResult || aiError) && (
            <button
              onClick={discoverHidden}
              disabled={aiLoading}
              className="ml-auto p-1 text-[var(--text-ghost)] hover:text-[var(--color-warning)] transition-colors disabled:opacity-40"
              title="Re-run analysis"
            >
              <RefreshCw size={11} className={aiLoading ? 'animate-spin' : ''} />
            </button>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto min-h-0 px-3 py-3">
        {/* ── KNOWN ACTORS VIEW ── */}
        {activeView === 'known' && (
          <>
            {error && (
              <div className="flex items-center justify-center h-32 font-mono text-[0.62rem] text-[var(--color-danger)] tracking-widest">
                FAILED TO LOAD — {error}
              </div>
            )}
            {loading && !campaigns && !error && (
              <div className="flex items-center justify-center h-32 font-mono text-[0.65rem] text-[var(--text-ghost)] tracking-widest animate-pulse">
                RECONSTRUCTING CAMPAIGNS...
              </div>
            )}
            {!loading && !error && campaigns?.length === 0 && (
              <div className="flex flex-col items-center justify-center h-48 gap-3 text-center">
                <Clock size={28} className="text-[var(--text-ghost)]" />
                <div>
                  <p className="font-mono text-[0.65rem] text-[var(--text-ghost)] tracking-widest mb-1">
                    NO CAMPAIGNS IN {daysBack}D WINDOW
                  </p>
                  <p className="text-[0.7rem] text-[var(--text-muted)] max-w-xs leading-relaxed">
                    Campaigns are built from news items that mention known threat actors.
                    Try a wider window or wait for more threat intelligence to be collected.
                  </p>
                </div>
              </div>
            )}
            {campaigns?.map(c => <CampaignCard key={c.actor} camp={c} />)}
          </>
        )}

        {/* ── AI DISCOVER VIEW ── */}
        {activeView === 'hidden' && (
          <>
            {aiLoading && (
              <div className="flex flex-col items-center justify-center h-48 gap-3">
                <Sparkles size={24} className="text-[var(--color-warning)] animate-pulse" />
                <div className="text-center">
                  <p className="font-mono text-[0.65rem] text-[var(--color-warning)] tracking-widest animate-pulse mb-1">
                    ANALYSING THREAT PATTERNS...
                  </p>
                  <p className="text-[0.66rem] text-[var(--text-ghost)]">LLM scanning {daysBack}d of intelligence for hidden campaigns</p>
                </div>
              </div>
            )}

            {aiError && !aiLoading && (
              <div className="flex flex-col items-center justify-center h-32 gap-2">
                <p className="font-mono text-[0.62rem] text-[var(--color-danger)] tracking-widest">AI ANALYSIS FAILED</p>
                <p className="text-[0.66rem] text-[var(--text-muted)]">{aiError}</p>
                <button
                  onClick={discoverHidden}
                  className="mt-2 font-mono text-[0.52rem] tracking-widest px-3 py-1.5 border border-[var(--border-accent)] text-[var(--color-primary)] hover:bg-[rgba(0,212,255,0.08)] transition-colors"
                >
                  RETRY
                </button>
              </div>
            )}

            {!aiLoading && !aiError && aiResult && (
              <>
                {/* Summary bar */}
                <div className="mb-3 px-3 py-2 border border-[rgba(255,170,0,0.2)] bg-[rgba(255,170,0,0.05)]">
                  <div className="flex items-center gap-2 mb-1">
                    <Sparkles size={9} className="text-[var(--color-warning)]" />
                    <span className="font-mono text-[0.5rem] tracking-widest text-[var(--color-warning)]">AI THREAT ANALYSIS</span>
                    <span className="font-mono text-[0.48rem] text-[var(--text-ghost)] ml-auto">
                      {aiResult.news_analyzed} articles • {aiResult.days_back}d window
                    </span>
                  </div>
                  {aiResult.analysis_summary && (
                    <p className="text-[0.7rem] text-[var(--text-muted)] leading-relaxed">{aiResult.analysis_summary}</p>
                  )}
                </div>

                {aiResult.campaigns.length === 0 && (
                  <div className="flex flex-col items-center justify-center h-32 gap-2 text-center">
                    <Sparkles size={24} className="text-[var(--text-ghost)]" />
                    <p className="font-mono text-[0.62rem] text-[var(--text-ghost)] tracking-widest">NO HIDDEN CAMPAIGNS DETECTED</p>
                    <p className="text-[0.66rem] text-[var(--text-muted)] max-w-xs">The AI found no clearly coordinated patterns in the current window.</p>
                  </div>
                )}

                {aiResult.campaigns.map((c, i) => (
                  <HiddenCampaignCard key={i} camp={c} />
                ))}
              </>
            )}

            {!aiLoading && !aiError && !aiResult && (
              <div className="flex flex-col items-center justify-center h-48 gap-3 text-center">
                <Sparkles size={28} className="text-[var(--text-ghost)]" />
                <div>
                  <p className="font-mono text-[0.65rem] text-[var(--text-ghost)] tracking-widest mb-1">AI CAMPAIGN DISCOVERY</p>
                  <p className="text-[0.7rem] text-[var(--text-muted)] max-w-xs leading-relaxed">
                    Uses LLM analysis to find hidden campaigns in unattributed threat intelligence data.
                  </p>
                </div>
                <button
                  onClick={discoverHidden}
                  className="font-mono text-[0.52rem] tracking-widest px-4 py-2 border border-[rgba(255,170,0,0.4)] text-[var(--color-warning)] hover:bg-[rgba(255,170,0,0.08)] transition-colors"
                >
                  RUN ANALYSIS
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
