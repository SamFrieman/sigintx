import { useState, useEffect } from 'react'
import { Clock } from 'lucide-react'

interface Zone {
  id: string
  label: string
  tz: string
  abbr: string
  color: string
}

const ZONES: Zone[] = [
  { id: 'utc',    label: 'UTC',           tz: 'UTC',                   abbr: 'UTC',  color: '#00d4ff' },
  { id: 'nyc',    label: 'NEW YORK',      tz: 'America/New_York',      abbr: 'ET',   color: '#22c55e' },
  { id: 'lon',    label: 'LONDON',        tz: 'Europe/London',         abbr: 'GMT',  color: '#f59e0b' },
  { id: 'dxb',    label: 'DUBAI',         tz: 'Asia/Dubai',            abbr: 'GST',  color: '#a855f7' },
  { id: 'tok',    label: 'TOKYO',         tz: 'Asia/Tokyo',            abbr: 'JST',  color: '#ef4444' },
]

function getTimeInZone(tz: string): { time: string; date: string; isDay: boolean } {
  const now = new Date()
  const timeStr = now.toLocaleTimeString('en-US', {
    timeZone: tz,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
  const dateStr = now.toLocaleDateString('en-US', {
    timeZone: tz,
    weekday: 'short',
    month: 'short',
    day: 'numeric',
  })
  const hour = parseInt(
    now.toLocaleString('en-US', { timeZone: tz, hour: 'numeric', hour12: false }),
    10,
  )
  return { time: timeStr, date: dateStr, isDay: hour >= 6 && hour < 20 }
}

function ClockCard({ zone, now }: { zone: Zone; now: Date }) {
  const { time, date, isDay } = getTimeInZone(zone.tz)
  const [hh, mm, ss] = time.split(':').map(Number)
  const secDeg  = ss * 6
  const minDeg  = mm * 6 + ss * 0.1
  const hourDeg = (hh % 12) * 30 + mm * 0.5

  return (
    <div className="flex items-center gap-3 px-4 py-3 border-b border-[var(--border-base)] last:border-b-0">
      {/* Analog mini-clock */}
      <div className="shrink-0 relative" style={{ width: 36, height: 36 }}>
        <svg width="36" height="36" viewBox="0 0 36 36">
          {/* Face */}
          <circle cx="18" cy="18" r="17" fill="none" stroke={`${zone.color}22`} strokeWidth="1.5" />
          <circle cx="18" cy="18" r="17" fill="none" stroke={zone.color} strokeWidth="0.5" opacity="0.4" />
          {/* Hour hand */}
          <line
            x1="18" y1="18"
            x2={18 + 8 * Math.sin((hourDeg * Math.PI) / 180)}
            y2={18 - 8 * Math.cos((hourDeg * Math.PI) / 180)}
            stroke={zone.color} strokeWidth="2" strokeLinecap="round"
          />
          {/* Minute hand */}
          <line
            x1="18" y1="18"
            x2={18 + 12 * Math.sin((minDeg * Math.PI) / 180)}
            y2={18 - 12 * Math.cos((minDeg * Math.PI) / 180)}
            stroke={zone.color} strokeWidth="1.5" strokeLinecap="round" opacity="0.9"
          />
          {/* Second hand */}
          <line
            x1="18" y1="20"
            x2={18 + 14 * Math.sin((secDeg * Math.PI) / 180)}
            y2={18 - 14 * Math.cos((secDeg * Math.PI) / 180)}
            stroke="#ff4444" strokeWidth="0.8" strokeLinecap="round"
          />
          {/* Center dot */}
          <circle cx="18" cy="18" r="1.5" fill={zone.color} />
        </svg>
      </div>

      {/* Text info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5 mb-0.5">
          <span
            className="font-mono text-[0.52rem] tracking-widest font-semibold"
            style={{ color: zone.color }}
          >
            {zone.label}
          </span>
          <span
            className="font-mono text-[0.42rem] px-1 py-0.5 border"
            style={{ color: zone.color, borderColor: `${zone.color}44`, background: `${zone.color}11` }}
          >
            {zone.abbr}
          </span>
          <span className="text-[0.5rem]">{isDay ? '☀️' : '🌙'}</span>
        </div>
        <div className="font-mono text-[0.58rem] text-[var(--text-dim)]">{date}</div>
      </div>

      {/* Digital time */}
      <div
        className="font-mono text-[0.95rem] tabular-nums tracking-wider shrink-0"
        style={{ color: zone.color }}
      >
        {time}
      </div>
    </div>
  )
}

export function WorldClocks({ compact }: { compact?: boolean }) {
  const [now, setNow] = useState(new Date())

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  if (compact) {
    return (
      <div className="panel flex flex-col h-full">
        <div className="panel-header shrink-0">
          <div className="flex items-center gap-2">
            <Clock size={11} className="text-[var(--color-primary)]" />
            <span className="panel-title">WORLD CLOCKS</span>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto min-h-0 divide-y divide-[var(--border-base)]">
          {ZONES.map(zone => {
            const { time, isDay } = getTimeInZone(zone.tz)
            return (
              <div key={zone.id} className="flex items-center justify-between px-3 py-1.5">
                <div className="flex items-center gap-1.5">
                  <span className="text-[0.5rem]">{isDay ? '☀' : '☽'}</span>
                  <span className="font-mono text-[0.5rem] tracking-widest" style={{ color: zone.color }}>{zone.abbr}</span>
                </div>
                <span className="font-mono text-[0.72rem] tabular-nums tracking-wider" style={{ color: zone.color }}>{time}</span>
              </div>
            )
          })}
        </div>
      </div>
    )
  }

  return (
    <div className="panel flex flex-col h-full">
      {/* Header */}
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <Clock size={11} className="text-[var(--color-primary)]" />
          <span className="panel-title">WORLD CLOCKS</span>
        </div>
        <span className="font-mono text-[0.5rem] text-[var(--text-ghost)] tracking-widest">
          5 ZONES
        </span>
      </div>

      {/* Clocks */}
      <div className="flex-1 overflow-y-auto min-h-0">
        {ZONES.map(zone => (
          <ClockCard key={zone.id} zone={zone} now={now} />
        ))}
      </div>

      <div className="px-4 py-1.5 border-t border-[var(--border-base)] shrink-0">
        <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-widest">
          UTC · ET · GMT · GST · JST
        </span>
      </div>
    </div>
  )
}
