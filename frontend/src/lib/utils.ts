import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { formatDistanceToNow, parseISO } from 'date-fns'
import type { SeverityLevel } from '@/types'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function timeAgo(iso: string | null): string {
  if (!iso) return 'unknown'
  try {
    // Backend stores naive UTC — append Z so date-fns treats it as UTC, not local time
    const normalized = /[Z+\-]\d*$/.test(iso) ? iso : iso + 'Z'
    return formatDistanceToNow(parseISO(normalized), { addSuffix: true })
  } catch {
    return 'unknown'
  }
}

export function sevColor(sev: SeverityLevel): string {
  switch (sev) {
    case 'CRITICAL': return '#ff2255'
    case 'HIGH':     return '#ffaa00'
    case 'MEDIUM':   return '#00d4ff'
    case 'INFO':     return '#00ff88'
  }
}

export function sevBg(sev: SeverityLevel): string {
  switch (sev) {
    case 'CRITICAL': return 'rgba(255,34,85,0.12)'
    case 'HIGH':     return 'rgba(255,170,0,0.10)'
    case 'MEDIUM':   return 'rgba(0,212,255,0.08)'
    case 'INFO':     return 'rgba(0,255,136,0.08)'
  }
}

export function sevBorder(sev: SeverityLevel): string {
  switch (sev) {
    case 'CRITICAL': return 'rgba(255,34,85,0.35)'
    case 'HIGH':     return 'rgba(255,170,0,0.30)'
    case 'MEDIUM':   return 'rgba(0,212,255,0.25)'
    case 'INFO':     return 'rgba(0,255,136,0.20)'
  }
}

export function cvssColor(score: number | null): string {
  if (!score) return '#6888aa'
  if (score >= 9) return '#ff2255'
  if (score >= 7) return '#ffaa00'
  if (score >= 4) return '#00d4ff'
  return '#00ff88'
}

export function countryFlag(country: string | null): string {
  const map: Record<string, string> = {
    'Russia':        '🇷🇺',
    'China':         '🇨🇳',
    'North Korea':   '🇰🇵',
    'Iran':          '🇮🇷',
    'United States': '🇺🇸',
    'Israel':        '🇮🇱',
    'Vietnam':       '🇻🇳',
    'Unknown':       '🌐',
  }
  return country ? (map[country] ?? '🌐') : '🌐'
}
