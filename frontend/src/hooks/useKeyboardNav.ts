/**
 * Global keyboard navigation hook for SIGINTX.
 * Implements a "leader key" pattern: g + <key> navigates to a tab.
 * Also handles /, ?, r, Escape shortcuts.
 */
import { useState, useEffect, useRef, useCallback } from 'react'

interface UseKeyboardNavProps {
  onNavigate: (tab: string) => void
  onRefresh:  () => void
}

// Map second key → tab name
const GOTO_MAP: Record<string, string> = {
  d: 'dashboard',
  n: 'news',
  c: 'cves',
  a: 'actors',
  r: 'graph',
  t: 'campaigns',
  m: 'map',
  i: 'iocs',
  x: 'analyst',
  s: 'settings',
  w: 'watchlists',
  u: 'rules',
}

function isTyping(e: KeyboardEvent): boolean {
  const el = e.target as HTMLElement
  if (!el) return false
  const tag = el.tagName.toLowerCase()
  if (tag === 'input' || tag === 'textarea' || tag === 'select') return true
  if (el.isContentEditable) return true
  return false
}

export function useKeyboardNav({ onNavigate, onRefresh }: UseKeyboardNavProps): {
  showHelp: boolean
  setShowHelp: (v: boolean) => void
} {
  const [showHelp, setShowHelp] = useState(false)

  // Track whether we are in "leader key" mode (g was pressed)
  const leaderActive  = useRef(false)
  const leaderTimeout = useRef<ReturnType<typeof setTimeout> | null>(null)

  const clearLeader = useCallback(() => {
    leaderActive.current = false
    if (leaderTimeout.current) {
      clearTimeout(leaderTimeout.current)
      leaderTimeout.current = null
    }
  }, [])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Never fire when typing in form fields
      if (isTyping(e)) return

      const key = e.key

      // --- Leader key sequence: g + <char> ---
      if (leaderActive.current) {
        clearLeader()
        if (key in GOTO_MAP) {
          e.preventDefault()
          onNavigate(GOTO_MAP[key])
        }
        return
      }

      // --- Single-key shortcuts ---
      switch (key) {
        case 'g':
          // Enter leader mode; wait 1000ms for second key
          e.preventDefault()
          leaderActive.current = true
          leaderTimeout.current = setTimeout(() => {
            leaderActive.current = false
            leaderTimeout.current = null
          }, 1000)
          break

        case '/':
          e.preventDefault()
          document.dispatchEvent(new CustomEvent('sigintx:focussearch'))
          break

        case '?':
          e.preventDefault()
          setShowHelp(prev => !prev)
          break

        case 'r':
          if (!e.ctrlKey && !e.metaKey) {
            e.preventDefault()
            onRefresh()
            document.dispatchEvent(new CustomEvent('sigintx:refresh'))
          }
          break

        case 'Escape':
          setShowHelp(false)
          document.dispatchEvent(new CustomEvent('sigintx:escape'))
          break

        default:
          break
      }
    }

    document.addEventListener('keydown', handler)
    return () => {
      document.removeEventListener('keydown', handler)
      clearLeader()
    }
  }, [onNavigate, onRefresh, clearLeader])

  return { showHelp, setShowHelp }
}
