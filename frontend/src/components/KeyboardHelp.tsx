/**
 * KeyboardHelp — modal overlay showing all keyboard shortcuts.
 * Triggered by pressing '?' anywhere in the app.
 */
import { useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Keyboard, X } from 'lucide-react'

interface Props {
  onClose: () => void
}

const VERSION = 'SIGINTX v3.0.0'

interface Shortcut {
  keys: string[]
  desc: string
}

const NAV_SHORTCUTS: Shortcut[] = [
  { keys: ['g', 'd'], desc: 'Dashboard' },
  { keys: ['g', 'n'], desc: 'News Feed' },
  { keys: ['g', 'c'], desc: 'CVE Explorer' },
  { keys: ['g', 'a'], desc: 'Threat Actors' },
  { keys: ['g', 'r'], desc: 'Correlation Graph' },
  { keys: ['g', 't'], desc: 'Campaigns' },
  { keys: ['g', 'm'], desc: 'Global Map' },
  { keys: ['g', 'i'], desc: 'IOC Explorer' },
  { keys: ['g', 'x'], desc: 'AI Analyst' },
  { keys: ['g', 's'], desc: 'Settings' },
  { keys: ['g', 'w'], desc: 'Watchlists' },
  { keys: ['g', 'u'], desc: 'Alert Rules' },
]

const ACTION_SHORTCUTS: Shortcut[] = [
  { keys: ['/'],      desc: 'Focus global search' },
  { keys: ['?'],      desc: 'Toggle this help overlay' },
  { keys: ['r'],      desc: 'Refresh current view' },
  { keys: ['Esc'],    desc: 'Close overlay / cancel' },
]

function Key({ label }: { label: string }) {
  return (
    <kbd
      className="inline-flex items-center justify-center px-1.5 py-0.5 font-mono text-[0.58rem] min-w-[20px]"
      style={{
        background:   'var(--bg-elevated)',
        border:       '1px solid var(--border-accent)',
        color:        'var(--color-primary)',
        borderRadius: '2px',
        boxShadow:    '0 1px 0 rgba(0,212,255,0.3)',
      }}
    >
      {label}
    </kbd>
  )
}

function ShortcutRow({ keys, desc }: Shortcut) {
  return (
    <div className="flex items-center justify-between gap-4 py-1.5 border-b" style={{ borderColor: 'var(--border-base)' }}>
      <span className="font-mono text-[0.6rem]" style={{ color: 'var(--text-muted)' }}>
        {desc}
      </span>
      <div className="flex items-center gap-1 shrink-0">
        {keys.map((k, i) => (
          <span key={i} className="flex items-center gap-0.5">
            {i > 0 && <span className="font-mono text-[0.46rem] mx-0.5" style={{ color: 'var(--text-ghost)' }}>then</span>}
            <Key label={k} />
          </span>
        ))}
      </div>
    </div>
  )
}

export function KeyboardHelp({ onClose }: Props) {
  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <AnimatePresence>
      {/* Backdrop */}
      <motion.div
        key="backdrop"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.15 }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        style={{ background: 'rgba(3,6,9,0.85)', backdropFilter: 'blur(2px)' }}
        onClick={onClose}
      >
        {/* Modal */}
        <motion.div
          key="modal"
          initial={{ opacity: 0, scale: 0.94, y: 12 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.94, y: 12 }}
          transition={{ duration: 0.2, ease: 'easeOut' }}
          className="w-full max-w-lg"
          style={{
            background:  'var(--bg-card)',
            border:      '1px solid var(--border-accent)',
            boxShadow:   '0 0 40px rgba(0,212,255,0.08)',
          }}
          onClick={e => e.stopPropagation()}
        >
          {/* Header */}
          <div
            className="flex items-center justify-between px-5 py-3 border-b"
            style={{ borderColor: 'var(--border-base)', background: 'var(--bg-surface)' }}
          >
            <div className="flex items-center gap-2">
              <Keyboard size={12} style={{ color: 'var(--color-primary)' }} />
              <span className="font-mono text-[0.65rem] tracking-widest" style={{ color: 'var(--color-primary)' }}>
                KEYBOARD SHORTCUTS
              </span>
            </div>
            <div className="flex items-center gap-3">
              <span className="font-mono text-[0.48rem] tracking-widest" style={{ color: 'var(--text-ghost)' }}>
                {VERSION}
              </span>
              <button
                onClick={onClose}
                className="transition-colors"
                style={{ color: 'var(--text-dim)' }}
                onMouseEnter={e => ((e.currentTarget as HTMLButtonElement).style.color = 'var(--text-base)')}
                onMouseLeave={e => ((e.currentTarget as HTMLButtonElement).style.color = 'var(--text-dim)')}
              >
                <X size={14} />
              </button>
            </div>
          </div>

          {/* Body — two columns */}
          <div className="grid grid-cols-2 gap-0 divide-x" style={{ borderColor: 'var(--border-base)' }}>
            {/* Navigation column */}
            <div className="px-5 py-4">
              <p className="font-mono text-[0.5rem] tracking-[0.25em] mb-3" style={{ color: 'var(--text-ghost)' }}>
                NAVIGATION  <span style={{ color: 'var(--color-primary)' }}>g + key</span>
              </p>
              <div className="flex flex-col">
                {NAV_SHORTCUTS.map((s, i) => (
                  <ShortcutRow key={i} {...s} />
                ))}
              </div>
            </div>

            {/* Actions column */}
            <div className="px-5 py-4">
              <p className="font-mono text-[0.5rem] tracking-[0.25em] mb-3" style={{ color: 'var(--text-ghost)' }}>
                ACTIONS
              </p>
              <div className="flex flex-col">
                {ACTION_SHORTCUTS.map((s, i) => (
                  <ShortcutRow key={i} {...s} />
                ))}
              </div>

              {/* Leader key note */}
              <div
                className="mt-4 px-3 py-2"
                style={{
                  background: 'rgba(0,212,255,0.04)',
                  border:     '1px solid rgba(0,212,255,0.15)',
                }}
              >
                <p className="font-mono text-[0.54rem]" style={{ color: 'var(--text-muted)' }}>
                  <span style={{ color: 'var(--color-primary)' }}>g</span> is a leader key — press it, then press the second key within 1 second.
                </p>
              </div>
            </div>
          </div>

          {/* Footer */}
          <div
            className="flex items-center justify-center px-5 py-2 border-t"
            style={{ borderColor: 'var(--border-base)', background: 'var(--bg-surface)' }}
          >
            <span className="font-mono text-[0.48rem] tracking-widest" style={{ color: 'var(--text-ghost)' }}>
              Press <span style={{ color: 'var(--color-primary)' }}>?</span> or <span style={{ color: 'var(--color-primary)' }}>Esc</span> to close
            </span>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
}
