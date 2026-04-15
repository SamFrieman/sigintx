import { motion, AnimatePresence } from 'framer-motion'
import { Radio, Wifi, WifiOff, RefreshCw, Zap } from 'lucide-react'
import type { WSMessage } from '@/types'
import { triggerCollect } from '@/hooks/useApi'
import { useState } from 'react'
import { GlobalSearch } from '@/components/GlobalSearch'

interface Props {
  isConnected: boolean
  lastMessage: WSMessage | null
  onRefresh: () => void
  onNavigate: (tab: string) => void
}

export function StatusBar({ isConnected, lastMessage, onRefresh, onNavigate }: Props) {
  const [triggering, setTriggering] = useState(false)

  const handleTrigger = async () => {
    setTriggering(true)
    await triggerCollect('rss')
    setTimeout(() => {
      setTriggering(false)
      onRefresh()
    }, 2000)
  }

  return (
    <div className="sticky top-0 z-50 border-b border-[var(--border-base)] bg-[var(--bg-surface)]/90 backdrop-blur-sm">
      <div className="flex items-center justify-between gap-2 px-4 py-2 max-w-[1800px] mx-auto">

        {/* Left: Logo + connection status */}
        <div className="flex items-center gap-4 shrink-0">
          <div className="flex items-center gap-2">
            <span
              className="font-display text-[0.85rem] font-black tracking-widest text-[var(--color-primary)]"
              style={{ textShadow: '0 0 20px rgba(0,212,255,0.4)' }}
            >
              SIGINTX
            </span>
            <span className="font-mono text-[0.46rem] text-[var(--text-ghost)] tracking-widest hidden md:block">
              // CYBER WORLD MONITOR
            </span>
          </div>

          <div className="flex items-center gap-1.5">
            {isConnected ? (
              <>
                <span className="live-dot" />
                <Wifi size={10} className="text-[var(--color-success)]" />
                <span className="font-mono text-[0.55rem] text-[var(--color-success)] tracking-wider">LIVE</span>
              </>
            ) : (
              <>
                <WifiOff size={10} className="text-[var(--text-dim)]" />
                <span className="font-mono text-[0.55rem] text-[var(--text-dim)] tracking-wider">OFFLINE</span>
              </>
            )}
          </div>
        </div>

        {/* Right: Search + Actions */}
        <div className="flex items-center gap-2 shrink-0">
          <GlobalSearch onNavigate={onNavigate} />

          <AnimatePresence>
            {lastMessage?.type === 'rss_update' && (
              <motion.div
                initial={{ opacity: 0, x: 10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0 }}
                className="hidden sm:flex items-center gap-1 px-2 py-0.5 border"
                style={{
                  borderColor: 'rgba(0,255,136,0.25)',
                  background:  'rgba(0,255,136,0.05)',
                }}
              >
                <Radio size={9} className="text-[var(--color-success)]" />
                <span className="font-mono text-[0.52rem] text-[var(--color-success)] tracking-wider">
                  +{lastMessage.new_items} NEW
                </span>
              </motion.div>
            )}
          </AnimatePresence>

          <button
            onClick={handleTrigger}
            disabled={triggering}
            className="flex items-center gap-1.5 px-3 py-1 border border-[var(--border-accent)] bg-[var(--bg-card)] hover:bg-[var(--bg-elevated)] hover:border-[var(--color-primary)] text-[var(--text-muted)] hover:text-[var(--color-primary)] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            title="Trigger manual collection"
          >
            <RefreshCw size={10} className={triggering ? 'animate-spin' : ''} />
            <span className="font-mono text-[0.55rem] tracking-wider hidden sm:block">COLLECT</span>
          </button>

          <button
            onClick={onRefresh}
            className="flex items-center gap-1.5 px-3 py-1 border border-[var(--border-accent)] bg-[var(--bg-card)] hover:bg-[var(--bg-elevated)] hover:border-[var(--color-primary)] text-[var(--text-muted)] hover:text-[var(--color-primary)] transition-colors"
            title="Refresh all panels"
          >
            <Zap size={10} />
            <span className="font-mono text-[0.55rem] tracking-wider hidden sm:block">REFRESH</span>
          </button>
        </div>
      </div>

    </div>
  )
}
