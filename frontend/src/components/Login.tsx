/**
 * Full-screen login page — SIGINTX terminal aesthetic.
 * Checks if auth is disabled by probing /api/v1/auth/me without a token.
 * If that succeeds (200), auto-logs-in as "local".
 */
import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Loader2, Lock, AlertTriangle, Terminal, Shield } from 'lucide-react'

interface Props {
  onLogin: (token: string, username: string) => void
}

const VERSION = 'v3.0.0'

export function Login({ onLogin }: Props) {
  const [username,     setUsername]     = useState('')
  const [password,     setPassword]     = useState('')
  const [loading,      setLoading]      = useState(false)
  const [error,        setError]        = useState('')
  const [authDisabled, setAuthDisabled] = useState<boolean | null>(null)  // null = checking
  const [checking,     setChecking]     = useState(true)

  const usernameRef = useRef<HTMLInputElement>(null)

  // On mount: check if auth is disabled
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const res = await fetch('/api/v1/auth/me')
        if (cancelled) return
        if (res.ok) {
          // Auth is disabled — server accepts requests without token
          setAuthDisabled(true)
          // Auto-login with a synthetic token
          onLogin('auth-disabled', 'local')
        } else {
          setAuthDisabled(false)
        }
      } catch {
        if (!cancelled) setAuthDisabled(false)
      } finally {
        if (!cancelled) setChecking(false)
      }
    })()
    return () => { cancelled = true }
  }, [onLogin])

  // Focus username when form is ready
  useEffect(() => {
    if (!checking && !authDisabled) {
      setTimeout(() => usernameRef.current?.focus(), 50)
    }
  }, [checking, authDisabled])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!username.trim() || !password) return
    setLoading(true)
    setError('')
    try {
      const res = await fetch('/api/v1/auth/login', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ username: username.trim(), password }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        setError((body as { detail?: string }).detail ?? 'Authentication failed. Check credentials.')
        setLoading(false)
        return
      }
      const data = await res.json() as { access_token: string; token_type: string }
      onLogin(data.access_token, username.trim())
    } catch {
      setError('Unable to connect to server. Is the backend running?')
      setLoading(false)
    }
  }

  return (
    <div
      className="relative flex flex-col items-center justify-center min-h-screen overflow-hidden"
      style={{ background: 'var(--bg-base)', fontFamily: 'monospace' }}
    >
      {/* Animated scan-lines overlay */}
      <style>{`
        @keyframes scanline {
          0%   { transform: translateY(-100%); }
          100% { transform: translateY(100vh); }
        }
        .scanline {
          pointer-events: none;
          position: absolute;
          inset: 0;
          z-index: 0;
          overflow: hidden;
        }
        .scanline::before {
          content: '';
          position: absolute;
          left: 0;
          right: 0;
          height: 2px;
          background: linear-gradient(
            to bottom,
            transparent,
            rgba(0, 212, 255, 0.06),
            transparent
          );
          animation: scanline 6s linear infinite;
        }
        .scanline::after {
          content: '';
          position: absolute;
          inset: 0;
          background: repeating-linear-gradient(
            0deg,
            transparent,
            transparent 2px,
            rgba(0, 0, 0, 0.03) 2px,
            rgba(0, 0, 0, 0.03) 4px
          );
        }
        @keyframes glow-pulse {
          0%, 100% { text-shadow: 0 0 8px rgba(0,212,255,0.5), 0 0 20px rgba(0,212,255,0.2); }
          50%       { text-shadow: 0 0 16px rgba(0,212,255,0.8), 0 0 40px rgba(0,212,255,0.35); }
        }
        .logo-glow { animation: glow-pulse 3s ease-in-out infinite; }
        @keyframes border-flicker {
          0%, 96%, 100% { opacity: 1; }
          97%            { opacity: 0.7; }
          98%            { opacity: 1; }
          99%            { opacity: 0.8; }
        }
        .terminal-border { animation: border-flicker 8s infinite; }
      `}</style>

      <div className="scanline" />

      {/* Grid background */}
      <div
        className="absolute inset-0 z-0 opacity-[0.03]"
        style={{
          backgroundImage: `
            linear-gradient(var(--color-primary) 1px, transparent 1px),
            linear-gradient(90deg, var(--color-primary) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
        }}
      />

      {/* Main card */}
      <motion.div
        initial={{ opacity: 0, y: 24, scale: 0.97 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.4, ease: 'easeOut' }}
        className="relative z-10 w-full max-w-sm mx-4"
      >
        {/* Terminal-style header bar */}
        <div
          className="terminal-border flex items-center gap-2 px-4 py-2 border border-b-0"
          style={{
            borderColor:  'var(--border-accent)',
            background:   'var(--bg-surface)',
          }}
        >
          <div className="w-2 h-2 rounded-full" style={{ background: 'var(--color-danger)' }} />
          <div className="w-2 h-2 rounded-full" style={{ background: 'var(--color-warning)' }} />
          <div className="w-2 h-2 rounded-full" style={{ background: 'var(--color-success)' }} />
          <span className="ml-2 font-mono text-[0.52rem] tracking-widest" style={{ color: 'var(--text-ghost)' }}>
            sigintx — auth terminal
          </span>
        </div>

        {/* Card body */}
        <div
          className="terminal-border px-8 py-10 border flex flex-col items-center gap-6"
          style={{
            borderColor: 'var(--border-accent)',
            background:  'var(--bg-card)',
          }}
        >
          {/* Logo */}
          <div className="flex flex-col items-center gap-2 select-none">
            <div className="flex items-center gap-3 mb-1">
              <Shield
                size={28}
                style={{ color: 'var(--color-primary)', filter: 'drop-shadow(0 0 6px rgba(0,212,255,0.6))' }}
              />
              <span
                className="logo-glow text-[2rem] font-bold tracking-[0.15em] uppercase"
                style={{
                  fontFamily:  "'Orbitron', 'Share Tech Mono', monospace",
                  color:       'var(--color-primary)',
                  letterSpacing: '0.2em',
                }}
              >
                SIGINTX
              </span>
            </div>
            <span
              className="font-mono text-[0.52rem] tracking-[0.35em] uppercase"
              style={{ color: 'var(--text-ghost)' }}
            >
              SIGNALS INTELLIGENCE PLATFORM
            </span>
          </div>

          {/* Auth disabled banner */}
          <AnimatePresence>
            {authDisabled === true && (
              <motion.div
                initial={{ opacity: 0, y: -6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="w-full flex items-center gap-2 px-3 py-2"
                style={{
                  border:     '1px solid rgba(0,255,136,0.25)',
                  background: 'rgba(0,255,136,0.06)',
                }}
              >
                <Terminal size={11} style={{ color: 'var(--color-success)', flexShrink: 0 }} />
                <span className="font-mono text-[0.58rem]" style={{ color: 'var(--color-success)' }}>
                  Auth disabled — running in local mode
                </span>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Checking state */}
          {checking && (
            <div className="flex items-center gap-2" style={{ color: 'var(--text-ghost)' }}>
              <Loader2 size={14} className="animate-spin" />
              <span className="font-mono text-[0.6rem] tracking-widest">INITIALIZING...</span>
            </div>
          )}

          {/* Login form */}
          {!checking && !authDisabled && (
            <form onSubmit={handleSubmit} className="w-full flex flex-col gap-4">
              {/* Username */}
              <div className="flex flex-col gap-1.5">
                <label
                  className="font-mono text-[0.52rem] tracking-widest"
                  style={{ color: 'var(--text-dim)' }}
                >
                  USERNAME
                </label>
                <input
                  ref={usernameRef}
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  autoComplete="username"
                  spellCheck={false}
                  placeholder="operator"
                  className="w-full px-3 py-2.5 font-mono text-[0.75rem] outline-none transition-colors"
                  style={{
                    background:   'var(--bg-elevated)',
                    border:       '1px solid var(--border-base)',
                    color:        'var(--text-secondary)',
                    caretColor:   'var(--color-primary)',
                  }}
                  onFocus={e => (e.target.style.borderColor = 'var(--border-accent)')}
                  onBlur={e  => (e.target.style.borderColor = 'var(--border-base)')}
                />
              </div>

              {/* Password */}
              <div className="flex flex-col gap-1.5">
                <label
                  className="font-mono text-[0.52rem] tracking-widest"
                  style={{ color: 'var(--text-dim)' }}
                >
                  PASSWORD
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  autoComplete="current-password"
                  placeholder="••••••••"
                  className="w-full px-3 py-2.5 font-mono text-[0.75rem] outline-none transition-colors"
                  style={{
                    background:   'var(--bg-elevated)',
                    border:       '1px solid var(--border-base)',
                    color:        'var(--text-secondary)',
                    caretColor:   'var(--color-primary)',
                  }}
                  onFocus={e => (e.target.style.borderColor = 'var(--border-accent)')}
                  onBlur={e  => (e.target.style.borderColor = 'var(--border-base)')}
                />
              </div>

              {/* Error */}
              <AnimatePresence>
                {error && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="flex items-center gap-2 px-3 py-2"
                    style={{
                      border:     '1px solid rgba(255,34,85,0.3)',
                      background: 'rgba(255,34,85,0.06)',
                    }}
                  >
                    <AlertTriangle size={10} style={{ color: 'var(--color-danger)', flexShrink: 0 }} />
                    <span className="font-mono text-[0.58rem]" style={{ color: 'var(--color-danger)' }}>
                      {error}
                    </span>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Submit */}
              <button
                type="submit"
                disabled={loading || !username.trim() || !password}
                className="flex items-center justify-center gap-2 py-3 font-mono text-[0.65rem] tracking-[0.25em] uppercase transition-all disabled:opacity-40"
                style={{
                  background:   loading ? 'rgba(0,212,255,0.12)' : 'rgba(0,212,255,0.09)',
                  border:       '1px solid var(--border-accent)',
                  color:        'var(--color-primary)',
                  cursor:       loading ? 'wait' : 'pointer',
                }}
                onMouseEnter={e => {
                  if (!loading) (e.currentTarget as HTMLButtonElement).style.background = 'rgba(0,212,255,0.15)'
                }}
                onMouseLeave={e => {
                  (e.currentTarget as HTMLButtonElement).style.background = 'rgba(0,212,255,0.09)'
                }}
              >
                {loading ? (
                  <><Loader2 size={12} className="animate-spin" />AUTHENTICATING</>
                ) : (
                  <><Lock size={12} />AUTHENTICATE</>
                )}
              </button>
            </form>
          )}
        </div>

        {/* Bottom footer */}
        <div
          className="flex items-center justify-between px-4 py-2 border border-t-0"
          style={{
            borderColor: 'var(--border-accent)',
            background:  'var(--bg-surface)',
          }}
        >
          <span className="font-mono text-[0.46rem] tracking-widest" style={{ color: 'var(--text-ghost)' }}>
            SIGINTX {VERSION}
          </span>
          <span className="font-mono text-[0.46rem] tracking-widest" style={{ color: 'var(--text-ghost)' }}>
            &copy; 2026 — LOCAL INSTANCE
          </span>
        </div>
      </motion.div>
    </div>
  )
}
