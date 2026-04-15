/**
 * JWT authentication hook.
 * AUTH_DISABLED=true on backend means any request goes through.
 * Stores JWT in localStorage under key 'sigintx_token'.
 */
import { useState, useEffect, useCallback } from 'react'

const TOKEN_KEY = 'sigintx_token'
const USER_KEY  = 'sigintx_username'

export interface AuthState {
  token:            string | null
  isAuthenticated:  boolean
  username:         string | null
  login:            (username: string, password: string) => Promise<boolean>
  logout:           () => void
  getAuthHeaders:   () => Record<string, string>
}

export function useAuth(): AuthState {
  const [token,    setToken]    = useState<string | null>(() => localStorage.getItem(TOKEN_KEY))
  const [username, setUsername] = useState<string | null>(() => localStorage.getItem(USER_KEY))
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  // On mount (or token change) validate the token via /api/v1/auth/me
  useEffect(() => {
    if (!token) {
      setIsAuthenticated(false)
      return
    }

    let cancelled = false
    fetch('/api/v1/auth/me', {
      headers: { Authorization: `Bearer ${token}` },
    }).then(res => {
      if (cancelled) return
      if (res.ok) {
        setIsAuthenticated(true)
      } else {
        // Token invalid — clear it
        localStorage.removeItem(TOKEN_KEY)
        localStorage.removeItem(USER_KEY)
        setToken(null)
        setUsername(null)
        setIsAuthenticated(false)
      }
    }).catch(() => {
      if (cancelled) return
      // Network error: keep token, assume valid (offline resilience)
      setIsAuthenticated(true)
    })

    return () => { cancelled = true }
  }, [token])

  const login = useCallback(async (u: string, p: string): Promise<boolean> => {
    try {
      const res = await fetch('/api/v1/auth/login', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ username: u, password: p }),
      })
      if (!res.ok) return false
      const data = await res.json() as { access_token: string; token_type: string }
      const t = data.access_token
      localStorage.setItem(TOKEN_KEY, t)
      localStorage.setItem(USER_KEY, u)
      setToken(t)
      setUsername(u)
      setIsAuthenticated(true)
      return true
    } catch {
      return false
    }
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
    setToken(null)
    setUsername(null)
    setIsAuthenticated(false)
  }, [])

  const getAuthHeaders = useCallback((): Record<string, string> => {
    if (!token) return {}
    return { Authorization: `Bearer ${token}` }
  }, [token])

  return { token, isAuthenticated, username, login, logout, getAuthHeaders }
}
