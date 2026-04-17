import { useState, useEffect, useCallback, useRef } from 'react'

// When VITE_API_URL is set (e.g. https://sigintx-api.onrender.com), API calls
// go directly to that origin. Otherwise relative URLs work via the Vite proxy.
const _apiOrigin = import.meta.env.VITE_API_URL?.replace(/\/$/, '') ?? ''
const API_BASE = _apiOrigin ? `${_apiOrigin}/api/v1` : '/api/v1'

// Stable param serialisation: sort keys so {b:2,a:1} === {a:1,b:2}
function stableParamKey(params?: Record<string, string | number | boolean | undefined | null>): string {
  if (!params) return ''
  return Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('&')
}

export async function fetchJson<T>(
  path: string,
  params?: Record<string, string | number | boolean | undefined | null>,
  signal?: AbortSignal,
): Promise<T> {
  // If API_BASE is absolute (starts with http), new URL() uses it as-is.
  // If it's relative (/api/v1), window.location.origin fills in the host.
  const url = new URL(API_BASE + path, window.location.origin)
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v))
    })
  }
  const res = await fetch(url.toString(), { signal })
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw Object.assign(new Error(`API ${res.status}: ${path}`), {
      status: res.status,
      body,
    })
  }
  return res.json() as Promise<T>
}

export function useApi<T>(
  path: string,
  params?: Record<string, string | number | boolean | undefined | null>,
  refreshTrigger?: number,
  refreshInterval?: number,
) {
  const [data, setData]       = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState<string | null>(null)
  const abortRef              = useRef<AbortController | null>(null)

  // Stable string key so memoisation doesn't flip on key-order changes
  const paramKey = stableParamKey(params)

  const load = useCallback(async () => {
    // Cancel any in-flight request
    abortRef.current?.abort()
    abortRef.current = new AbortController()

    try {
      setLoading(true)
      const result = await fetchJson<T>(
        path,
        params,
        abortRef.current.signal,
      )
      setData(result)
      setError(null)
    } catch (e: unknown) {
      if ((e as Error).name === 'AbortError') return   // intentional cancel
      const msg = e instanceof Error ? e.message : String(e)
      setError(msg)
    } finally {
      setLoading(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, paramKey])

  // Load on mount / refreshTrigger change; cancel on unmount
  useEffect(() => {
    load()
    return () => { abortRef.current?.abort() }
  }, [load, refreshTrigger])

  // Polling interval — also cancel on cleanup
  useEffect(() => {
    if (!refreshInterval) return
    const id = setInterval(load, refreshInterval)
    return () => clearInterval(id)
  }, [load, refreshInterval])

  return { data, loading, error, refetch: load }
}

export async function triggerCollect(type: 'rss' | 'cves' | 'abusech' | 'ransomwatch') {
  const res = await fetch(`${API_BASE}/collect/${type}`, { method: 'POST' })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.detail ?? `Trigger failed: HTTP ${res.status}`)
  }
}
