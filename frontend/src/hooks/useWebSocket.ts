import { useEffect, useRef, useState, useCallback } from 'react'
import type { WSMessage } from '@/types'

const MAX_RECONNECT_ATTEMPTS = 12          // stop after ~4 min of trying
const HEARTBEAT_INTERVAL_MS  = 25_000     // ping every 25 s to detect dead sockets

interface UseWebSocketReturn {
  lastMessage: WSMessage | null
  isConnected: boolean
  reconnectCount: number
}

export function useWebSocket(url: string): UseWebSocketReturn {
  const [lastMessage, setLastMessage]   = useState<WSMessage | null>(null)
  const [isConnected, setIsConnected]   = useState(false)
  const [reconnectCount, setReconnectCount] = useState(0)

  const wsRef           = useRef<WebSocket | null>(null)
  const reconnectRef    = useRef(0)           // mirrors state for use inside callbacks
  const timerRef        = useRef<ReturnType<typeof setTimeout> | null>(null)
  const heartbeatRef    = useRef<ReturnType<typeof setInterval> | null>(null)
  const unmountedRef    = useRef(false)

  const clearTimers = () => {
    if (timerRef.current)     { clearTimeout(timerRef.current);   timerRef.current = null }
    if (heartbeatRef.current) { clearInterval(heartbeatRef.current); heartbeatRef.current = null }
  }

  const connect = useCallback(() => {
    if (unmountedRef.current) return

    // Close any existing socket before opening a new one (prevents duplicates)
    if (wsRef.current && wsRef.current.readyState < WebSocket.CLOSING) {
      wsRef.current.onclose = null   // suppress reconnect loop from old socket
      wsRef.current.close()
    }

    try {
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        if (unmountedRef.current) { ws.close(); return }
        setIsConnected(true)
        reconnectRef.current = 0
        setReconnectCount(0)

        // Start heartbeat — send ping, close if server doesn't respond
        clearInterval(heartbeatRef.current!)
        heartbeatRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            try { ws.send(JSON.stringify({ type: 'ping' })) } catch { /* ignore */ }
          } else {
            clearInterval(heartbeatRef.current!)
          }
        }, HEARTBEAT_INTERVAL_MS)
      }

      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data) as WSMessage
          if (data.type !== 'ping') setLastMessage(data)
        } catch {
          // malformed message — ignore, log for debug
          console.debug('[WS] unparseable message:', e.data)
        }
      }

      ws.onclose = () => {
        if (unmountedRef.current) return
        setIsConnected(false)
        clearInterval(heartbeatRef.current!)

        if (reconnectRef.current >= MAX_RECONNECT_ATTEMPTS) {
          console.warn('[WS] max reconnect attempts reached — giving up')
          return
        }

        // Exponential backoff: 2s, 4s, 8s … capped at 30s
        const delay = Math.min(2000 * Math.pow(2, reconnectRef.current), 30_000)
        reconnectRef.current += 1
        setReconnectCount(reconnectRef.current)

        timerRef.current = setTimeout(() => {
          if (!unmountedRef.current) connect()
        }, delay)
      }

      ws.onerror = () => {
        // onerror always fires before onclose, so just close — onclose handles retry
        ws.close()
      }
    } catch {
      // WebSocket not available in SSR / test environments
    }
  }, [url])

  useEffect(() => {
    unmountedRef.current = false
    connect()
    return () => {
      unmountedRef.current = true
      clearTimers()
      if (wsRef.current) {
        wsRef.current.onclose = null  // prevent reconnect loop on intentional unmount
        wsRef.current.close()
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url])

  return { lastMessage, isConnected, reconnectCount }
}
