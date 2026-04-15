import { useState, useEffect, useCallback } from 'react'
import { TrendingUp, TrendingDown, RefreshCw, AlertTriangle } from 'lucide-react'

interface CoinData {
  id: string
  symbol: string
  name: string
  image: string
  current_price: number
  price_change_percentage_24h: number | null
  market_cap: number
  market_cap_rank: number
  total_volume: number
  high_24h: number
  low_24h: number
}

const COINGECKO_URL =
  'https://api.coingecko.com/api/v3/coins/markets' +
  '?vs_currency=usd&order=market_cap_desc&per_page=10&page=1' +
  '&sparkline=false&price_change_percentage=24h'

function fmtPrice(n: number): string {
  if (n >= 1000) return n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })
  if (n >= 1)    return n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 4 })
  return n.toLocaleString('en-US', { minimumFractionDigits: 4, maximumFractionDigits: 6 })
}

function fmtMcap(n: number): string {
  if (n >= 1e12) return `$${(n / 1e12).toFixed(2)}T`
  if (n >= 1e9)  return `$${(n / 1e9).toFixed(1)}B`
  if (n >= 1e6)  return `$${(n / 1e6).toFixed(0)}M`
  return `$${n.toLocaleString()}`
}

function MiniBar({ value, max }: { value: number; max: number }) {
  const pct = Math.min(100, (value / max) * 100)
  return (
    <div className="w-12 h-0.5 bg-[var(--bg-elevated)] rounded-full overflow-hidden">
      <div
        className="h-full rounded-full"
        style={{ width: `${pct}%`, background: 'var(--color-primary)', opacity: 0.6 }}
      />
    </div>
  )
}

export function CryptoPricePanel({ compact }: { compact?: boolean }) {
  const [coins, setCoins]       = useState<CoinData[]>([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState<string | null>(null)
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null)

  const fetchPrices = useCallback(async () => {
    try {
      const resp = await fetch(COINGECKO_URL)
      if (!resp.ok) throw new Error(`CoinGecko returned ${resp.status}`)
      const data: CoinData[] = await resp.json()
      setCoins(data)
      setLastUpdate(new Date())
      setError(null)
    } catch (e: unknown) {
      setError((e as Error).message ?? 'Failed to load prices')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchPrices()
    const id = setInterval(fetchPrices, 60_000)
    return () => clearInterval(id)
  }, [fetchPrices])

  const maxMcap = coins[0]?.market_cap ?? 1

  if (compact) {
    return (
      <div className="panel flex flex-col h-full">
        <div className="panel-header shrink-0">
          <div className="flex items-center gap-2">
            <TrendingUp size={11} className="text-[#f7931a]" />
            <span className="panel-title">CRYPTO MARKETS</span>
          </div>
          <button onClick={fetchPrices} className="text-[var(--text-dim)] hover:text-[#f7931a] transition-colors">
            <RefreshCw size={10} />
          </button>
        </div>
        <div className="flex-1 overflow-x-auto overflow-y-hidden min-h-0">
          <div className="flex items-center gap-0 h-full divide-x divide-[var(--border-base)]" style={{ minWidth: 'max-content' }}>
            {coins.slice(0, 10).map(coin => {
              const change = coin.price_change_percentage_24h ?? 0
              const up = change >= 0
              const changeColor = up ? '#22c55e' : '#ef4444'
              return (
                <div key={coin.id} className="flex flex-col items-center justify-center gap-1 px-3 h-full min-w-[80px]">
                  <div className="flex items-center gap-1">
                    <img src={coin.image} alt={coin.symbol} className="w-3.5 h-3.5 rounded-full" />
                    <span className="font-mono text-[0.55rem] tracking-wide uppercase text-[var(--text-base)]">{coin.symbol}</span>
                  </div>
                  <span className="font-mono text-[0.62rem] text-[var(--text-base)] tabular-nums">${fmtPrice(coin.current_price)}</span>
                  <span className="font-mono text-[0.48rem] tabular-nums" style={{ color: changeColor }}>
                    {up ? '+' : ''}{change.toFixed(2)}%
                  </span>
                </div>
              )
            })}
            {(loading || error) && (
              <div className="flex items-center justify-center w-full h-full px-4">
                <span className="font-mono text-[0.52rem] text-[var(--text-ghost)]">
                  {loading ? 'LOADING...' : 'RATE LIMITED'}
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="panel flex flex-col h-full">
      {/* Header */}
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <TrendingUp size={11} className="text-[#f7931a]" />
          <span className="panel-title">CRYPTO MARKETS</span>
          {lastUpdate && (
            <span className="font-mono text-[0.5rem] text-[var(--text-ghost)]">
              {lastUpdate.toLocaleTimeString()}
            </span>
          )}
        </div>
        <button
          onClick={fetchPrices}
          className="text-[var(--text-dim)] hover:text-[var(--color-primary)] transition-colors"
          title="Refresh prices"
        >
          <RefreshCw size={11} />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto min-h-0">
        {loading && (
          <div className="flex flex-col">
            {Array.from({ length: 10 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-2.5 border-b border-[var(--border-base)] animate-pulse">
                <div className="w-5 h-5 rounded-full bg-[var(--bg-elevated)]" />
                <div className="flex-1 space-y-1">
                  <div className="h-2.5 bg-[var(--bg-elevated)] rounded w-24" />
                  <div className="h-1.5 bg-[var(--bg-elevated)] rounded w-16" />
                </div>
                <div className="h-3 bg-[var(--bg-elevated)] rounded w-20" />
              </div>
            ))}
          </div>
        )}

        {error && !loading && (
          <div className="flex flex-col items-center justify-center h-32 gap-2 px-4">
            <AlertTriangle size={16} className="text-[var(--color-warn)]" />
            <p className="font-mono text-[0.62rem] text-[var(--text-dim)] text-center">{error}</p>
            <p className="font-mono text-[0.52rem] text-[var(--text-ghost)] text-center">
              CoinGecko free tier has rate limits. Retries every 60s.
            </p>
          </div>
        )}

        {!loading && !error && coins.map((coin, idx) => {
          const change = coin.price_change_percentage_24h ?? 0
          const up     = change >= 0
          const changeColor = up ? '#22c55e' : '#ef4444'

          return (
            <div
              key={coin.id}
              className="flex items-center gap-3 px-4 py-2.5 border-b border-[var(--border-base)] hover:bg-[var(--bg-card-hover)] transition-colors"
            >
              {/* Rank */}
              <span className="font-mono text-[0.5rem] text-[var(--text-ghost)] w-4 shrink-0 text-right">
                {idx + 1}
              </span>

              {/* Icon + name */}
              <img src={coin.image} alt={coin.name} className="w-5 h-5 rounded-full shrink-0" />
              <div className="min-w-0 w-20 shrink-0">
                <div className="font-mono text-[0.65rem] text-[var(--text-base)] tracking-wide uppercase">
                  {coin.symbol}
                </div>
                <div className="font-mono text-[0.5rem] text-[var(--text-ghost)] truncate">
                  {coin.name}
                </div>
              </div>

              {/* Market cap bar */}
              <div className="flex-1 flex justify-center">
                <MiniBar value={coin.market_cap} max={maxMcap} />
              </div>

              {/* Market cap */}
              <span className="font-mono text-[0.55rem] text-[var(--text-dim)] w-14 text-right shrink-0 hidden sm:block">
                {fmtMcap(coin.market_cap)}
              </span>

              {/* 24h change */}
              <div
                className="flex items-center gap-0.5 w-14 justify-end shrink-0"
                style={{ color: changeColor }}
              >
                {up ? <TrendingUp size={9} /> : <TrendingDown size={9} />}
                <span className="font-mono text-[0.6rem]">
                  {up ? '+' : ''}{change.toFixed(2)}%
                </span>
              </div>

              {/* Price */}
              <div className="font-mono text-[0.7rem] text-[var(--text-base)] w-24 text-right shrink-0">
                ${fmtPrice(coin.current_price)}
              </div>
            </div>
          )
        })}
      </div>

      {/* Footer */}
      <div className="px-4 py-1.5 border-t border-[var(--border-base)] shrink-0">
        <span className="font-mono text-[0.45rem] text-[var(--text-ghost)] tracking-widest">
          DATA: COINGECKO FREE API · UPDATES EVERY 60s · TOP 10 BY MARKET CAP
        </span>
      </div>
    </div>
  )
}
