/**
 * ErrorBoundary — Catches runtime errors in child component trees.
 * Wraps each dashboard panel so one crash doesn't take down the entire app.
 */
import { Component, type ReactNode, type ErrorInfo } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

interface Props {
  children: ReactNode
  label?: string     // panel name shown in the error card
}

interface State {
  error:     Error | null
  errorInfo: ErrorInfo | null
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, errorInfo: null }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ error, errorInfo })
    console.error(`[ErrorBoundary:${this.props.label ?? 'unknown'}]`, error, errorInfo)
  }

  reset = () => this.setState({ error: null, errorInfo: null })

  render() {
    const { error } = this.state
    const { label = 'PANEL', children } = this.props

    if (error) {
      return (
        <div className="panel flex flex-col items-center justify-center h-full gap-4 p-6 text-center">
          <div className="border border-[rgba(255,34,85,0.3)] bg-[rgba(255,34,85,0.06)] p-4 max-w-sm w-full">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle size={13} className="text-[var(--color-danger)] shrink-0" />
              <span className="font-mono text-[0.6rem] tracking-widest text-[var(--color-danger)]">
                {label} — RUNTIME ERROR
              </span>
            </div>
            <p className="font-code text-[0.65rem] text-[var(--text-muted)] text-left leading-relaxed break-all">
              {error.message}
            </p>
          </div>
          <button
            onClick={this.reset}
            className="flex items-center gap-2 px-3 py-1.5 border border-[var(--border-base)] font-mono text-[0.55rem] tracking-widest text-[var(--text-dim)] hover:text-[var(--color-primary)] hover:border-[var(--border-accent)] transition-colors"
          >
            <RefreshCw size={10} />
            RESET {label}
          </button>
        </div>
      )
    }

    return children
  }
}
