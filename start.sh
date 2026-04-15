#!/usr/bin/env bash
# SIGINTX — Unified dev launcher (macOS / Linux)
# Starts the FastAPI backend + Vite frontend, both logging to ./logs/

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$ROOT/logs"
mkdir -p "$LOG_DIR"

cleanup() {
  echo ""
  echo "[SIGINTX] Shutting down..."
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null
  wait "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null
  echo "[SIGINTX] Done."
}
trap cleanup EXIT INT TERM

echo "[SIGINTX] Starting backend..."
cd "$ROOT/backend"
source venv/bin/activate 2>/dev/null || true
uvicorn main:app --reload --port 8000 2>&1 | tee "$LOG_DIR/backend.log" &
BACKEND_PID=$!

echo "[SIGINTX] Starting frontend..."
cd "$ROOT/frontend"
npm run dev 2>&1 | tee "$LOG_DIR/frontend.log" &
FRONTEND_PID=$!

echo ""
echo "  Backend  → http://localhost:8000"
echo "  Frontend → http://localhost:5173"
echo "  Logs     → $LOG_DIR/"
echo ""
echo "  Press Ctrl+C to stop all services."
echo ""

wait
