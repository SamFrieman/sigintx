"""
SIGINTX — Session Logger
Captures every log record from all backend loggers + every HTTP request
into (a) rotating log files on disk and (b) an in-memory ring buffer
that the /api/v1/logs endpoint serves to the dashboard.
"""

import logging
import os
import time
from collections import deque
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# ── In-memory ring buffer ──────────────────────────────────────────────────────

_RING_SIZE = 2_000          # entries kept in memory
_ring: deque[dict] = deque(maxlen=_RING_SIZE)

# Map Python log level integers → short label
_LEVEL_NAMES = {
    logging.DEBUG:    "DEBUG",
    logging.INFO:     "INFO",
    logging.WARNING:  "WARNING",
    logging.ERROR:    "ERROR",
    logging.CRITICAL: "CRITICAL",
}


class _RingHandler(logging.Handler):
    """Appends every log record to the shared in-memory ring buffer."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            _ring.append({
                "ts":      datetime.fromtimestamp(record.created, tz=timezone.utc)
                           .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "level":   _LEVEL_NAMES.get(record.levelno, record.levelname),
                "logger":  record.name,
                "message": self.format(record),
            })
        except Exception:
            pass   # never crash the application for a log record


# ── Public API ─────────────────────────────────────────────────────────────────

def setup_session_logging(
    log_dir: str = "logs",
    max_bytes: int = 10 * 1024 * 1024,   # 10 MB per file
    backup_count: int = 5,
) -> None:
    """
    Call once at startup (before the FastAPI app starts accepting requests).

    Sets up:
    - A RotatingFileHandler writing to  logs/sigintx.log
    - The _RingHandler writing to the in-memory ring buffer
    Both handlers are attached to the root logger so every library's
    log output (uvicorn, sqlalchemy, httpx, …) is captured.
    """
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "sigintx.log")

    fmt = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    # Rotating file handler
    fh = RotatingFileHandler(log_path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8")
    fh.setFormatter(fmt)
    fh.setLevel(logging.DEBUG)

    # In-memory ring handler
    rh = _RingHandler()
    rh.setFormatter(fmt)
    rh.setLevel(logging.DEBUG)

    root = logging.getLogger()
    # Avoid adding duplicate handlers on hot-reload
    if not any(isinstance(h, _RingHandler) for h in root.handlers):
        root.addHandler(rh)
    if not any(isinstance(h, RotatingFileHandler) and getattr(h, 'baseFilename', '') == os.path.abspath(log_path) for h in root.handlers):
        root.addHandler(fh)

    # Quiet overly chatty third-party libraries at WARNING level
    for noisy in ("httpx", "httpcore", "aiohttp", "asyncio", "multipart"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_recent_logs(limit: int = 200, level: str | None = None) -> list[dict]:
    """
    Return up to `limit` entries from the ring buffer, newest last.
    Optional `level` filter: DEBUG | INFO | WARNING | ERROR | CRITICAL
    """
    entries = list(_ring)
    if level:
        lvl = level.upper()
        entries = [e for e in entries if e["level"] == lvl]
    return entries[-limit:]


# ── Request timing middleware ──────────────────────────────────────────────────

_req_logger = logging.getLogger("sigintx.http")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Logs every inbound HTTP request as:
        POST /api/v1/ai/chat → 200  (847 ms)
    WebSocket upgrades are logged separately by the WS endpoint itself.
    Static/health paths can be filtered to DEBUG to reduce noise.
    """

    _QUIET_PATHS = frozenset({
        "/api/v1/health",
        "/api/v1/stats",
        "/api/v1/collect/status",
    })

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        t0 = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception as exc:
            elapsed = int((time.perf_counter() - t0) * 1000)
            _req_logger.error(
                "%s %s → ERROR (%d ms) — %s",
                request.method, request.url.path, elapsed, exc,
            )
            raise

        elapsed = int((time.perf_counter() - t0) * 1000)
        path = request.url.path

        level = logging.DEBUG if path in self._QUIET_PATHS else logging.INFO
        _req_logger.log(
            level,
            "%s %s → %d  (%d ms)",
            request.method, path, response.status_code, elapsed,
        )
        return response
