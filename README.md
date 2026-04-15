# SIGINTX — Cyber Intelligence Platform

### v3.6.0 · MIT License · Zero Paid APIs Required · 100% Open Source

A real-time cyber intelligence dashboard that aggregates live threat data from 63 RSS feeds and multiple free APIs, correlates CVEs with threat actors, runs AI-powered campaign analysis via local or cloud LLMs, and presents everything in a terminal-aesthetic 8-tab dashboard with WebSocket live updates.

---

## Tech Stack

| Layer | Technology | Version | Purpose |
|---|---|---|---|
| **Frontend** | React | 18.3 | Component-based UI |
| **Frontend** | TypeScript | 5.4 | Type-safe development |
| **Frontend** | Vite | 5.4 | Dev server + bundler |
| **Frontend** | Tailwind CSS | 3.4 | Utility-first styling with custom design tokens |
| **Frontend** | Framer Motion | 11 | Animations and transitions |
| **Frontend** | React Flow | 11 | Correlation graph rendering |
| **Frontend** | react-globe.gl | 2.27 | 3D WebGL threat map globe |
| **Frontend** | Lucide React | 0.383 | Icon system |
| **Backend** | Python | 3.12 | Runtime |
| **Backend** | FastAPI | 0.115 | REST API + WebSocket server |
| **Backend** | SQLAlchemy | 2.0 | Async ORM |
| **Backend** | SQLite / aiosqlite | — | Zero-config local persistence |
| **Backend** | APScheduler | 3.10 | Cron-style data collection jobs |
| **Backend** | httpx | 0.27 | Async HTTP client for collectors |
| **Backend** | feedparser | 6.0 | RSS/Atom feed parsing |
| **Backend** | BeautifulSoup4 | 4.12 | HTML summary extraction |
| **AI** | Ollama | — | Local LLM inference (auto-managed) |
| **AI** | Groq API | — | Optional cloud fallback (free tier) |
| **AI** | OpenRouter | — | Optional cloud fallback (pay-per-use) |
| **Production** | PostgreSQL 16 | — | Production database |
| **Production** | Redis 7 | — | Pub/sub + Celery broker |
| **Production** | Celery | 5.3 | Distributed task queue |
| **Production** | Nginx | — | Reverse proxy + static file serving |
| **Production** | Docker Compose | — | Service orchestration |

---

## Features

### 8-Panel Dashboard

| Tab | Description |
|---|---|
| **Dashboard** | Live stat cards (news/CVEs/IOCs/actors), split news + CVE panels, cyber threat level indicator |
| **News Feed** | 63-source live feed with severity filter, full-text search, expandable per-item AI summaries with model selector |
| **CVE Explorer** | Sortable CVE table with CVSS gauge, EPSS exploitation probability, KEV badge, actor linkage |
| **Threat Actors** | Country-filtered actor profiles with MITRE ATT&CK technique chips and alias expansion |
| **Campaigns** | Actor-grouped campaign timelines + AI-powered hidden campaign discovery from unattributed intel |
| **Correlation** | AI-generated threat graph (actors → campaigns → techniques → news) with animated edges, time-window selector |
| **Threat Map** | 3D WebGL globe — diamond nodes for threat actor origins, circle nodes for attack targets; click any node for full incident details |
| **AI Analyst** | Multi-turn threat analyst chat with model selector, streaming responses, quick-prompt library, agent mode with tool calls, briefing generator, threat delta |

### Intelligence Pipeline

Every ingested item passes through:

1. **Severity classification** — keyword scoring → `CRITICAL / HIGH / MEDIUM / INFO` (CVSS override for CVEs: ≥9.0=CRITICAL, ≥7.0=HIGH, ≥4.0=MEDIUM)
2. **Tag extraction** — 17 categories: `ransomware`, `zero-day`, `APT`, `supply-chain`, `DDoS`, `cloud`, `phishing`, `data-breach`, `critical-infra`, `windows`, `linux`, `network`, `patch`, `CISA`, `malware`, `exploitation`, `vulnerability`
3. **Threat actor detection** — 20+ groups with alias expansion (APT28/Fancy Bear, APT29/Cozy Bear, Lazarus, Volt Typhoon, LockBit, ALPHV/BlackCat, Cl0p, etc.)
4. **CVE extraction** — regex `CVE-YYYY-NNNNN` across title + summary
5. **KEV flagging** — CISA Known Exploited Vulnerabilities catalog, auto-elevates severity
6. **EPSS scoring** — FIRST.org exploitation probability (0.0–1.0)
7. **Semantic deduplication** — title-hash dedup (stop-word stripped, sorted tokens, SHA-1) prevents duplicate stories from multiple RSS sources

### AI Capabilities

- **Streaming chat** — multi-turn analyst with tool calls (query news and actors from DB); news-based CVE references only
- **Model selector** — choose any pulled Ollama model per-conversation from the AI Analyst header
- **Threat briefing** — on-demand streaming briefing formatted for team distribution
- **AI correlation graph** — LLM generates a structured node/edge graph with JSON-mode output and three-stage fallback parser
- **Hidden campaign discovery** — scans unattributed news items for coordinated attack patterns, outputs campaigns with confidence rating, techniques, indicators, and supporting evidence
- **Provider chain** — Ollama (local, auto-managed) → Groq → OpenRouter → Generic OpenAI-compatible endpoint; falls back automatically

### Session Logging

All backend activity during a localhost session is captured to:

- `logs/sigintx.log` — rotating log file (10 MB max, 5 backups kept)
- In-memory ring buffer (last 2,000 entries) — accessible at `GET /api/v1/logs`
- SSE live stream — `GET /api/v1/logs/stream` pushes new entries in real time

Log entries include timestamp, severity level, logger name, and message. Every HTTP request is logged with method, path, response code, and latency in ms. The unified launcher scripts (`start.sh` / `start.bat`) additionally pipe frontend terminal output to `logs/frontend.log`.

---

## Data Sources

| Source | Data | Refresh | API Key |
|---|---|---|---|
| NVD 2.0 API | CVEs + CVSS scores | Every 2 hours | No |
| CISA KEV | Exploited CVE catalog | Every 6 hours | No |
| FIRST EPSS | Exploitation probability | With CVE fetch | No |
| MITRE ATT&CK (GitHub) | Threat actor profiles + techniques | On startup | No |
| AlienVault OTX | Threat pulses + IOCs | Every 30 min | Optional (`OTX_API_KEY`) |
| Abuse.ch MalwareBazaar | Malware hashes | Every 30 min | No |
| Abuse.ch URLhaus | Malicious URLs | Every 30 min | No |
| Abuse.ch ThreatFox | IOCs with confidence scores | Every 30 min | No |
| RansomWatch | Ransomware victim feed | Every 15 min | No |
| **63 RSS feeds** | Security / Tech / Crypto / Politics news | Every 5 min | No |

**RSS feed categories:** 16 security feeds (BleepingComputer, Krebs, The Hacker News, SecurityWeek, Dark Reading, SANS ISC, CISA, Schneier, CrowdStrike, Rapid7, Talos, Google Project Zero, Malwarebytes, and more) · 16 tech feeds · 15 crypto feeds · 16 politics/geopolitics feeds

---

## Running Locally (Development)

### Prerequisites

- Python 3.11+
- Node.js 20+
- Git
- [Ollama](https://ollama.com) (optional — auto-installed if missing)

### 1 — Clone the repository

```bash
git clone https://github.com/yourname/sigintx
cd sigintx
```

### 2 — Option A: Unified launcher (recommended)

The launcher starts both services and logs all terminal output to the `logs/` directory.

**Windows:**
```bat
start.bat
```

**macOS / Linux:**
```bash
chmod +x start.sh
./start.sh
```

Both services will start in parallel. Log files are written to:
```
logs/sigintx.log    ← backend Python logs (all levels)
logs/backend.log    ← raw backend terminal output
logs/frontend.log   ← raw frontend terminal output
```

### 2 — Option B: Manual (two terminals)

**Terminal 1 — Backend:**
```bash
cd backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate          # macOS / Linux
venv\Scripts\activate             # Windows

# Install dependencies
pip install -r requirements.txt

# Start the API server
uvicorn main:app --reload --port 8000
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm install
npm run dev
```

The API is live at `http://localhost:8000`. On first start it will:
- Initialize the SQLite database
- Seed threat actors from MITRE ATT&CK
- Populate the 63 RSS feeds
- Begin background data collection immediately
- Auto-download and start Ollama with `llama3.2:3b` (if Ollama is installed)

Dashboard at `http://localhost:5173` — Vite proxies `/api` and `/ws` to the backend automatically.

### Optional: Configure AI providers

Open the **Settings** tab in the dashboard:

| Setting | Description |
|---|---|
| `GROQ_API_KEY` | Free-tier cloud LLM fallback (groq.com) |
| `OPENROUTER_API_KEY` | Pay-per-use cloud LLM router |
| `OTX_API_KEY` | AlienVault OTX threat pulses |
| `WEBHOOK_URL` | Slack/Discord/custom alert webhook |
| `WEBHOOK_MIN_SEVERITY` | Minimum severity to trigger webhook |

All settings persist to the database — no `.env` file required for development.

---

## Running in Production (Docker Compose)

```bash
# Build and start all services
docker compose up -d --build

# Tail all logs
docker compose logs -f

# Tail a specific service
docker compose logs -f api

# Stop all services
docker compose down

# Stop and wipe database volumes
docker compose down -v
```

| Service | Port | Description |
|---|---|---|
| `postgres` | 5432 (internal) | PostgreSQL 16 database |
| `redis` | 6379 (internal) | Cache + Celery broker |
| `api` | 8000 | FastAPI backend + WebSocket |
| `worker` | — | Celery async task worker |
| `beat` | — | Celery Beat scheduler |
| `frontend` | 5173 | Nginx serving built React app + API proxy |

**Required environment variables** (`docker-compose.yml` or `.env`):

```env
DATABASE_URL=postgresql+asyncpg://sigintx:sigintx@postgres/sigintx
REDIS_URL=redis://redis:6379
JWT_SECRET=change-me-in-production
AUTH_DISABLED=false

# Optional AI providers
GROQ_API_KEY=
OPENROUTER_API_KEY=

# Optional data sources
OTX_API_KEY=
```

---

## Key API Endpoints

### Data
```
GET  /api/v1/health                          Server health + version
GET  /api/v1/stats                           Aggregate counts (news/CVEs/IOCs/actors)
GET  /api/v1/news?limit=50&severity=HIGH     Filtered news feed with FTS search
GET  /api/v1/cves?in_kev=true&min_cvss=7     CVE explorer
GET  /api/v1/actors?country=Russia           Threat actor profiles
GET  /api/v1/campaigns?days_back=30          Actor-grouped campaign timelines
GET  /api/v1/iocs                            IOC database
GET  /api/v1/threat-level                    DEFCON-style cyber threat level (1–5)
GET  /api/v1/source-health                   RSS + collector health status
GET  /api/v1/alert-log                       Triggered alert history
GET  /api/v1/audit-log                       Admin audit trail
```

### Collection triggers
```
POST /api/v1/collect/rss                     Manually trigger RSS collection
POST /api/v1/collect/ransomwatch             Manually trigger RansomWatch fetch
POST /api/v1/analyze                         SSE stream — item AI analysis
```

### Correlation & Campaigns
```
GET  /api/v1/correlation                     Static CVE↔actor graph data
GET  /api/v1/correlation/ai?hours_back=48    AI-generated correlation graph (cached 10 min)
POST /api/v1/campaigns/ai-discover           AI hidden campaign discovery
```

### AI Analyst
```
GET  /api/v1/ai/status                       LLM provider chain + model list
GET  /api/v1/ai/context                      Live threat context snapshot
GET  /api/v1/ai/delta                        Current vs baseline threat comparison
POST /api/v1/ai/chat                         SSE streaming analyst chat
POST /api/v1/ai/agent/chat                   SSE agentic ReAct loop (DB tool calls)
POST /api/v1/ai/briefing/generate            Generate briefing (non-streaming)
POST /api/v1/ai/briefing/stream              SSE streaming briefing generation
GET  /api/v1/ai/briefing                     Latest stored briefing
GET  /api/v1/ai/briefings                    Briefing history
GET  /api/v1/ai/chat/history                 Persistent chat history
POST /api/v1/ai/chat/history                 Save a chat message
DELETE /api/v1/ai/chat/history/{session_id}  Clear session history
```

### Ollama management
```
GET  /api/v1/ollama/setup-status             Auto-install progress
GET  /api/v1/ollama/models                   Pulled model list
POST /api/v1/ollama/pull                     Pull a new model (SSE progress)
DELETE /api/v1/ollama/models/{name}          Delete a model
```

### Settings, Feeds & Watchlists
```
GET  /api/v1/settings                        All persisted settings
POST /api/v1/settings                        Update a setting
POST /api/v1/settings/test                   Test webhook/API key
GET  /api/v1/feeds                           RSS feed list + enabled status
POST /api/v1/feeds                           Add a custom RSS feed
DELETE /api/v1/feeds/{id}                    Remove a feed
POST /api/v1/feeds/reset                     Reset to canonical feed list
GET  /api/v1/watchlists                      Keyword watchlist entries
POST /api/v1/watchlists                      Add a watchlist entry
DELETE /api/v1/watchlists/{id}               Remove a watchlist entry
```

### Logging
```
GET  /api/v1/logs?limit=200&level=INFO       Recent session log entries (ring buffer)
GET  /api/v1/logs/stream                     SSE live log stream
```

### WebSocket
```
WS   /ws                                     Live push notifications (new items, alerts)
```

---

## Project Structure

```
sigintx/
├── start.sh                     # Unified launcher — macOS/Linux (logs both terminals)
├── start.bat                    # Unified launcher — Windows  (logs both terminals)
├── docker-compose.yml
├── README.md
│
├── logs/                        # Created at runtime
│   ├── sigintx.log              # Rotating backend log (10 MB × 5 backups)
│   ├── backend.log              # Raw backend terminal output (via launcher)
│   └── frontend.log             # Raw frontend terminal output (via launcher)
│
├── backend/
│   ├── main.py                  # FastAPI app, all routes, WebSocket, lifespan
│   ├── database.py              # SQLAlchemy async models (17 tables)
│   ├── enrichment.py            # Severity scoring, tagging, actor detection, CVE extraction
│   ├── correlate.py             # CVE↔actor co-occurrence, campaign reconstruction, webhooks
│   ├── agents.py                # AI analyst system prompt, tool dispatch, context builder
│   ├── llm.py                   # Multi-provider LLM client (Ollama → Groq → OpenRouter)
│   ├── session_logger.py        # In-memory ring buffer + rotating file log + HTTP middleware
│   ├── ollama_manager.py        # Automatic Ollama install/serve/pull lifecycle
│   ├── rules_engine.py          # Alert rule evaluation engine
│   ├── scheduler.py             # APScheduler job runner
│   ├── auth.py                  # JWT auth + AUTH_DISABLED bypass
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── alembic.ini
│   └── collectors/
│       ├── rss_collector.py     # 63 RSS feeds, semantic dedup, orphan cleanup
│       ├── cve_collector.py     # NVD 2.0 + CISA KEV + EPSS
│       ├── mitre_collector.py   # MITRE ATT&CK STIX → ThreatActor seed
│       ├── abusech_collector.py # MalwareBazaar + URLhaus + ThreatFox
│       ├── otx_collector.py     # AlienVault OTX pulses
│       └── ransomwatch_collector.py
│
└── frontend/
    └── src/
        ├── App.tsx              # Root layout, 8-tab navigation, WebSocket integration
        ├── types/index.ts       # TypeScript interfaces
        ├── hooks/
        │   ├── useApi.ts        # Fetch hook with abort, polling, refresh triggers
        │   └── useWebSocket.ts  # Auto-reconnecting WebSocket
        └── components/
            ├── StatusBar.tsx         # Top bar: logo, stats, threat level, collect triggers
            ├── IntelSummary.tsx      # Animated stat cards
            ├── NewsFeed.tsx          # Live feed with search, filters, per-item AI analysis
            ├── CveExplorer.tsx       # CVE table with CVSS/EPSS gauges + KEV badge
            ├── ThreatActors.tsx      # Actor cards with MITRE technique chips
            ├── CampaignTimeline.tsx  # Campaign timelines + AI hidden campaign discovery
            ├── CorrelationGraph.tsx  # AI-generated React Flow graph (type-grouped rows)
            ├── ThreatMap.tsx         # 3D WebGL globe — interactive actor + target nodes
            ├── AiAnalyst.tsx         # Streaming chat, model selector, briefing, agent mode
            ├── DefconIndicator.tsx   # Animated 5-bar threat level widget
            ├── IocExplorer.tsx       # IOC indicator browser
            ├── Settings.tsx          # Persistent settings panel
            ├── ModelManager.tsx      # Ollama model management UI
            ├── AlertRules.tsx        # Alert rule editor
            ├── Watchlists.tsx        # Keyword watchlist manager
            └── ActivityPanel.tsx     # Recent activity feed
```

---

## Design System

SIGINTX uses a three-layer token architecture (Primitive → Semantic → Component) defined in `tailwind.config.ts` and `index.css`.

**Severity palette:**

| Level | Color | Trigger |
|---|---|---|
| `CRITICAL` | `#ff2255` | Zero-days, KEV-listed, active ransomware, CVSS ≥ 9 |
| `HIGH` | `#ffaa00` | APT activity, mass exploitation, CVSS ≥ 7 |
| `MEDIUM` | `#00d4ff` | New CVEs, advisories, patching news, CVSS ≥ 4 |
| `INFO` | `#00ff88` | Research, patches, general security news |

**Threat Map node colors:**

| Country | Color |
|---|---|
| Russia | `#ff4444` |
| China | `#ff6600` |
| North Korea | `#aa44ff` |
| Iran | `#00d4ff` |

**Fonts:** Orbitron (display headings) · Rajdhani (section headings) · Share Tech Mono (labels/badges) · IBM Plex Mono (code)

**Effects:** CRT scanline overlay · vignette · dot-grid background · glowing borders on active elements · diamond-glow pulse animation on threat actor origin nodes

---

## Changelog

### v3.6.0 — 2026-04-14
- `ADDED` `session_logger.py` — captures all backend log output to rotating files (`logs/sigintx.log`) and an in-memory ring buffer (2,000 entries) accessible at `GET /api/v1/logs`
- `ADDED` `GET /api/v1/logs/stream` — SSE endpoint that live-tails the log ring buffer (1-second poll)
- `ADDED` `RequestLoggingMiddleware` — every HTTP request logged with method, path, status code, and latency (ms); quiet paths like `/health` downgraded to DEBUG
- `ADDED` `start.sh` / `start.bat` — unified launchers that start backend + frontend together and pipe both terminal sessions to log files (`logs/backend.log`, `logs/frontend.log`)
- `ADDED` AI Analyst model selector — `AUTO` button + one button per pulled Ollama model; selected model passed as `model` in the POST body to `/api/v1/ai/chat` and `/api/v1/ai/agent/chat`
- `FIXED` ThreatMap diamond node square-outline bug — added dedicated `@keyframes diamond-pulse` that preserves `rotate(45deg)` in every frame, preventing diamond halos from collapsing into square outlines
- `IMPROVED` ThreatMap actor origin nodes — country name label below each diamond; `e.stopPropagation()` on click events prevents the globe's pan handler from swallowing node clicks
- `IMPROVED` ThreatMap attack target nodes — city name label below each circle; `e.stopPropagation()` on click; secondary outer ring for `CRITICAL` targets

### v3.5.0 — 2026-04-13
- `FIXED` Correlation graph HTTP 500 — JSON-mode (`response_format: json_object`) added to Ollama calls + three-stage fallback JSON parser (direct → extract `{}` → bracket-repair truncated output)
- `FIXED` Dead RSS feeds still running — bulk SQL `UPDATE ... WHERE name NOT IN (canonical_names)` correctly disables stale DB entries on every startup
- `FIXED` AI campaign cache was global — now keyed by `days_back` so 30D and 60D windows cache independently
- `FIXED` `suspected_actor: null` displayed as literal string — backend normalises `"null"`, `"none"`, `"unknown"` to Python `None`; frontend adds secondary string guard
- `IMPROVED` ThreatMap — dark earth night texture (city lights), thicker arcs (stroke 1.2), larger nodes (CRITICAL 16px, HIGH 11px), stronger glow, atmosphere altitude 0.25
- `IMPROVED` ThreatMap — diamond nodes (actor origins) + circle nodes (attack targets) with clickable detail panels; arc source/destination split to separate node types
- `IMPROVED` AI Analyst — `loadStatus()` throttled to once per 60 s eliminating Ollama `/api/tags` saturation

### v3.4.0 — 2026-04-12
- `ADDED` `POST /api/v1/campaigns/ai-discover` — LLM scans unattributed news for hidden campaigns; returns confidence, techniques, indicators, supporting articles
- `ADDED` `CampaignTimeline` AI Discover tab — amber-themed with loading/error/empty states, per-window cache invalidation
- `ADDED` `llm.py` `json_mode` parameter — `response_format: {"type": "json_object"}`
- `FIXED` AI status endpoint — 30-second server-side TTL prevents repeated Ollama polling
- `FIXED` AI correlation — asyncio `Future` in-flight deduplication prevents concurrent duplicate LLM calls

### v3.3.0 — 2026-04-10
- `FIXED` Campaigns tab unclickable — `AnimatePresence mode="wait"` replacing `"sync"` + removed `position: absolute` from exit animation that left invisible overlay
- `FIXED` Correlation graph single-row layout — LLM edge IDs were case-mismatched against node IDs; added case-insensitive lookup map
- `FIXED` DefconIndicator bar overflow — clamped bar height formula
- `FIXED` Scrollbars visible across panels — global `scrollbar-width: none` added
- `REPLACED` Dagre layout — removed dependency; custom type-grouped row layout (actors → campaigns → techniques → news)
- `IMPROVED` Correlation edges — animated technique/target edges, drop-shadow on verified edges

### v3.2.0 — 2026-04-09
- `ADDED` Multi-provider LLM chain — Ollama → Groq → OpenRouter → Generic, automatic failover
- `ADDED` Ollama auto-manager — detects, installs, starts, and pulls default model
- `ADDED` AI Analyst v2 — streaming multi-turn chat, quick-prompt library, agent mode with DB tool calls, history persistence
- `ADDED` Threat briefing generator — streaming formatted briefing with executive summary
- `ADDED` AI correlation graph — LLM-generated node/edge graph from recent high-severity news
- `ADDED` Auth layer — JWT-based login with `AUTH_DISABLED` env var
- `ADDED` Alert rules engine — configurable severity/keyword/actor triggers
- `ADDED` DefconIndicator — animated 5-bar threat level widget
- `REPLACED` Cobe globe → react-globe.gl — richer arc visualization with HTML node overlays

### v1.3.0 — 2026-04-06
- `ADDED` `correlate.py` — CVE ↔ actor co-occurrence engine + actor campaign timelines
- `ADDED` Webhook alert system (Slack/Discord/custom endpoint)
- `ADDED` Settings tab + database-persisted settings
- `ADDED` `CampaignTimeline.tsx` — expandable actor campaign cards with event timeline
- `ADDED` MITRE ATT&CK technique drill-down in actor cards
- `REPLACED` SVG flat map → Cobe WebGL 3D globe

### v1.2.0 — 2026-04-04
- `ADDED` React Flow correlation graph (CVE ↔ Actor ↔ News nodes)
- `ADDED` Per-item Ollama streaming analysis panel
- `ADDED` Abuse.ch collectors (MalwareBazaar, URLhaus, ThreatFox)
- `ADDED` AlienVault OTX pulse ingestion
- `ADDED` RansomWatch victim feed collector
- `ADDED` SQLite FTS5 full-text search

### v1.1.0 — 2026-04-01
- `ARCH` FastAPI async backend + SQLite + APScheduler + WebSocket
- `ADDED` NVD 2.0 + CISA KEV + FIRST EPSS + MITRE ATT&CK collectors
- `ADDED` 15+ RSS feeds with semantic deduplication
- `ADDED` Enrichment engine: severity, tags, actor detection, CVE extraction
- `DESIGN` SIGINTX terminal design system (three-layer token architecture)
- `UI` All 5 initial dashboard views

### v1.0.0 — 2026-03-31
- Initial architecture specification and design system definition
