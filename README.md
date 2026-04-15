# SIGINTX — Cyber Intelligence Platform

### v4.0.0 · MIT License · Zero Paid APIs Required · 100% Open Source

A real-time signals intelligence dashboard that aggregates live data from **148 RSS feeds** across security, tech, crypto, politics, and AI — delivering a new article every 1–2 minutes. Tracks threat actors, correlates campaigns, maps global attacks on a 3D globe, and lets you query everything through a built-in AI analyst powered by Ollama, Groq, or OpenRouter.

**[Live Demo](https://sigintx.vercel.app)** · **[Deploy on Render + Vercel](#deploy-to-render--vercel-free)**

---

## Screenshots

> Dashboard · Threat Map · AI Analyst · Correlation Graph

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Frontend** | React 18 + TypeScript 5 | Component UI |
| **Frontend** | Vite 5 | Dev server + production bundler |
| **Frontend** | Tailwind CSS 3 | Utility-first styling with custom design tokens |
| **Frontend** | Framer Motion 11 | Animations and transitions |
| **Frontend** | React Flow | Correlation graph rendering |
| **Frontend** | react-globe.gl | 3D WebGL interactive threat map |
| **Frontend** | Lucide React | Icon system |
| **Backend** | Python 3.12 + FastAPI | REST API + WebSocket server |
| **Backend** | SQLAlchemy 2.0 (async) | ORM — SQLite for dev, PostgreSQL for prod |
| **Backend** | APScheduler | Background data collection (3-min RSS cycle) |
| **Backend** | httpx + feedparser | Async HTTP + RSS/Atom parsing |
| **Backend** | BeautifulSoup4 | HTML summary extraction |
| **AI** | Ollama | Local LLM inference (auto-managed) |
| **AI** | Groq API | Free-tier cloud fallback |
| **AI** | OpenRouter | Pay-per-use multi-model fallback |
| **Production** | PostgreSQL 16 | Production database |
| **Production** | Redis 7 | Pub/sub + Celery task broker |
| **Production** | Celery 5 | Distributed task queue |
| **Production** | Nginx | Reverse proxy + static serving + security headers |
| **Deploy** | Render | Backend hosting (free tier) |
| **Deploy** | Vercel | Frontend hosting (free tier) |
| **Deploy** | Docker Compose | Self-hosted alternative |

---

## Features

### 8-Panel Dashboard

| Tab | Description |
|---|---|
| **Dashboard** | Live stat cards, split news + activity feed, DEFCON cyber threat level indicator |
| **News Feed** | 148-source live feed — filter by category (Security / Tech / Crypto / Politics / AI), severity, full-text search, per-item AI analysis |
| **Threat Actors** | Country-filtered actor profiles with MITRE ATT&CK technique chips and alias expansion |
| **Campaigns** | Actor-grouped campaign timelines + AI-powered hidden campaign discovery from unattributed intel |
| **Correlation** | AI-generated threat graph (actors → campaigns → techniques → news) with animated edges and time-window selector |
| **Threat Map** | 3D WebGL globe — diamond nodes for threat actor origins, circle nodes for attack targets; click any node for full incident details |
| **AI Analyst** | Multi-turn threat analyst chat with model selector, streaming responses, quick-prompt library, agent mode with DB tool calls, briefing generator, and threat delta |
| **Settings** | Persistent configuration — AI providers, webhook alerts, watchlists, RSS feeds, Ollama model manager |

### Intelligence Pipeline

Every ingested item passes through an enrichment chain:

1. **Severity classification** — keyword scoring → `CRITICAL / HIGH / MEDIUM / INFO`
2. **Tag extraction** — 17 categories: `ransomware`, `zero-day`, `APT`, `supply-chain`, `DDoS`, `cloud`, `phishing`, `data-breach`, `critical-infra`, `windows`, `linux`, `network`, `patch`, `CISA`, `malware`, `exploitation`, `vulnerability`
3. **Threat actor detection** — 20+ groups with alias expansion (APT28/Fancy Bear, APT29/Cozy Bear, Lazarus, Volt Typhoon, LockBit, ALPHV/BlackCat, Cl0p, and more)
4. **CVE extraction** — regex `CVE-YYYY-NNNNN` across title + summary
5. **Semantic deduplication** — title-hash dedup (stop-word stripped, sorted tokens, SHA-1) prevents the same story from multiple RSS sources counting twice

### AI Capabilities

- **Streaming chat** — multi-turn analyst with live tool calls querying the news and actor database
- **Model selector** — choose any pulled Ollama model per-conversation
- **Full markdown rendering** — tables, bold, italic, code blocks, blockquotes all render correctly
- **Threat briefing** — on-demand streaming briefing formatted for team distribution
- **AI correlation graph** — LLM generates a structured node/edge graph with JSON-mode output and three-stage fallback parser
- **Hidden campaign discovery** — scans unattributed news items for coordinated attack patterns; outputs confidence rating, techniques, indicators, and supporting evidence
- **Provider chain** — Ollama (local, auto-managed) → Groq → OpenRouter → Generic OpenAI-compatible endpoint; falls back automatically if any provider is unavailable

### Session Logging

All backend activity is captured to:

- `logs/sigintx.log` — rotating log file (10 MB max, 5 backups)
- In-memory ring buffer (last 2,000 entries) — accessible at `GET /api/v1/logs`
- SSE live stream — `GET /api/v1/logs/stream` pushes new entries in real time

Every HTTP request is logged with method, path, status code, and latency in ms.

---

## Data Sources

| Source | Data | Refresh | API Key |
|---|---|---|---|
| NVD 2.0 API | CVEs + CVSS scores | Every 2 hours | No |
| CISA KEV | Exploited CVE catalog | Every 6 hours | No |
| FIRST EPSS | Exploitation probability | With CVE fetch | No |
| MITRE ATT&CK | Threat actor profiles + techniques | On startup | No |
| AlienVault OTX | Threat pulses + IOCs | Every 30 min | Optional |
| Abuse.ch MalwareBazaar | Malware hashes | Every 30 min | No |
| Abuse.ch URLhaus | Malicious URLs | Every 30 min | No |
| Abuse.ch ThreatFox | IOCs with confidence scores | Every 30 min | No |
| RansomWatch | Ransomware victim feed | Every 10 min | No |
| **148 RSS feeds** | Security / Tech / Crypto / Politics / AI | Every 3 min | No |

### RSS Feed Coverage (148 feeds · ~1 new article every 1–2 minutes)

| Category | Count | Notable Sources |
|---|---|---|
| **Security** | 31 | BleepingComputer, Krebs on Security, The Hacker News, SecurityWeek, Dark Reading, CISA, Talos, Unit 42, Securelist, WeLiveSecurity, CrowdStrike, CyberScoop, The Record, and more |
| **Tech** | 31 | Ars Technica, The Verge, TechCrunch, Wired, MIT Tech Review, IEEE Spectrum, CNET, Slashdot, 9to5Google, Tom's Hardware, The Next Web, TechRadar, and more |
| **Crypto** | 25 | CoinDesk, CoinTelegraph, Decrypt, The Block, Blockworks, Bitcoin Magazine, CryptoSlate, BeInCrypto, The Defiant, and more |
| **Politics** | 31 | Reuters, BBC World, AP News, Al Jazeera, Foreign Policy, Defense One, Lawfare, Brookings, War on the Rocks, The Intercept, and more |
| **AI** | 27 | VentureBeat AI, TechCrunch AI, Hugging Face Blog, OpenAI Blog, Google DeepMind, The Batch, The Decoder, MIT News AI, NVIDIA Blog, Google AI Blog, and more |

---

## Running Locally

### Prerequisites

- Python 3.11+
- Node.js 20+
- Git
- [Ollama](https://ollama.com) — optional, enables local AI inference

### 1 — Clone

```powershell
git clone https://github.com/YOUR_USERNAME/sigintx
cd sigintx
```

### 2A — Unified launcher (recommended)

Starts both services and tees all output to `logs/`.

**Windows (PowerShell):**
```powershell
.\start.bat
```

**macOS / Linux:**
```bash
chmod +x start.sh && ./start.sh
```

### 2B — Manual (two terminals)

**Terminal 1 — Backend:**
```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1       # Windows PowerShell
# source venv/bin/activate        # macOS / Linux
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**Terminal 2 — Frontend:**
```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` — the Vite dev server proxies `/api` and `/ws` to the backend automatically.

On first start the backend will:
- Create the SQLite database
- Seed threat actors from MITRE ATT&CK
- Populate all 148 RSS feeds
- Begin background collection immediately
- Auto-download and start Ollama with `llama3.2:3b` (if Ollama is installed)

> **Auth in dev mode:** `AUTH_DISABLED=true` by default locally — no login required. Set it to `false` and provide a `JWT_SECRET` if you want to test the auth flow.

---

## Deploy to Render + Vercel (Free)

The fastest way to get SIGINTX running publicly at zero cost.

### Architecture

```
Browser → Vercel (React frontend)
             ↓ VITE_API_URL
        Render (FastAPI backend)
             ↓
        Render PostgreSQL + Redis
```

### Step 1 — Push to GitHub

```powershell
cd sigintx

# Delete local DB and logs before first commit
Remove-Item -Force backend\sigintx.db, backend\sigintx.db-shm, backend\sigintx.db-wal -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force logs -ErrorAction SilentlyContinue

git init
git branch -M main
git add .
git status        # verify no .db / .env / venv files appear
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/sigintx.git
git push -u origin main
```

### Step 2 — Deploy backend on Render

1. Go to [render.com](https://render.com) → **New → Blueprint**
2. Connect your GitHub repo — Render detects `render.yaml` and creates the API service, PostgreSQL, and Redis automatically
3. Wait for the first deploy to complete (~3 min)
4. Copy your backend URL: `https://sigintx-api.onrender.com`

### Step 3 — Deploy frontend on Vercel

1. Go to [vercel.com](https://vercel.com) → **New Project** → import your repo
2. Set **Root Directory** to `frontend`
3. Add these environment variables:

| Variable | Value |
|---|---|
| `VITE_API_URL` | `https://sigintx-api.onrender.com` |
| `VITE_AUTH_DISABLED` | `true` |

4. Deploy — Vercel auto-detects Vite and runs `npm run build`

### Step 4 — Update CORS on Render

In **Render Dashboard → sigintx-api → Environment**, update `ALLOWED_ORIGINS` to include your Vercel URL:

```
https://sigintx-abc123.vercel.app,http://localhost:5173
```

Render restarts the service automatically.

> **Free tier notes:** Render's free web service sleeps after 15 min of inactivity — expect a ~30s cold start on the first visit. Upgrade to the Starter plan ($7/mo) for always-on. Free PostgreSQL is limited to 1 GB.

---

## Self-Hosted with Docker Compose

For running on your own Linux server or VPS.

```bash
# 1. Copy the environment template and fill in your values
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD, REDIS_PASSWORD, JWT_SECRET at minimum

# 2. Generate a JWT secret
openssl rand -hex 32

# 3. Start all services
docker compose up -d --build

# 4. Tail logs
docker compose logs -f api
```

| Service | Exposed | Description |
|---|---|---|
| `postgres` | Internal only | PostgreSQL 16 |
| `redis` | Internal only | Cache + Celery broker |
| `api` | Internal only (via nginx) | FastAPI backend + WebSocket |
| `worker` | — | Celery async task worker |
| `beat` | — | Celery Beat scheduler |
| `frontend` | `80` | Nginx: React app + API proxy + security headers |

All secrets are read from `.env` — see `.env.example` for the full list of required variables.

---

## API Reference

### Core data
```
GET  /api/v1/health                          Server health + version
GET  /api/v1/stats                           Aggregate counts
GET  /api/v1/news?limit=50&severity=HIGH     Filtered + searchable news feed
GET  /api/v1/actors?country=Russia           Threat actor profiles
GET  /api/v1/campaigns?days_back=30          Campaign timelines
GET  /api/v1/iocs                            IOC database
GET  /api/v1/threat-level                    DEFCON-style threat level (1–5)
GET  /api/v1/source-health                   RSS + collector status
GET  /api/v1/cves?in_kev=true&min_cvss=7     CVE explorer
```

### Collection
```
POST /api/v1/collect/rss                     Trigger RSS collection
POST /api/v1/collect/ransomwatch             Trigger RansomWatch fetch
POST /api/v1/analyze                         SSE stream — single-item AI analysis
```

### Correlation & campaigns
```
GET  /api/v1/correlation/ai?hours_back=48    AI correlation graph (cached 10 min)
POST /api/v1/campaigns/ai-discover           AI hidden campaign discovery
```

### AI Analyst
```
GET  /api/v1/ai/status                       LLM provider chain + available models
POST /api/v1/ai/chat                         SSE streaming analyst chat
POST /api/v1/ai/agent/chat                   SSE agentic mode (DB tool calls)
POST /api/v1/ai/briefing/stream              SSE streaming briefing
GET  /api/v1/ai/briefing                     Latest stored briefing
GET  /api/v1/ai/delta                        Threat delta (current vs baseline)
GET  /api/v1/ai/chat/history                 Persistent chat history
DELETE /api/v1/ai/chat/history/{session_id}  Clear session
```

### Ollama management
```
GET  /api/v1/ollama/models                   Pulled model list
POST /api/v1/ollama/pull                     Pull a new model (SSE progress)
DELETE /api/v1/ollama/models/{name}          Delete a model
```

### Settings, feeds & watchlists
```
GET  /api/v1/settings                        All persisted settings
POST /api/v1/settings                        Update a setting
GET  /api/v1/feeds                           RSS feed list + enabled status
POST /api/v1/feeds                           Add a custom RSS feed
DELETE /api/v1/feeds/{id}                    Remove a feed
POST /api/v1/feeds/reset                     Reset to defaults
GET  /api/v1/watchlists                      Keyword watchlist entries
POST /api/v1/watchlists                      Add entry
DELETE /api/v1/watchlists/{id}               Remove entry
```

### Logging
```
GET  /api/v1/logs?limit=200&level=INFO       Recent log ring buffer
GET  /api/v1/logs/stream                     SSE live log tail
WS   /ws                                     Live push (new items, alerts)
```

---

## Project Structure

```
sigintx/
├── .env.example                 # Environment variable template — copy to .env
├── .gitignore
├── render.yaml                  # Render Blueprint — auto-creates API + DB + Redis
├── docker-compose.yml           # Self-hosted alternative
├── start.sh                     # Dev launcher — macOS/Linux
├── start.bat                    # Dev launcher — Windows
│
├── backend/
│   ├── main.py                  # FastAPI app, all routes, WebSocket, lifespan
│   ├── database.py              # SQLAlchemy async models
│   ├── auth.py                  # JWT auth (disabled by default for demo)
│   ├── enrichment.py            # Severity, tags, actor detection, CVE extraction
│   ├── correlate.py             # CVE↔actor co-occurrence, campaign engine, webhooks
│   ├── agents.py                # AI analyst prompt, tool dispatch, context builder
│   ├── llm.py                   # Multi-provider LLM client (Ollama→Groq→OpenRouter)
│   ├── session_logger.py        # Ring buffer + rotating file + HTTP middleware
│   ├── ollama_manager.py        # Automatic Ollama install/serve/pull lifecycle
│   ├── rules_engine.py          # Alert rule evaluation
│   ├── scheduler.py             # APScheduler (dev) / Celery Beat (prod)
│   ├── requirements.txt         # Pinned dependencies
│   ├── Dockerfile
│   └── collectors/
│       ├── rss_collector.py     # 148 RSS feeds, semantic dedup, 3-min cycle
│       ├── cve_collector.py     # NVD 2.0 + CISA KEV + EPSS
│       ├── mitre_collector.py   # MITRE ATT&CK STIX → ThreatActor seed
│       ├── abusech_collector.py # MalwareBazaar + URLhaus + ThreatFox
│       ├── otx_collector.py     # AlienVault OTX pulses
│       └── ransomwatch_collector.py
│
└── frontend/
    ├── vercel.json              # Vercel SPA routing
    ├── Dockerfile               # Multi-stage build (builder → nginx)
    ├── nginx.conf               # Security headers + proxy + gzip + asset caching
    └── src/
        ├── App.tsx              # Root layout, 8-tab navigation, WebSocket
        ├── vite-env.d.ts        # VITE_API_URL / VITE_AUTH_DISABLED type declarations
        ├── types/index.ts       # TypeScript interfaces
        ├── hooks/
        │   ├── useApi.ts        # Fetch hook — env-aware base URL, abort, polling
        │   └── useWebSocket.ts  # Auto-reconnecting WebSocket with heartbeat
        └── components/
            ├── StatusBar.tsx         # Top bar: logo, stats, threat level
            ├── NewsFeed.tsx          # Live feed — 5 category tabs, search, filters
            ├── ThreatActors.tsx      # Actor cards with MITRE technique chips
            ├── CampaignTimeline.tsx  # Campaign timelines + AI discovery
            ├── CorrelationGraph.tsx  # AI-generated React Flow graph
            ├── ThreatMap.tsx         # 3D WebGL globe — interactive nodes + panels
            ├── AiAnalyst.tsx         # Streaming chat, model selector, briefing
            ├── DefconIndicator.tsx   # Animated 5-bar threat level widget
            ├── Settings.tsx          # Persistent settings panel
            ├── ModelManager.tsx      # Ollama model management UI
            ├── AlertRules.tsx        # Alert rule editor
            ├── Watchlists.tsx        # Keyword watchlist manager
            ├── ConferenceCalendar.tsx# Security conference calendar
            ├── IocExplorer.tsx       # IOC browser
            └── ActivityPanel.tsx     # Recent activity feed
```

---

## Design System

SIGINTX uses a three-layer token architecture (Primitive → Semantic → Component).

**Severity palette:**

| Level | Color | Trigger |
|---|---|---|
| `CRITICAL` | `#ff2255` | Zero-days, KEV-listed, active ransomware, CVSS ≥ 9 |
| `HIGH` | `#ffaa00` | APT activity, mass exploitation, CVSS ≥ 7 |
| `MEDIUM` | `#00d4ff` | New CVEs, advisories, CVSS ≥ 4 |
| `INFO` | `#00ff88` | Research, patches, general news |

**Category palette:**

| Category | Color |
|---|---|
| Security | `#ff4444` |
| Tech | `#00d4ff` |
| Crypto | `#f7931a` |
| Politics | `#a855f7` |
| AI | `#22d3a5` |

**Threat Map node colors:**

| Actor Origin | Color |
|---|---|
| Russia | `#ff4444` |
| China | `#ff6600` |
| North Korea | `#aa44ff` |
| Iran | `#00d4ff` |

**Fonts:** Orbitron (display) · Rajdhani (headings) · Share Tech Mono (labels) · IBM Plex Mono (code)

**Effects:** CRT scanline overlay · vignette · dot-grid background · glowing borders · diamond-glow pulse on actor origin nodes

---

## Changelog

### v4.0.0 — 2026-04-14
- `ADDED` **AI news category** — 27 new feeds: OpenAI Blog, Google DeepMind, Hugging Face, The Batch, The Decoder, MIT News AI, NVIDIA Blog, Google AI Blog, Meta AI Blog, VentureBeat AI, and more
- `ADDED` **148 total RSS feeds** (was 63) — +85 new feeds across all categories; article flow ~1 every 1–2 minutes
- `ADDED` **Render + Vercel deployment** — `render.yaml` Blueprint for one-click Render deploy; `frontend/vercel.json` for Vercel SPA routing
- `ADDED` **`VITE_API_URL`** env var — frontend API and WebSocket calls route to any backend origin at build time
- `ADDED` **`VITE_AUTH_DISABLED`** env var — frontend skips login screen for public demo deployments
- `ADDED` **`vite-env.d.ts`** — typed `ImportMetaEnv` for `VITE_API_URL` and `VITE_AUTH_DISABLED`
- `ADDED` **`.env.example`** — fully documented environment variable template
- `ADDED` **`.gitignore`** — project-root ignore file covering `.env`, `*.db`, `venv/`, `node_modules/`, `logs/`
- `SECURITY` `AUTH_DISABLED` default flipped to `false` — auth is now ON by default; set `AUTH_DISABLED=true` explicitly for local dev
- `SECURITY` JWT secret now hard-fails on startup if unset and auth is enabled; no silent weak fallback
- `SECURITY` CORS locked to `ALLOWED_ORIGINS` env var (was `allow_origins=["*"]`)
- `SECURITY` First-boot admin password is auto-generated (`secrets.token_urlsafe(20)`) and printed to stdout; overridable via `ADMIN_PASSWORD=` env var
- `SECURITY` All secrets removed from `docker-compose.yml` — replaced with `${VAR:?error}` syntax
- `SECURITY` nginx security headers added: `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`, `Content-Security-Policy`
- `IMPROVED` RSS per-feed entry cap raised 30 → 50; collection interval tightened 5 min → 3 min
- `IMPROVED` `requirements.txt` fully pinned (`==` versions for reproducible builds)
- `FIXED` Tab switching black screen — removed `AnimatePresence`/`motion.div` wrapper from main content area; rapid clicks no longer leave opacity at 0
- `FIXED` AI markdown rendering — full rewrite of `MarkdownText` component: tables, bold, italic, inline code, fenced code blocks, blockquotes, horizontal rules all render correctly
- `FIXED` Health endpoint version string updated to `3.5.0` → now tracks actual app version

### v3.6.0 — 2026-04-14
- `ADDED` `session_logger.py` — rotating log file + in-memory ring buffer + `GET /api/v1/logs` + SSE stream
- `ADDED` `RequestLoggingMiddleware` — every HTTP request logged with method, path, status, and latency
- `ADDED` `start.sh` / `start.bat` — unified launchers that start both services and pipe output to `logs/`
- `ADDED` AI Analyst model selector — `AUTO` + per-model buttons; selected model passed in POST body
- `FIXED` ThreatMap diamond node square-outline bug — `@keyframes diamond-pulse` preserves `rotate(45deg)`
- `IMPROVED` ThreatMap actor origin nodes — country label, `stopPropagation()` on click
- `IMPROVED` ThreatMap attack target nodes — city label, outer ring for CRITICAL targets

### v3.5.0 — 2026-04-13
- `FIXED` Correlation graph HTTP 500 — JSON-mode + three-stage fallback parser
- `FIXED` Dead RSS feeds — bulk SQL UPDATE correctly disables stale DB entries on startup
- `FIXED` AI campaign cache keyed by `days_back` — independent caches per time window
- `IMPROVED` ThreatMap — night earth texture, thicker arcs, larger nodes, stronger glow
- `IMPROVED` AI Analyst — `loadStatus()` throttled to 60s, eliminating Ollama polling saturation

### v3.4.0 — 2026-04-12
- `ADDED` `POST /api/v1/campaigns/ai-discover` — LLM hidden campaign discovery
- `ADDED` AI Discover tab in Campaign Timeline
- `FIXED` AI status endpoint — 30s server-side TTL

### v3.3.0 — 2026-04-10
- `FIXED` Campaigns tab unclickable — `AnimatePresence` mode fix
- `FIXED` Correlation graph single-row layout — case-insensitive node ID lookup
- `REPLACED` Dagre layout → custom type-grouped row layout

### v3.2.0 — 2026-04-09
- `ADDED` Multi-provider LLM chain — Ollama → Groq → OpenRouter → Generic
- `ADDED` Ollama auto-manager — install, start, and pull on first boot
- `ADDED` AI Analyst v2 — streaming chat, agent mode, briefing generator
- `ADDED` Auth layer — JWT login with `AUTH_DISABLED` bypass
- `ADDED` Alert rules engine and DefconIndicator widget
- `REPLACED` Cobe globe → react-globe.gl

### v1.3.0 — 2026-04-06
- `ADDED` `correlate.py` — CVE↔actor co-occurrence + campaign timelines + webhook alerts
- `ADDED` Settings tab with database-persisted configuration
- `ADDED` MITRE ATT&CK technique drill-down in actor cards

### v1.2.0 — 2026-04-04
- `ADDED` React Flow correlation graph
- `ADDED` Abuse.ch collectors (MalwareBazaar, URLhaus, ThreatFox)
- `ADDED` AlienVault OTX, RansomWatch, SQLite FTS5 full-text search

### v1.1.0 — 2026-04-01
- `ARCH` FastAPI + SQLite + APScheduler + WebSocket backend
- `ADDED` NVD 2.0, CISA KEV, FIRST EPSS, MITRE ATT&CK collectors
- `ADDED` Enrichment engine: severity, tags, actor detection, CVE extraction
- `DESIGN` SIGINTX terminal design system

### v1.0.0 — 2026-03-31
- Initial architecture and design system

---

## License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE) for details.
