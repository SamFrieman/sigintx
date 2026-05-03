<div align="center">

# SIGINTX — Cyber Intelligence Platform

**Open-source signals intelligence dashboard for threat tracking, campaign correlation, and global attack mapping**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-React-blue?logo=typescript)](https://typescriptlang.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-async-green?logo=fastapi)](https://fastapi.tiangolo.com)

[Live Demo](https://samfrieman.github.io/portfolio-site/) · [Deploy on Render + Vercel](#cloud-deployment) · [Run Locally](#local-development)

</div>

---

## What It Does

SIGINTX aggregates **148+ RSS feeds** and open-source threat intelligence APIs into a single real-time dashboard. Every article passes through an enrichment pipeline — severity classification, CVE extraction, threat actor detection, and semantic deduplication — before appearing in any panel.

**Intelligence sources:** NVD 2.0, CISA KEV, FIRST EPSS, MITRE ATT&CK, Abuse.ch (MalwareBazaar, URLhaus, ThreatFox), AlienVault OTX, RansomWatch, and 148 curated RSS feeds (BleepingComputer, Krebs, Reuters, and more).

---

## Dashboard Panels

| Panel | Description |
|-------|-------------|
| **Dashboard** | Live stats, activity feed, DEFCON-style threat indicator |
| **News Feed** | Full-text search, severity filter, category filter across all sources |
| **Threat Actors** | MITRE ATT&CK technique mappings, alias expansion, 20+ known groups |
| **Campaigns** | Timeline view, AI-powered hidden campaign discovery |
| **Correlation** | Force-directed graph — actor → campaign → technique relationships |
| **Threat Map** | 3D WebGL globe with attack origin/target nodes |
| **AI Analyst** | Multi-turn chat, model selection, streaming responses (Ollama / Groq / OpenRouter) |
| **Settings** | Webhooks, watchlists, RSS feed customization, model management |

---

## Architecture

```
Frontend  React 18 + TypeScript + Vite + Tailwind CSS + Framer Motion
Backend   Python 3.12 + FastAPI + async SQLAlchemy + APScheduler
AI Layer  Ollama (local) → Groq (free tier) → OpenRouter (fallback chain)
Storage   PostgreSQL 16 + Redis 7 caching
Queue     Celery task queue + Nginx reverse proxy
```

**Intelligence pipeline per article:**
1. Severity classification (CRITICAL / HIGH / MEDIUM / INFO)
2. Tag extraction across 17 categories
3. Threat actor detection (20+ groups)
4. CVE identifier extraction
5. Semantic deduplication

---

## Local Development

**Prerequisites:** Python 3.12+, Node 18+, PostgreSQL 16, Redis 7

```bash
git clone https://github.com/SamFrieman/sigintx
cd sigintx

# Backend
cd backend
python -m venv venv && source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env  # configure DATABASE_URL and REDIS_URL

# Frontend
cd ../frontend
npm install

# Launch both
./start.sh        # Linux/Mac
start.bat         # Windows
```

Ollama is provisioned automatically on first launch if installed.

---

## Cloud Deployment

One-click deploy via Render Blueprint (backend) + Vercel (frontend) — both free tier, zero paid APIs required.

```bash
# Render
render blueprint apply render.yaml

# Vercel
vercel --prod
```

## Docker

```bash
docker compose up --build
```

Spins up PostgreSQL, Redis, Celery workers, FastAPI, and Nginx.

---

## Zero Required Paid APIs

All integrations use free tiers or open data:

| Source | Data Type | Cost |
|--------|-----------|------|
| NVD 2.0 | CVE database | Free |
| CISA KEV | Known exploited vulns | Free |
| MITRE ATT&CK | TTP framework | Free |
| AlienVault OTX | Threat indicators | Free |
| Abuse.ch | Malware/C2 IOCs | Free |
| Ollama | Local LLM inference | Free |
| Groq API | Cloud LLM | Free tier |

---

## License

MIT — use it, fork it, build on it.
