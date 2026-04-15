"""
SIGINTX — RSS Collector (v4.0.0)
Ingests security, tech, crypto, politics, and AI RSS feeds.

Deduplication strategy (two layers):
  1. URL-exact: skip if the exact URL already exists (fast, catches reposts).
  2. Semantic / title-hash: normalise the title (lowercase, strip punctuation,
     remove common stop-words), SHA-1 hash it, skip if an identical hash was
     seen within the last 24 hours.  Catches the same story published by
     multiple RSS sources with slightly different URLs.

Categories:
  security    — threat intel, vulnerability research, incident response
  tech        — general technology news and announcements
  politics    — geopolitical news, policy, defense, international affairs
  crypto      — cryptocurrency and blockchain news
  ai          — artificial intelligence research and industry news
"""
import hashlib
import json
import logging
import re
import feedparser
import httpx
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Optional

from database import SessionLocal, NewsItem, RssFeed
from enrichment import enrich_news_item
from sqlalchemy import select, func

logger = logging.getLogger("sigintx.rss")

# ── Semantic deduplication helpers ────────────────────────────────────────────

# Common English stop-words that carry no semantic signal for news titles.
_STOP_WORDS = frozenset({
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "was", "are", "were", "be", "been",
    "has", "have", "had", "will", "would", "could", "should", "may", "might",
    "new", "news", "update", "updated", "report", "reported",
})

_PUNCT_RE = re.compile(r"[^a-z0-9\s]")


def _title_hash(title: str) -> str:
    """
    Return a 12-character hex digest that is stable for titles that describe
    the same event, regardless of source-specific phrasing differences.

    Pipeline:
        lowercase → strip punctuation → split → drop stop-words →
        sort tokens alphabetically → join → SHA-1 → first 12 hex chars
    """
    normalised = _PUNCT_RE.sub("", title.lower())
    tokens = [t for t in normalised.split() if t and t not in _STOP_WORDS]
    canonical = " ".join(sorted(tokens))
    return hashlib.sha1(canonical.encode()).hexdigest()[:12]


# ── Feed registry ─────────────────────────────────────────────────────────────
# Format: (display_name, feed_url, category)
# v4.0.0: Expanded to 145 feeds + new "ai" category for consistent article flow.
# Dead feeds removed: Threatpost, NVD RSS, Naked Security, Recorded Future, Mandiant.

RSS_FEEDS: list[tuple[str, str, str]] = [

    # ════════════════════════════════════════════════════════════════════════
    # SECURITY  (31 feeds)
    # ════════════════════════════════════════════════════════════════════════
    ("BleepingComputer",        "https://www.bleepingcomputer.com/feed/",                         "security"),
    ("Krebs on Security",       "https://krebsonsecurity.com/feed/",                              "security"),
    ("The Hacker News",         "https://feeds.feedburner.com/TheHackersNews",                    "security"),
    ("SecurityWeek",            "https://feeds.feedburner.com/Securityweek",                      "security"),
    ("Dark Reading",            "https://www.darkreading.com/rss.xml",                            "security"),
    ("SANS ISC",                "https://isc.sans.edu/rssfeed_full.xml",                          "security"),
    ("CISA Advisories",         "https://www.cisa.gov/uscert/ncas/current-activity.xml",          "security"),
    ("Schneier on Security",    "https://www.schneier.com/blog/atom.xml",                         "security"),
    ("Graham Cluley",           "https://grahamcluley.com/feed/",                                 "security"),
    ("Talos Intelligence",      "https://blog.talosintelligence.com/rss/",                        "security"),
    ("Google Project Zero",     "https://googleprojectzero.blogspot.com/feeds/posts/default",     "security"),
    ("Malwarebytes Labs",       "https://blog.malwarebytes.com/feed/",                            "security"),
    ("CrowdStrike Blog",        "https://www.crowdstrike.com/blog/feed/",                         "security"),
    ("Rapid7 Blog",             "https://www.rapid7.com/blog/rss/",                               "security"),
    ("InfoSec Magazine",        "https://www.infosecurity-magazine.com/rss/news/",                "security"),
    ("Cybersecurity Dive",      "https://www.cybersecuritydive.com/feeds/news/",                  "security"),
    # ── New security feeds ───────────────────────────────────────────────────
    ("WeLiveSecurity",          "https://www.welivesecurity.com/feed/",                           "security"),
    ("Securelist",              "https://securelist.com/feed/",                                   "security"),
    ("Unit 42",                 "https://unit42.paloaltonetworks.com/feed/",                      "security"),
    ("Microsoft Security",      "https://www.microsoft.com/en-us/security/blog/feed/",            "security"),
    ("Sophos News",             "https://news.sophos.com/en-us/feed/",                            "security"),
    ("Check Point Research",    "https://research.checkpoint.com/feed/",                          "security"),
    ("Packet Storm",            "https://packetstormsecurity.com/headlines.xml",                  "security"),
    ("Security Affairs",        "https://securityaffairs.com/feed",                               "security"),
    ("Red Canary Blog",         "https://redcanary.com/blog/feed/",                               "security"),
    ("SentinelOne Blog",        "https://www.sentinelone.com/blog/feed/",                         "security"),
    ("NCC Group Research",      "https://research.nccgroup.com/feed/",                            "security"),
    ("Trend Micro Research",    "https://feeds.trendmicro.com/TrendMicroResearch",                "security"),
    ("CyberScoop",              "https://cyberscoop.com/feed/",                                   "security"),
    ("SC Media",                "https://www.scmagazine.com/feed",                                "security"),
    ("Recorded Future News",    "https://therecord.media/feed",                                   "security"),

    # ════════════════════════════════════════════════════════════════════════
    # TECH  (31 feeds)
    # ════════════════════════════════════════════════════════════════════════
    ("Ars Technica",            "https://feeds.arstechnica.com/arstechnica/index",                "tech"),
    ("Hacker News (YC)",        "https://news.ycombinator.com/rss",                               "tech"),
    ("The Verge",               "https://www.theverge.com/rss/index.xml",                         "tech"),
    ("TechCrunch",              "https://techcrunch.com/feed/",                                   "tech"),
    ("Wired",                   "https://www.wired.com/feed/rss",                                 "tech"),
    ("MIT Tech Review",         "https://www.technologyreview.com/feed/",                         "tech"),
    ("IEEE Spectrum",           "https://spectrum.ieee.org/feeds/feed.rss",                       "tech"),
    ("Engadget",                "https://www.engadget.com/rss.xml",                               "tech"),
    ("Gizmodo",                 "https://gizmodo.com/rss",                                        "tech"),
    ("VentureBeat",             "https://venturebeat.com/feed/",                                  "tech"),
    ("ZDNet",                   "https://www.zdnet.com/news/rss.xml",                             "tech"),
    ("The Register",            "https://www.theregister.com/headlines.atom",                     "tech"),
    ("TechRepublic",            "https://www.techrepublic.com/rssfeeds/articles/",                "tech"),
    ("ReadWrite",               "https://readwrite.com/feed/",                                    "tech"),
    ("PCMag",                   "https://www.pcmag.com/feeds/all",                                "tech"),
    ("Mashable Tech",           "https://mashable.com/feeds/rss/tech",                            "tech"),
    # ── New tech feeds ───────────────────────────────────────────────────────
    ("CNET News",               "https://www.cnet.com/rss/news/",                                 "tech"),
    ("Slashdot",                "https://rss.slashdot.org/Slashdot/slashdotMain",                 "tech"),
    ("9to5Google",              "https://9to5google.com/feed/",                                   "tech"),
    ("9to5Mac",                 "https://9to5mac.com/feed/",                                      "tech"),
    ("MacRumors",               "https://feeds.macrumors.com/MacRumors-All",                      "tech"),
    ("Digital Trends",          "https://www.digitaltrends.com/feed/",                            "tech"),
    ("Tom's Hardware",          "https://www.tomshardware.com/feeds/all",                         "tech"),
    ("The Next Web",            "https://thenextweb.com/feed/",                                   "tech"),
    ("Fast Company Tech",       "https://www.fastcompany.com/technology/rss",                     "tech"),
    ("InfoWorld",               "https://www.infoworld.com/index.rss",                            "tech"),
    ("Computerworld",           "https://www.computerworld.com/index.rss",                        "tech"),
    ("SiliconANGLE",            "https://siliconangle.com/feed/",                                 "tech"),
    ("Hacker Noon",             "https://hackernoon.com/feed",                                    "tech"),
    ("SD Times",                "https://sdtimes.com/feed/",                                      "tech"),
    ("TechRadar",               "https://www.techradar.com/rss",                                  "tech"),

    # ════════════════════════════════════════════════════════════════════════
    # CRYPTO  (25 feeds)
    # ════════════════════════════════════════════════════════════════════════
    ("CoinDesk",                "https://www.coindesk.com/arc/outboundfeeds/rss/",                "crypto"),
    ("CoinTelegraph",           "https://cointelegraph.com/rss",                                  "crypto"),
    ("Decrypt",                 "https://decrypt.co/feed",                                        "crypto"),
    ("Bitcoinist",              "https://bitcoinist.com/feed/",                                   "crypto"),
    ("The Block",               "https://www.theblock.co/rss.xml",                                "crypto"),
    ("Blockworks",              "https://blockworks.co/feed",                                     "crypto"),
    ("CryptoSlate",             "https://cryptoslate.com/feed/",                                  "crypto"),
    ("NewsBTC",                 "https://www.newsbtc.com/feed/",                                  "crypto"),
    ("Bitcoin.com News",        "https://news.bitcoin.com/feed/",                                 "crypto"),
    ("Crypto Briefing",         "https://cryptobriefing.com/feed/",                               "crypto"),
    ("AMBCrypto",               "https://ambcrypto.com/feed/",                                    "crypto"),
    ("Cryptonews",              "https://cryptonews.com/news/feed/",                              "crypto"),
    ("BeInCrypto",              "https://beincrypto.com/feed/",                                   "crypto"),
    ("The Defiant",             "https://thedefiant.io/feed/",                                    "crypto"),
    ("DL News",                 "https://www.dlnews.com/rss/",                                    "crypto"),
    # ── New crypto feeds ─────────────────────────────────────────────────────
    ("Bitcoin Magazine",        "https://bitcoinmagazine.com/feed",                               "crypto"),
    ("CryptoDaily",             "https://cryptodaily.co.uk/feed",                                 "crypto"),
    ("CoinGape",                "https://coingape.com/feed/",                                     "crypto"),
    ("U.Today",                 "https://u.today/rss",                                            "crypto"),
    ("99Bitcoins",              "https://99bitcoins.com/feed/",                                   "crypto"),
    ("Crypto Potato",           "https://cryptopotato.com/feed/",                                 "crypto"),
    ("Protos",                  "https://protos.com/feed/",                                       "crypto"),
    ("CoinJournal",             "https://coinjournal.net/feed/",                                  "crypto"),
    ("Unchained Crypto",        "https://unchainedcrypto.com/feed/",                              "crypto"),
    ("ZyCrypto",                "https://zycrypto.com/feed/",                                     "crypto"),

    # ════════════════════════════════════════════════════════════════════════
    # POLITICS  (31 feeds)
    # ════════════════════════════════════════════════════════════════════════
    ("PBS NewsHour World",      "https://www.pbs.org/newshour/feeds/rss/world",                   "politics"),
    ("Politico EU",             "https://www.politico.eu/feed/",                                  "politics"),
    ("The Hill",                "https://thehill.com/feed/",                                      "politics"),
    ("Roll Call",               "https://rollcall.com/feed/",                                     "politics"),
    ("Foreign Policy",          "https://foreignpolicy.com/feed/",                                "politics"),
    ("The Diplomat",            "https://thediplomat.com/feed/",                                  "politics"),
    ("BBC World News",          "https://feeds.bbci.co.uk/news/world/rss.xml",                    "politics"),
    ("NPR Politics",            "https://feeds.npr.org/1014/rss.xml",                             "politics"),
    ("Associated Press",        "https://feeds.apnews.com/rss/apf-topnews",                       "politics"),
    ("The Guardian US",         "https://www.theguardian.com/us-news/rss",                        "politics"),
    ("Al Jazeera",              "https://www.aljazeera.com/xml/rss/all.xml",                      "politics"),
    ("Washington Post World",   "https://feeds.washingtonpost.com/rss/world",                     "politics"),
    ("The Atlantic",            "https://www.theatlantic.com/feed/all/",                          "politics"),
    ("Defense One",             "https://www.defenseone.com/rss/all/",                            "politics"),
    ("Breaking Defense",        "https://breakingdefense.com/feed/",                              "politics"),
    ("RAND Corporation",        "https://www.rand.org/pubs/research_reports.xml",                 "politics"),
    # ── New politics feeds ───────────────────────────────────────────────────
    ("Reuters World",           "https://feeds.reuters.com/reuters/worldNews",                    "politics"),
    ("Reuters Politics",        "https://feeds.reuters.com/Reuters/PoliticsNews",                 "politics"),
    ("CNN World",               "https://rss.cnn.com/rss/edition_world.rss",                      "politics"),
    ("ABC News",                "https://feeds.abcnews.com/abcnews/topstories",                   "politics"),
    ("NBC News",                "https://feeds.nbcnews.com/nbcnews/public/news",                  "politics"),
    ("CBS News",                "https://www.cbsnews.com/latest/rss/main",                        "politics"),
    ("Politico US",             "https://www.politico.com/rss/politicopicks.xml",                 "politics"),
    ("Axios World",             "https://api.axios.com/feed/world/",                              "politics"),
    ("The Intercept",           "https://theintercept.com/feed/",                                 "politics"),
    ("ProPublica",              "https://feeds.propublica.org/propublica/main",                   "politics"),
    ("War on the Rocks",        "https://warontherocks.com/feed/",                                "politics"),
    ("Lawfare",                 "https://lawfareblog.com/rss.xml",                                "politics"),
    ("The National Interest",   "https://nationalinterest.org/rss.xml",                           "politics"),
    ("Brookings",               "https://www.brookings.edu/feed/",                                "politics"),
    ("Foreign Affairs",         "https://www.foreignaffairs.com/rss.xml",                         "politics"),

    # ════════════════════════════════════════════════════════════════════════
    # AI  (27 feeds)  — new category
    # ════════════════════════════════════════════════════════════════════════
    ("VentureBeat AI",          "https://venturebeat.com/category/ai/feed/",                      "ai"),
    ("TechCrunch AI",           "https://techcrunch.com/category/artificial-intelligence/feed/",  "ai"),
    ("Wired AI",                "https://www.wired.com/feed/tag/artificial-intelligence/rss",     "ai"),
    ("Ars Technica AI",         "https://feeds.arstechnica.com/arstechnica/technology-lab",       "ai"),
    ("MIT News AI",             "https://news.mit.edu/rss/topic/artificial-intelligence2",        "ai"),
    ("IEEE Spectrum AI",        "https://spectrum.ieee.org/topic/artificial-intelligence/feed",   "ai"),
    ("The Batch",               "https://www.deeplearning.ai/the-batch/feed/",                    "ai"),
    ("Hugging Face Blog",       "https://huggingface.co/blog/feed.xml",                           "ai"),
    ("OpenAI Blog",             "https://openai.com/blog/rss.xml",                                "ai"),
    ("Google DeepMind",         "https://deepmind.google/blog/feed/basic",                        "ai"),
    ("AI Alignment Forum",      "https://www.alignmentforum.org/feed.xml",                        "ai"),
    ("LessWrong",               "https://www.lesswrong.com/feed.xml",                             "ai"),
    ("The Gradient",            "https://thegradient.pub/rss/",                                   "ai"),
    ("Import AI",               "https://jack-clark.net/feed/",                                   "ai"),
    ("Synced Review",           "https://syncedreview.com/feed/",                                 "ai"),
    ("Analytics Vidhya",        "https://www.analyticsvidhya.com/feed/",                          "ai"),
    ("Towards Data Science",    "https://towardsdatascience.com/feed",                             "ai"),
    ("KDnuggets",               "https://www.kdnuggets.com/feed",                                 "ai"),
    ("AI Business",             "https://aibusiness.com/rss.xml",                                 "ai"),
    ("NVIDIA Blog",             "https://blogs.nvidia.com/feed/",                                  "ai"),
    ("Google AI Blog",          "https://blog.research.google/feeds/posts/default",               "ai"),
    ("Microsoft AI Blog",       "https://blogs.microsoft.com/ai/feed/",                           "ai"),
    ("Meta AI Blog",            "https://ai.meta.com/blog/rss/",                                  "ai"),
    ("AWS ML Blog",             "https://aws.amazon.com/blogs/machine-learning/feed/",            "ai"),
    ("Weights & Biases Blog",   "https://wandb.ai/fully-connected/feed.xml",                      "ai"),
    ("Last Week in AI",         "https://lastweekin.ai/feed",                                     "ai"),
    ("The Decoder",             "https://the-decoder.com/feed/",                                  "ai"),
]


def _parse_date(entry) -> datetime:
    """Best-effort date parsing from a feedparser entry."""
    for attr in ("published", "updated", "created"):
        val = getattr(entry, attr, None)
        if val:
            try:
                return parsedate_to_datetime(val).replace(tzinfo=None)
            except Exception:
                pass
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        return datetime(*entry.published_parsed[:6])
    return datetime.utcnow()


def _get_summary(entry) -> Optional[str]:
    """Extract plain-text summary from entry."""
    summary = getattr(entry, "summary", None) or getattr(entry, "description", None)
    if summary:
        from bs4 import BeautifulSoup
        return BeautifulSoup(summary, "html.parser").get_text(separator=" ", strip=True)[:1000]
    return None


async def collect_rss_feed(feed_name: str, feed_url: str, category: str = "security") -> int:
    """Fetch a single RSS feed and upsert new items. Returns count of new items."""
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SIGINTX/1.5; +https://github.com/sigintx) Feedfetcher/1.0",
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
    }
    try:
        async with httpx.AsyncClient(timeout=15, headers=headers) as client:
            resp = await client.get(feed_url, follow_redirects=True)
            resp.raise_for_status()
            content = resp.content
    except Exception as e:
        logger.warning(f"RSS fetch failed [{feed_name}]: {e}")
        return 0

    feed = feedparser.parse(content)
    new_count = 0

    dedup_window = datetime.utcnow() - timedelta(hours=24)

    async with SessionLocal() as db:
        for entry in feed.entries[:50]:   # cap at 50 per feed run
            url = getattr(entry, "link", None)
            title = getattr(entry, "title", "").strip()
            if not url or not title:
                continue

            # Layer 1 — exact URL dedup
            if await db.scalar(select(NewsItem).where(NewsItem.url == url)):
                continue

            # Layer 2 — semantic title-hash dedup (same story, different source)
            th = _title_hash(title)
            if await db.scalar(
                select(NewsItem).where(
                    NewsItem.title_hash == th,
                    NewsItem.published_at >= dedup_window,
                )
            ):
                logger.debug("Semantic dedup hit: '%s' (hash=%s)", title[:60], th)
                continue

            summary = _get_summary(entry)
            enrichment = enrich_news_item(title, summary or "")

            item = NewsItem(
                title=title,
                url=url,
                source=feed_name,
                summary=summary,
                published_at=_parse_date(entry),
                severity=enrichment["severity"],
                tags=enrichment["tags"],
                threat_actors=enrichment["threat_actors"],
                cve_refs=enrichment["cve_refs"],
                title_hash=th,
                category=category,
            )
            db.add(item)
            new_count += 1

        await db.commit()

    if new_count:
        logger.info(f"RSS [{feed_name}] ({category}): +{new_count} new items")
    return new_count


async def _get_active_feeds() -> list[tuple[str, str, str]]:
    """
    Return feed list as (name, url, category) triples from the rss_feeds DB table
    (if populated), falling back to the hardcoded RSS_FEEDS default list.
    """
    try:
        async with SessionLocal() as db:
            rows = (await db.scalars(
                select(RssFeed).where(RssFeed.enabled == True)  # noqa: E712
            )).all()
        if rows:
            return [(r.name, r.url, r.category or "security") for r in rows]
    except Exception as e:
        logger.warning(f"Could not read feeds from DB: {e}")
    return RSS_FEEDS


async def seed_default_feeds() -> None:
    """
    Populate rss_feeds table from hardcoded defaults.

    Strategy:
    - Upsert by feed name: if a name matches, update URL + category (handles
      dead-feed replacements without manual DB migrations).
    - Disable any DB feed whose name is no longer in RSS_FEEDS (orphan cleanup).
    - Skip inserting a new row if the URL already exists under a different name.
    """
    from sqlalchemy import update as sa_update, not_

    canonical_names = {name for name, _, _ in RSS_FEEDS}
    added = updated = disabled = 0

    try:
        async with SessionLocal() as db:

            # ── Per-feed upsert (each row isolated so one bad entry can't abort the rest)
            for name, url, category in RSS_FEEDS:
                try:
                    existing = await db.scalar(select(RssFeed).where(RssFeed.name == name))
                    if existing:
                        changed = False
                        if existing.url != url:
                            # Remove any other row already holding the target URL
                            # to prevent UNIQUE constraint crash on the UPDATE.
                            url_conflict = await db.scalar(
                                select(RssFeed).where(
                                    RssFeed.url == url,
                                    RssFeed.name != name,
                                )
                            )
                            if url_conflict:
                                await db.delete(url_conflict)
                                await db.flush()
                                logger.info(
                                    "Removed duplicate feed row '%s' (URL reassigned to '%s')",
                                    url_conflict.name, name,
                                )
                            existing.url = url
                            changed = True
                        if existing.category != category:
                            existing.category = category
                            changed = True
                        if not existing.enabled:
                            existing.enabled = True
                            changed = True
                        if changed:
                            updated += 1
                    else:
                        # Skip if the URL is already registered under a different name
                        if not await db.scalar(select(RssFeed).where(RssFeed.url == url)):
                            db.add(RssFeed(name=name, url=url, enabled=True, category=category))
                            added += 1

                    await db.flush()   # surface constraint errors per-row, not at commit

                except Exception as row_err:
                    logger.warning("Feed seed: skipping '%s' due to error: %s", name, row_err)
                    await db.rollback()   # rollback only this row's change, keep session alive

            # ── Orphan cleanup: disable DB feeds no longer in the canonical list
            result = await db.execute(
                sa_update(RssFeed)
                .where(not_(RssFeed.name.in_(list(canonical_names))))
                .where(RssFeed.enabled == True)  # noqa: E712
                .values(enabled=False)
            )
            disabled = result.rowcount

            await db.commit()

    except Exception as e:
        logger.warning("Feed seed error: %s", e)

    parts = []
    if added:    parts.append(f"{added} added")
    if updated:  parts.append(f"{updated} updated")
    if disabled: parts.append(f"{disabled} disabled (orphaned)")
    if parts:
        logger.info("RSS feeds seeded: %s", ", ".join(parts))


async def collect_all_rss() -> int:
    """Collect all active RSS feeds. Returns total new items."""
    feeds = await _get_active_feeds()
    total = 0
    for name, url, category in feeds:
        total += await collect_rss_feed(name, url, category)
    return total
