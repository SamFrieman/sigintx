"""
SIGINTX — Celery application
Broker + result backend: Redis.
Beat schedule mirrors the old APScheduler job list.

Usage:
    # Worker (runs tasks)
    celery -A celery_app worker --loglevel=info --concurrency=4

    # Beat scheduler (fires tasks on schedule)
    celery -A celery_app beat --loglevel=info

    # Combined (dev only — don't use in production)
    celery -A celery_app worker --beat --loglevel=info
"""
import os

from celery import Celery
from celery.schedules import schedule as celery_schedule

REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

app = Celery(
    "sigintx",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["tasks"],   # module where tasks are defined
)

app.conf.update(
    # Serialisation
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    # Reliability
    task_acks_late=True,               # acknowledge only after task succeeds
    worker_prefetch_multiplier=1,      # one task at a time per worker process
    task_reject_on_worker_lost=True,   # requeue if worker crashes mid-task

    # Results
    result_expires=3600,               # keep results for 1 hour

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Beat schedule — intervals in seconds
    beat_schedule={
        "collect_rss": {
            "task": "tasks.collect_rss_task",
            "schedule": celery_schedule(run_every=300),   # 5 min
        },
        "collect_cves": {
            "task": "tasks.collect_cves_task",
            "schedule": celery_schedule(run_every=900),   # 15 min
        },
        "kev_sync": {
            "task": "tasks.kev_sync_task",
            "schedule": celery_schedule(run_every=21600), # 6 hr
        },
        "collect_abusech": {
            "task": "tasks.collect_abusech_task",
            "schedule": celery_schedule(run_every=900),   # 15 min
        },
        "collect_otx": {
            "task": "tasks.collect_otx_task",
            "schedule": celery_schedule(run_every=1800),  # 30 min
        },
        "collect_ransomwatch": {
            "task": "tasks.collect_ransomwatch_task",
            "schedule": celery_schedule(run_every=600),   # 10 min
        },
        "collect_misp": {
            "task": "tasks.collect_misp_task",
            "schedule": celery_schedule(run_every=3600),  # 1 hr
        },
        "correlate": {
            "task": "tasks.correlate_task",
            "schedule": celery_schedule(run_every=900),   # 15 min
        },
        "run_alert_rules": {
            "task": "tasks.run_alert_rules_task",
            "schedule": celery_schedule(run_every=300),   # 5 min
        },
        "scan_shodan": {
            "task": "tasks.scan_shodan_task",
            "schedule": celery_schedule(run_every=21600), # 6 hr
        },
        "ai_briefing": {
            "task": "tasks.ai_briefing_task",
            "schedule": celery_schedule(run_every=3600),  # 1 hr
        },
        "enrich_iocs": {
            "task": "tasks.enrich_iocs_task",
            "schedule": celery_schedule(run_every=1800),  # 30 min
        },
    },
)
