"""Celery application configuration and initialization."""

from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

# Initialize Celery app
celery_app = Celery(
    "threat_hunt_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.tasks.threat_intel_tasks",
        "app.tasks.mitre_tasks",
        "app.tasks.enrichment_tasks",
    ]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    task_soft_time_limit=3300,  # 55 minutes soft limit
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)

# Celery Beat schedule for periodic tasks
celery_app.conf.beat_schedule = {
    "update-threat-intel-feeds": {
        "task": "app.tasks.threat_intel_tasks.update_all_feeds_task",
        "schedule": crontab(minute=0, hour=f"*/{settings.THREAT_INTEL_UPDATE_INTERVAL}"),  # Every 6 hours by default
    },
    "update-mitre-attack": {
        "task": "app.tasks.mitre_tasks.update_mitre_attack_task",
        "schedule": crontab(minute=0, hour=0),  # Daily at midnight
    },
    "deduplicate-iocs-weekly": {
        "task": "app.tasks.enrichment_tasks.deduplicate_iocs_task",
        "schedule": crontab(minute=0, hour=2, day_of_week=1),  # Every Monday at 2 AM
    },
}
