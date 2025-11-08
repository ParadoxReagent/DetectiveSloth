"""Celery tasks for MITRE ATT&CK updates."""

import logging
import asyncio
from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.services.mitre_service import MitreAttackService

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.mitre_tasks.update_mitre_attack_task")
def update_mitre_attack_task():
    """Background task to update MITRE ATT&CK data."""
    logger.info("Starting update_mitre_attack_task")

    db = SessionLocal()
    try:
        service = MitreAttackService(db)

        # Run async function in sync context
        count = asyncio.run(service.update_attack_data())

        logger.info(f"Completed update_mitre_attack_task: {count} techniques")
        return {
            "status": "success",
            "count": count
        }
    except Exception as e:
        logger.error(f"Error in update_mitre_attack_task: {e}")
        return {
            "status": "error",
            "error": str(e)
        }
    finally:
        db.close()
