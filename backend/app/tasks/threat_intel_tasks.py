"""Celery tasks for threat intelligence updates."""

import logging
import asyncio
from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.services.threat_intel_service import ThreatIntelService

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.threat_intel_tasks.update_all_feeds_task")
def update_all_feeds_task():
    """Background task to update all threat intelligence feeds."""
    logger.info("Starting update_all_feeds_task")

    db = SessionLocal()
    try:
        service = ThreatIntelService(db)

        # Run async function in sync context
        results = asyncio.run(service.update_all_feeds())

        logger.info(f"Completed update_all_feeds_task: {results}")
        return {
            "status": "success",
            "results": results,
            "total": sum(results.values())
        }
    except Exception as e:
        logger.error(f"Error in update_all_feeds_task: {e}")
        return {
            "status": "error",
            "error": str(e)
        }
    finally:
        db.close()


@celery_app.task(name="app.tasks.threat_intel_tasks.update_otx_task")
def update_otx_task(days: int = 7):
    """Background task to update AlienVault OTX indicators."""
    logger.info(f"Starting update_otx_task (days={days})")

    db = SessionLocal()
    try:
        service = ThreatIntelService(db)
        count = asyncio.run(service.ingest_otx_indicators(days=days))

        logger.info(f"Completed update_otx_task: {count} indicators")
        return {
            "status": "success",
            "feed": "otx",
            "count": count
        }
    except Exception as e:
        logger.error(f"Error in update_otx_task: {e}")
        return {
            "status": "error",
            "feed": "otx",
            "error": str(e)
        }
    finally:
        db.close()


@celery_app.task(name="app.tasks.threat_intel_tasks.update_urlhaus_task")
def update_urlhaus_task():
    """Background task to update URLhaus indicators."""
    logger.info("Starting update_urlhaus_task")

    db = SessionLocal()
    try:
        service = ThreatIntelService(db)
        count = asyncio.run(service.ingest_abusech_urlhaus())

        logger.info(f"Completed update_urlhaus_task: {count} URLs")
        return {
            "status": "success",
            "feed": "urlhaus",
            "count": count
        }
    except Exception as e:
        logger.error(f"Error in update_urlhaus_task: {e}")
        return {
            "status": "error",
            "feed": "urlhaus",
            "error": str(e)
        }
    finally:
        db.close()


@celery_app.task(name="app.tasks.threat_intel_tasks.update_threatfox_task")
def update_threatfox_task():
    """Background task to update ThreatFox indicators."""
    logger.info("Starting update_threatfox_task")

    db = SessionLocal()
    try:
        service = ThreatIntelService(db)
        count = asyncio.run(service.ingest_abusech_threatfox())

        logger.info(f"Completed update_threatfox_task: {count} IOCs")
        return {
            "status": "success",
            "feed": "threatfox",
            "count": count
        }
    except Exception as e:
        logger.error(f"Error in update_threatfox_task: {e}")
        return {
            "status": "error",
            "feed": "threatfox",
            "error": str(e)
        }
    finally:
        db.close()


@celery_app.task(name="app.tasks.threat_intel_tasks.update_cisa_kev_task")
def update_cisa_kev_task():
    """Background task to update CISA KEV catalog."""
    logger.info("Starting update_cisa_kev_task")

    db = SessionLocal()
    try:
        service = ThreatIntelService(db)
        count = asyncio.run(service.ingest_cisa_kev())

        logger.info(f"Completed update_cisa_kev_task: {count} CVEs")
        return {
            "status": "success",
            "feed": "cisa_kev",
            "count": count
        }
    except Exception as e:
        logger.error(f"Error in update_cisa_kev_task: {e}")
        return {
            "status": "error",
            "feed": "cisa_kev",
            "error": str(e)
        }
    finally:
        db.close()


@celery_app.task(name="app.tasks.threat_intel_tasks.update_greynoise_task")
def update_greynoise_task(classification: str = "malicious"):
    """Background task to update GreyNoise indicators."""
    logger.info(f"Starting update_greynoise_task (classification={classification})")

    db = SessionLocal()
    try:
        service = ThreatIntelService(db)
        count = asyncio.run(service.ingest_greynoise(classification=classification))

        logger.info(f"Completed update_greynoise_task: {count} IPs")
        return {
            "status": "success",
            "feed": "greynoise",
            "count": count
        }
    except Exception as e:
        logger.error(f"Error in update_greynoise_task: {e}")
        return {
            "status": "error",
            "feed": "greynoise",
            "error": str(e)
        }
    finally:
        db.close()
