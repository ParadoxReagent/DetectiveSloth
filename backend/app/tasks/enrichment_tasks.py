"""Celery tasks for enrichment and bulk operations."""

import logging
import asyncio
from typing import Optional
from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.services.enrichment_service import EnrichmentService
from app.services.cve_correlation_service import CVECorrelationService

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.enrichment_tasks.deduplicate_iocs_task")
def deduplicate_iocs_task():
    """Background task to deduplicate IOCs."""
    logger.info("Starting deduplicate_iocs_task")

    db = SessionLocal()
    try:
        service = EnrichmentService(db)
        results = service.deduplicate_iocs()

        logger.info(f"Completed deduplicate_iocs_task: {results}")
        return {
            "status": "success",
            "results": results
        }
    except Exception as e:
        logger.error(f"Error in deduplicate_iocs_task: {e}")
        return {
            "status": "error",
            "error": str(e)
        }
    finally:
        db.close()


@celery_app.task(name="app.tasks.enrichment_tasks.correlate_all_cves_task")
def correlate_all_cves_task(limit: Optional[int] = None):
    """Background task to correlate all CVEs with exploits and techniques.

    Args:
        limit: Maximum number of CVEs to process (None for all)
    """
    logger.info(f"Starting correlate_all_cves_task (limit={limit})")

    db = SessionLocal()
    try:
        service = CVECorrelationService(db)

        # Run async function in sync context
        count = asyncio.run(service.correlate_all_cves(limit=limit))

        logger.info(f"Completed correlate_all_cves_task: {count} CVEs correlated")
        return {
            "status": "success",
            "count": count
        }
    except Exception as e:
        logger.error(f"Error in correlate_all_cves_task: {e}")
        return {
            "status": "error",
            "error": str(e)
        }
    finally:
        db.close()


@celery_app.task(name="app.tasks.enrichment_tasks.enrich_cve_task")
def enrich_cve_task(cve_id: str):
    """Background task to enrich a single CVE from NVD.

    Args:
        cve_id: CVE identifier (e.g., CVE-2023-1234)
    """
    logger.info(f"Starting enrich_cve_task for {cve_id}")

    db = SessionLocal()
    try:
        service = CVECorrelationService(db)

        # Run async function in sync context
        success = asyncio.run(service.enrich_cve_from_nvd(cve_id))

        logger.info(f"Completed enrich_cve_task for {cve_id}: success={success}")
        return {
            "status": "success",
            "cve_id": cve_id,
            "enriched": success
        }
    except Exception as e:
        logger.error(f"Error in enrich_cve_task for {cve_id}: {e}")
        return {
            "status": "error",
            "cve_id": cve_id,
            "error": str(e)
        }
    finally:
        db.close()
