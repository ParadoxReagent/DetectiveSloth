"""API endpoints for IOC enrichment and intelligence processing."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional, Dict
from pydantic import BaseModel
from celery.result import AsyncResult
from ..core.database import get_db
from ..services.enrichment_service import EnrichmentService
from ..services.ttp_extraction_service import TTPExtractionService
from ..tasks.enrichment_tasks import deduplicate_iocs_task

router = APIRouter(prefix="/api/enrichment", tags=["enrichment"])


class EnrichIOCRequest(BaseModel):
    """Request to enrich a specific IOC."""
    ioc_value: str
    ioc_type: str


class BulkEnrichRequest(BaseModel):
    """Request to enrich multiple IOCs."""
    limit: Optional[int] = None


class TaskResponse(BaseModel):
    """Response for background task operations."""
    task_id: str
    status: str
    message: str


class TaskStatusResponse(BaseModel):
    """Response for task status check."""
    task_id: str
    status: str
    result: Optional[Dict] = None


class ExtractTTPsRequest(BaseModel):
    """Request to extract TTPs from text."""
    text: str
    confidence_threshold: Optional[float] = 0.5


class ThreatReportRequest(BaseModel):
    """Request to analyze a threat report."""
    report_text: str
    metadata: Optional[dict] = None


@router.post("/ioc")
async def enrich_ioc(request: EnrichIOCRequest, db: Session = Depends(get_db)):
    """Enrich a single IOC with aggregated intelligence."""
    service = EnrichmentService(db)
    enrichment = service.enrich_ioc(request.ioc_value, request.ioc_type)

    if not enrichment:
        raise HTTPException(status_code=404, detail="IOC not found")

    return {
        "ioc_value": enrichment.ioc_value,
        "ioc_type": enrichment.ioc_type,
        "risk_score": enrichment.risk_score,
        "prevalence_score": enrichment.prevalence_score,
        "recency_score": enrichment.recency_score,
        "source_credibility_score": enrichment.source_credibility_score,
        "total_source_count": enrichment.total_source_count,
        "seen_in_sources": enrichment.seen_in_sources,
        "threat_families": enrichment.threat_families,
        "threat_actors": enrichment.threat_actors,
        "campaigns": enrichment.campaigns,
        "associated_techniques": enrichment.associated_techniques,
        "technique_frequency": enrichment.technique_frequency,
        "extracted_ttps": enrichment.extracted_ttps,
        "last_enriched": enrichment.last_enriched.isoformat() if enrichment.last_enriched else None,
    }


@router.post("/bulk")
async def bulk_enrich_iocs(request: BulkEnrichRequest, db: Session = Depends(get_db)):
    """Enrich all IOCs in the database."""
    service = EnrichmentService(db)
    count = service.enrich_all_iocs(limit=request.limit)

    return {
        "status": "completed",
        "iocs_enriched": count,
        "message": f"Successfully enriched {count} IOCs"
    }


@router.post("/deduplicate", response_model=TaskResponse)
async def deduplicate_iocs():
    """Remove duplicate IOC entries (async background task)."""
    try:
        task = deduplicate_iocs_task.delay()
        return TaskResponse(
            task_id=task.id,
            status="processing",
            message=f"IOC deduplication started. Use /api/enrichment/tasks/{task.id} to check status."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start deduplication task: {str(e)}")


@router.get("/tasks/{task_id}", response_model=TaskStatusResponse)
async def get_task_status(task_id: str):
    """Get the status of a background task."""
    try:
        task_result = AsyncResult(task_id)

        response = TaskStatusResponse(
            task_id=task_id,
            status=task_result.status.lower(),
            result=task_result.result if task_result.ready() else None
        )

        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get task status: {str(e)}")


@router.get("/top-iocs")
async def get_top_iocs(
    limit: int = 100,
    min_risk_score: float = 50.0,
    db: Session = Depends(get_db)
):
    """Get top IOCs by risk score."""
    service = EnrichmentService(db)
    iocs = service.get_top_iocs(limit=limit, min_risk_score=min_risk_score)

    return {
        "count": len(iocs),
        "iocs": [
            {
                "ioc_value": ioc.ioc_value,
                "ioc_type": ioc.ioc_type,
                "risk_score": ioc.risk_score,
                "threat_families": ioc.threat_families,
                "threat_actors": ioc.threat_actors,
                "source_count": ioc.total_source_count,
            }
            for ioc in iocs
        ]
    }


@router.post("/extract-ttps")
async def extract_ttps_from_text(request: ExtractTTPsRequest, db: Session = Depends(get_db)):
    """Extract MITRE ATT&CK techniques from unstructured text."""
    service = TTPExtractionService(db)
    techniques = service.extract_techniques_from_text(
        request.text,
        confidence_threshold=request.confidence_threshold
    )

    return {
        "techniques_found": len(techniques),
        "techniques": [
            {
                "technique_id": tid,
                "confidence": conf
            }
            for tid, conf in techniques
        ]
    }


@router.post("/analyze-report")
async def analyze_threat_report(request: ThreatReportRequest, db: Session = Depends(get_db)):
    """Analyze a threat report and extract comprehensive TTP information."""
    service = TTPExtractionService(db)
    analysis = service.extract_ttps_from_report(
        request.report_text,
        report_metadata=request.metadata
    )

    return analysis


@router.post("/enrich-with-ttps/{ioc_value}")
async def enrich_ioc_with_ttps(ioc_value: str, db: Session = Depends(get_db)):
    """Enrich an IOC with TTP extraction."""
    service = TTPExtractionService(db)
    enrichment = service.enrich_ioc_with_ttps(ioc_value)

    if not enrichment:
        raise HTTPException(status_code=404, detail="IOC not found")

    return {
        "ioc_value": enrichment.ioc_value,
        "extracted_ttps": enrichment.extracted_ttps,
        "extraction_confidence": enrichment.extraction_confidence,
        "associated_techniques": enrichment.associated_techniques,
    }
