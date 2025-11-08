"""Threat intelligence API endpoints."""

from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from celery.result import AsyncResult

from ..core.database import get_db
from ..services.threat_intel_service import ThreatIntelService
from ..tasks.threat_intel_tasks import (
    update_all_feeds_task,
    update_otx_task,
    update_urlhaus_task,
    update_threatfox_task,
    update_cisa_kev_task,
    update_greynoise_task
)

router = APIRouter()


class IOCResponse(BaseModel):
    """Response model for IOC."""
    id: int
    source: str
    ioc_type: str
    ioc_value: str
    confidence_score: Optional[int]
    tags: List[str]
    associated_techniques: List[str]

    class Config:
        from_attributes = True


class UpdateResponse(BaseModel):
    """Response for update operations."""
    success: bool
    message: str
    results: Dict[str, int]


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


@router.get("/recent", response_model=List[IOCResponse])
async def get_recent_iocs(
    days: int = 7,
    ioc_type: Optional[str] = None,
    source: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get recent IOCs from threat intelligence feeds."""
    service = ThreatIntelService(db)
    iocs = service.get_recent_iocs(days=days, ioc_type=ioc_type, source=source)
    return iocs[skip:skip + limit]


@router.get("/by-technique/{technique_id}", response_model=List[IOCResponse])
async def get_iocs_by_technique(
    technique_id: str,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get IOCs associated with a specific MITRE technique."""
    service = ThreatIntelService(db)
    iocs = service.get_iocs_by_technique(technique_id)
    return iocs[skip:skip + limit]


@router.post("/update", response_model=TaskResponse)
async def update_threat_intel():
    """Update threat intelligence from all feeds (async background task)."""
    try:
        task = update_all_feeds_task.delay()
        return TaskResponse(
            task_id=task.id,
            status="processing",
            message="Threat intelligence update started. Use /api/threat-intel/tasks/{task_id} to check status."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start update task: {str(e)}")


@router.post("/update/otx", response_model=TaskResponse)
async def update_otx(days: int = 7):
    """Update IOCs from AlienVault OTX (async background task)."""
    try:
        task = update_otx_task.delay(days=days)
        return TaskResponse(
            task_id=task.id,
            status="processing",
            message=f"OTX update started. Use /api/threat-intel/tasks/{task.id} to check status."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start OTX update: {str(e)}")


@router.post("/update/urlhaus", response_model=TaskResponse)
async def update_urlhaus():
    """Update URLs from URLhaus (async background task)."""
    try:
        task = update_urlhaus_task.delay()
        return TaskResponse(
            task_id=task.id,
            status="processing",
            message=f"URLhaus update started. Use /api/threat-intel/tasks/{task.id} to check status."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start URLhaus update: {str(e)}")


@router.post("/update/threatfox", response_model=TaskResponse)
async def update_threatfox():
    """Update IOCs from ThreatFox (async background task)."""
    try:
        task = update_threatfox_task.delay()
        return TaskResponse(
            task_id=task.id,
            status="processing",
            message=f"ThreatFox update started. Use /api/threat-intel/tasks/{task.id} to check status."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start ThreatFox update: {str(e)}")


@router.post("/update/cisa-kev", response_model=TaskResponse)
async def update_cisa_kev():
    """Update CVEs from CISA Known Exploited Vulnerabilities catalog (async background task)."""
    try:
        task = update_cisa_kev_task.delay()
        return TaskResponse(
            task_id=task.id,
            status="processing",
            message=f"CISA KEV update started. Use /api/threat-intel/tasks/{task.id} to check status."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start CISA KEV update: {str(e)}")


@router.post("/update/greynoise", response_model=TaskResponse)
async def update_greynoise(classification: str = "malicious"):
    """Update IPs from GreyNoise (async background task).

    Args:
        classification: Filter by classification (malicious, benign, unknown)
    """
    try:
        task = update_greynoise_task.delay(classification=classification)
        return TaskResponse(
            task_id=task.id,
            status="processing",
            message=f"GreyNoise update started. Use /api/threat-intel/tasks/{task.id} to check status."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start GreyNoise update: {str(e)}")


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
