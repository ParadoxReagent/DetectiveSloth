"""MITRE ATT&CK techniques API endpoints."""

from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from celery.result import AsyncResult

from ..core.database import get_db
from ..services.mitre_service import MitreAttackService
from ..models.mitre import MitreTechnique
from ..tasks.mitre_tasks import update_mitre_attack_task

router = APIRouter()


class TechniqueResponse(BaseModel):
    """Response model for a technique."""
    id: int
    technique_id: str
    name: str
    description: str
    tactics: List[str]
    platforms: List[str]
    data_sources: List[str]
    version: str

    class Config:
        from_attributes = True


class UpdateResponse(BaseModel):
    """Response for update operations."""
    success: bool
    message: str
    count: int


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


@router.get("/", response_model=List[TechniqueResponse])
async def list_techniques(
    tactic: Optional[str] = None,
    platform: Optional[str] = None,
    keyword: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List MITRE ATT&CK techniques with optional filters."""
    service = MitreAttackService(db)
    techniques = service.search_techniques(keyword=keyword, tactic=tactic, platform=platform)
    return techniques[skip:skip + limit]


@router.get("/{technique_id}", response_model=TechniqueResponse)
async def get_technique(technique_id: str, db: Session = Depends(get_db)):
    """Get a specific technique by ID."""
    service = MitreAttackService(db)
    technique = service.get_technique_by_id(technique_id)

    if not technique:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")

    return technique


@router.get("/meta/tactics")
async def list_tactics(db: Session = Depends(get_db)):
    """Get all unique tactics."""
    service = MitreAttackService(db)
    tactics = service.get_all_tactics()
    return {"tactics": tactics}


@router.get("/meta/platforms")
async def list_platforms(db: Session = Depends(get_db)):
    """Get all unique platforms."""
    service = MitreAttackService(db)
    platforms = service.get_all_platforms()
    return {"platforms": platforms}


@router.post("/update", response_model=TaskResponse)
async def update_techniques():
    """Update MITRE ATT&CK techniques from online source (async background task)."""
    try:
        task = update_mitre_attack_task.delay()
        return TaskResponse(
            task_id=task.id,
            status="processing",
            message=f"MITRE ATT&CK update started. Use /api/techniques/tasks/{task.id} to check status."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start update task: {str(e)}")


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
