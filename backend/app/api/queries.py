"""Query generation API endpoints."""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..core.database import get_db
from ..services.query_generator import QueryGenerator

router = APIRouter()


class QueryRequest(BaseModel):
    """Request model for query generation."""
    technique_ids: List[str]
    platforms: List[str]
    timeframe: Optional[str] = "7d"
    include_iocs: bool = True
    ioc_types: Optional[List[str]] = None


class QueryResponse(BaseModel):
    """Response model for generated query."""
    query_id: int
    query: str
    metadata: Dict[str, Any]
    technique: Optional[Dict[str, Any]] = None


class TemplateRequest(BaseModel):
    """Request model for adding a template."""
    technique_id: str
    platform: str
    query_template: str
    variables: Optional[Dict] = None
    confidence: str = "medium"
    false_positive_notes: Optional[str] = None
    data_sources_required: Optional[List[str]] = None
    created_by: str = "user"


@router.post("/generate", response_model=Dict[str, QueryResponse])
async def generate_queries(request: QueryRequest, db: Session = Depends(get_db)):
    """Generate threat hunting queries for specified platforms and techniques."""
    generator = QueryGenerator(db)

    results = generator.generate_multi_platform(
        technique_ids=request.technique_ids,
        platforms=request.platforms,
        timeframe=request.timeframe,
        include_iocs=request.include_iocs,
        ioc_types=request.ioc_types
    )

    if not results:
        raise HTTPException(
            status_code=404,
            detail="No templates found for the specified techniques and platforms"
        )

    return results


@router.post("/templates")
async def add_template(request: TemplateRequest, db: Session = Depends(get_db)):
    """Add a new detection template."""
    generator = QueryGenerator(db)

    try:
        template = generator.add_template(
            technique_id=request.technique_id,
            platform=request.platform,
            query_template=request.query_template,
            variables=request.variables,
            confidence=request.confidence,
            false_positive_notes=request.false_positive_notes,
            data_sources_required=request.data_sources_required,
            created_by=request.created_by
        )

        return {
            "success": True,
            "message": f"Template added for {request.technique_id} on {request.platform}",
            "template_id": template.id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add template: {str(e)}")


@router.get("/templates/{technique_id}")
async def get_templates(technique_id: str, db: Session = Depends(get_db)):
    """Get all templates for a specific technique."""
    generator = QueryGenerator(db)
    templates = generator.get_templates_for_technique(technique_id)

    return {
        "technique_id": technique_id,
        "templates": [
            {
                "id": t.id,
                "platform": t.platform,
                "confidence": t.confidence,
                "data_sources_required": t.data_sources_required,
                "created_by": t.created_by,
                "version": t.version
            }
            for t in templates
        ]
    }
