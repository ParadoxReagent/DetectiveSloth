"""Threat intelligence API endpoints."""

from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..core.database import get_db
from ..services.threat_intel_service import ThreatIntelService

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


@router.post("/update", response_model=UpdateResponse)
async def update_threat_intel(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Update threat intelligence from all feeds."""
    service = ThreatIntelService(db)

    try:
        results = await service.update_all_feeds()
        total = sum(results.values())

        return UpdateResponse(
            success=True,
            message=f"Successfully updated {total} indicators from {len(results)} feeds",
            results=results
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update threat intel: {str(e)}")


@router.post("/update/otx")
async def update_otx(days: int = 7, db: Session = Depends(get_db)):
    """Update IOCs from AlienVault OTX."""
    service = ThreatIntelService(db)

    try:
        count = await service.ingest_otx_indicators(days=days)
        return {
            "success": True,
            "message": f"Successfully ingested {count} indicators from OTX",
            "count": count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update OTX: {str(e)}")


@router.post("/update/urlhaus")
async def update_urlhaus(db: Session = Depends(get_db)):
    """Update URLs from URLhaus."""
    service = ThreatIntelService(db)

    try:
        count = await service.ingest_abusech_urlhaus()
        return {
            "success": True,
            "message": f"Successfully ingested {count} URLs from URLhaus",
            "count": count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update URLhaus: {str(e)}")


@router.post("/update/threatfox")
async def update_threatfox(db: Session = Depends(get_db)):
    """Update IOCs from ThreatFox."""
    service = ThreatIntelService(db)

    try:
        count = await service.ingest_abusech_threatfox()
        return {
            "success": True,
            "message": f"Successfully ingested {count} IOCs from ThreatFox",
            "count": count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update ThreatFox: {str(e)}")


@router.post("/update/cisa-kev")
async def update_cisa_kev(db: Session = Depends(get_db)):
    """Update CVEs from CISA Known Exploited Vulnerabilities catalog."""
    service = ThreatIntelService(db)

    try:
        count = await service.ingest_cisa_kev()
        return {
            "success": True,
            "message": f"Successfully ingested {count} CVEs from CISA KEV",
            "count": count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update CISA KEV: {str(e)}")


@router.post("/update/greynoise")
async def update_greynoise(classification: str = "malicious", db: Session = Depends(get_db)):
    """Update IPs from GreyNoise.

    Args:
        classification: Filter by classification (malicious, benign, unknown)
    """
    service = ThreatIntelService(db)

    try:
        count = await service.ingest_greynoise(classification=classification)
        return {
            "success": True,
            "message": f"Successfully ingested {count} IPs from GreyNoise",
            "count": count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update GreyNoise: {str(e)}")
