"""Hunt campaigns API endpoints."""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..core.database import get_db
from ..models.campaign import HuntCampaign

router = APIRouter()


class CampaignCreate(BaseModel):
    """Request model for creating a campaign."""
    name: str
    description: Optional[str] = None
    techniques: List[str]
    threat_actor: Optional[str] = None
    analyst: Optional[str] = None


class CampaignUpdate(BaseModel):
    """Request model for updating a campaign."""
    status: Optional[str] = None
    end_date: Optional[datetime] = None
    findings: Optional[dict] = None


class CampaignResponse(BaseModel):
    """Response model for campaign."""
    id: int
    name: str
    description: Optional[str]
    techniques: List[str]
    threat_actor: Optional[str]
    start_date: datetime
    end_date: Optional[datetime]
    status: str
    findings: dict
    analyst: Optional[str]

    class Config:
        from_attributes = True


@router.post("/", response_model=CampaignResponse)
async def create_campaign(campaign: CampaignCreate, db: Session = Depends(get_db)):
    """Create a new hunt campaign."""
    new_campaign = HuntCampaign(
        name=campaign.name,
        description=campaign.description,
        techniques=campaign.techniques,
        threat_actor=campaign.threat_actor,
        analyst=campaign.analyst,
        status="active"
    )

    db.add(new_campaign)
    db.commit()
    db.refresh(new_campaign)

    return new_campaign


@router.get("/", response_model=List[CampaignResponse])
async def list_campaigns(
    status: Optional[str] = None,
    threat_actor: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List hunt campaigns with optional filters."""
    query = db.query(HuntCampaign)

    if status:
        query = query.filter(HuntCampaign.status == status)

    if threat_actor:
        query = query.filter(HuntCampaign.threat_actor == threat_actor)

    campaigns = query.offset(skip).limit(limit).all()
    return campaigns


@router.get("/{campaign_id}", response_model=CampaignResponse)
async def get_campaign(campaign_id: int, db: Session = Depends(get_db)):
    """Get a specific campaign by ID."""
    campaign = db.query(HuntCampaign).filter(HuntCampaign.id == campaign_id).first()

    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    return campaign


@router.patch("/{campaign_id}", response_model=CampaignResponse)
async def update_campaign(
    campaign_id: int,
    update: CampaignUpdate,
    db: Session = Depends(get_db)
):
    """Update a campaign."""
    campaign = db.query(HuntCampaign).filter(HuntCampaign.id == campaign_id).first()

    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    if update.status is not None:
        campaign.status = update.status

    if update.end_date is not None:
        campaign.end_date = update.end_date

    if update.findings is not None:
        campaign.findings = update.findings

    db.commit()
    db.refresh(campaign)

    return campaign


@router.delete("/{campaign_id}")
async def delete_campaign(campaign_id: int, db: Session = Depends(get_db)):
    """Delete a campaign."""
    campaign = db.query(HuntCampaign).filter(HuntCampaign.id == campaign_id).first()

    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    db.delete(campaign)
    db.commit()

    return {"success": True, "message": f"Campaign {campaign_id} deleted"}
