"""API endpoints for threat actor profiling."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from ..core.database import get_db
from ..services.threat_actor_service import ThreatActorService

router = APIRouter(prefix="/api/threat-actors", tags=["threat-actors"])


class CreateActorRequest(BaseModel):
    """Request to create a threat actor profile."""
    name: str
    aliases: Optional[List[str]] = None
    actor_type: Optional[str] = None
    motivation: Optional[str] = None
    sophistication: Optional[str] = None
    suspected_origin: Optional[str] = None
    description: Optional[str] = None


class BuildProfileRequest(BaseModel):
    """Request to build actor profile from IOCs."""
    actor_name: str


class CompareActorsRequest(BaseModel):
    """Request to compare two actors."""
    actor1_name: str
    actor2_name: str


@router.post("/")
async def create_actor(request: CreateActorRequest, db: Session = Depends(get_db)):
    """Create or update a threat actor profile."""
    service = ThreatActorService(db)
    actor = service.create_or_update_actor(
        name=request.name,
        aliases=request.aliases,
        actor_type=request.actor_type,
        motivation=request.motivation,
        sophistication=request.sophistication,
        suspected_origin=request.suspected_origin,
        description=request.description
    )

    return {
        "status": "success",
        "actor": {
            "name": actor.name,
            "aliases": actor.aliases,
            "type": actor.actor_type,
            "motivation": actor.motivation,
            "origin": actor.suspected_origin,
        }
    }


@router.get("/")
async def list_actors(
    limit: int = 100,
    active_only: bool = False,
    db: Session = Depends(get_db)
):
    """List threat actors."""
    from ..models.threat_actor import ThreatActor

    query = db.query(ThreatActor)

    if active_only:
        query = query.filter(ThreatActor.active_status == "active")

    actors = query.limit(limit).all()

    return {
        "count": len(actors),
        "actors": [
            {
                "name": actor.name,
                "aliases": actor.aliases,
                "type": actor.actor_type,
                "motivation": actor.motivation,
                "origin": actor.suspected_origin,
                "status": actor.active_status,
                "technique_count": len(actor.techniques or []),
                "last_observed": actor.last_observed.isoformat() if actor.last_observed else None,
            }
            for actor in actors
        ]
    }


@router.get("/{actor_name}")
async def get_actor(actor_name: str, db: Session = Depends(get_db)):
    """Get detailed information about a threat actor."""
    service = ThreatActorService(db)
    actor = service.get_actor_by_name(actor_name)

    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")

    return {
        "name": actor.name,
        "aliases": actor.aliases,
        "type": actor.actor_type,
        "motivation": actor.motivation,
        "sophistication": actor.sophistication,
        "origin": actor.suspected_origin,
        "attribution_confidence": actor.attribution_confidence,
        "status": actor.active_status,
        "first_observed": actor.first_observed.isoformat() if actor.first_observed else None,
        "last_observed": actor.last_observed.isoformat() if actor.last_observed else None,
        "techniques": actor.techniques,
        "tactics": actor.tactics,
        "tools": actor.tools,
        "targeted_sectors": actor.targeted_sectors,
        "targeted_countries": actor.targeted_countries,
        "known_campaigns": actor.known_campaigns,
        "description": actor.description,
        "references": actor.references,
    }


@router.post("/build-profile")
async def build_actor_profile(request: BuildProfileRequest, db: Session = Depends(get_db)):
    """Build or enhance actor profile from associated IOCs."""
    service = ThreatActorService(db)
    actor = service.build_profile_from_iocs(request.actor_name)

    return {
        "status": "success",
        "actor_name": actor.name,
        "techniques_found": len(actor.techniques or []),
        "tools_found": len(actor.tools or []),
        "campaigns_found": len(actor.known_campaigns or []),
    }


@router.get("/active/recent")
async def get_active_actors(days: int = 90, db: Session = Depends(get_db)):
    """Get recently active threat actors."""
    service = ThreatActorService(db)
    actors = service.get_active_actors(days=days)

    return {
        "count": len(actors),
        "actors": [
            {
                "name": actor.name,
                "type": actor.actor_type,
                "last_observed": actor.last_observed.isoformat() if actor.last_observed else None,
                "techniques": actor.techniques,
                "targeted_sectors": actor.targeted_sectors,
            }
            for actor in actors
        ]
    }


@router.get("/by-technique/{technique_id}")
async def get_actors_by_technique(technique_id: str, db: Session = Depends(get_db)):
    """Get actors known to use a specific technique."""
    service = ThreatActorService(db)
    actors = service.get_actors_by_technique(technique_id)

    return {
        "technique_id": technique_id,
        "count": len(actors),
        "actors": [
            {
                "name": actor.name,
                "type": actor.actor_type,
                "origin": actor.suspected_origin,
            }
            for actor in actors
        ]
    }


@router.get("/by-sector/{sector}")
async def get_actors_by_sector(sector: str, db: Session = Depends(get_db)):
    """Get actors targeting a specific sector."""
    service = ThreatActorService(db)
    actors = service.get_actors_by_sector(sector)

    return {
        "sector": sector,
        "count": len(actors),
        "actors": [
            {
                "name": actor.name,
                "type": actor.actor_type,
                "motivation": actor.motivation,
                "techniques": actor.techniques,
            }
            for actor in actors
        ]
    }


@router.post("/compare")
async def compare_actors(request: CompareActorsRequest, db: Session = Depends(get_db)):
    """Compare two threat actors."""
    service = ThreatActorService(db)
    comparison = service.compare_actors(request.actor1_name, request.actor2_name)

    return comparison


@router.get("/{actor_name}/report")
async def generate_actor_report(actor_name: str, db: Session = Depends(get_db)):
    """Generate comprehensive intelligence report for a threat actor."""
    service = ThreatActorService(db)
    report = service.generate_actor_report(actor_name)

    if "error" in report:
        raise HTTPException(status_code=404, detail=report["error"])

    return report
