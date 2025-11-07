"""Enhanced query generation API endpoints for Phase 4."""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from ..core.database import get_db
from ..services.enhanced_query_generator import EnhancedQueryGenerator

router = APIRouter()


class HuntCampaignRequest(BaseModel):
    """Request model for hunt campaign generation."""
    technique_ids: List[str] = Field(..., description="List of MITRE ATT&CK technique IDs")
    platforms: List[str] = Field(..., description="EDR platforms (defender, crowdstrike, carbonblack, sentinelone)")
    threat_actor: Optional[str] = Field(None, description="Threat actor name for context")
    timeframe: Optional[str] = Field("7d", description="Time range (e.g., '7d', '24h', '30d')")
    include_variations: bool = Field(True, description="Generate broad, balanced, and specific variations")


class QueryVariationRequest(BaseModel):
    """Request model for single query with variations."""
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID")
    platform: str = Field(..., description="EDR platform")
    variation: str = Field("balanced", description="Query variation: broad, balanced, or specific")
    timeframe: Optional[str] = Field("7d", description="Time range")
    threat_actor: Optional[str] = Field(None, description="Threat actor for context")


class HuntCampaignResponse(BaseModel):
    """Response model for hunt campaign."""
    queries: Dict[str, List[Dict[str, Any]]]
    reasoning: Dict[str, Any]
    hunt_sequence: List[Dict[str, Any]]
    threat_context: Optional[Dict[str, Any]]
    generated_at: str


@router.post("/hunt-campaign", response_model=HuntCampaignResponse)
async def generate_hunt_campaign(
    request: HuntCampaignRequest,
    db: Session = Depends(get_db)
):
    """Generate a complete hunt campaign with queries, variations, and analytic reasoning.

    This endpoint generates:
    - Multiple query variations (broad, balanced, specific) for each technique/platform
    - Analytic reasoning and hunt hypothesis
    - Recommended hunt sequence
    - Threat actor context and IOCs (if provided)
    - Investigation guidance

    Example:
    ```json
    {
        "technique_ids": ["T1055", "T1003.001"],
        "platforms": ["defender", "crowdstrike"],
        "threat_actor": "APT29",
        "timeframe": "7d",
        "include_variations": true
    }
    ```
    """
    generator = EnhancedQueryGenerator(db)

    try:
        campaign = generator.generate_hunt_campaign_queries(
            technique_ids=request.technique_ids,
            platforms=request.platforms,
            threat_actor=request.threat_actor,
            timeframe=request.timeframe,
            include_variations=request.include_variations
        )

        if not campaign["queries"]:
            raise HTTPException(
                status_code=404,
                detail="No templates found for the specified techniques and platforms"
            )

        return campaign

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate hunt campaign: {str(e)}"
        )


@router.post("/query-with-explanation")
async def generate_query_with_explanation(
    request: QueryVariationRequest,
    db: Session = Depends(get_db)
):
    """Generate a single query with detailed explanation.

    This endpoint generates a query with:
    - Selected variation (broad, balanced, or specific)
    - Detailed explanation of the query logic
    - False positive guidance
    - Expected results
    - Investigation recommendations

    Example:
    ```json
    {
        "technique_id": "T1055",
        "platform": "defender",
        "variation": "balanced",
        "timeframe": "7d",
        "threat_actor": "APT29"
    }
    ```
    """
    generator = EnhancedQueryGenerator(db)

    try:
        # Get threat actor context if provided
        actor_context = None
        if request.threat_actor:
            actor_context = generator._get_threat_actor_context(
                request.threat_actor,
                [request.technique_id]
            )

        # Get template
        templates = generator._get_matching_templates(
            request.technique_id,
            request.platform
        )

        if not templates:
            raise HTTPException(
                status_code=404,
                detail=f"No template found for {request.technique_id} on {request.platform}"
            )

        # Generate query
        query = generator._generate_single_query(
            technique_id=request.technique_id,
            template=templates[0],
            variation=request.variation,
            timeframe=request.timeframe,
            actor_context=actor_context
        )

        if not query:
            raise HTTPException(
                status_code=500,
                detail="Failed to generate query"
            )

        return query

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate query: {str(e)}"
        )


@router.get("/hunt-sequence/{technique_ids}")
async def get_hunt_sequence(
    technique_ids: str,  # Comma-separated list
    db: Session = Depends(get_db)
):
    """Get recommended hunt sequence for techniques.

    Returns the recommended order to hunt for specified techniques
    based on typical attack progression through MITRE tactics.

    Example: /hunt-sequence/T1055,T1003.001,T1059.001
    """
    generator = EnhancedQueryGenerator(db)

    technique_list = [tid.strip() for tid in technique_ids.split(",")]

    try:
        sequence = generator._recommend_hunt_sequence(technique_list)

        return {
            "technique_ids": technique_list,
            "recommended_sequence": sequence
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate hunt sequence: {str(e)}"
        )


@router.get("/related-techniques/{technique_id}")
async def get_related_techniques(
    technique_id: str,
    db: Session = Depends(get_db)
):
    """Get related techniques to hunt for.

    Returns techniques that share tactics with the specified technique,
    useful for expanding hunt campaigns.

    Example: /related-techniques/T1055
    """
    generator = EnhancedQueryGenerator(db)

    try:
        related = generator._find_related_techniques([technique_id])

        return {
            "technique_id": technique_id,
            "related_techniques": related
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to find related techniques: {str(e)}"
        )


@router.post("/analytic-reasoning")
async def generate_analytic_reasoning(
    technique_ids: List[str],
    threat_actor: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Generate analytic reasoning for a set of techniques.

    Returns:
    - Hunt hypothesis
    - Expected results
    - Investigation guidance
    - Related techniques

    Example:
    ```json
    {
        "technique_ids": ["T1055", "T1003.001"],
        "threat_actor": "APT29"
    }
    ```
    """
    generator = EnhancedQueryGenerator(db)

    try:
        # Get threat actor context
        actor_context = None
        if threat_actor:
            actor_context = generator._get_threat_actor_context(
                threat_actor,
                technique_ids
            )

        reasoning = generator._generate_analytic_reasoning(
            technique_ids=technique_ids,
            threat_actor=threat_actor,
            actor_context=actor_context
        )

        return {
            "technique_ids": technique_ids,
            "threat_actor": threat_actor,
            "reasoning": reasoning,
            "threat_context": actor_context
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate analytic reasoning: {str(e)}"
        )


@router.get("/query-variations/{technique_id}/{platform}")
async def get_query_variations(
    technique_id: str,
    platform: str,
    timeframe: str = "7d",
    threat_actor: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get all three query variations (broad, balanced, specific) for a technique.

    Example: /query-variations/T1055/defender?timeframe=7d&threat_actor=APT29
    """
    generator = EnhancedQueryGenerator(db)

    try:
        # Get threat actor context if provided
        actor_context = None
        if threat_actor:
            actor_context = generator._get_threat_actor_context(
                threat_actor,
                [technique_id]
            )

        # Get template
        templates = generator._get_matching_templates(technique_id, platform)

        if not templates:
            raise HTTPException(
                status_code=404,
                detail=f"No template found for {technique_id} on {platform}"
            )

        # Generate all variations
        variations = generator._generate_query_variations(
            technique_id=technique_id,
            template=templates[0],
            timeframe=timeframe,
            actor_context=actor_context
        )

        return {
            "technique_id": technique_id,
            "platform": platform,
            "variations": {
                var["metadata"]["variation"]: var
                for var in variations
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate query variations: {str(e)}"
        )
