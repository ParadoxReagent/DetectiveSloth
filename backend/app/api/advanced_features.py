"""Advanced features API endpoints for Phase 6."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel

from ..core.database import get_db
from ..services.hypothesis_service import HypothesisService
from ..services.playbook_service import PlaybookService
from ..services.query_optimization_service import QueryOptimizationService
from ..services.edr_integration_service import EDRIntegrationService
from ..services.siem_export_service import SIEMExportService
from ..services.collaboration_service import CollaborationService


router = APIRouter(prefix="/api/advanced", tags=["Advanced Features"])


# Request/Response Models

class RelatedTechniquesRequest(BaseModel):
    technique_id: str
    limit: int = 5


class HuntSequenceRequest(BaseModel):
    technique_ids: List[str]


class CoverageGapRequest(BaseModel):
    tactic: Optional[str] = None


class HypothesisRequest(BaseModel):
    technique_id: str
    context: Optional[dict] = None


class PlaybookExecuteRequest(BaseModel):
    threat_actor: str
    platforms: List[str]
    analyst: str
    create_campaign: bool = True


class EDRConfigRequest(BaseModel):
    platform: str
    config: dict


class ExecuteQueryRequest(BaseModel):
    query_id: int
    execute_immediately: bool = False


class DeduplicateRequest(BaseModel):
    execution_ids: List[int]


class ExportRequest(BaseModel):
    query_id: int
    timeframe: str = "7d"


class SOARPlaybookRequest(BaseModel):
    campaign_id: int
    platform: str = "generic"


class TicketRequest(BaseModel):
    finding_id: int
    ticket_system: str = "jira"
    config: Optional[dict] = None


class ShareCampaignRequest(BaseModel):
    campaign_id: int
    shared_by: str
    shared_with: str
    permission_level: str = "read"


class AnnotationRequest(BaseModel):
    author: str
    annotation_text: str


class UpdateAnnotationRequest(BaseModel):
    annotation_text: str
    author: str


class CombineQueriesRequest(BaseModel):
    technique_ids: List[str]
    platform: str


class BenchmarkRequest(BaseModel):
    query_text: str
    platform: str
    estimated_time: Optional[float] = None


# Intelligence Features Endpoints

@router.post("/intelligence/related-techniques")
def get_related_techniques(
    request: RelatedTechniquesRequest,
    db: Session = Depends(get_db)
):
    """Suggest related techniques for threat hunting."""
    service = HypothesisService(db)
    return service.suggest_related_techniques(
        technique_id=request.technique_id,
        limit=request.limit
    )


@router.post("/intelligence/hunt-sequence")
def recommend_hunt_sequence(
    request: HuntSequenceRequest,
    db: Session = Depends(get_db)
):
    """Recommend optimal hunting sequence based on kill chain."""
    service = HypothesisService(db)
    return service.recommend_hunt_sequence(request.technique_ids)


@router.post("/intelligence/coverage-gaps")
def identify_coverage_gaps(
    request: CoverageGapRequest,
    db: Session = Depends(get_db)
):
    """Identify gaps in detection coverage."""
    service = HypothesisService(db)
    return service.identify_coverage_gaps(tactic=request.tactic)


@router.post("/intelligence/hypothesis")
def generate_hypothesis(
    request: HypothesisRequest,
    db: Session = Depends(get_db)
):
    """Generate comprehensive hunting hypothesis."""
    service = HypothesisService(db)
    return service.generate_hypothesis(
        technique_id=request.technique_id,
        context=request.context
    )


# Threat Actor Playbook Endpoints

@router.post("/playbooks/initialize")
def initialize_playbooks(db: Session = Depends(get_db)):
    """Initialize pre-built threat actor playbooks."""
    service = PlaybookService(db)
    return service.initialize_playbooks()


@router.get("/playbooks")
def list_playbooks(
    active_only: bool = True,
    industry: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List all threat actor playbooks."""
    service = PlaybookService(db)
    return service.list_playbooks(active_only=active_only, industry=industry)


@router.get("/playbooks/{threat_actor}")
def get_playbook(threat_actor: str, db: Session = Depends(get_db)):
    """Get a specific threat actor playbook."""
    service = PlaybookService(db)
    result = service.get_playbook(threat_actor)
    if result is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return result


@router.post("/playbooks/execute")
def execute_playbook(
    request: PlaybookExecuteRequest,
    db: Session = Depends(get_db)
):
    """Execute a threat actor playbook."""
    service = PlaybookService(db)
    return service.execute_playbook(
        threat_actor=request.threat_actor,
        platforms=request.platforms,
        analyst=request.analyst,
        create_campaign=request.create_campaign
    )


@router.get("/playbooks/{threat_actor}/timeline")
def get_ttp_timeline(threat_actor: str, db: Session = Depends(get_db)):
    """Get TTP timeline for a threat actor."""
    service = PlaybookService(db)
    return service.get_ttp_timeline(threat_actor)


@router.get("/playbooks/search/technique/{technique_id}")
def search_playbooks_by_technique(
    technique_id: str,
    db: Session = Depends(get_db)
):
    """Search playbooks that use a specific technique."""
    service = PlaybookService(db)
    return service.search_playbooks_by_technique(technique_id)


# Query Optimization Endpoints

@router.get("/optimization/query/{query_id}")
def analyze_query_performance(query_id: int, db: Session = Depends(get_db)):
    """Analyze performance of a specific query."""
    service = QueryOptimizationService(db)
    return service.analyze_query_performance(query_id)


@router.get("/optimization/indexes/{platform}")
def suggest_index_improvements(platform: str, db: Session = Depends(get_db)):
    """Suggest database index improvements for a platform."""
    service = QueryOptimizationService(db)
    return service.suggest_index_improvements(platform)


@router.post("/optimization/combine")
def combine_related_queries(
    request: CombineQueriesRequest,
    db: Session = Depends(get_db)
):
    """Combine multiple related queries for optimization."""
    service = QueryOptimizationService(db)
    return service.combine_related_queries(
        technique_ids=request.technique_ids,
        platform=request.platform
    )


@router.post("/optimization/benchmark")
def benchmark_query(
    request: BenchmarkRequest,
    db: Session = Depends(get_db)
):
    """Benchmark a query and provide optimization suggestions."""
    service = QueryOptimizationService(db)
    return service.benchmark_query(
        query_text=request.query_text,
        platform=request.platform,
        estimated_time=request.estimated_time
    )


# EDR Integration Endpoints

@router.post("/edr/configure")
def configure_edr_platform(
    request: EDRConfigRequest,
    db: Session = Depends(get_db)
):
    """Configure EDR platform connection."""
    service = EDRIntegrationService(db)
    return service.configure_platform(
        platform=request.platform,
        config=request.config
    )


@router.post("/edr/execute")
def execute_query_on_edr(
    request: ExecuteQueryRequest,
    db: Session = Depends(get_db)
):
    """Execute a query on configured EDR platform."""
    service = EDRIntegrationService(db)
    return service.execute_query(
        query_id=request.query_id,
        execute_immediately=request.execute_immediately
    )


@router.get("/edr/results/{execution_id}")
def get_execution_results(execution_id: int, db: Session = Depends(get_db)):
    """Get results from an EDR execution."""
    service = EDRIntegrationService(db)
    return service.collect_results(execution_id)


@router.post("/edr/deduplicate")
def deduplicate_findings(
    request: DeduplicateRequest,
    db: Session = Depends(get_db)
):
    """Deduplicate findings across multiple executions."""
    service = EDRIntegrationService(db)
    return service.deduplicate_findings(request.execution_ids)


@router.get("/edr/status/{query_id}")
def get_query_execution_status(query_id: int, db: Session = Depends(get_db)):
    """Get execution status for a query."""
    service = EDRIntegrationService(db)
    return service.get_execution_status(query_id)


@router.post("/edr/bulk-execute")
def bulk_execute_queries(
    query_ids: List[int],
    db: Session = Depends(get_db)
):
    """Execute multiple queries in bulk."""
    service = EDRIntegrationService(db)
    return service.bulk_execute(query_ids)


# SIEM/SOAR Export Endpoints

@router.post("/export/splunk")
def export_to_splunk(request: ExportRequest, db: Session = Depends(get_db)):
    """Export query to Splunk SPL format."""
    service = SIEMExportService(db)
    return service.export_to_splunk(
        query_id=request.query_id,
        timeframe=request.timeframe
    )


@router.post("/export/sentinel")
def export_to_sentinel(request: ExportRequest, db: Session = Depends(get_db)):
    """Export query to Microsoft Sentinel KQL format."""
    service = SIEMExportService(db)
    return service.export_to_sentinel(
        query_id=request.query_id,
        timeframe=request.timeframe
    )


@router.post("/export/chronicle")
def export_to_chronicle(request: ExportRequest, db: Session = Depends(get_db)):
    """Export query to Google Chronicle YARA-L format."""
    service = SIEMExportService(db)
    return service.export_to_chronicle(
        query_id=request.query_id,
        timeframe=request.timeframe
    )


@router.post("/soar/playbook")
def create_soar_playbook(
    request: SOARPlaybookRequest,
    db: Session = Depends(get_db)
):
    """Create a SOAR playbook from a hunt campaign."""
    service = SIEMExportService(db)
    return service.create_soar_playbook(
        campaign_id=request.campaign_id,
        platform=request.platform
    )


@router.post("/soar/ticket")
def create_ticket(request: TicketRequest, db: Session = Depends(get_db)):
    """Create a ticket for a finding."""
    service = SIEMExportService(db)
    return service.create_ticket(
        finding_id=request.finding_id,
        ticket_system=request.ticket_system,
        config=request.config
    )


@router.get("/export/campaign/{campaign_id}")
def export_campaign_report(
    campaign_id: int,
    format: str = "json",
    db: Session = Depends(get_db)
):
    """Export comprehensive campaign report."""
    service = SIEMExportService(db)
    return service.export_campaign_report(campaign_id, format)


# Collaboration Endpoints

@router.post("/collaboration/share")
def share_campaign(
    request: ShareCampaignRequest,
    db: Session = Depends(get_db)
):
    """Share a campaign with team member."""
    service = CollaborationService(db)
    return service.share_campaign(
        campaign_id=request.campaign_id,
        shared_by=request.shared_by,
        shared_with=request.shared_with,
        permission_level=request.permission_level
    )


@router.delete("/collaboration/share/{share_id}")
def revoke_share(share_id: int, db: Session = Depends(get_db)):
    """Revoke a campaign share."""
    service = CollaborationService(db)
    return service.revoke_share(share_id)


@router.get("/collaboration/campaigns/{user}")
def get_shared_campaigns(
    user: str,
    include_owned: bool = True,
    db: Session = Depends(get_db)
):
    """Get campaigns shared with a user."""
    service = CollaborationService(db)
    return service.get_shared_campaigns(user, include_owned)


@router.get("/collaboration/shares/{campaign_id}")
def get_campaign_shares(campaign_id: int, db: Session = Depends(get_db)):
    """Get all shares for a campaign."""
    service = CollaborationService(db)
    return service.get_campaign_shares(campaign_id)


@router.post("/annotations/query/{query_id}")
def add_query_annotation(
    query_id: int,
    request: AnnotationRequest,
    db: Session = Depends(get_db)
):
    """Add annotation to a query."""
    service = CollaborationService(db)
    return service.add_query_annotation(
        query_id=query_id,
        author=request.author,
        annotation_text=request.annotation_text
    )


@router.post("/annotations/campaign/{campaign_id}")
def add_campaign_annotation(
    campaign_id: int,
    request: AnnotationRequest,
    db: Session = Depends(get_db)
):
    """Add annotation to a campaign."""
    service = CollaborationService(db)
    return service.add_campaign_annotation(
        campaign_id=campaign_id,
        author=request.author,
        annotation_text=request.annotation_text
    )


@router.put("/annotations/{annotation_type}/{annotation_id}")
def update_annotation(
    annotation_type: str,
    annotation_id: int,
    request: UpdateAnnotationRequest,
    db: Session = Depends(get_db)
):
    """Update an annotation."""
    service = CollaborationService(db)
    return service.update_annotation(
        annotation_id=annotation_id,
        annotation_type=annotation_type,
        annotation_text=request.annotation_text,
        author=request.author
    )


@router.delete("/annotations/{annotation_type}/{annotation_id}")
def delete_annotation(
    annotation_type: str,
    annotation_id: int,
    author: str,
    db: Session = Depends(get_db)
):
    """Delete an annotation."""
    service = CollaborationService(db)
    return service.delete_annotation(
        annotation_id=annotation_id,
        annotation_type=annotation_type,
        author=author
    )


@router.get("/annotations/query/{query_id}")
def get_query_annotations(query_id: int, db: Session = Depends(get_db)):
    """Get all annotations for a query."""
    service = CollaborationService(db)
    return service.get_query_annotations(query_id)


@router.get("/annotations/campaign/{campaign_id}")
def get_campaign_annotations(campaign_id: int, db: Session = Depends(get_db)):
    """Get all annotations for a campaign."""
    service = CollaborationService(db)
    return service.get_campaign_annotations(campaign_id)


# Effectiveness Tracking Endpoints

@router.get("/effectiveness/campaign/{campaign_id}")
def track_campaign_effectiveness(campaign_id: int, db: Session = Depends(get_db)):
    """Track effectiveness of a hunt campaign."""
    service = CollaborationService(db)
    return service.track_hunt_effectiveness(campaign_id)


@router.get("/effectiveness/query/{query_id}")
def track_query_effectiveness(query_id: int, db: Session = Depends(get_db)):
    """Get effectiveness metrics for a query."""
    service = CollaborationService(db)
    return service.track_query_effectiveness(query_id)


@router.get("/effectiveness/top-queries")
def get_top_performing_queries(
    platform: Optional[str] = None,
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """Get top performing queries."""
    service = CollaborationService(db)
    return service.get_top_performing_queries(platform, limit)


@router.get("/collaboration/activity/{user}")
def get_collaboration_activity(
    user: str,
    days: int = 7,
    db: Session = Depends(get_db)
):
    """Get collaboration activity for a user."""
    service = CollaborationService(db)
    return service.get_collaboration_activity(user, days)
