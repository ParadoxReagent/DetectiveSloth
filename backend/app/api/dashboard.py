"""Dashboard API endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta
from typing import Dict, List, Any

from ..core.database import get_db
from ..models import (
    MitreTechnique,
    ThreatIntel,
    HuntCampaign,
    GeneratedQuery,
    DetectionTemplate,
    CVE,
    ThreatActor
)

router = APIRouter()


@router.get("/api/dashboard/statistics")
async def get_dashboard_statistics(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Get dashboard statistics including:
    - Total techniques, templates, campaigns
    - Recent threat intel summary
    - Recent query generation activity
    - Active campaigns
    """

    # Basic counts
    total_techniques = db.query(MitreTechnique).count()
    total_templates = db.query(DetectionTemplate).count()
    total_campaigns = db.query(HuntCampaign).count()
    active_campaigns = db.query(HuntCampaign).filter(
        HuntCampaign.status.in_(["active", "in_progress"])
    ).count()

    # Threat intel statistics
    last_24h = datetime.utcnow() - timedelta(hours=24)
    last_7d = datetime.utcnow() - timedelta(days=7)

    recent_iocs_24h = db.query(ThreatIntel).filter(
        ThreatIntel.first_seen >= last_24h
    ).count()

    recent_iocs_7d = db.query(ThreatIntel).filter(
        ThreatIntel.first_seen >= last_7d
    ).count()

    # IOC type breakdown
    ioc_types = db.query(
        ThreatIntel.ioc_type,
        func.count(ThreatIntel.id).label('count')
    ).group_by(ThreatIntel.ioc_type).all()

    ioc_type_breakdown = {ioc_type: count for ioc_type, count in ioc_types}

    # Recent queries generated
    recent_queries = db.query(GeneratedQuery).filter(
        GeneratedQuery.created_at >= last_7d
    ).count()

    # Platform breakdown
    platform_breakdown = db.query(
        GeneratedQuery.platform,
        func.count(GeneratedQuery.id).label('count')
    ).group_by(GeneratedQuery.platform).all()

    platform_stats = {platform: count for platform, count in platform_breakdown}

    # CVE statistics
    total_cves = db.query(CVE).count()
    high_risk_cves = db.query(CVE).filter(
        CVE.exploited_in_wild == True
    ).count()

    # Threat actor statistics
    total_threat_actors = db.query(ThreatActor).count()
    recently_active_actors = db.query(ThreatActor).filter(
        ThreatActor.last_activity >= last_7d
    ).count()

    # Top techniques by template count
    top_techniques = db.query(
        DetectionTemplate.technique_id,
        func.count(DetectionTemplate.id).label('template_count')
    ).group_by(
        DetectionTemplate.technique_id
    ).order_by(
        desc('template_count')
    ).limit(10).all()

    top_techniques_list = [
        {
            "technique_id": tech_id,
            "template_count": count
        }
        for tech_id, count in top_techniques
    ]

    return {
        "totals": {
            "techniques": total_techniques,
            "templates": total_templates,
            "campaigns": total_campaigns,
            "active_campaigns": active_campaigns,
            "cves": total_cves,
            "high_risk_cves": high_risk_cves,
            "threat_actors": total_threat_actors,
            "recently_active_actors": recently_active_actors
        },
        "threat_intel": {
            "recent_24h": recent_iocs_24h,
            "recent_7d": recent_iocs_7d,
            "ioc_type_breakdown": ioc_type_breakdown
        },
        "query_activity": {
            "recent_7d": recent_queries,
            "platform_breakdown": platform_stats
        },
        "top_techniques": top_techniques_list,
        "last_updated": datetime.utcnow().isoformat()
    }


@router.get("/api/dashboard/mitre-coverage")
async def get_mitre_coverage(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Get MITRE ATT&CK coverage statistics.
    Returns tactics and techniques with template counts for heatmap visualization.
    """

    # Get all techniques with their tactics
    techniques = db.query(MitreTechnique).all()

    # Get template counts per technique
    template_counts = db.query(
        DetectionTemplate.technique_id,
        func.count(DetectionTemplate.id).label('count')
    ).group_by(DetectionTemplate.technique_id).all()

    template_count_map = {tech_id: count for tech_id, count in template_counts}

    # Organize by tactic
    tactics_coverage = {}

    for technique in techniques:
        for tactic in technique.tactics:
            if tactic not in tactics_coverage:
                tactics_coverage[tactic] = []

            coverage = {
                "technique_id": technique.technique_id,
                "name": technique.name,
                "template_count": template_count_map.get(technique.technique_id, 0),
                "platforms": technique.platforms
            }
            tactics_coverage[tactic].append(coverage)

    # Calculate overall coverage percentage
    total_techniques = len(techniques)
    covered_techniques = len([t for t in techniques if template_count_map.get(t.technique_id, 0) > 0])
    coverage_percentage = (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0

    return {
        "coverage_percentage": round(coverage_percentage, 2),
        "total_techniques": total_techniques,
        "covered_techniques": covered_techniques,
        "tactics": tactics_coverage
    }


@router.get("/api/dashboard/recent-activity")
async def get_recent_activity(
    limit: int = 20,
    db: Session = Depends(get_db)
) -> List[Dict[str, Any]]:
    """
    Get recent activity across the system (queries, campaigns, intel updates).
    """

    activities = []

    # Recent queries
    recent_queries = db.query(GeneratedQuery).order_by(
        desc(GeneratedQuery.created_at)
    ).limit(limit).all()

    for query in recent_queries:
        activities.append({
            "type": "query_generated",
            "timestamp": query.created_at.isoformat(),
            "details": {
                "platform": query.platform,
                "technique_ids": query.technique_ids,
                "id": query.id
            }
        })

    # Recent campaigns
    recent_campaigns = db.query(HuntCampaign).order_by(
        desc(HuntCampaign.created_at)
    ).limit(limit).all()

    for campaign in recent_campaigns:
        activities.append({
            "type": "campaign_created",
            "timestamp": campaign.created_at.isoformat(),
            "details": {
                "name": campaign.name,
                "techniques": campaign.techniques,
                "threat_actor": campaign.threat_actor,
                "status": campaign.status,
                "id": campaign.id
            }
        })

    # Recent threat intel
    recent_intel = db.query(ThreatIntel).order_by(
        desc(ThreatIntel.first_seen)
    ).limit(limit).all()

    for intel in recent_intel:
        activities.append({
            "type": "threat_intel_added",
            "timestamp": intel.first_seen.isoformat(),
            "details": {
                "source": intel.source,
                "ioc_type": intel.ioc_type,
                "ioc_value": intel.ioc_value[:50],  # Truncate for display
                "associated_techniques": intel.associated_techniques
            }
        })

    # Sort all activities by timestamp and limit
    activities.sort(key=lambda x: x["timestamp"], reverse=True)

    return activities[:limit]
