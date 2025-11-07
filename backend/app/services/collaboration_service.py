"""Collaboration service for campaign sharing and annotations."""

from typing import List, Dict, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from ..models import (
    CampaignShare,
    HuntCampaign,
    QueryAnnotation,
    CampaignAnnotation,
    GeneratedQuery,
    HuntFinding,
    QueryEffectiveness
)


class CollaborationService:
    """Manage team collaboration features."""

    def __init__(self, db: Session):
        self.db = db

    # Campaign Sharing

    def share_campaign(
        self,
        campaign_id: int,
        shared_by: str,
        shared_with: str,
        permission_level: str = "read"
    ) -> Dict:
        """
        Share a campaign with a team member.

        Args:
            campaign_id: Campaign ID
            shared_by: User sharing the campaign
            shared_with: User or team to share with
            permission_level: read, write, or admin

        Returns:
            Share status
        """
        # Validate campaign exists
        campaign = self.db.query(HuntCampaign).filter(
            HuntCampaign.id == campaign_id
        ).first()

        if not campaign:
            return {"error": "Campaign not found"}

        # Check if already shared
        existing_share = self.db.query(CampaignShare).filter(
            and_(
                CampaignShare.campaign_id == campaign_id,
                CampaignShare.shared_with == shared_with,
                CampaignShare.active == True
            )
        ).first()

        if existing_share:
            # Update permission level
            existing_share.permission_level = permission_level
            existing_share.shared_at = datetime.utcnow()
            self.db.commit()
            return {
                "success": True,
                "share_id": existing_share.id,
                "message": "Share updated",
                "updated": True
            }

        # Create new share
        share = CampaignShare(
            campaign_id=campaign_id,
            shared_by=shared_by,
            shared_with=shared_with,
            permission_level=permission_level,
            shared_at=datetime.utcnow(),
            active=True
        )
        self.db.add(share)
        self.db.commit()

        return {
            "success": True,
            "share_id": share.id,
            "campaign_id": campaign_id,
            "shared_with": shared_with,
            "permission_level": permission_level,
            "shared_at": share.shared_at.isoformat()
        }

    def revoke_share(
        self,
        share_id: int
    ) -> Dict:
        """Revoke a campaign share."""
        share = self.db.query(CampaignShare).filter(
            CampaignShare.id == share_id
        ).first()

        if not share:
            return {"error": "Share not found"}

        share.active = False
        self.db.commit()

        return {
            "success": True,
            "share_id": share_id,
            "message": "Share revoked"
        }

    def get_shared_campaigns(
        self,
        user: str,
        include_owned: bool = True
    ) -> List[Dict]:
        """Get all campaigns shared with a user."""
        # Get campaigns shared with user
        shared = self.db.query(HuntCampaign, CampaignShare).join(
            CampaignShare,
            and_(
                CampaignShare.campaign_id == HuntCampaign.id,
                CampaignShare.shared_with == user,
                CampaignShare.active == True
            )
        ).all()

        campaigns = []
        for campaign, share in shared:
            campaigns.append({
                "id": campaign.id,
                "name": campaign.name,
                "description": campaign.description,
                "status": campaign.status,
                "threat_actor": campaign.threat_actor,
                "analyst": campaign.analyst,
                "techniques_count": len(campaign.techniques or []),
                "shared_by": share.shared_by,
                "permission_level": share.permission_level,
                "shared_at": share.shared_at.isoformat(),
                "is_owner": False
            })

        # Optionally include campaigns owned by user
        if include_owned:
            owned = self.db.query(HuntCampaign).filter(
                HuntCampaign.analyst == user
            ).all()

            for campaign in owned:
                if not any(c["id"] == campaign.id for c in campaigns):
                    campaigns.append({
                        "id": campaign.id,
                        "name": campaign.name,
                        "description": campaign.description,
                        "status": campaign.status,
                        "threat_actor": campaign.threat_actor,
                        "analyst": campaign.analyst,
                        "techniques_count": len(campaign.techniques or []),
                        "is_owner": True
                    })

        return campaigns

    def get_campaign_shares(
        self,
        campaign_id: int
    ) -> List[Dict]:
        """Get all shares for a campaign."""
        shares = self.db.query(CampaignShare).filter(
            and_(
                CampaignShare.campaign_id == campaign_id,
                CampaignShare.active == True
            )
        ).all()

        return [{
            "share_id": s.id,
            "shared_with": s.shared_with,
            "shared_by": s.shared_by,
            "permission_level": s.permission_level,
            "shared_at": s.shared_at.isoformat(),
            "last_accessed": s.accessed_at.isoformat() if s.accessed_at else None
        } for s in shares]

    # Annotations

    def add_query_annotation(
        self,
        query_id: int,
        author: str,
        annotation_text: str
    ) -> Dict:
        """Add an annotation to a query."""
        # Validate query exists
        query = self.db.query(GeneratedQuery).filter(
            GeneratedQuery.id == query_id
        ).first()

        if not query:
            return {"error": "Query not found"}

        annotation = QueryAnnotation(
            query_id=query_id,
            author=author,
            annotation_text=annotation_text,
            created_at=datetime.utcnow()
        )
        self.db.add(annotation)
        self.db.commit()

        return {
            "success": True,
            "annotation_id": annotation.id,
            "query_id": query_id,
            "author": author,
            "created_at": annotation.created_at.isoformat()
        }

    def add_campaign_annotation(
        self,
        campaign_id: int,
        author: str,
        annotation_text: str
    ) -> Dict:
        """Add an annotation to a campaign."""
        # Validate campaign exists
        campaign = self.db.query(HuntCampaign).filter(
            HuntCampaign.id == campaign_id
        ).first()

        if not campaign:
            return {"error": "Campaign not found"}

        annotation = CampaignAnnotation(
            campaign_id=campaign_id,
            author=author,
            annotation_text=annotation_text,
            created_at=datetime.utcnow()
        )
        self.db.add(annotation)
        self.db.commit()

        return {
            "success": True,
            "annotation_id": annotation.id,
            "campaign_id": campaign_id,
            "author": author,
            "created_at": annotation.created_at.isoformat()
        }

    def update_annotation(
        self,
        annotation_id: int,
        annotation_type: str,
        annotation_text: str,
        author: str
    ) -> Dict:
        """Update an annotation (author must match)."""
        if annotation_type == "query":
            annotation = self.db.query(QueryAnnotation).filter(
                QueryAnnotation.id == annotation_id
            ).first()
        elif annotation_type == "campaign":
            annotation = self.db.query(CampaignAnnotation).filter(
                CampaignAnnotation.id == annotation_id
            ).first()
        else:
            return {"error": "Invalid annotation type"}

        if not annotation:
            return {"error": "Annotation not found"}

        if annotation.author != author:
            return {"error": "Only the author can update this annotation"}

        annotation.annotation_text = annotation_text
        annotation.updated_at = datetime.utcnow()
        self.db.commit()

        return {
            "success": True,
            "annotation_id": annotation_id,
            "updated_at": annotation.updated_at.isoformat()
        }

    def delete_annotation(
        self,
        annotation_id: int,
        annotation_type: str,
        author: str
    ) -> Dict:
        """Delete an annotation (author must match)."""
        if annotation_type == "query":
            annotation = self.db.query(QueryAnnotation).filter(
                QueryAnnotation.id == annotation_id
            ).first()
        elif annotation_type == "campaign":
            annotation = self.db.query(CampaignAnnotation).filter(
                CampaignAnnotation.id == annotation_id
            ).first()
        else:
            return {"error": "Invalid annotation type"}

        if not annotation:
            return {"error": "Annotation not found"}

        if annotation.author != author:
            return {"error": "Only the author can delete this annotation"}

        self.db.delete(annotation)
        self.db.commit()

        return {
            "success": True,
            "annotation_id": annotation_id,
            "message": "Annotation deleted"
        }

    def get_query_annotations(
        self,
        query_id: int
    ) -> List[Dict]:
        """Get all annotations for a query."""
        annotations = self.db.query(QueryAnnotation).filter(
            QueryAnnotation.query_id == query_id
        ).order_by(QueryAnnotation.created_at.desc()).all()

        return [{
            "annotation_id": a.id,
            "author": a.author,
            "text": a.annotation_text,
            "created_at": a.created_at.isoformat(),
            "updated_at": a.updated_at.isoformat() if a.updated_at else None
        } for a in annotations]

    def get_campaign_annotations(
        self,
        campaign_id: int
    ) -> List[Dict]:
        """Get all annotations for a campaign."""
        annotations = self.db.query(CampaignAnnotation).filter(
            CampaignAnnotation.campaign_id == campaign_id
        ).order_by(CampaignAnnotation.created_at.desc()).all()

        return [{
            "annotation_id": a.id,
            "author": a.author,
            "text": a.annotation_text,
            "created_at": a.created_at.isoformat(),
            "updated_at": a.updated_at.isoformat() if a.updated_at else None
        } for a in annotations]

    # Hunt Effectiveness Tracking

    def track_hunt_effectiveness(
        self,
        campaign_id: int
    ) -> Dict:
        """Track effectiveness of a hunt campaign."""
        campaign = self.db.query(HuntCampaign).filter(
            HuntCampaign.id == campaign_id
        ).first()

        if not campaign:
            return {"error": "Campaign not found"}

        # Get all findings for this campaign
        findings = self.db.query(HuntFinding).filter(
            HuntFinding.campaign_id == campaign_id
        ).all()

        # Calculate effectiveness metrics
        total_findings = len(findings)
        true_positives = len([f for f in findings if f.finding_type == "true_positive"])
        false_positives = len([f for f in findings if f.finding_type == "false_positive"])

        # Calculate by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.severity or "unknown"
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Calculate by technique
        technique_counts = {}
        for finding in findings:
            tech = finding.technique_id
            technique_counts[tech] = technique_counts.get(tech, 0) + 1

        # Calculate resolution status
        resolution_counts = {}
        for finding in findings:
            status = finding.remediation_status or "unknown"
            resolution_counts[status] = resolution_counts.get(status, 0) + 1

        effectiveness_score = 0
        if total_findings > 0:
            # Score based on true positives and resolution
            tp_ratio = true_positives / total_findings
            resolved = len([f for f in findings if f.remediation_status == "resolved"])
            resolution_ratio = resolved / total_findings if total_findings > 0 else 0
            effectiveness_score = (tp_ratio * 0.6 + resolution_ratio * 0.4) * 100

        return {
            "campaign_id": campaign_id,
            "campaign_name": campaign.name,
            "total_findings": total_findings,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "precision": round(true_positives / (true_positives + false_positives), 3) if (true_positives + false_positives) > 0 else None,
            "effectiveness_score": round(effectiveness_score, 2),
            "by_severity": severity_counts,
            "by_technique": technique_counts,
            "by_resolution_status": resolution_counts,
            "techniques_hunted": len(campaign.techniques or []),
            "start_date": campaign.start_date.isoformat() if campaign.start_date else None,
            "end_date": campaign.end_date.isoformat() if campaign.end_date else None
        }

    def track_query_effectiveness(
        self,
        query_id: int
    ) -> Dict:
        """Get effectiveness metrics for a specific query."""
        effectiveness = self.db.query(QueryEffectiveness).filter(
            QueryEffectiveness.query_id == query_id
        ).first()

        if not effectiveness:
            return {
                "query_id": query_id,
                "status": "no_data",
                "message": "Query has not been executed yet"
            }

        return {
            "query_id": query_id,
            "technique_id": effectiveness.technique_id,
            "platform": effectiveness.platform,
            "execution_count": effectiveness.execution_count,
            "true_positives": effectiveness.true_positive_count,
            "false_positives": effectiveness.false_positive_count,
            "precision": round(effectiveness.precision, 3) if effectiveness.precision else None,
            "avg_execution_time": round(effectiveness.avg_execution_time, 2) if effectiveness.avg_execution_time else None,
            "performance_score": round(effectiveness.performance_score, 2) if effectiveness.performance_score else None,
            "last_execution": effectiveness.last_execution.isoformat() if effectiveness.last_execution else None,
            "updated_at": effectiveness.updated_at.isoformat() if effectiveness.updated_at else None
        }

    def get_top_performing_queries(
        self,
        platform: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict]:
        """Get top performing queries by effectiveness score."""
        query = self.db.query(QueryEffectiveness)

        if platform:
            query = query.filter(QueryEffectiveness.platform == platform)

        top_queries = query.filter(
            QueryEffectiveness.performance_score.isnot(None)
        ).order_by(
            QueryEffectiveness.performance_score.desc()
        ).limit(limit).all()

        return [{
            "query_id": q.query_id,
            "technique_id": q.technique_id,
            "platform": q.platform,
            "performance_score": round(q.performance_score, 2),
            "precision": round(q.precision, 3) if q.precision else None,
            "execution_count": q.execution_count,
            "true_positives": q.true_positive_count
        } for q in top_queries]

    def get_collaboration_activity(
        self,
        user: str,
        days: int = 7
    ) -> Dict:
        """Get collaboration activity for a user."""
        # Get recent annotations by user
        query_annotations = self.db.query(QueryAnnotation).filter(
            QueryAnnotation.author == user
        ).order_by(QueryAnnotation.created_at.desc()).limit(10).all()

        campaign_annotations = self.db.query(CampaignAnnotation).filter(
            CampaignAnnotation.author == user
        ).order_by(CampaignAnnotation.created_at.desc()).limit(10).all()

        # Get campaigns shared by user
        shares_given = self.db.query(CampaignShare).filter(
            and_(
                CampaignShare.shared_by == user,
                CampaignShare.active == True
            )
        ).all()

        # Get campaigns shared with user
        shares_received = self.db.query(CampaignShare).filter(
            and_(
                CampaignShare.shared_with == user,
                CampaignShare.active == True
            )
        ).all()

        return {
            "user": user,
            "query_annotations": len(query_annotations),
            "campaign_annotations": len(campaign_annotations),
            "campaigns_shared_by_user": len(shares_given),
            "campaigns_shared_with_user": len(shares_received),
            "recent_activity": {
                "annotations": [
                    {
                        "type": "query",
                        "id": a.id,
                        "created_at": a.created_at.isoformat()
                    }
                    for a in query_annotations[:5]
                ] + [
                    {
                        "type": "campaign",
                        "id": a.id,
                        "created_at": a.created_at.isoformat()
                    }
                    for a in campaign_annotations[:5]
                ]
            }
        }
