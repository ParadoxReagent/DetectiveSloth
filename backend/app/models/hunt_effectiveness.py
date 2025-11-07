"""Hunt effectiveness tracking models."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, JSON, ForeignKey, Boolean, Float
from ..core.database import Base


class HuntFinding(Base):
    """Track actual threat findings from hunt campaigns."""

    __tablename__ = "hunt_findings"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("hunt_campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    query_id = Column(Integer, ForeignKey("generated_queries.id", ondelete="SET NULL"), index=True)
    technique_id = Column(String(20), nullable=False, index=True)
    finding_type = Column(String(50), nullable=False)  # true_positive, false_positive, benign_true_positive
    severity = Column(String(20))  # critical, high, medium, low, informational
    title = Column(String(200), nullable=False)
    description = Column(Text)
    affected_hosts = Column(JSON, default=list)  # List of affected hosts/devices
    iocs_found = Column(JSON, default=dict)  # IOCs discovered in the finding
    remediation_status = Column(String(50), default="pending")  # pending, in_progress, resolved, false_alarm
    analyst = Column(String(100))
    discovered_at = Column(TIMESTAMP, default=datetime.utcnow, index=True)
    resolved_at = Column(TIMESTAMP)
    metadata = Column(JSON, default=dict)

    def __repr__(self):
        return f"<HuntFinding(id={self.id}, campaign_id={self.campaign_id}, type={self.finding_type}, severity={self.severity})>"


class QueryEffectiveness(Base):
    """Track effectiveness metrics for queries."""

    __tablename__ = "query_effectiveness"

    id = Column(Integer, primary_key=True, index=True)
    query_id = Column(Integer, ForeignKey("generated_queries.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    technique_id = Column(String(20), nullable=False, index=True)
    platform = Column(String(50), nullable=False, index=True)
    execution_count = Column(Integer, default=0)
    true_positive_count = Column(Integer, default=0)
    false_positive_count = Column(Integer, default=0)
    precision = Column(Float)  # true_positives / (true_positives + false_positives)
    last_execution = Column(TIMESTAMP)
    avg_execution_time = Column(Float)  # Average query execution time in seconds
    performance_score = Column(Float)  # Overall performance score (0-100)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<QueryEffectiveness(id={self.id}, query_id={self.query_id}, precision={self.precision})>"


class CampaignShare(Base):
    """Track campaign sharing with team members."""

    __tablename__ = "campaign_shares"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("hunt_campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    shared_by = Column(String(100), nullable=False)
    shared_with = Column(String(100), nullable=False, index=True)  # User or team identifier
    permission_level = Column(String(20), default="read")  # read, write, admin
    shared_at = Column(TIMESTAMP, default=datetime.utcnow, index=True)
    accessed_at = Column(TIMESTAMP)  # Last access by shared user
    active = Column(Boolean, default=True)

    def __repr__(self):
        return f"<CampaignShare(id={self.id}, campaign_id={self.campaign_id}, shared_with={self.shared_with})>"
