"""Hunt campaign model."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, JSON, ARRAY
from ..core.database import Base


class HuntCampaign(Base):
    """Threat hunting campaigns."""

    __tablename__ = "hunt_campaigns"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    techniques = Column(ARRAY(String), default=list)  # MITRE technique IDs
    threat_actor = Column(String(100), index=True)  # Optional: APT29, Lazarus, etc.
    start_date = Column(TIMESTAMP, default=datetime.utcnow)
    end_date = Column(TIMESTAMP)
    status = Column(String(50), default="active")  # active, completed, archived
    findings = Column(JSON, default=dict)  # Store hunt results
    analyst = Column(String(100))

    def __repr__(self):
        return f"<HuntCampaign(id={self.id}, name={self.name}, status={self.status})>"
