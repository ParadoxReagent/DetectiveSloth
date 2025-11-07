"""Threat Actor profiling model."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, JSON, ARRAY
from ..core.database import Base


class ThreatActor(Base):
    """Threat actor profiles with TTPs and campaigns."""

    __tablename__ = "threat_actors"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), unique=True, nullable=False, index=True)  # Primary name
    aliases = Column(ARRAY(String), default=list)  # Alternative names

    # Classification
    actor_type = Column(String(100))  # APT, Cybercrime, Hacktivist, Nation-state, etc.
    motivation = Column(String(100))  # Financial, Espionage, Destruction, etc.
    sophistication = Column(String(50))  # Expert, Advanced, Intermediate, Novice

    # Attribution
    suspected_origin = Column(String(100))  # Country or region
    attribution_confidence = Column(String(20))  # High, Medium, Low

    # Activity
    first_observed = Column(TIMESTAMP)
    last_observed = Column(TIMESTAMP)
    active_status = Column(String(20), default="active")  # active, dormant, retired

    # TTPs
    techniques = Column(ARRAY(String), default=list)  # MITRE ATT&CK technique IDs
    tactics = Column(ARRAY(String), default=list)  # MITRE ATT&CK tactics
    tools = Column(ARRAY(String), default=list)  # Known tools and malware

    # Targets
    targeted_sectors = Column(ARRAY(String), default=list)  # Industry sectors
    targeted_countries = Column(ARRAY(String), default=list)  # Geographic targets

    # Infrastructure
    known_infrastructure = Column(JSON)  # IPs, domains, etc.

    # Campaigns
    known_campaigns = Column(ARRAY(String), default=list)  # Campaign names

    # Description and context
    description = Column(Text)
    objectives = Column(Text)
    context = Column(JSON)  # Additional metadata

    # References
    references = Column(ARRAY(String), default=list)  # URLs to reports
    mitre_group_id = Column(String(50))  # MITRE ATT&CK Group ID (e.g., G0016)

    # Tracking
    source = Column(String(100))  # otx, mitre, custom
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<ThreatActor(name={self.name}, type={self.actor_type}, origin={self.suspected_origin})>"
