"""Threat intelligence model."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, JSON, ARRAY
from ..core.database import Base


class ThreatIntel(Base):
    """Threat intelligence data from various feeds."""

    __tablename__ = "threat_intel"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(100), nullable=False, index=True)
    ioc_type = Column(String(50), nullable=False, index=True)  # hash, ip, domain, url, email, etc.
    ioc_value = Column(Text, nullable=False, index=True)
    context = Column(JSON)  # Additional context as JSON
    associated_techniques = Column(ARRAY(String), default=list)  # MITRE technique IDs
    confidence_score = Column(Integer)  # 0-100
    first_seen = Column(TIMESTAMP, default=datetime.utcnow)
    last_seen = Column(TIMESTAMP, default=datetime.utcnow)
    tags = Column(ARRAY(String), default=list)

    def __repr__(self):
        return f"<ThreatIntel(id={self.id}, type={self.ioc_type}, value={self.ioc_value[:50]})>"
