"""Detection template model."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, JSON, ARRAY
from ..core.database import Base


class DetectionTemplate(Base):
    """Query templates for different EDR platforms."""

    __tablename__ = "detection_templates"

    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String(20), nullable=False, index=True)  # MITRE technique ID
    platform = Column(String(50), nullable=False, index=True)  # defender, crowdstrike, carbonblack, sentinelone
    query_template = Column(Text, nullable=False)  # Jinja2 template with variables
    variables = Column(JSON, default=dict)  # Expected template variables and defaults
    confidence = Column(String(20))  # high, medium, low
    false_positive_notes = Column(Text)
    data_sources_required = Column(ARRAY(String), default=list)  # Data sources needed for this query
    created_by = Column(String(100))
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    version = Column(Integer, default=1)

    def __repr__(self):
        return f"<DetectionTemplate(id={self.id}, technique={self.technique_id}, platform={self.platform})>"
