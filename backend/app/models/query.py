"""Generated query model."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, JSON, ARRAY, Boolean
from ..core.database import Base


class GeneratedQuery(Base):
    """Generated threat hunting queries."""

    __tablename__ = "generated_queries"

    id = Column(Integer, primary_key=True, index=True)
    technique_ids = Column(ARRAY(String), nullable=False)  # Multiple techniques can be combined
    platform = Column(String(50), nullable=False, index=True)
    query_text = Column(Text, nullable=False)
    metadata = Column(JSON, default=dict)  # Additional metadata like timeframe, IOCs used, etc.
    created_at = Column(TIMESTAMP, default=datetime.utcnow, index=True)
    executed = Column(Boolean, default=False)
    results_count = Column(Integer)

    def __repr__(self):
        return f"<GeneratedQuery(id={self.id}, techniques={self.technique_ids}, platform={self.platform})>"
