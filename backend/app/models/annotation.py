"""Annotation models for queries and campaigns."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, ForeignKey
from ..core.database import Base


class QueryAnnotation(Base):
    """Annotations for generated queries."""

    __tablename__ = "query_annotations"

    id = Column(Integer, primary_key=True, index=True)
    query_id = Column(Integer, ForeignKey("generated_queries.id", ondelete="CASCADE"), nullable=False, index=True)
    author = Column(String(100), nullable=False)
    annotation_text = Column(Text, nullable=False)
    created_at = Column(TIMESTAMP, default=datetime.utcnow, index=True)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<QueryAnnotation(id={self.id}, query_id={self.query_id}, author={self.author})>"


class CampaignAnnotation(Base):
    """Annotations for hunt campaigns."""

    __tablename__ = "campaign_annotations"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("hunt_campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    author = Column(String(100), nullable=False)
    annotation_text = Column(Text, nullable=False)
    created_at = Column(TIMESTAMP, default=datetime.utcnow, index=True)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<CampaignAnnotation(id={self.id}, campaign_id={self.campaign_id}, author={self.author})>"
