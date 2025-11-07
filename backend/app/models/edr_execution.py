"""EDR query execution results model."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, JSON, ForeignKey, Boolean
from ..core.database import Base


class EDRExecution(Base):
    """EDR platform query execution results."""

    __tablename__ = "edr_executions"

    id = Column(Integer, primary_key=True, index=True)
    query_id = Column(Integer, ForeignKey("generated_queries.id", ondelete="CASCADE"), nullable=False, index=True)
    platform = Column(String(50), nullable=False, index=True)
    execution_status = Column(String(50), default="pending")  # pending, running, completed, failed
    started_at = Column(TIMESTAMP, default=datetime.utcnow, index=True)
    completed_at = Column(TIMESTAMP)
    results = Column(JSON, default=dict)  # Raw results from EDR platform
    results_count = Column(Integer, default=0)
    error_message = Column(Text)
    deduplicated = Column(Boolean, default=False)  # Whether results have been deduplicated
    findings = Column(JSON, default=list)  # Processed findings
    metadata = Column(JSON, default=dict)  # Additional execution metadata

    def __repr__(self):
        return f"<EDRExecution(id={self.id}, query_id={self.query_id}, platform={self.platform}, status={self.execution_status})>"
