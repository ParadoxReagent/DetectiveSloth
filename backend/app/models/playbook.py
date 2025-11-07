"""Threat actor playbook models."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, JSON, ARRAY, Boolean
from ..core.database import Base


class ThreatActorPlaybook(Base):
    """Pre-built hunt campaigns for known threat actors."""

    __tablename__ = "threat_actor_playbooks"

    id = Column(Integer, primary_key=True, index=True)
    threat_actor = Column(String(100), nullable=False, unique=True, index=True)
    aliases = Column(ARRAY(String), default=list)  # Alternative names for the threat actor
    description = Column(Text)
    techniques = Column(ARRAY(String), default=list)  # MITRE technique IDs
    techniques_timeline = Column(JSON, default=list)  # Timeline of TTPs [{phase: str, techniques: [], description: str}]
    target_industries = Column(ARRAY(String), default=list)
    target_countries = Column(ARRAY(String), default=list)
    tools = Column(ARRAY(String), default=list)  # Known tools used
    iocs = Column(JSON, default=dict)  # Associated IOCs by type
    campaigns = Column(ARRAY(String), default=list)  # Known campaign names
    first_seen = Column(TIMESTAMP)
    last_activity = Column(TIMESTAMP)
    active = Column(Boolean, default=True)
    confidence = Column(String(20), default="medium")  # low, medium, high
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    sources = Column(ARRAY(String), default=list)  # Intelligence sources

    def __repr__(self):
        return f"<ThreatActorPlaybook(id={self.id}, actor={self.threat_actor}, active={self.active})>"


class PlaybookExecution(Base):
    """Track execution of threat actor playbooks."""

    __tablename__ = "playbook_executions"

    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(Integer, nullable=False, index=True)
    campaign_id = Column(Integer)  # Associated hunt campaign if created
    executed_by = Column(String(100), nullable=False)
    execution_status = Column(String(50), default="pending")  # pending, in_progress, completed
    started_at = Column(TIMESTAMP, default=datetime.utcnow, index=True)
    completed_at = Column(TIMESTAMP)
    queries_generated = Column(Integer, default=0)
    findings = Column(JSON, default=list)
    notes = Column(Text)

    def __repr__(self):
        return f"<PlaybookExecution(id={self.id}, playbook_id={self.playbook_id}, status={self.execution_status})>"
