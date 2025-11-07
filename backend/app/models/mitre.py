"""MITRE ATT&CK technique model."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, ARRAY
from ..core.database import Base


class MitreTechnique(Base):
    """MITRE ATT&CK technique data."""

    __tablename__ = "mitre_techniques"

    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String(20), unique=True, nullable=False, index=True)  # e.g., T1055
    name = Column(String(200), nullable=False)
    description = Column(Text)
    tactics = Column(ARRAY(String), default=list)  # e.g., ["Defense Evasion", "Privilege Escalation"]
    platforms = Column(ARRAY(String), default=list)  # e.g., ["Windows", "Linux", "macOS"]
    data_sources = Column(ARRAY(String), default=list)  # e.g., ["Process", "File", "Network"]
    detection_notes = Column(Text)
    mitigation_notes = Column(Text)
    version = Column(String(10))  # ATT&CK version
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<MitreTechnique(id={self.technique_id}, name={self.name})>"
