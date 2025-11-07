"""IOC Enrichment model for storing enriched intelligence data."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, JSON, Float, ForeignKey
from sqlalchemy.orm import relationship
from ..core.database import Base


class IOCEnrichment(Base):
    """Enriched IOC data with scoring and deduplication."""

    __tablename__ = "ioc_enrichments"

    id = Column(Integer, primary_key=True, index=True)
    ioc_value = Column(String(500), nullable=False, index=True)
    ioc_type = Column(String(50), nullable=False, index=True)

    # Enrichment scoring
    risk_score = Column(Float, default=0.0)  # 0-100 calculated risk score
    prevalence_score = Column(Float, default=0.0)  # How common across feeds
    recency_score = Column(Float, default=0.0)  # Based on last seen
    source_credibility_score = Column(Float, default=0.0)  # Weighted by source quality

    # Deduplication
    seen_in_sources = Column(JSON, default=dict)  # {source_name: timestamp}
    total_source_count = Column(Integer, default=0)
    first_seen_global = Column(TIMESTAMP)
    last_seen_global = Column(TIMESTAMP)

    # Context aggregation
    aggregated_context = Column(JSON)  # Combined context from all sources
    threat_families = Column(JSON, default=list)  # Associated malware families
    threat_actors = Column(JSON, default=list)  # Associated threat actors
    campaigns = Column(JSON, default=list)  # Associated campaigns

    # MITRE mapping
    associated_techniques = Column(JSON, default=list)  # Aggregated techniques
    technique_frequency = Column(JSON, default=dict)  # {technique_id: count}

    # Behavioral analysis
    behavioral_tags = Column(JSON, default=list)  # Extracted behavioral indicators
    kill_chain_phases = Column(JSON, default=list)  # Cyber Kill Chain phases

    # Geographic and temporal data
    geographic_distribution = Column(JSON, default=dict)  # Countries where seen
    temporal_pattern = Column(JSON)  # Activity over time

    # Related IOCs
    related_iocs = Column(JSON, default=list)  # Related indicators
    similarity_clusters = Column(JSON, default=list)  # Cluster IDs

    # TTP extraction (NLP-derived)
    extracted_ttps = Column(JSON, default=list)  # TTPs extracted via NLP
    extraction_confidence = Column(Float)  # Confidence in extraction

    # Tracking
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_enriched = Column(TIMESTAMP, default=datetime.utcnow)

    def __repr__(self):
        return f"<IOCEnrichment(value={self.ioc_value[:50]}, risk={self.risk_score}, sources={self.total_source_count})>"
