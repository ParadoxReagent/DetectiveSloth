"""IOC enrichment and deduplication service."""

import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..models.threat_intel import ThreatIntel
from ..models.ioc_enrichment import IOCEnrichment

logger = logging.getLogger(__name__)


class EnrichmentService:
    """Service for enriching and deduplicating IOCs."""

    def __init__(self, db: Session):
        self.db = db

        # Source credibility weights (0-1)
        self.source_weights = {
            "cisa_kev": 1.0,  # Highest credibility
            "threatfox": 0.9,
            "otx": 0.8,
            "urlhaus": 0.85,
            "greynoise": 0.75,
        }

    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Optional[IOCEnrichment]:
        """Enrich a single IOC by aggregating data from all sources.

        Args:
            ioc_value: The IOC value (hash, IP, domain, etc.)
            ioc_type: The type of IOC

        Returns:
            IOCEnrichment object with aggregated data
        """
        # Get all instances of this IOC from different sources
        ioc_instances = self.db.query(ThreatIntel).filter(
            ThreatIntel.ioc_value == ioc_value,
            ThreatIntel.ioc_type == ioc_type
        ).all()

        if not ioc_instances:
            return None

        logger.info(f"Enriching IOC {ioc_value} found in {len(ioc_instances)} sources")

        # Check if enrichment already exists
        enrichment = self.db.query(IOCEnrichment).filter(
            IOCEnrichment.ioc_value == ioc_value,
            IOCEnrichment.ioc_type == ioc_type
        ).first()

        if not enrichment:
            enrichment = IOCEnrichment(
                ioc_value=ioc_value,
                ioc_type=ioc_type
            )

        # Aggregate data from all sources
        seen_in_sources = {}
        aggregated_context = {}
        threat_families = set()
        threat_actors = set()
        campaigns = set()
        all_techniques = []
        technique_frequency = defaultdict(int)

        first_seen = None
        last_seen = None

        for instance in ioc_instances:
            # Track sources
            seen_in_sources[instance.source] = instance.last_seen.isoformat() if instance.last_seen else None

            # Track dates
            if instance.first_seen:
                if not first_seen or instance.first_seen < first_seen:
                    first_seen = instance.first_seen
            if instance.last_seen:
                if not last_seen or instance.last_seen > last_seen:
                    last_seen = instance.last_seen

            # Aggregate context
            if instance.context:
                # Extract threat families
                if "threat" in instance.context:
                    threat_families.add(instance.context["threat"])
                if "malware" in instance.context:
                    threat_families.add(instance.context["malware"])

                # Extract threat actors
                if "adversary" in instance.context:
                    threat_actors.add(instance.context["adversary"])
                if "actor" in instance.context:
                    threat_actors.add(instance.context["actor"])

                # Extract campaigns
                if "pulse_name" in instance.context:
                    campaigns.add(instance.context["pulse_name"])

                # Store context by source
                aggregated_context[instance.source] = instance.context

            # Aggregate techniques
            if instance.associated_techniques:
                all_techniques.extend(instance.associated_techniques)
                for technique in instance.associated_techniques:
                    technique_frequency[technique] += 1

        # Calculate scores
        prevalence_score = self._calculate_prevalence_score(len(ioc_instances))
        recency_score = self._calculate_recency_score(last_seen)
        source_credibility_score = self._calculate_source_credibility(seen_in_sources)
        risk_score = self._calculate_risk_score(
            prevalence_score, recency_score, source_credibility_score, len(all_techniques)
        )

        # Update enrichment
        enrichment.risk_score = risk_score
        enrichment.prevalence_score = prevalence_score
        enrichment.recency_score = recency_score
        enrichment.source_credibility_score = source_credibility_score
        enrichment.seen_in_sources = seen_in_sources
        enrichment.total_source_count = len(ioc_instances)
        enrichment.first_seen_global = first_seen
        enrichment.last_seen_global = last_seen
        enrichment.aggregated_context = aggregated_context
        enrichment.threat_families = list(threat_families)
        enrichment.threat_actors = list(threat_actors)
        enrichment.campaigns = list(campaigns)
        enrichment.associated_techniques = list(set(all_techniques))
        enrichment.technique_frequency = dict(technique_frequency)
        enrichment.last_enriched = datetime.utcnow()

        # Save or update
        if enrichment.id is None:
            self.db.add(enrichment)

        self.db.commit()
        self.db.refresh(enrichment)

        return enrichment

    def enrich_all_iocs(self, limit: Optional[int] = None) -> int:
        """Enrich all IOCs in the database.

        Args:
            limit: Maximum number of IOCs to enrich (None for all)

        Returns:
            Number of IOCs enriched
        """
        logger.info("Starting bulk IOC enrichment")

        # Get unique IOC values
        unique_iocs = self.db.query(
            ThreatIntel.ioc_value,
            ThreatIntel.ioc_type
        ).distinct().limit(limit).all()

        count = 0
        for ioc_value, ioc_type in unique_iocs:
            try:
                self.enrich_ioc(ioc_value, ioc_type)
                count += 1
                if count % 100 == 0:
                    logger.info(f"Enriched {count} IOCs...")
            except Exception as e:
                logger.error(f"Error enriching IOC {ioc_value}: {e}")
                continue

        logger.info(f"Completed enrichment of {count} IOCs")
        return count

    def deduplicate_iocs(self) -> Dict[str, int]:
        """Remove duplicate IOC entries within the same source.

        Returns:
            Dictionary with deduplication statistics
        """
        logger.info("Starting IOC deduplication")

        duplicates_removed = 0
        unique_iocs_kept = 0

        # Group IOCs by value, type, and source
        ioc_groups = self.db.query(
            ThreatIntel.ioc_value,
            ThreatIntel.ioc_type,
            ThreatIntel.source,
            func.count(ThreatIntel.id).label('count')
        ).group_by(
            ThreatIntel.ioc_value,
            ThreatIntel.ioc_type,
            ThreatIntel.source
        ).having(func.count(ThreatIntel.id) > 1).all()

        for ioc_value, ioc_type, source, count in ioc_groups:
            # Get all instances
            instances = self.db.query(ThreatIntel).filter(
                ThreatIntel.ioc_value == ioc_value,
                ThreatIntel.ioc_type == ioc_type,
                ThreatIntel.source == source
            ).order_by(ThreatIntel.last_seen.desc()).all()

            # Keep the most recent one, merge context
            if len(instances) > 1:
                keeper = instances[0]
                merged_context = keeper.context or {}
                merged_tags = set(keeper.tags or [])
                merged_techniques = set(keeper.associated_techniques or [])

                # Merge data from duplicates
                for duplicate in instances[1:]:
                    if duplicate.context:
                        merged_context.update(duplicate.context)
                    if duplicate.tags:
                        merged_tags.update(duplicate.tags)
                    if duplicate.associated_techniques:
                        merged_techniques.update(duplicate.associated_techniques)

                    # Delete duplicate
                    self.db.delete(duplicate)
                    duplicates_removed += 1

                # Update keeper with merged data
                keeper.context = merged_context
                keeper.tags = list(merged_tags)
                keeper.associated_techniques = list(merged_techniques)
                unique_iocs_kept += 1

        self.db.commit()
        logger.info(f"Deduplication complete: removed {duplicates_removed}, kept {unique_iocs_kept}")

        return {
            "duplicates_removed": duplicates_removed,
            "unique_iocs_kept": unique_iocs_kept
        }

    def _calculate_prevalence_score(self, source_count: int) -> float:
        """Calculate prevalence score based on number of sources.

        Args:
            source_count: Number of sources reporting this IOC

        Returns:
            Score from 0-100
        """
        # More sources = higher prevalence
        # Max out at 5 sources = 100 points
        return min(100.0, (source_count / 5.0) * 100.0)

    def _calculate_recency_score(self, last_seen: Optional[datetime]) -> float:
        """Calculate recency score based on last seen date.

        Args:
            last_seen: Last seen datetime

        Returns:
            Score from 0-100
        """
        if not last_seen:
            return 0.0

        days_ago = (datetime.utcnow() - last_seen).days

        # Recent = higher score
        if days_ago < 1:
            return 100.0
        elif days_ago < 7:
            return 80.0
        elif days_ago < 30:
            return 60.0
        elif days_ago < 90:
            return 40.0
        elif days_ago < 180:
            return 20.0
        else:
            return 10.0

    def _calculate_source_credibility(self, seen_in_sources: Dict[str, str]) -> float:
        """Calculate weighted credibility score based on sources.

        Args:
            seen_in_sources: Dictionary of source names

        Returns:
            Score from 0-100
        """
        if not seen_in_sources:
            return 0.0

        total_weight = 0.0
        for source in seen_in_sources.keys():
            weight = self.source_weights.get(source, 0.5)
            total_weight += weight

        # Average weight, scaled to 100
        avg_weight = total_weight / len(seen_in_sources)
        return avg_weight * 100.0

    def _calculate_risk_score(
        self,
        prevalence: float,
        recency: float,
        credibility: float,
        technique_count: int
    ) -> float:
        """Calculate overall risk score.

        Args:
            prevalence: Prevalence score
            recency: Recency score
            credibility: Source credibility score
            technique_count: Number of associated techniques

        Returns:
            Risk score from 0-100
        """
        # Weighted average of factors
        base_score = (prevalence * 0.3) + (recency * 0.4) + (credibility * 0.3)

        # Boost if associated with many techniques
        technique_boost = min(20.0, technique_count * 5.0)

        return min(100.0, base_score + technique_boost)

    def get_top_iocs(self, limit: int = 100, min_risk_score: float = 50.0) -> List[IOCEnrichment]:
        """Get top IOCs by risk score.

        Args:
            limit: Maximum number of IOCs to return
            min_risk_score: Minimum risk score filter

        Returns:
            List of enriched IOCs
        """
        return self.db.query(IOCEnrichment).filter(
            IOCEnrichment.risk_score >= min_risk_score
        ).order_by(IOCEnrichment.risk_score.desc()).limit(limit).all()

    def get_iocs_by_threat_actor(self, threat_actor: str) -> List[IOCEnrichment]:
        """Get IOCs associated with a specific threat actor.

        Args:
            threat_actor: Threat actor name

        Returns:
            List of enriched IOCs
        """
        return self.db.query(IOCEnrichment).filter(
            IOCEnrichment.threat_actors.contains([threat_actor])
        ).order_by(IOCEnrichment.risk_score.desc()).all()
