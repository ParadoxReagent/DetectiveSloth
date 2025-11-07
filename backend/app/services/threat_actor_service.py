"""Threat actor profiling service."""

import logging
from typing import List, Dict, Optional
from datetime import datetime
from collections import Counter
from sqlalchemy.orm import Session
from ..models.threat_actor import ThreatActor
from ..models.threat_intel import ThreatIntel
from ..models.ioc_enrichment import IOCEnrichment
from ..models.mitre import MitreTechnique

logger = logging.getLogger(__name__)


class ThreatActorService:
    """Service for building and maintaining threat actor profiles."""

    def __init__(self, db: Session):
        self.db = db

    def create_or_update_actor(
        self,
        name: str,
        aliases: Optional[List[str]] = None,
        actor_type: Optional[str] = None,
        motivation: Optional[str] = None,
        **kwargs
    ) -> ThreatActor:
        """Create or update a threat actor profile.

        Args:
            name: Primary threat actor name
            aliases: Alternative names
            actor_type: Type (APT, Cybercrime, etc.)
            motivation: Primary motivation
            **kwargs: Additional actor attributes

        Returns:
            ThreatActor object
        """
        # Check if actor exists
        actor = self.db.query(ThreatActor).filter(
            ThreatActor.name == name
        ).first()

        if actor:
            # Update existing actor
            if aliases:
                actor.aliases = list(set((actor.aliases or []) + aliases))
            if actor_type:
                actor.actor_type = actor_type
            if motivation:
                actor.motivation = motivation

            # Update other fields
            for key, value in kwargs.items():
                if hasattr(actor, key):
                    setattr(actor, key, value)

            actor.updated_at = datetime.utcnow()
        else:
            # Create new actor
            actor = ThreatActor(
                name=name,
                aliases=aliases or [],
                actor_type=actor_type,
                motivation=motivation,
                **kwargs
            )
            self.db.add(actor)

        self.db.commit()
        self.db.refresh(actor)

        return actor

    def build_profile_from_iocs(self, actor_name: str) -> ThreatActor:
        """Build or enhance actor profile from associated IOCs.

        Args:
            actor_name: Threat actor name

        Returns:
            Updated ThreatActor object
        """
        logger.info(f"Building profile for {actor_name} from IOCs")

        # Get or create actor
        actor = self.db.query(ThreatActor).filter(
            ThreatActor.name == actor_name
        ).first()

        if not actor:
            actor = ThreatActor(name=actor_name)
            self.db.add(actor)

        # Find IOCs mentioning this actor
        related_iocs = self._find_actor_iocs(actor_name, actor.aliases or [])

        if not related_iocs:
            logger.warning(f"No IOCs found for {actor_name}")
            return actor

        # Extract techniques from IOCs
        techniques = []
        sectors = set()
        countries = set()
        tools = set()
        campaigns = set()

        for ioc in related_iocs:
            if ioc.associated_techniques:
                techniques.extend(ioc.associated_techniques)

            if ioc.context:
                # Extract targeting information
                if "targeted_sectors" in ioc.context:
                    sectors.update(ioc.context["targeted_sectors"])
                if "targeted_countries" in ioc.context:
                    countries.update(ioc.context["targeted_countries"])

                # Extract tools
                if "malware" in ioc.context:
                    tools.add(ioc.context["malware"])

                # Extract campaigns
                if "pulse_name" in ioc.context:
                    campaigns.add(ioc.context["pulse_name"])

        # Count technique frequency
        technique_counts = Counter(techniques)

        # Get unique techniques and sort by frequency
        top_techniques = [t for t, _ in technique_counts.most_common(20)]

        # Derive tactics from techniques
        tactics = self._get_tactics_from_techniques(top_techniques)

        # Update actor profile
        actor.techniques = top_techniques
        actor.tactics = list(tactics)
        actor.tools = list(tools)
        actor.targeted_sectors = list(sectors)
        actor.targeted_countries = list(countries)
        actor.known_campaigns = list(campaigns)
        actor.last_observed = datetime.utcnow()
        actor.updated_at = datetime.utcnow()

        self.db.commit()
        logger.info(f"Updated {actor_name} with {len(top_techniques)} techniques, {len(tools)} tools")

        return actor

    def _find_actor_iocs(self, actor_name: str, aliases: List[str]) -> List[ThreatIntel]:
        """Find IOCs associated with an actor.

        Args:
            actor_name: Actor name to search for
            aliases: Alternative names

        Returns:
            List of related IOCs
        """
        iocs = []
        all_names = [actor_name] + (aliases or [])

        # Search in IOC context
        for ioc in self.db.query(ThreatIntel).all():
            if ioc.context:
                context_str = str(ioc.context).lower()
                if any(name.lower() in context_str for name in all_names):
                    iocs.append(ioc)

        return iocs

    def _get_tactics_from_techniques(self, technique_ids: List[str]) -> set:
        """Get MITRE tactics from technique IDs.

        Args:
            technique_ids: List of technique IDs

        Returns:
            Set of tactic names
        """
        tactics = set()

        for tid in technique_ids:
            technique = self.db.query(MitreTechnique).filter(
                MitreTechnique.technique_id == tid
            ).first()

            if technique and technique.tactics:
                tactics.update(technique.tactics)

        return tactics

    def get_actor_by_name(self, name: str) -> Optional[ThreatActor]:
        """Get threat actor by name or alias.

        Args:
            name: Actor name or alias

        Returns:
            ThreatActor object if found
        """
        # Search by primary name
        actor = self.db.query(ThreatActor).filter(
            ThreatActor.name == name
        ).first()

        if actor:
            return actor

        # Search by alias
        actors = self.db.query(ThreatActor).all()
        for actor in actors:
            if actor.aliases and name.lower() in [a.lower() for a in actor.aliases]:
                return actor

        return None

    def get_active_actors(self, days: int = 90) -> List[ThreatActor]:
        """Get recently active threat actors.

        Args:
            days: Consider actors active within this many days

        Returns:
            List of active ThreatActor objects
        """
        cutoff = datetime.utcnow() - timedelta(days=days)

        return self.db.query(ThreatActor).filter(
            ThreatActor.last_observed >= cutoff,
            ThreatActor.active_status == "active"
        ).order_by(ThreatActor.last_observed.desc()).all()

    def get_actors_by_technique(self, technique_id: str) -> List[ThreatActor]:
        """Get actors known to use a specific technique.

        Args:
            technique_id: MITRE ATT&CK technique ID

        Returns:
            List of ThreatActor objects
        """
        return self.db.query(ThreatActor).filter(
            ThreatActor.techniques.contains([technique_id])
        ).all()

    def get_actors_by_sector(self, sector: str) -> List[ThreatActor]:
        """Get actors targeting a specific sector.

        Args:
            sector: Industry sector

        Returns:
            List of ThreatActor objects
        """
        return self.db.query(ThreatActor).filter(
            ThreatActor.targeted_sectors.contains([sector])
        ).all()

    def compare_actors(self, actor1_name: str, actor2_name: str) -> Dict:
        """Compare two threat actors.

        Args:
            actor1_name: First actor name
            actor2_name: Second actor name

        Returns:
            Dictionary with comparison data
        """
        actor1 = self.get_actor_by_name(actor1_name)
        actor2 = self.get_actor_by_name(actor2_name)

        if not actor1 or not actor2:
            return {"error": "One or both actors not found"}

        # Find overlaps
        common_techniques = set(actor1.techniques or []) & set(actor2.techniques or [])
        common_tools = set(actor1.tools or []) & set(actor2.tools or [])
        common_sectors = set(actor1.targeted_sectors or []) & set(actor2.targeted_sectors or [])
        common_countries = set(actor1.targeted_countries or []) & set(actor2.targeted_countries or [])

        # Calculate similarity score (0-100)
        total_techniques = len(set(actor1.techniques or []) | set(actor2.techniques or []))
        technique_similarity = len(common_techniques) / total_techniques if total_techniques > 0 else 0

        total_tools = len(set(actor1.tools or []) | set(actor2.tools or []))
        tool_similarity = len(common_tools) / total_tools if total_tools > 0 else 0

        overall_similarity = ((technique_similarity * 0.6) + (tool_similarity * 0.4)) * 100

        return {
            "actor1": {
                "name": actor1.name,
                "type": actor1.actor_type,
                "technique_count": len(actor1.techniques or []),
                "tool_count": len(actor1.tools or [])
            },
            "actor2": {
                "name": actor2.name,
                "type": actor2.actor_type,
                "technique_count": len(actor2.techniques or []),
                "tool_count": len(actor2.tools or [])
            },
            "overlap": {
                "common_techniques": list(common_techniques),
                "common_tools": list(common_tools),
                "common_sectors": list(common_sectors),
                "common_countries": list(common_countries)
            },
            "similarity_score": round(overall_similarity, 2),
            "assessment": self._assess_similarity(overall_similarity)
        }

    def _assess_similarity(self, score: float) -> str:
        """Provide assessment of similarity score.

        Args:
            score: Similarity score (0-100)

        Returns:
            Assessment string
        """
        if score >= 80:
            return "Very High - Possible same actor or closely related"
        elif score >= 60:
            return "High - Significant overlap in TTPs"
        elif score >= 40:
            return "Medium - Some shared characteristics"
        elif score >= 20:
            return "Low - Limited similarities"
        else:
            return "Very Low - Minimal overlap"

    def generate_actor_report(self, actor_name: str) -> Dict:
        """Generate comprehensive report for a threat actor.

        Args:
            actor_name: Actor name

        Returns:
            Dictionary with actor intelligence report
        """
        actor = self.get_actor_by_name(actor_name)

        if not actor:
            return {"error": "Actor not found"}

        # Get technique details
        technique_details = []
        for tid in actor.techniques or []:
            technique = self.db.query(MitreTechnique).filter(
                MitreTechnique.technique_id == tid
            ).first()
            if technique:
                technique_details.append({
                    "id": technique.technique_id,
                    "name": technique.name,
                    "tactics": technique.tactics
                })

        return {
            "overview": {
                "name": actor.name,
                "aliases": actor.aliases,
                "type": actor.actor_type,
                "motivation": actor.motivation,
                "sophistication": actor.sophistication,
                "origin": actor.suspected_origin,
                "status": actor.active_status
            },
            "activity": {
                "first_observed": actor.first_observed.isoformat() if actor.first_observed else None,
                "last_observed": actor.last_observed.isoformat() if actor.last_observed else None,
                "known_campaigns": actor.known_campaigns or []
            },
            "ttps": {
                "techniques": technique_details,
                "tactics": actor.tactics or [],
                "tools": actor.tools or []
            },
            "targeting": {
                "sectors": actor.targeted_sectors or [],
                "countries": actor.targeted_countries or []
            },
            "infrastructure": actor.known_infrastructure or {},
            "references": actor.references or []
        }


from datetime import timedelta
