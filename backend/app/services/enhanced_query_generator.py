"""Phase 4: Enhanced query generation engine with variations and analytic reasoning.

This module provides advanced query generation capabilities including:
- Template matching with data source validation
- Query variations (broad vs. specific)
- Analytic reasoning and explanation generation
- Enhanced IOC integration
- Multi-query generation for hunt campaigns
"""

import logging
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
from jinja2 import Template
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..models.template import DetectionTemplate
from ..models.query import GeneratedQuery
from ..models.mitre import MitreTechnique
from ..models.threat_intel import ThreatIntel
from ..models.threat_actor import ThreatActor
from ..core.config import settings
from .query_generator import QueryGenerator

logger = logging.getLogger(__name__)


class EnhancedQueryGenerator(QueryGenerator):
    """Enhanced query generator with variations and analytic reasoning."""

    def __init__(self, db: Session):
        super().__init__(db)
        self.query_variations = ["broad", "specific", "balanced"]

    def generate_hunt_campaign_queries(
        self,
        technique_ids: List[str],
        platforms: List[str],
        threat_actor: Optional[str] = None,
        timeframe: Optional[str] = None,
        include_variations: bool = True
    ) -> Dict[str, Any]:
        """Generate a complete set of queries for a hunt campaign.

        Args:
            technique_ids: List of MITRE ATT&CK technique IDs
            platforms: List of EDR platforms
            threat_actor: Optional threat actor name for context
            timeframe: Time range for queries
            include_variations: Whether to generate query variations

        Returns:
            Dictionary with queries, context, and analytic reasoning
        """
        logger.info(f"Generating hunt campaign for techniques: {technique_ids}")

        # Get threat actor context if provided
        actor_context = None
        if threat_actor:
            actor_context = self._get_threat_actor_context(threat_actor, technique_ids)

        # Generate queries for each platform
        campaign_queries = {}
        for platform in platforms:
            platform_queries = []

            for technique_id in technique_ids:
                # Get all available templates for this technique/platform
                templates = self._get_matching_templates(technique_id, platform)

                if not templates:
                    logger.warning(f"No templates found for {technique_id} on {platform}")
                    continue

                # Use the best template (highest confidence)
                template = templates[0]

                if include_variations:
                    # Generate variations: broad, balanced, specific
                    variations = self._generate_query_variations(
                        technique_id=technique_id,
                        template=template,
                        timeframe=timeframe,
                        actor_context=actor_context
                    )
                    platform_queries.extend(variations)
                else:
                    # Generate single balanced query
                    query = self._generate_single_query(
                        technique_id=technique_id,
                        template=template,
                        variation="balanced",
                        timeframe=timeframe,
                        actor_context=actor_context
                    )
                    if query:
                        platform_queries.append(query)

            campaign_queries[platform] = platform_queries

        # Generate analytic reasoning and hunt guidance
        reasoning = self._generate_analytic_reasoning(
            technique_ids=technique_ids,
            threat_actor=threat_actor,
            actor_context=actor_context
        )

        # Generate hunt sequence recommendations
        hunt_sequence = self._recommend_hunt_sequence(technique_ids)

        return {
            "queries": campaign_queries,
            "reasoning": reasoning,
            "hunt_sequence": hunt_sequence,
            "threat_context": actor_context,
            "generated_at": datetime.utcnow().isoformat()
        }

    def _get_matching_templates(
        self,
        technique_id: str,
        platform: str
    ) -> List[DetectionTemplate]:
        """Get matching templates sorted by confidence.

        Args:
            technique_id: MITRE technique ID
            platform: EDR platform

        Returns:
            List of matching templates sorted by confidence
        """
        templates = self.db.query(DetectionTemplate).filter(
            DetectionTemplate.technique_id == technique_id,
            DetectionTemplate.platform == platform
        ).all()

        # Sort by confidence (high > medium > low)
        confidence_order = {"high": 3, "medium": 2, "low": 1}
        return sorted(
            templates,
            key=lambda t: confidence_order.get(t.confidence, 0),
            reverse=True
        )

    def _generate_query_variations(
        self,
        technique_id: str,
        template: DetectionTemplate,
        timeframe: Optional[str],
        actor_context: Optional[Dict]
    ) -> List[Dict[str, Any]]:
        """Generate broad, balanced, and specific query variations.

        Args:
            technique_id: MITRE technique ID
            template: Detection template
            timeframe: Time range
            actor_context: Threat actor context

        Returns:
            List of query variations
        """
        variations = []

        for variation_type in ["broad", "balanced", "specific"]:
            query = self._generate_single_query(
                technique_id=technique_id,
                template=template,
                variation=variation_type,
                timeframe=timeframe,
                actor_context=actor_context
            )
            if query:
                variations.append(query)

        return variations

    def _generate_single_query(
        self,
        technique_id: str,
        template: DetectionTemplate,
        variation: str,
        timeframe: Optional[str],
        actor_context: Optional[Dict]
    ) -> Optional[Dict[str, Any]]:
        """Generate a single query with specified variation.

        Args:
            technique_id: MITRE technique ID
            template: Detection template
            variation: "broad", "balanced", or "specific"
            timeframe: Time range
            actor_context: Threat actor context

        Returns:
            Query dictionary with metadata
        """
        # Get technique details
        technique = self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id == technique_id
        ).first()

        if not technique:
            return None

        # Prepare variables based on variation type
        variables = self._prepare_variation_variables(
            technique_id=technique_id,
            variation=variation,
            timeframe=timeframe or settings.DEFAULT_TIMEFRAME,
            template_vars=template.variables or {},
            actor_context=actor_context
        )

        # Render the query
        query_text = self._render_template(template.query_template, variables)

        # Generate explanation
        explanation = self._generate_query_explanation(
            technique=technique,
            variation=variation,
            template=template,
            variables=variables
        )

        # Create metadata
        metadata = {
            "technique_id": technique_id,
            "technique_name": technique.name,
            "variation": variation,
            "confidence": template.confidence,
            "data_sources": template.data_sources_required,
            "false_positive_notes": template.false_positive_notes,
            "timeframe": timeframe or settings.DEFAULT_TIMEFRAME,
            "iocs_included": variables.get("has_iocs", False),
            "explanation": explanation
        }

        return {
            "query": query_text,
            "metadata": metadata,
            "technique": {
                "id": technique.technique_id,
                "name": technique.name,
                "description": technique.description,
                "tactics": technique.tactics,
                "platforms": technique.platforms
            }
        }

    def _prepare_variation_variables(
        self,
        technique_id: str,
        variation: str,
        timeframe: str,
        template_vars: Dict,
        actor_context: Optional[Dict]
    ) -> Dict[str, Any]:
        """Prepare variables based on query variation type.

        Args:
            technique_id: MITRE technique ID
            variation: Query variation type
            timeframe: Time range
            template_vars: Template default variables
            actor_context: Threat actor context

        Returns:
            Variables dictionary for template rendering
        """
        variables = {
            "timeframe": timeframe,
            "technique_id": technique_id,
        }

        # Add default template variables
        variables.update(template_vars)

        # Get IOCs based on variation
        if variation == "specific":
            # Include more IOCs and stricter matching for specific queries
            iocs = self._get_relevant_iocs(
                [technique_id],
                ioc_types=None,
                limit=100,
                min_confidence=7  # Higher confidence IOCs only
            )
            variables.update(iocs)
            variables["has_iocs"] = any(len(v) > 0 for v in iocs.values())

            # Add threat actor specific IOCs if available
            if actor_context and actor_context.get("iocs"):
                for ioc_type, values in actor_context["iocs"].items():
                    if ioc_type in variables:
                        variables[ioc_type].extend(values)
                        variables[ioc_type] = list(set(variables[ioc_type]))[:100]

        elif variation == "balanced":
            # Include moderate IOCs for balanced queries
            iocs = self._get_relevant_iocs(
                [technique_id],
                ioc_types=None,
                limit=50,
                min_confidence=5
            )
            variables.update(iocs)
            variables["has_iocs"] = any(len(v) > 0 for v in iocs.values())

        else:  # broad
            # Minimal IOCs for broad queries - focus on behavior
            variables["has_iocs"] = False

        return variables

    def _get_relevant_iocs(
        self,
        technique_ids: List[str],
        ioc_types: Optional[List[str]] = None,
        limit: int = 50,
        min_confidence: int = 5
    ) -> Dict[str, List[str]]:
        """Get relevant IOCs with confidence filtering.

        Args:
            technique_ids: MITRE technique IDs
            ioc_types: Types of IOCs to retrieve
            limit: Maximum IOCs per type
            min_confidence: Minimum confidence score (1-10)

        Returns:
            Dictionary of IOC lists by type
        """
        iocs = {
            "hashes": [],
            "ips": [],
            "domains": [],
            "urls": [],
            "file_names": []
        }

        for technique_id in technique_ids:
            # Get IOCs with confidence filtering
            query = self.db.query(ThreatIntel).filter(
                ThreatIntel.associated_techniques.contains([technique_id]),
                ThreatIntel.confidence_score >= min_confidence
            )

            # Order by confidence and recency
            query = query.order_by(
                ThreatIntel.confidence_score.desc(),
                ThreatIntel.last_seen.desc()
            ).limit(limit * 2)

            technique_iocs = query.all()

            for ioc in technique_iocs:
                if ioc_types and ioc.ioc_type not in ioc_types:
                    continue

                if ioc.ioc_type in ["md5", "sha1", "sha256"]:
                    iocs["hashes"].append(ioc.ioc_value)
                elif ioc.ioc_type in ["ip", "ipv4", "ipv6"]:
                    iocs["ips"].append(ioc.ioc_value)
                elif ioc.ioc_type == "domain":
                    iocs["domains"].append(ioc.ioc_value)
                elif ioc.ioc_type == "url":
                    iocs["urls"].append(ioc.ioc_value)
                elif ioc.ioc_type == "filename":
                    iocs["file_names"].append(ioc.ioc_value)

        # Deduplicate and limit
        for key in iocs:
            iocs[key] = list(set(iocs[key]))[:limit]

        return iocs

    def _get_threat_actor_context(
        self,
        threat_actor: str,
        technique_ids: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Get threat actor context and related IOCs.

        Args:
            threat_actor: Threat actor name
            technique_ids: MITRE technique IDs

        Returns:
            Threat actor context dictionary
        """
        actor = self.db.query(ThreatActor).filter(
            func.lower(ThreatActor.name) == threat_actor.lower()
        ).first()

        if not actor:
            logger.warning(f"Threat actor not found: {threat_actor}")
            return None

        # Get IOCs associated with this threat actor
        actor_iocs = self.db.query(ThreatIntel).filter(
            ThreatIntel.tags.contains([threat_actor.lower()])
        ).limit(200).all()

        iocs = {
            "hashes": [],
            "ips": [],
            "domains": [],
            "urls": [],
            "file_names": []
        }

        for ioc in actor_iocs:
            if ioc.ioc_type in ["md5", "sha1", "sha256"]:
                iocs["hashes"].append(ioc.ioc_value)
            elif ioc.ioc_type in ["ip", "ipv4", "ipv6"]:
                iocs["ips"].append(ioc.ioc_value)
            elif ioc.ioc_type == "domain":
                iocs["domains"].append(ioc.ioc_value)
            elif ioc.ioc_type == "url":
                iocs["urls"].append(ioc.ioc_value)
            elif ioc.ioc_type == "filename":
                iocs["file_names"].append(ioc.ioc_value)

        # Deduplicate
        for key in iocs:
            iocs[key] = list(set(iocs[key]))[:50]

        return {
            "name": actor.name,
            "aliases": actor.aliases,
            "description": actor.description,
            "techniques": actor.techniques,
            "iocs": iocs,
            "first_seen": actor.first_seen.isoformat() if actor.first_seen else None,
            "last_seen": actor.last_seen.isoformat() if actor.last_seen else None
        }

    def _generate_query_explanation(
        self,
        technique: MitreTechnique,
        variation: str,
        template: DetectionTemplate,
        variables: Dict[str, Any]
    ) -> str:
        """Generate human-readable explanation of the query.

        Args:
            technique: MITRE technique object
            variation: Query variation type
            template: Detection template
            variables: Template variables used

        Returns:
            Query explanation string
        """
        explanation_parts = []

        # Technique description
        explanation_parts.append(
            f"This query hunts for {technique.name} ({technique.technique_id})."
        )

        # Variation explanation
        variation_descriptions = {
            "broad": "This is a BROAD query designed to cast a wide net and may produce more results. "
                    "It focuses on behavioral patterns and may have higher false positives. "
                    "Use this for initial reconnaissance or when you suspect activity but lack specific indicators.",

            "balanced": "This is a BALANCED query that combines behavioral detection with some specific indicators. "
                       "It aims to reduce false positives while maintaining good coverage. "
                       "Use this as your primary hunting query for most investigations.",

            "specific": "This is a SPECIFIC query incorporating known IOCs and strict matching criteria. "
                       "It has lower false positive rates but may miss novel or variant attacks. "
                       "Use this when you have threat intelligence or are conducting targeted hunting."
        }
        explanation_parts.append(variation_descriptions[variation])

        # IOC information
        if variables.get("has_iocs"):
            ioc_count = sum(
                len(variables.get(key, []))
                for key in ["hashes", "ips", "domains", "urls", "file_names"]
            )
            explanation_parts.append(
                f"The query incorporates {ioc_count} known indicators of compromise from threat intelligence feeds."
            )

        # Data sources
        if template.data_sources_required:
            sources = ", ".join(template.data_sources_required)
            explanation_parts.append(f"Required data sources: {sources}")

        # False positive guidance
        if template.false_positive_notes:
            explanation_parts.append(f"False Positive Guidance: {template.false_positive_notes}")

        # Expected behavior
        tactics_str = ", ".join(technique.tactics) if technique.tactics else "Unknown"
        explanation_parts.append(
            f"This technique is associated with the {tactics_str} tactic(s) "
            f"and targets {', '.join(technique.platforms[:3]) if technique.platforms else 'various'} platforms."
        )

        return " ".join(explanation_parts)

    def _generate_analytic_reasoning(
        self,
        technique_ids: List[str],
        threat_actor: Optional[str],
        actor_context: Optional[Dict]
    ) -> Dict[str, Any]:
        """Generate analytic reasoning for the hunt campaign.

        Args:
            technique_ids: MITRE technique IDs
            threat_actor: Threat actor name
            actor_context: Threat actor context

        Returns:
            Analytic reasoning dictionary
        """
        reasoning = {
            "hypothesis": self._generate_hypothesis(technique_ids, threat_actor, actor_context),
            "expected_results": self._generate_expected_results(technique_ids),
            "investigation_guidance": self._generate_investigation_guidance(technique_ids),
            "related_techniques": self._find_related_techniques(technique_ids)
        }

        return reasoning

    def _generate_hypothesis(
        self,
        technique_ids: List[str],
        threat_actor: Optional[str],
        actor_context: Optional[Dict]
    ) -> str:
        """Generate hunt hypothesis.

        Args:
            technique_ids: MITRE technique IDs
            threat_actor: Threat actor name
            actor_context: Threat actor context

        Returns:
            Hunt hypothesis string
        """
        techniques = self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id.in_(technique_ids)
        ).all()

        if not techniques:
            return "Hunting for suspicious activity based on selected techniques."

        tactics = set()
        for tech in techniques:
            tactics.update(tech.tactics)

        hypothesis_parts = []

        if threat_actor and actor_context:
            hypothesis_parts.append(
                f"Based on known {threat_actor} activity, we hypothesize that the threat actor may be "
                f"attempting to {' and '.join(t.lower() for t in list(tactics)[:3])} "
                f"using techniques including {', '.join(t.name for t in techniques[:3])}."
            )

            if actor_context.get("last_seen"):
                hypothesis_parts.append(
                    f"This actor was last observed on {actor_context['last_seen'][:10]}."
                )
        else:
            hypothesis_parts.append(
                f"Hunting for {', '.join(t.lower() for t in list(tactics)[:3])} activity "
                f"using techniques: {', '.join(t.name for t in techniques[:3])}."
            )

        return " ".join(hypothesis_parts)

    def _generate_expected_results(self, technique_ids: List[str]) -> Dict[str, str]:
        """Generate expected results guidance.

        Args:
            technique_ids: MITRE technique IDs

        Returns:
            Expected results dictionary
        """
        # This is simplified - in production, you might base this on historical data
        return {
            "typical_volume": "2-10 events per day in a typical enterprise environment",
            "investigation_threshold": "Investigate any results, as these techniques are high-value detections",
            "triage_priority": "High - these techniques are commonly used by adversaries",
            "retention_recommendation": "Retain logs for at least 90 days to enable historical hunting"
        }

    def _generate_investigation_guidance(self, technique_ids: List[str]) -> List[str]:
        """Generate investigation guidance steps.

        Args:
            technique_ids: MITRE technique IDs

        Returns:
            List of investigation steps
        """
        guidance = [
            "Review the process execution chain (parent and child processes)",
            "Check for network connections from suspicious processes",
            "Validate user account activity and authorization",
            "Correlate findings with authentication logs",
            "Check for persistence mechanisms on affected hosts",
            "Review file system changes and dropped files",
            "Analyze command-line arguments for suspicious patterns",
            "Correlate with threat intelligence feeds",
            "Document findings and timeline of events",
            "Escalate confirmed threats to incident response team"
        ]

        return guidance

    def _find_related_techniques(self, technique_ids: List[str]) -> List[Dict[str, str]]:
        """Find related techniques to hunt for.

        Args:
            technique_ids: MITRE technique IDs

        Returns:
            List of related technique dictionaries
        """
        # Get the techniques
        techniques = self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id.in_(technique_ids)
        ).all()

        if not techniques:
            return []

        # Collect tactics from input techniques
        tactics = set()
        for tech in techniques:
            tactics.update(tech.tactics)

        # Find other techniques in the same tactics
        related = self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id.notin_(technique_ids)
        ).limit(100).all()

        related_techniques = []
        for tech in related:
            # Check if technique shares any tactics
            if any(tactic in tech.tactics for tactic in tactics):
                related_techniques.append({
                    "id": tech.technique_id,
                    "name": tech.name,
                    "tactics": tech.tactics,
                    "reason": f"Shares {', '.join(set(tech.tactics) & tactics)} tactic(s)"
                })

        # Limit to top 10 most relevant
        return related_techniques[:10]

    def _recommend_hunt_sequence(self, technique_ids: List[str]) -> List[Dict[str, Any]]:
        """Recommend sequence for hunting techniques.

        Args:
            technique_ids: MITRE technique IDs

        Returns:
            List of techniques in recommended hunt order
        """
        techniques = self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id.in_(technique_ids)
        ).all()

        if not techniques:
            return []

        # Define tactic order based on typical attack chain
        tactic_order = {
            "Initial Access": 1,
            "Execution": 2,
            "Persistence": 3,
            "Privilege Escalation": 4,
            "Defense Evasion": 5,
            "Credential Access": 6,
            "Discovery": 7,
            "Lateral Movement": 8,
            "Collection": 9,
            "Command And Control": 10,
            "Exfiltration": 11,
            "Impact": 12
        }

        # Score each technique based on earliest tactic
        scored_techniques = []
        for tech in techniques:
            min_order = min(
                (tactic_order.get(tactic, 99) for tactic in tech.tactics),
                default=99
            )
            scored_techniques.append((min_order, tech))

        # Sort by tactic order
        scored_techniques.sort(key=lambda x: x[0])

        sequence = []
        for order, tech in scored_techniques:
            sequence.append({
                "technique_id": tech.technique_id,
                "name": tech.name,
                "order": len(sequence) + 1,
                "rationale": f"Part of {tech.tactics[0] if tech.tactics else 'Unknown'} phase",
                "tactics": tech.tactics
            })

        return sequence
