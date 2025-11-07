"""Query generation engine for EDR platforms."""

import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
from jinja2 import Template, Environment, FileSystemLoader
from sqlalchemy.orm import Session
from ..models.template import DetectionTemplate
from ..models.query import GeneratedQuery
from ..models.mitre import MitreTechnique
from ..models.threat_intel import ThreatIntel
from ..core.config import settings

logger = logging.getLogger(__name__)


class QueryGenerator:
    """Generate threat hunting queries for different EDR platforms."""

    SUPPORTED_PLATFORMS = ["defender", "crowdstrike", "carbonblack", "sentinelone"]

    def __init__(self, db: Session):
        self.db = db
        self.jinja_env = Environment(autoescape=True)

    def generate_query(
        self,
        technique_ids: List[str],
        platform: str,
        timeframe: Optional[str] = None,
        include_iocs: bool = True,
        ioc_types: Optional[List[str]] = None
    ) -> Optional[Dict[str, Any]]:
        """Generate a threat hunting query for a specific platform.

        Args:
            technique_ids: List of MITRE ATT&CK technique IDs
            platform: EDR platform (defender, crowdstrike, carbonblack, sentinelone)
            timeframe: Time range for the query (e.g., "7d", "24h")
            include_iocs: Whether to include recent IOCs in the query
            ioc_types: Types of IOCs to include (hash, ip, domain, url)

        Returns:
            Dictionary with query details or None if no template found
        """
        if platform not in self.SUPPORTED_PLATFORMS:
            logger.error(f"Unsupported platform: {platform}")
            return None

        if not technique_ids:
            logger.error("No technique IDs provided")
            return None

        # Use primary technique for template lookup
        primary_technique_id = technique_ids[0]

        # Get template for this technique and platform
        template = self.db.query(DetectionTemplate).filter(
            DetectionTemplate.technique_id == primary_technique_id,
            DetectionTemplate.platform == platform
        ).first()

        if not template:
            logger.warning(f"No template found for {primary_technique_id} on {platform}")
            return None

        # Get technique details
        technique = self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id == primary_technique_id
        ).first()

        # Prepare template variables
        variables = self._prepare_variables(
            technique_ids=technique_ids,
            timeframe=timeframe or settings.DEFAULT_TIMEFRAME,
            include_iocs=include_iocs,
            ioc_types=ioc_types,
            template_vars=template.variables or {}
        )

        # Render the query from template
        query_text = self._render_template(template.query_template, variables)

        # Create metadata
        metadata = {
            "techniques": technique_ids,
            "technique_names": [technique.name] if technique else [],
            "platform": platform,
            "timeframe": timeframe or settings.DEFAULT_TIMEFRAME,
            "confidence": template.confidence,
            "data_sources": template.data_sources_required,
            "false_positive_notes": template.false_positive_notes,
            "iocs_included": include_iocs,
            "generated_at": datetime.utcnow().isoformat()
        }

        # Save generated query
        generated_query = GeneratedQuery(
            technique_ids=technique_ids,
            platform=platform,
            query_text=query_text,
            metadata=metadata
        )
        self.db.add(generated_query)
        self.db.commit()

        return {
            "query_id": generated_query.id,
            "query": query_text,
            "metadata": metadata,
            "technique": {
                "id": technique.technique_id,
                "name": technique.name,
                "description": technique.description,
                "tactics": technique.tactics
            } if technique else None
        }

    def _prepare_variables(
        self,
        technique_ids: List[str],
        timeframe: str,
        include_iocs: bool,
        ioc_types: Optional[List[str]],
        template_vars: Dict
    ) -> Dict[str, Any]:
        """Prepare variables for template rendering.

        Args:
            technique_ids: MITRE technique IDs
            timeframe: Time range
            include_iocs: Whether to include IOCs
            ioc_types: Types of IOCs to include
            template_vars: Default variables from template

        Returns:
            Dictionary of variables for template rendering
        """
        variables = {
            "timeframe": timeframe,
            "technique_ids": technique_ids,
        }

        # Add default variables from template
        variables.update(template_vars)

        # Add IOCs if requested
        if include_iocs:
            iocs = self._get_relevant_iocs(technique_ids, ioc_types)
            variables.update(iocs)

        return variables

    def _get_relevant_iocs(
        self,
        technique_ids: List[str],
        ioc_types: Optional[List[str]] = None
    ) -> Dict[str, List[str]]:
        """Get relevant IOCs for the techniques.

        Args:
            technique_ids: MITRE technique IDs
            ioc_types: Types of IOCs to retrieve

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
            # Get IOCs associated with this technique
            technique_iocs = self.db.query(ThreatIntel).filter(
                ThreatIntel.associated_techniques.contains([technique_id])
            ).limit(100).all()

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
            iocs[key] = list(set(iocs[key]))[:50]  # Limit to 50 per type

        return iocs

    def _render_template(self, template_str: str, variables: Dict[str, Any]) -> str:
        """Render a Jinja2 template with variables.

        Args:
            template_str: Template string
            variables: Variables for rendering

        Returns:
            Rendered template string
        """
        try:
            template = Template(template_str)
            return template.render(**variables)
        except Exception as e:
            logger.error(f"Error rendering template: {e}")
            return template_str

    def generate_multi_platform(
        self,
        technique_ids: List[str],
        platforms: List[str],
        **kwargs
    ) -> Dict[str, Any]:
        """Generate queries for multiple platforms.

        Args:
            technique_ids: MITRE technique IDs
            platforms: List of EDR platforms
            **kwargs: Additional arguments for query generation

        Returns:
            Dictionary mapping platforms to their queries
        """
        results = {}

        for platform in platforms:
            if platform not in self.SUPPORTED_PLATFORMS:
                logger.warning(f"Skipping unsupported platform: {platform}")
                continue

            query_result = self.generate_query(technique_ids, platform, **kwargs)
            if query_result:
                results[platform] = query_result

        return results

    def add_template(
        self,
        technique_id: str,
        platform: str,
        query_template: str,
        variables: Optional[Dict] = None,
        confidence: str = "medium",
        false_positive_notes: Optional[str] = None,
        data_sources_required: Optional[List[str]] = None,
        created_by: str = "system"
    ) -> DetectionTemplate:
        """Add a new detection template.

        Args:
            technique_id: MITRE technique ID
            platform: EDR platform
            query_template: Jinja2 template string
            variables: Default variables for the template
            confidence: Detection confidence (high, medium, low)
            false_positive_notes: Notes about false positives
            data_sources_required: Required data sources
            created_by: Creator identifier

        Returns:
            Created DetectionTemplate object
        """
        template = DetectionTemplate(
            technique_id=technique_id,
            platform=platform,
            query_template=query_template,
            variables=variables or {},
            confidence=confidence,
            false_positive_notes=false_positive_notes,
            data_sources_required=data_sources_required or [],
            created_by=created_by
        )

        self.db.add(template)
        self.db.commit()

        logger.info(f"Added template for {technique_id} on {platform}")
        return template

    def get_templates_for_technique(
        self,
        technique_id: str
    ) -> List[DetectionTemplate]:
        """Get all templates for a technique across all platforms.

        Args:
            technique_id: MITRE technique ID

        Returns:
            List of DetectionTemplate objects
        """
        return self.db.query(DetectionTemplate).filter(
            DetectionTemplate.technique_id == technique_id
        ).all()
