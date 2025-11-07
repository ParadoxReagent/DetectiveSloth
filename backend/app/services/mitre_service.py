"""MITRE ATT&CK framework integration service."""

import logging
from typing import List, Dict, Optional
import httpx
from sqlalchemy.orm import Session
from stix2 import MemoryStore, Filter
from ..models.mitre import MitreTechnique
from ..core.config import settings

logger = logging.getLogger(__name__)


class MitreAttackService:
    """Service for downloading and managing MITRE ATT&CK data."""

    def __init__(self, db: Session):
        self.db = db
        self.stix_url = settings.MITRE_STIX_URL

    async def download_attack_data(self) -> Dict:
        """Download MITRE ATT&CK STIX data from GitHub."""
        logger.info(f"Downloading MITRE ATT&CK data from {self.stix_url}")

        async with httpx.AsyncClient() as client:
            response = await client.get(self.stix_url, timeout=60.0)
            response.raise_for_status()
            return response.json()

    def parse_and_store_techniques(self, stix_data: Dict) -> int:
        """Parse STIX data and store techniques in database."""
        logger.info("Parsing MITRE ATT&CK techniques from STIX data")

        # Create STIX memory store
        memory_store = MemoryStore(stix_data=stix_data.get("objects", []))

        # Get all attack patterns (techniques)
        techniques = memory_store.query([Filter("type", "=", "attack-pattern")])

        count = 0
        for technique in techniques:
            try:
                # Extract technique ID from external references
                technique_id = None
                for ref in technique.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        technique_id = ref.get("external_id")
                        break

                if not technique_id:
                    continue

                # Extract tactics from kill chain phases
                tactics = [
                    phase.get("phase_name", "").replace("-", " ").title()
                    for phase in technique.get("kill_chain_phases", [])
                ]

                # Extract platforms
                platforms = technique.get("x_mitre_platforms", [])

                # Extract data sources (if available)
                data_sources = []
                if hasattr(technique, "x_mitre_data_sources"):
                    data_sources = technique.x_mitre_data_sources

                # Check if technique already exists
                existing = self.db.query(MitreTechnique).filter(
                    MitreTechnique.technique_id == technique_id
                ).first()

                if existing:
                    # Update existing technique
                    existing.name = technique.get("name", "")
                    existing.description = technique.get("description", "")
                    existing.tactics = tactics
                    existing.platforms = platforms
                    existing.data_sources = data_sources
                    existing.version = technique.get("x_mitre_version", "1.0")
                else:
                    # Create new technique
                    new_technique = MitreTechnique(
                        technique_id=technique_id,
                        name=technique.get("name", ""),
                        description=technique.get("description", ""),
                        tactics=tactics,
                        platforms=platforms,
                        data_sources=data_sources,
                        version=technique.get("x_mitre_version", "1.0")
                    )
                    self.db.add(new_technique)

                count += 1

            except Exception as e:
                logger.error(f"Error processing technique: {e}")
                continue

        self.db.commit()
        logger.info(f"Successfully processed {count} MITRE ATT&CK techniques")
        return count

    async def update_attack_data(self) -> int:
        """Download and update MITRE ATT&CK data."""
        stix_data = await self.download_attack_data()
        count = self.parse_and_store_techniques(stix_data)
        return count

    def get_technique_by_id(self, technique_id: str) -> Optional[MitreTechnique]:
        """Get a technique by its ID."""
        return self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id == technique_id
        ).first()

    def search_techniques(
        self,
        keyword: Optional[str] = None,
        tactic: Optional[str] = None,
        platform: Optional[str] = None
    ) -> List[MitreTechnique]:
        """Search techniques by keyword, tactic, or platform."""
        query = self.db.query(MitreTechnique)

        if keyword:
            query = query.filter(
                (MitreTechnique.name.ilike(f"%{keyword}%")) |
                (MitreTechnique.description.ilike(f"%{keyword}%"))
            )

        if tactic:
            # Array contains operator for PostgreSQL
            # For SQLite, this will need a different approach
            query = query.filter(MitreTechnique.tactics.contains([tactic]))

        if platform:
            query = query.filter(MitreTechnique.platforms.contains([platform]))

        return query.all()

    def get_all_tactics(self) -> List[str]:
        """Get all unique tactics from stored techniques."""
        techniques = self.db.query(MitreTechnique).all()
        tactics = set()
        for tech in techniques:
            tactics.update(tech.tactics)
        return sorted(list(tactics))

    def get_all_platforms(self) -> List[str]:
        """Get all unique platforms from stored techniques."""
        techniques = self.db.query(MitreTechnique).all()
        platforms = set()
        for tech in techniques:
            platforms.update(tech.platforms)
        return sorted(list(platforms))
