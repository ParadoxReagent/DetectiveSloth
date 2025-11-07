"""Threat intelligence ingestion service."""

import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import httpx
from sqlalchemy.orm import Session
from sqlalchemy import and_
from ..models.threat_intel import ThreatIntel
from ..models.cve import CVE
from ..core.config import settings

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """Service for ingesting threat intelligence from multiple feeds."""

    def __init__(self, db: Session):
        self.db = db

    async def ingest_otx_indicators(self, days: int = 7) -> int:
        """Ingest indicators from AlienVault OTX.

        Args:
            days: Number of days of recent pulses to retrieve

        Returns:
            Number of indicators ingested
        """
        if not settings.OTX_API_KEY:
            logger.warning("OTX_API_KEY not configured, skipping OTX ingestion")
            return 0

        logger.info(f"Ingesting OTX indicators from last {days} days")

        headers = {"X-OTX-API-KEY": settings.OTX_API_KEY}
        base_url = "https://otx.alienvault.com/api/v1"

        count = 0

        try:
            async with httpx.AsyncClient() as client:
                # Get recent pulses
                url = f"{base_url}/pulses/subscribed"
                params = {"modified_since": (datetime.utcnow() - timedelta(days=days)).isoformat()}

                response = await client.get(url, headers=headers, params=params, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                for pulse in data.get("results", []):
                    # Extract indicators from pulse
                    for indicator in pulse.get("indicators", []):
                        ioc_type = indicator.get("type", "").lower()
                        ioc_value = indicator.get("indicator", "")

                        if not ioc_value:
                            continue

                        # Extract associated MITRE techniques
                        techniques = []
                        for attack_id in pulse.get("attack_ids", []):
                            techniques.append(attack_id.get("id", ""))

                        # Build context
                        context = {
                            "pulse_name": pulse.get("name"),
                            "pulse_id": pulse.get("id"),
                            "description": pulse.get("description"),
                            "tags": pulse.get("tags", []),
                            "adversary": pulse.get("adversary"),
                            "targeted_countries": pulse.get("targeted_countries", []),
                        }

                        # Check if IOC already exists
                        existing = self.db.query(ThreatIntel).filter(
                            and_(
                                ThreatIntel.source == "otx",
                                ThreatIntel.ioc_value == ioc_value
                            )
                        ).first()

                        if existing:
                            # Update last_seen
                            existing.last_seen = datetime.utcnow()
                            existing.context = context
                            existing.associated_techniques = techniques
                        else:
                            # Create new entry
                            new_ioc = ThreatIntel(
                                source="otx",
                                ioc_type=ioc_type,
                                ioc_value=ioc_value,
                                context=context,
                                associated_techniques=techniques,
                                confidence_score=70,  # Default score for OTX
                                tags=pulse.get("tags", [])
                            )
                            self.db.add(new_ioc)

                        count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} indicators from OTX")

        except Exception as e:
            logger.error(f"Error ingesting OTX indicators: {e}")
            self.db.rollback()

        return count

    async def ingest_abusech_urlhaus(self) -> int:
        """Ingest malware URLs from URLhaus (Abuse.ch).

        Returns:
            Number of URLs ingested
        """
        logger.info("Ingesting URLhaus data")

        url = "https://urlhaus.abuse.ch/downloads/json_recent/"
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                for entry in data:
                    url_value = entry.get("url", "")
                    if not url_value:
                        continue

                    # Build context
                    context = {
                        "threat": entry.get("threat"),
                        "tags": entry.get("tags", []),
                        "reporter": entry.get("reporter"),
                        "larted": entry.get("larted"),
                        "urlhaus_reference": entry.get("urlhaus_reference"),
                    }

                    # Check if URL already exists
                    existing = self.db.query(ThreatIntel).filter(
                        and_(
                            ThreatIntel.source == "urlhaus",
                            ThreatIntel.ioc_value == url_value
                        )
                    ).first()

                    if existing:
                        existing.last_seen = datetime.utcnow()
                        existing.context = context
                    else:
                        new_ioc = ThreatIntel(
                            source="urlhaus",
                            ioc_type="url",
                            ioc_value=url_value,
                            context=context,
                            confidence_score=80,
                            tags=entry.get("tags", [])
                        )
                        self.db.add(new_ioc)

                    count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} URLs from URLhaus")

        except Exception as e:
            logger.error(f"Error ingesting URLhaus data: {e}")
            self.db.rollback()

        return count

    async def ingest_abusech_threatfox(self) -> int:
        """Ingest IOCs from ThreatFox (Abuse.ch).

        Returns:
            Number of IOCs ingested
        """
        logger.info("Ingesting ThreatFox data")

        url = "https://threatfox.abuse.ch/export/json/recent/"
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                for ioc_id, entry in data.items():
                    if ioc_id == "status":
                        continue

                    ioc_value = entry.get("ioc", "")
                    ioc_type = entry.get("ioc_type", "").lower()

                    if not ioc_value:
                        continue

                    # Build context
                    context = {
                        "threat_type": entry.get("threat_type"),
                        "malware": entry.get("malware"),
                        "malware_alias": entry.get("malware_alias"),
                        "confidence_level": entry.get("confidence_level"),
                        "reporter": entry.get("reporter"),
                        "reference": entry.get("reference"),
                    }

                    # Check if IOC already exists
                    existing = self.db.query(ThreatIntel).filter(
                        and_(
                            ThreatIntel.source == "threatfox",
                            ThreatIntel.ioc_value == ioc_value
                        )
                    ).first()

                    if existing:
                        existing.last_seen = datetime.utcnow()
                        existing.context = context
                    else:
                        new_ioc = ThreatIntel(
                            source="threatfox",
                            ioc_type=ioc_type,
                            ioc_value=ioc_value,
                            context=context,
                            confidence_score=entry.get("confidence_level", 50),
                            tags=entry.get("tags", [])
                        )
                        self.db.add(new_ioc)

                    count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} IOCs from ThreatFox")

        except Exception as e:
            logger.error(f"Error ingesting ThreatFox data: {e}")
            self.db.rollback()

        return count

    async def update_all_feeds(self) -> Dict[str, int]:
        """Update all threat intelligence feeds.

        Returns:
            Dictionary with feed names and count of ingested indicators
        """
        logger.info("Updating all threat intelligence feeds")

        results = {
            "otx": await self.ingest_otx_indicators(),
            "urlhaus": await self.ingest_abusech_urlhaus(),
            "threatfox": await self.ingest_abusech_threatfox(),
            "cisa_kev": await self.ingest_cisa_kev(),
            "greynoise": await self.ingest_greynoise(),
        }

        total = sum(results.values())
        logger.info(f"Total indicators ingested: {total}")

        return results

    def get_recent_iocs(
        self,
        days: int = 7,
        ioc_type: Optional[str] = None,
        source: Optional[str] = None
    ) -> List[ThreatIntel]:
        """Get recent IOCs from the database.

        Args:
            days: Number of days to look back
            ioc_type: Filter by IOC type (hash, ip, domain, url)
            source: Filter by source (otx, urlhaus, threatfox)

        Returns:
            List of ThreatIntel objects
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        query = self.db.query(ThreatIntel).filter(ThreatIntel.last_seen >= cutoff_date)

        if ioc_type:
            query = query.filter(ThreatIntel.ioc_type == ioc_type)

        if source:
            query = query.filter(ThreatIntel.source == source)

        return query.order_by(ThreatIntel.last_seen.desc()).all()

    def get_iocs_by_technique(self, technique_id: str) -> List[ThreatIntel]:
        """Get IOCs associated with a specific MITRE technique.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1055)

        Returns:
            List of ThreatIntel objects
        """
        return self.db.query(ThreatIntel).filter(
            ThreatIntel.associated_techniques.contains([technique_id])
        ).all()

    async def ingest_cisa_kev(self) -> int:
        """Ingest CISA Known Exploited Vulnerabilities (KEV) catalog.

        Returns:
            Number of CVEs ingested
        """
        logger.info("Ingesting CISA KEV catalog")

        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                for vuln in data.get("vulnerabilities", []):
                    cve_id = vuln.get("cveID", "")
                    if not cve_id:
                        continue

                    # Parse dates
                    date_added = vuln.get("dateAdded")
                    due_date = vuln.get("dueDate")

                    date_added_dt = datetime.fromisoformat(date_added) if date_added else None
                    due_date_dt = datetime.fromisoformat(due_date) if due_date else None

                    # Build context
                    context = {
                        "vulnerability_name": vuln.get("vulnerabilityName"),
                        "short_description": vuln.get("shortDescription"),
                        "required_action": vuln.get("requiredAction"),
                        "known_ransomware_campaign_use": vuln.get("knownRansomwareCampaignUse"),
                        "notes": vuln.get("notes"),
                    }

                    # Check if CVE already exists
                    existing = self.db.query(CVE).filter(CVE.cve_id == cve_id).first()

                    if existing:
                        # Update existing CVE
                        existing.last_seen = datetime.utcnow()
                        existing.context = context
                        existing.exploited_in_wild = True
                        existing.added_to_kev = date_added_dt
                        existing.remediation_deadline = due_date_dt
                        existing.ransomware_use = vuln.get("knownRansomwareCampaignUse") == "Known"
                    else:
                        # Create new CVE entry
                        new_cve = CVE(
                            cve_id=cve_id,
                            description=vuln.get("shortDescription"),
                            vendor=vuln.get("vendorProject"),
                            product=vuln.get("product"),
                            exploited_in_wild=True,
                            ransomware_use=vuln.get("knownRansomwareCampaignUse") == "Known",
                            added_to_kev=date_added_dt,
                            remediation_required=True,
                            remediation_deadline=due_date_dt,
                            context=context,
                            source="cisa_kev",
                        )
                        self.db.add(new_cve)

                    count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} CVEs from CISA KEV")

        except Exception as e:
            logger.error(f"Error ingesting CISA KEV: {e}")
            self.db.rollback()

        return count

    async def ingest_greynoise(self, classification: str = "malicious") -> int:
        """Ingest internet scanner IPs from GreyNoise.

        Args:
            classification: Filter by classification (malicious, benign, unknown)

        Returns:
            Number of IPs ingested
        """
        if not settings.GREYNOISE_API_KEY:
            logger.warning("GREYNOISE_API_KEY not configured, skipping GreyNoise ingestion")
            return 0

        logger.info(f"Ingesting GreyNoise IPs with classification: {classification}")

        headers = {"key": settings.GREYNOISE_API_KEY}
        base_url = "https://api.greynoise.io/v3"
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                # Query for IPs with specified classification
                url = f"{base_url}/community"

                # Get recent malicious IPs using GNQL
                gnql_url = f"{base_url}/gnql"
                query = f"classification:{classification} last_seen:7d"

                params = {
                    "query": query,
                    "size": 1000  # Maximum results per request
                }

                response = await client.get(gnql_url, headers=headers, params=params, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                for entry in data.get("data", []):
                    ip_address = entry.get("ip", "")
                    if not ip_address:
                        continue

                    # Extract MITRE techniques from metadata
                    techniques = []
                    metadata = entry.get("metadata", {})

                    # Build context
                    context = {
                        "classification": entry.get("classification"),
                        "first_seen": entry.get("first_seen"),
                        "last_seen": entry.get("last_seen"),
                        "actor": entry.get("actor"),
                        "tags": entry.get("tags", []),
                        "metadata": metadata,
                        "raw_data": entry.get("raw_data", {}),
                        "seen": entry.get("seen"),
                        "spoofable": entry.get("spoofable"),
                    }

                    # Check if IP already exists
                    existing = self.db.query(ThreatIntel).filter(
                        and_(
                            ThreatIntel.source == "greynoise",
                            ThreatIntel.ioc_value == ip_address
                        )
                    ).first()

                    if existing:
                        existing.last_seen = datetime.utcnow()
                        existing.context = context
                    else:
                        new_ioc = ThreatIntel(
                            source="greynoise",
                            ioc_type="ip",
                            ioc_value=ip_address,
                            context=context,
                            associated_techniques=techniques,
                            confidence_score=90 if classification == "malicious" else 50,
                            tags=entry.get("tags", [])
                        )
                        self.db.add(new_ioc)

                    count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} IPs from GreyNoise")

        except Exception as e:
            logger.error(f"Error ingesting GreyNoise data: {e}")
            self.db.rollback()

        return count
