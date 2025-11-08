"""Threat intelligence ingestion service."""

import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import httpx
import feedparser
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

    async def update_all_feeds(self, include_optional: bool = False) -> Dict[str, int]:
        """Update all threat intelligence feeds.

        Args:
            include_optional: Include optional/paid feeds if configured

        Returns:
            Dictionary with feed names and count of ingested indicators
        """
        logger.info("Updating all threat intelligence feeds")

        # Core free feeds (no API key required)
        results = {
            "urlhaus": await self.ingest_abusech_urlhaus(),
            "threatfox": await self.ingest_abusech_threatfox(),
            "cisa_kev": await self.ingest_cisa_kev(),
            "malware_bazaar": await self.ingest_malware_bazaar(),
            "feodo_tracker": await self.ingest_feodo_tracker(),
            "sslbl": await self.ingest_sslbl(),
            "blocklist_de": await self.ingest_blocklist_de(),
            "spamhaus_drop": await self.ingest_spamhaus_drop(),
        }

        # Feeds requiring API keys
        results["otx"] = await self.ingest_otx_indicators()
        results["greynoise"] = await self.ingest_greynoise()
        results["abuseipdb"] = await self.ingest_abuseipdb()
        results["phishtank"] = await self.ingest_phishtank()
        results["pulsedive"] = await self.ingest_pulsedive()
        results["urlscan"] = await self.ingest_urlscan()

        # Optional paid/limited feeds
        if include_optional:
            results["virustotal"] = await self.ingest_virustotal_iocs(limit=100)
            results["hybrid_analysis"] = await self.ingest_hybrid_analysis()
            results["shodan"] = await self.ingest_shodan(limit=100)

        # Platform-based feeds (if configured)
        results["misp"] = await self.ingest_misp()
        results["opencti"] = await self.ingest_opencti()

        # RSS feeds
        results["rss_feeds"] = await self.ingest_rss_feeds()

        total = sum(results.values())
        logger.info(f"Total indicators ingested: {total} from {len(results)} feeds")

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

    async def ingest_virustotal_iocs(self, limit: int = 100) -> int:
        """Ingest IOCs from VirusTotal using recent submissions.

        Args:
            limit: Maximum number of IOCs to retrieve

        Returns:
            Number of IOCs ingested
        """
        if not settings.VIRUSTOTAL_API_KEY:
            logger.warning("VIRUSTOTAL_API_KEY not configured, skipping VirusTotal ingestion")
            return 0

        logger.info(f"Ingesting VirusTotal IOCs (limit: {limit})")

        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        base_url = "https://www.virustotal.com/api/v3"
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                # Get recent malicious files
                url = f"{base_url}/intelligence/search"
                params = {
                    "query": "positives:5+ fs:2024-01-01+",
                    "limit": min(limit, 300)  # VT free tier limit
                }

                response = await client.get(url, headers=headers, params=params, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                for item in data.get("data", []):
                    attributes = item.get("attributes", {})
                    item_type = item.get("type", "")

                    # Extract hash for files
                    if item_type == "file":
                        ioc_value = attributes.get("sha256", "")
                        ioc_type = "hash"
                    elif item_type == "url":
                        ioc_value = attributes.get("url", "")
                        ioc_type = "url"
                    elif item_type == "domain":
                        ioc_value = item.get("id", "")
                        ioc_type = "domain"
                    elif item_type == "ip_address":
                        ioc_value = item.get("id", "")
                        ioc_type = "ip"
                    else:
                        continue

                    if not ioc_value:
                        continue

                    # Extract malware families and tags
                    last_analysis = attributes.get("last_analysis_stats", {})
                    malicious_count = last_analysis.get("malicious", 0)
                    total_count = sum(last_analysis.values())

                    # Build context
                    context = {
                        "malicious_detections": malicious_count,
                        "total_scans": total_count,
                        "reputation": attributes.get("reputation", 0),
                        "popular_threat_label": attributes.get("popular_threat_label"),
                        "threat_names": attributes.get("last_analysis_results", {}).get("threat_names", []),
                        "tags": attributes.get("tags", []),
                        "creation_date": attributes.get("creation_date"),
                        "last_analysis_date": attributes.get("last_analysis_date"),
                    }

                    # Calculate confidence based on detection rate
                    confidence = min(100, int((malicious_count / max(total_count, 1)) * 100))

                    # Check if IOC already exists
                    existing = self.db.query(ThreatIntel).filter(
                        and_(
                            ThreatIntel.source == "virustotal",
                            ThreatIntel.ioc_value == ioc_value
                        )
                    ).first()

                    if existing:
                        existing.last_seen = datetime.utcnow()
                        existing.context = context
                        existing.confidence_score = confidence
                    else:
                        new_ioc = ThreatIntel(
                            source="virustotal",
                            ioc_type=ioc_type,
                            ioc_value=ioc_value,
                            context=context,
                            confidence_score=confidence,
                            tags=attributes.get("tags", [])
                        )
                        self.db.add(new_ioc)

                    count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} IOCs from VirusTotal")

        except Exception as e:
            logger.error(f"Error ingesting VirusTotal data: {e}")
            self.db.rollback()

        return count

    async def ingest_hybrid_analysis(self, days: int = 7) -> int:
        """Ingest malware sandbox analysis from Hybrid Analysis.

        Args:
            days: Number of days of recent reports to retrieve

        Returns:
            Number of reports ingested
        """
        if not settings.HYBRID_ANALYSIS_API_KEY:
            logger.warning("HYBRID_ANALYSIS_API_KEY not configured, skipping Hybrid Analysis ingestion")
            return 0

        logger.info(f"Ingesting Hybrid Analysis reports from last {days} days")

        headers = {
            "api-key": settings.HYBRID_ANALYSIS_API_KEY,
            "user-agent": "DetectiveSloth ThreatIntel"
        }
        base_url = "https://www.hybrid-analysis.com/api/v2"
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                # Get recent reports
                url = f"{base_url}/feed/latest"
                response = await client.get(url, headers=headers, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                for report in data.get("data", []):
                    # Extract file hash
                    sha256 = report.get("sha256", "")
                    if not sha256:
                        continue

                    # Extract network indicators
                    domains = report.get("domains", [])
                    hosts = report.get("hosts", [])

                    # Extract MITRE techniques
                    techniques = []
                    mitre_attcks = report.get("mitre_attcks", [])
                    for attack in mitre_attcks:
                        technique_id = attack.get("tactic", "")
                        if technique_id:
                            techniques.append(technique_id)

                    # Build context
                    context = {
                        "verdict": report.get("verdict"),
                        "threat_score": report.get("threat_score"),
                        "malware_family": report.get("malware_family"),
                        "av_detect": report.get("av_detect"),
                        "vx_family": report.get("vx_family"),
                        "tags": report.get("tags", []),
                        "analysis_start_time": report.get("analysis_start_time"),
                        "environment_description": report.get("environment_description"),
                        "submit_name": report.get("submit_name"),
                        "domains": domains,
                        "hosts": hosts,
                    }

                    # Ingest file hash
                    existing_file = self.db.query(ThreatIntel).filter(
                        and_(
                            ThreatIntel.source == "hybrid_analysis",
                            ThreatIntel.ioc_value == sha256
                        )
                    ).first()

                    threat_score = report.get("threat_score", 0) or 0
                    confidence = min(100, threat_score)

                    if existing_file:
                        existing_file.last_seen = datetime.utcnow()
                        existing_file.context = context
                        existing_file.associated_techniques = techniques
                        existing_file.confidence_score = confidence
                    else:
                        new_ioc = ThreatIntel(
                            source="hybrid_analysis",
                            ioc_type="hash",
                            ioc_value=sha256,
                            context=context,
                            associated_techniques=techniques,
                            confidence_score=confidence,
                            tags=report.get("tags", [])
                        )
                        self.db.add(new_ioc)

                    count += 1

                    # Also ingest contacted domains and IPs
                    for domain in domains:
                        existing_domain = self.db.query(ThreatIntel).filter(
                            and_(
                                ThreatIntel.source == "hybrid_analysis",
                                ThreatIntel.ioc_value == domain
                            )
                        ).first()

                        domain_context = {"related_hash": sha256, "from_sandbox": True}

                        if not existing_domain:
                            domain_ioc = ThreatIntel(
                                source="hybrid_analysis",
                                ioc_type="domain",
                                ioc_value=domain,
                                context=domain_context,
                                associated_techniques=techniques,
                                confidence_score=confidence,
                                tags=["sandbox"]
                            )
                            self.db.add(domain_ioc)
                            count += 1

                    for host in hosts:
                        existing_host = self.db.query(ThreatIntel).filter(
                            and_(
                                ThreatIntel.source == "hybrid_analysis",
                                ThreatIntel.ioc_value == host
                            )
                        ).first()

                        host_context = {"related_hash": sha256, "from_sandbox": True}

                        if not existing_host:
                            host_ioc = ThreatIntel(
                                source="hybrid_analysis",
                                ioc_type="ip",
                                ioc_value=host,
                                context=host_context,
                                associated_techniques=techniques,
                                confidence_score=confidence,
                                tags=["sandbox"]
                            )
                            self.db.add(host_ioc)
                            count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} IOCs from Hybrid Analysis")

        except Exception as e:
            logger.error(f"Error ingesting Hybrid Analysis data: {e}")
            self.db.rollback()

        return count

    async def ingest_shodan(self, query: str = "has_vuln:true", limit: int = 100) -> int:
        """Ingest exposed services from Shodan.

        Args:
            query: Shodan search query (default: devices with vulnerabilities)
            limit: Maximum number of results

        Returns:
            Number of IPs ingested
        """
        if not settings.SHODAN_API_KEY:
            logger.warning("SHODAN_API_KEY not configured, skipping Shodan ingestion")
            return 0

        logger.info(f"Ingesting Shodan data with query: {query}")

        base_url = "https://api.shodan.io"
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                # Search for vulnerable hosts
                url = f"{base_url}/shodan/host/search"
                params = {
                    "key": settings.SHODAN_API_KEY,
                    "query": query,
                    "limit": min(limit, 100)  # Free tier limit
                }

                response = await client.get(url, params=params, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                for result in data.get("matches", []):
                    ip_address = result.get("ip_str", "")
                    if not ip_address:
                        continue

                    # Extract vulnerabilities
                    vulns = result.get("vulns", [])

                    # Build context
                    context = {
                        "port": result.get("port"),
                        "transport": result.get("transport"),
                        "product": result.get("product"),
                        "version": result.get("version"),
                        "os": result.get("os"),
                        "hostnames": result.get("hostnames", []),
                        "domains": result.get("domains", []),
                        "org": result.get("org"),
                        "isp": result.get("isp"),
                        "asn": result.get("asn"),
                        "location": {
                            "country": result.get("location", {}).get("country_name"),
                            "city": result.get("location", {}).get("city"),
                        },
                        "vulns": vulns,
                        "tags": result.get("tags", []),
                        "timestamp": result.get("timestamp"),
                    }

                    # Calculate confidence based on vulnerability count
                    confidence = min(90, 50 + (len(vulns) * 10))

                    # Check if IP already exists
                    existing = self.db.query(ThreatIntel).filter(
                        and_(
                            ThreatIntel.source == "shodan",
                            ThreatIntel.ioc_value == ip_address
                        )
                    ).first()

                    if existing:
                        existing.last_seen = datetime.utcnow()
                        existing.context = context
                        existing.confidence_score = confidence
                    else:
                        new_ioc = ThreatIntel(
                            source="shodan",
                            ioc_type="ip",
                            ioc_value=ip_address,
                            context=context,
                            confidence_score=confidence,
                            tags=result.get("tags", []) + ["exposed_service"]
                        )
                        self.db.add(new_ioc)

                    count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} IPs from Shodan")

        except Exception as e:
            logger.error(f"Error ingesting Shodan data: {e}")
            self.db.rollback()

        return count

    async def ingest_abuseipdb(self, days: int = 7, confidence_min: int = 75) -> int:
        """Ingest malicious IPs from AbuseIPDB.

        Args:
            days: Number of days to look back
            confidence_min: Minimum confidence score (0-100)

        Returns:
            Number of IPs ingested
        """
        if not settings.ABUSEIPDB_API_KEY:
            logger.warning("ABUSEIPDB_API_KEY not configured, skipping AbuseIPDB ingestion")
            return 0

        logger.info(f"Ingesting AbuseIPDB IPs from last {days} days (confidence >= {confidence_min})")

        headers = {
            "Key": settings.ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        base_url = "https://api.abuseipdb.com/api/v2"
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                # Get blacklist
                url = f"{base_url}/blacklist"
                params = {
                    "confidenceMinimum": confidence_min,
                    "limit": 10000  # Maximum for free tier
                }

                response = await client.get(url, headers=headers, params=params, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                for entry in data.get("data", []):
                    ip_address = entry.get("ipAddress", "")
                    if not ip_address:
                        continue

                    # Build context
                    context = {
                        "abuse_confidence_score": entry.get("abuseConfidenceScore"),
                        "country_code": entry.get("countryCode"),
                        "usage_type": entry.get("usageType"),
                        "isp": entry.get("isp"),
                        "domain": entry.get("domain"),
                        "total_reports": entry.get("totalReports"),
                        "last_reported_at": entry.get("lastReportedAt"),
                    }

                    confidence = entry.get("abuseConfidenceScore", 75)

                    # Check if IP already exists
                    existing = self.db.query(ThreatIntel).filter(
                        and_(
                            ThreatIntel.source == "abuseipdb",
                            ThreatIntel.ioc_value == ip_address
                        )
                    ).first()

                    if existing:
                        existing.last_seen = datetime.utcnow()
                        existing.context = context
                        existing.confidence_score = confidence
                    else:
                        new_ioc = ThreatIntel(
                            source="abuseipdb",
                            ioc_type="ip",
                            ioc_value=ip_address,
                            context=context,
                            confidence_score=confidence,
                            tags=["abuse"]
                        )
                        self.db.add(new_ioc)

                    count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} IPs from AbuseIPDB")

        except Exception as e:
            logger.error(f"Error ingesting AbuseIPDB data: {e}")
            self.db.rollback()

        return count

    async def ingest_phishtank(self) -> int:
        """Ingest phishing URLs from PhishTank.

        Returns:
            Number of URLs ingested
        """
        if not settings.PHISHTANK_API_KEY:
            logger.warning("PHISHTANK_API_KEY not configured, skipping PhishTank ingestion")
            return 0

        logger.info("Ingesting PhishTank URLs")

        url = f"http://data.phishtank.com/data/{settings.PHISHTANK_API_KEY}/online-valid.json"
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=60.0)
                response.raise_for_status()
                data = response.json()

                for entry in data:
                    phish_url = entry.get("url", "")
                    if not phish_url:
                        continue

                    # Build context
                    context = {
                        "phish_id": entry.get("phish_id"),
                        "phish_detail_url": entry.get("phish_detail_url"),
                        "submission_time": entry.get("submission_time"),
                        "verified": entry.get("verified"),
                        "verification_time": entry.get("verification_time"),
                        "online": entry.get("online"),
                        "target": entry.get("target"),
                    }

                    # Check if URL already exists
                    existing = self.db.query(ThreatIntel).filter(
                        and_(
                            ThreatIntel.source == "phishtank",
                            ThreatIntel.ioc_value == phish_url
                        )
                    ).first()

                    if existing:
                        existing.last_seen = datetime.utcnow()
                        existing.context = context
                    else:
                        new_ioc = ThreatIntel(
                            source="phishtank",
                            ioc_type="url",
                            ioc_value=phish_url,
                            context=context,
                            confidence_score=95 if entry.get("verified") == "yes" else 70,
                            tags=["phishing"]
                        )
                        self.db.add(new_ioc)

                    count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} URLs from PhishTank")

        except Exception as e:
            logger.error(f"Error ingesting PhishTank data: {e}")
            self.db.rollback()

        return count

    async def ingest_malware_bazaar(self) -> int:
        """Ingest recent malware samples from MalwareBazaar (Abuse.ch).

        Returns:
            Number of samples ingested
        """
        logger.info("Ingesting MalwareBazaar samples")

        url = "https://mb-api.abuse.ch/api/v1/"
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                # Get recent samples
                payload = {"query": "get_recent"}
                response = await client.post(url, data=payload, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                for sample in data.get("data", []):
                    sha256_hash = sample.get("sha256_hash", "")
                    if not sha256_hash:
                        continue

                    # Build context
                    context = {
                        "first_seen": sample.get("first_seen"),
                        "last_seen": sample.get("last_seen"),
                        "file_name": sample.get("file_name"),
                        "file_type": sample.get("file_type"),
                        "file_size": sample.get("file_size"),
                        "signature": sample.get("signature"),
                        "tags": sample.get("tags", []),
                        "reporter": sample.get("reporter"),
                        "origin_country": sample.get("origin_country"),
                        "intelligence": sample.get("intelligence", {}),
                    }

                    # Check if hash already exists
                    existing = self.db.query(ThreatIntel).filter(
                        and_(
                            ThreatIntel.source == "malware_bazaar",
                            ThreatIntel.ioc_value == sha256_hash
                        )
                    ).first()

                    if existing:
                        existing.last_seen = datetime.utcnow()
                        existing.context = context
                    else:
                        new_ioc = ThreatIntel(
                            source="malware_bazaar",
                            ioc_type="hash",
                            ioc_value=sha256_hash,
                            context=context,
                            confidence_score=85,
                            tags=sample.get("tags", [])
                        )
                        self.db.add(new_ioc)

                    count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} samples from MalwareBazaar")

        except Exception as e:
            logger.error(f"Error ingesting MalwareBazaar data: {e}")
            self.db.rollback()

        return count

    async def ingest_feodo_tracker(self) -> int:
        """Ingest botnet C2 servers from Feodo Tracker (Abuse.ch).

        Returns:
            Number of C2 IPs ingested
        """
        logger.info("Ingesting Feodo Tracker C2 servers")

        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                for entry in data:
                    ip_address = entry.get("ip_address", "")
                    if not ip_address:
                        continue

                    # Build context
                    context = {
                        "first_seen": entry.get("first_seen"),
                        "last_online": entry.get("last_online"),
                        "malware": entry.get("malware"),
                        "status": entry.get("status"),
                        "as_number": entry.get("as_number"),
                        "as_name": entry.get("as_name"),
                        "country": entry.get("country"),
                    }

                    # Check if IP already exists
                    existing = self.db.query(ThreatIntel).filter(
                        and_(
                            ThreatIntel.source == "feodo_tracker",
                            ThreatIntel.ioc_value == ip_address
                        )
                    ).first()

                    malware_family = entry.get("malware", "")
                    tags = ["c2", "botnet"]
                    if malware_family:
                        tags.append(malware_family.lower())

                    if existing:
                        existing.last_seen = datetime.utcnow()
                        existing.context = context
                        existing.tags = tags
                    else:
                        new_ioc = ThreatIntel(
                            source="feodo_tracker",
                            ioc_type="ip",
                            ioc_value=ip_address,
                            context=context,
                            confidence_score=90,
                            tags=tags
                        )
                        self.db.add(new_ioc)

                    count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} C2 IPs from Feodo Tracker")

        except Exception as e:
            logger.error(f"Error ingesting Feodo Tracker data: {e}")
            self.db.rollback()

        return count

    async def ingest_sslbl(self) -> int:
        """Ingest malicious SSL certificates from SSL Blacklist (Abuse.ch).

        Returns:
            Number of SSL cert fingerprints ingested
        """
        logger.info("Ingesting SSL Blacklist certificates")

        url = "https://sslbl.abuse.ch/blacklist/sslblacklist.json"
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                for entry in data:
                    sha1_fingerprint = entry.get("sha1_hash", "")
                    if not sha1_fingerprint:
                        continue

                    # Build context
                    context = {
                        "listing_date": entry.get("listing_date"),
                        "listing_reason": entry.get("listing_reason"),
                        "subject_common_name": entry.get("subject_common_name"),
                        "issuer_common_name": entry.get("issuer_common_name"),
                        "destination_ip": entry.get("dst_ip"),
                        "destination_port": entry.get("dst_port"),
                    }

                    # Check if cert already exists
                    existing = self.db.query(ThreatIntel).filter(
                        and_(
                            ThreatIntel.source == "sslbl",
                            ThreatIntel.ioc_value == sha1_fingerprint
                        )
                    ).first()

                    if existing:
                        existing.last_seen = datetime.utcnow()
                        existing.context = context
                    else:
                        new_ioc = ThreatIntel(
                            source="sslbl",
                            ioc_type="hash",  # SSL cert fingerprint
                            ioc_value=sha1_fingerprint,
                            context=context,
                            confidence_score=85,
                            tags=["ssl", "c2"]
                        )
                        self.db.add(new_ioc)

                    count += 1

                    # Also ingest destination IP if present
                    dst_ip = entry.get("dst_ip")
                    if dst_ip:
                        existing_ip = self.db.query(ThreatIntel).filter(
                            and_(
                                ThreatIntel.source == "sslbl",
                                ThreatIntel.ioc_value == dst_ip
                            )
                        ).first()

                        ip_context = {
                            "related_cert": sha1_fingerprint,
                            "port": entry.get("dst_port"),
                        }

                        if not existing_ip:
                            ip_ioc = ThreatIntel(
                                source="sslbl",
                                ioc_type="ip",
                                ioc_value=dst_ip,
                                context=ip_context,
                                confidence_score=85,
                                tags=["c2", "ssl"]
                            )
                            self.db.add(ip_ioc)
                            count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} items from SSL Blacklist")

        except Exception as e:
            logger.error(f"Error ingesting SSL Blacklist data: {e}")
            self.db.rollback()

        return count

    async def ingest_urlscan(self, limit: int = 100) -> int:
        """Ingest malicious URLs from URLScan.io.

        Args:
            limit: Maximum number of results to retrieve

        Returns:
            Number of URLs ingested
        """
        logger.info(f"Ingesting URLScan.io results (limit: {limit})")

        base_url = "https://urlscan.io/api/v1"
        count = 0

        headers = {}
        if settings.URLSCAN_API_KEY:
            headers["API-Key"] = settings.URLSCAN_API_KEY

        try:
            async with httpx.AsyncClient() as client:
                # Search for malicious URLs
                url = f"{base_url}/search/"
                params = {
                    "q": "verdict:malicious",
                    "size": min(limit, 10000)
                }

                response = await client.get(url, headers=headers, params=params, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                for result in data.get("results", []):
                    page_url = result.get("page", {}).get("url", "")
                    if not page_url:
                        continue

                    task = result.get("task", {})
                    page = result.get("page", {})
                    verdicts = result.get("verdicts", {})

                    # Build context
                    context = {
                        "uuid": task.get("uuid"),
                        "time": task.get("time"),
                        "domain": page.get("domain"),
                        "ip": page.get("ip"),
                        "country": page.get("country"),
                        "server": page.get("server"),
                        "asn": page.get("asn"),
                        "asnname": page.get("asnname"),
                        "overall_verdict": verdicts.get("overall", {}).get("score"),
                        "malicious_score": verdicts.get("overall", {}).get("malicious"),
                        "categories": verdicts.get("overall", {}).get("categories", []),
                        "brands": verdicts.get("overall", {}).get("brands", []),
                        "tags": verdicts.get("overall", {}).get("tags", []),
                    }

                    # Calculate confidence from verdict score
                    verdict_score = verdicts.get("overall", {}).get("score", 0) or 0
                    confidence = min(100, max(50, verdict_score))

                    # Check if URL already exists
                    existing = self.db.query(ThreatIntel).filter(
                        and_(
                            ThreatIntel.source == "urlscan",
                            ThreatIntel.ioc_value == page_url
                        )
                    ).first()

                    if existing:
                        existing.last_seen = datetime.utcnow()
                        existing.context = context
                        existing.confidence_score = confidence
                    else:
                        new_ioc = ThreatIntel(
                            source="urlscan",
                            ioc_type="url",
                            ioc_value=page_url,
                            context=context,
                            confidence_score=confidence,
                            tags=verdicts.get("overall", {}).get("tags", [])
                        )
                        self.db.add(new_ioc)

                    count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} URLs from URLScan.io")

        except Exception as e:
            logger.error(f"Error ingesting URLScan.io data: {e}")
            self.db.rollback()

        return count

    async def ingest_pulsedive(self, risk: str = "high") -> int:
        """Ingest threat intelligence from Pulsedive.

        Args:
            risk: Risk level filter (high, medium, low)

        Returns:
            Number of IOCs ingested
        """
        if not settings.PULSEDIVE_API_KEY:
            logger.warning("PULSEDIVE_API_KEY not configured, skipping Pulsedive ingestion")
            return 0

        logger.info(f"Ingesting Pulsedive IOCs with risk: {risk}")

        base_url = "https://pulsedive.com/api"
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                # Get recent indicators
                url = f"{base_url}/explore.php"
                params = {
                    "key": settings.PULSEDIVE_API_KEY,
                    "risk": risk,
                    "limit": 1000
                }

                response = await client.get(url, params=params, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                for indicator in data.get("results", []):
                    ioc_value = indicator.get("indicator", "")
                    ioc_type = indicator.get("type", "").lower()

                    if not ioc_value:
                        continue

                    # Build context
                    context = {
                        "risk": indicator.get("risk"),
                        "risk_recommended": indicator.get("riskrecommended"),
                        "manualrisk": indicator.get("manualrisk"),
                        "retired": indicator.get("retired"),
                        "stamp_linked": indicator.get("stamp_linked"),
                        "stamp_seen": indicator.get("stamp_seen"),
                        "stamp_added": indicator.get("stamp_added"),
                        "properties": indicator.get("properties", []),
                        "threats": indicator.get("threats", []),
                        "feeds": indicator.get("feeds", []),
                    }

                    # Map risk to confidence
                    risk_map = {"critical": 95, "high": 85, "medium": 70, "low": 50, "none": 30}
                    confidence = risk_map.get(indicator.get("risk", "").lower(), 60)

                    # Check if IOC already exists
                    existing = self.db.query(ThreatIntel).filter(
                        and_(
                            ThreatIntel.source == "pulsedive",
                            ThreatIntel.ioc_value == ioc_value
                        )
                    ).first()

                    if existing:
                        existing.last_seen = datetime.utcnow()
                        existing.context = context
                        existing.confidence_score = confidence
                    else:
                        new_ioc = ThreatIntel(
                            source="pulsedive",
                            ioc_type=ioc_type,
                            ioc_value=ioc_value,
                            context=context,
                            confidence_score=confidence,
                            tags=indicator.get("properties", [])
                        )
                        self.db.add(new_ioc)

                    count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} IOCs from Pulsedive")

        except Exception as e:
            logger.error(f"Error ingesting Pulsedive data: {e}")
            self.db.rollback()

        return count

    async def ingest_blocklist_de(self) -> int:
        """Ingest brute force IPs from Blocklist.de.

        Returns:
            Number of IPs ingested
        """
        logger.info("Ingesting Blocklist.de IPs")

        # Different blocklists for different services
        blocklists = {
            "ssh": "https://lists.blocklist.de/lists/ssh.txt",
            "mail": "https://lists.blocklist.de/lists/mail.txt",
            "apache": "https://lists.blocklist.de/lists/apache.txt",
            "ftp": "https://lists.blocklist.de/lists/ftp.txt",
        }

        count = 0

        try:
            async with httpx.AsyncClient() as client:
                for service, url in blocklists.items():
                    try:
                        response = await client.get(url, timeout=30.0)
                        response.raise_for_status()

                        for line in response.text.splitlines():
                            line = line.strip()
                            # Skip comments and empty lines
                            if not line or line.startswith("#"):
                                continue

                            ip_address = line

                            # Build context
                            context = {
                                "service": service,
                                "attack_type": "brute_force",
                            }

                            # Check if IP already exists from this source
                            existing = self.db.query(ThreatIntel).filter(
                                and_(
                                    ThreatIntel.source == "blocklist_de",
                                    ThreatIntel.ioc_value == ip_address
                                )
                            ).first()

                            if existing:
                                # Update context to include multiple services if applicable
                                existing_services = existing.context.get("services", [service])
                                if service not in existing_services:
                                    existing_services.append(service)
                                existing.context["services"] = existing_services
                                existing.last_seen = datetime.utcnow()
                            else:
                                new_ioc = ThreatIntel(
                                    source="blocklist_de",
                                    ioc_type="ip",
                                    ioc_value=ip_address,
                                    context={"services": [service], "attack_type": "brute_force"},
                                    confidence_score=80,
                                    tags=["brute_force", service]
                                )
                                self.db.add(new_ioc)

                            count += 1

                    except Exception as e:
                        logger.warning(f"Error fetching {service} blocklist: {e}")
                        continue

                self.db.commit()
                logger.info(f"Successfully ingested {count} IPs from Blocklist.de")

        except Exception as e:
            logger.error(f"Error ingesting Blocklist.de data: {e}")
            self.db.rollback()

        return count

    async def ingest_spamhaus_drop(self) -> int:
        """Ingest netblocks from Spamhaus DROP and EDROP lists.

        Returns:
            Number of netblocks ingested
        """
        logger.info("Ingesting Spamhaus DROP/EDROP lists")

        lists = {
            "drop": "https://www.spamhaus.org/drop/drop.txt",
            "edrop": "https://www.spamhaus.org/drop/edrop.txt",
        }

        count = 0

        try:
            async with httpx.AsyncClient() as client:
                for list_type, url in lists.items():
                    try:
                        response = await client.get(url, timeout=30.0)
                        response.raise_for_status()

                        for line in response.text.splitlines():
                            line = line.strip()
                            # Skip comments and empty lines
                            if not line or line.startswith(";"):
                                continue

                            # Format: CIDR ; SBL number
                            parts = line.split(";")
                            if not parts:
                                continue

                            netblock = parts[0].strip()
                            sbl_ref = parts[1].strip() if len(parts) > 1 else ""

                            # Build context
                            context = {
                                "list_type": list_type.upper(),
                                "sbl_reference": sbl_ref,
                                "description": "Spamhaus Don't Route Or Peer netblock",
                            }

                            # Check if netblock already exists
                            existing = self.db.query(ThreatIntel).filter(
                                and_(
                                    ThreatIntel.source == "spamhaus_drop",
                                    ThreatIntel.ioc_value == netblock
                                )
                            ).first()

                            if existing:
                                existing.last_seen = datetime.utcnow()
                                existing.context = context
                            else:
                                new_ioc = ThreatIntel(
                                    source="spamhaus_drop",
                                    ioc_type="ip",  # CIDR netblock
                                    ioc_value=netblock,
                                    context=context,
                                    confidence_score=95,
                                    tags=["spam", "hijacked", list_type]
                                )
                                self.db.add(new_ioc)

                            count += 1

                    except Exception as e:
                        logger.warning(f"Error fetching {list_type} list: {e}")
                        continue

                self.db.commit()
                logger.info(f"Successfully ingested {count} netblocks from Spamhaus DROP")

        except Exception as e:
            logger.error(f"Error ingesting Spamhaus DROP data: {e}")
            self.db.rollback()

        return count

    async def ingest_misp(self, instance_url: Optional[str] = None, api_key: Optional[str] = None, days: int = 7) -> int:
        """Ingest threat intelligence from MISP instance.

        Args:
            instance_url: MISP instance URL (defaults to settings.MISP_URL)
            api_key: MISP API key (defaults to settings.MISP_API_KEY)
            days: Number of days to look back

        Returns:
            Number of IOCs ingested
        """
        misp_url = instance_url or settings.MISP_URL
        misp_key = api_key or settings.MISP_API_KEY

        if not misp_url or not misp_key:
            logger.warning("MISP_URL or MISP_API_KEY not configured, skipping MISP ingestion")
            return 0

        logger.info(f"Ingesting MISP events from {misp_url}")

        headers = {
            "Authorization": misp_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                # Get recent events
                url = f"{misp_url}/events/restSearch"
                payload = {
                    "returnFormat": "json",
                    "publish_timestamp": (datetime.utcnow() - timedelta(days=days)).timestamp(),
                    "published": True
                }

                response = await client.post(url, headers=headers, json=payload, timeout=60.0)
                response.raise_for_status()
                data = response.json()

                for event_wrapper in data.get("response", []):
                    event = event_wrapper.get("Event", {})
                    event_info = event.get("info", "")
                    event_id = event.get("id", "")

                    # Extract MITRE techniques from event tags
                    techniques = []
                    for tag in event.get("Tag", []):
                        tag_name = tag.get("name", "")
                        if "mitre-attack-pattern" in tag_name:
                            # Extract technique ID from tag
                            parts = tag_name.split(":")
                            if len(parts) > 1:
                                tech_id = parts[-1].strip('"')
                                techniques.append(tech_id)

                    # Process attributes (IOCs)
                    for attribute in event.get("Attribute", []):
                        ioc_type = attribute.get("type", "").lower()
                        ioc_value = attribute.get("value", "")

                        if not ioc_value:
                            continue

                        # Map MISP types to our IOC types
                        type_mapping = {
                            "md5": "hash",
                            "sha1": "hash",
                            "sha256": "hash",
                            "domain": "domain",
                            "hostname": "domain",
                            "ip-src": "ip",
                            "ip-dst": "ip",
                            "url": "url",
                            "email-src": "email",
                            "email-dst": "email",
                        }

                        mapped_type = type_mapping.get(ioc_type, "other")
                        if mapped_type == "other":
                            continue

                        # Build context
                        context = {
                            "misp_event_id": event_id,
                            "misp_event_info": event_info,
                            "threat_level": event.get("threat_level_id"),
                            "analysis": event.get("analysis"),
                            "category": attribute.get("category"),
                            "comment": attribute.get("comment"),
                            "to_ids": attribute.get("to_ids"),
                            "timestamp": attribute.get("timestamp"),
                        }

                        # Check if IOC already exists
                        existing = self.db.query(ThreatIntel).filter(
                            and_(
                                ThreatIntel.source == "misp",
                                ThreatIntel.ioc_value == ioc_value
                            )
                        ).first()

                        # Map threat level to confidence
                        threat_level_map = {1: 95, 2: 75, 3: 50, 4: 30}  # 1=High, 2=Med, 3=Low, 4=Undefined
                        confidence = threat_level_map.get(event.get("threat_level_id", 4), 50)

                        if existing:
                            existing.last_seen = datetime.utcnow()
                            existing.context = context
                            existing.associated_techniques = techniques
                            existing.confidence_score = confidence
                        else:
                            new_ioc = ThreatIntel(
                                source="misp",
                                ioc_type=mapped_type,
                                ioc_value=ioc_value,
                                context=context,
                                associated_techniques=techniques,
                                confidence_score=confidence,
                                tags=[attribute.get("category", "")]
                            )
                            self.db.add(new_ioc)

                        count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} IOCs from MISP")

        except Exception as e:
            logger.error(f"Error ingesting MISP data: {e}")
            self.db.rollback()

        return count

    async def ingest_opencti(self, instance_url: Optional[str] = None, api_key: Optional[str] = None, limit: int = 100) -> int:
        """Ingest threat intelligence from OpenCTI instance.

        Args:
            instance_url: OpenCTI instance URL (defaults to settings.OPENCTI_URL)
            api_key: OpenCTI API key (defaults to settings.OPENCTI_API_KEY)
            limit: Maximum number of indicators to retrieve

        Returns:
            Number of IOCs ingested
        """
        opencti_url = instance_url or settings.OPENCTI_URL
        opencti_key = api_key or settings.OPENCTI_API_KEY

        if not opencti_url or not opencti_key:
            logger.warning("OPENCTI_URL or OPENCTI_API_KEY not configured, skipping OpenCTI ingestion")
            return 0

        logger.info(f"Ingesting OpenCTI indicators from {opencti_url}")

        headers = {
            "Authorization": f"Bearer {opencti_key}",
            "Content-Type": "application/json"
        }
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                # GraphQL query for indicators
                url = f"{opencti_url}/graphql"
                query = """
                query GetIndicators($first: Int!) {
                    indicators(first: $first, orderBy: created_at, orderMode: desc) {
                        edges {
                            node {
                                id
                                pattern
                                pattern_type
                                name
                                description
                                indicator_types
                                confidence
                                created_at
                                modified_at
                                objectLabel {
                                    edges {
                                        node {
                                            value
                                        }
                                    }
                                }
                                killChainPhases {
                                    edges {
                                        node {
                                            kill_chain_name
                                            phase_name
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                """
                variables = {"first": limit}

                response = await client.post(
                    url,
                    headers=headers,
                    json={"query": query, "variables": variables},
                    timeout=60.0
                )
                response.raise_for_status()
                data = response.json()

                for edge in data.get("data", {}).get("indicators", {}).get("edges", []):
                    node = edge.get("node", {})
                    pattern = node.get("pattern", "")
                    pattern_type = node.get("pattern_type", "")

                    # Parse STIX pattern to extract IOC
                    # Simple extraction for common patterns like [ipv4-addr:value = '1.2.3.4']
                    ioc_value = ""
                    ioc_type = "other"

                    if "ipv4-addr:value" in pattern or "ipv6-addr:value" in pattern:
                        ioc_type = "ip"
                        # Extract IP from pattern
                        import re
                        match = re.search(r"= '([^']+)'", pattern)
                        if match:
                            ioc_value = match.group(1)
                    elif "domain-name:value" in pattern:
                        ioc_type = "domain"
                        import re
                        match = re.search(r"= '([^']+)'", pattern)
                        if match:
                            ioc_value = match.group(1)
                    elif "url:value" in pattern:
                        ioc_type = "url"
                        import re
                        match = re.search(r"= '([^']+)'", pattern)
                        if match:
                            ioc_value = match.group(1)
                    elif "file:hashes" in pattern:
                        ioc_type = "hash"
                        import re
                        match = re.search(r"= '([^']+)'", pattern)
                        if match:
                            ioc_value = match.group(1)

                    if not ioc_value or ioc_type == "other":
                        continue

                    # Extract labels/tags
                    tags = []
                    for label_edge in node.get("objectLabel", {}).get("edges", []):
                        label_value = label_edge.get("node", {}).get("value", "")
                        if label_value:
                            tags.append(label_value)

                    # Build context
                    context = {
                        "opencti_id": node.get("id"),
                        "name": node.get("name"),
                        "description": node.get("description"),
                        "indicator_types": node.get("indicator_types", []),
                        "pattern": pattern,
                        "pattern_type": pattern_type,
                        "created_at": node.get("created_at"),
                        "modified_at": node.get("modified_at"),
                        "kill_chain_phases": [
                            {
                                "kill_chain": kc.get("node", {}).get("kill_chain_name"),
                                "phase": kc.get("node", {}).get("phase_name")
                            }
                            for kc in node.get("killChainPhases", {}).get("edges", [])
                        ]
                    }

                    confidence = node.get("confidence", 50)

                    # Check if IOC already exists
                    existing = self.db.query(ThreatIntel).filter(
                        and_(
                            ThreatIntel.source == "opencti",
                            ThreatIntel.ioc_value == ioc_value
                        )
                    ).first()

                    if existing:
                        existing.last_seen = datetime.utcnow()
                        existing.context = context
                        existing.confidence_score = confidence
                        existing.tags = tags
                    else:
                        new_ioc = ThreatIntel(
                            source="opencti",
                            ioc_type=ioc_type,
                            ioc_value=ioc_value,
                            context=context,
                            confidence_score=confidence,
                            tags=tags
                        )
                        self.db.add(new_ioc)

                    count += 1

                self.db.commit()
                logger.info(f"Successfully ingested {count} IOCs from OpenCTI")

        except Exception as e:
            logger.error(f"Error ingesting OpenCTI data: {e}")
            self.db.rollback()

        return count

    async def ingest_rss_feeds(self, feeds: Optional[List[str]] = None) -> int:
        """Ingest threat intelligence from RSS/Atom feeds.

        Args:
            feeds: List of RSS feed URLs (defaults to predefined list)

        Returns:
            Number of items ingested
        """
        # Always use the allowed RSS feeds list as baseline
        allowed_feeds = [
            "https://www.cisa.gov/uscert/ncas/alerts.xml",
            "https://www.cisa.gov/uscert/ncas/current-activity.xml",
            "https://isc.sans.edu/rssfeed.xml",
            "https://www.bleepingcomputer.com/feed/",
            "https://krebsonsecurity.com/feed/",
            "https://threatpost.com/feed/",
        ]
        if feeds is None:
            feeds = allowed_feeds
        else:
            # Validate user-provided feeds against allowed list
            invalid_feeds = [url for url in feeds if url not in allowed_feeds]
            if invalid_feeds:
                logger.warning(f"Rejected untrusted RSS feed(s): {invalid_feeds}")
                # Optionally, skip invalid feeds, or raise an error to abort.
                # For this fix, filter and use only trusted feeds.
                feeds = [url for url in feeds if url in allowed_feeds]

        logger.info(f"Ingesting {len(feeds)} RSS feeds")
        count = 0

        try:
            async with httpx.AsyncClient() as client:
                for feed_url in feeds:
                    try:
                        response = await client.get(feed_url, timeout=30.0)
                        response.raise_for_status()

                        # Parse RSS/Atom feed
                        feed = feedparser.parse(response.text)

                        for entry in feed.entries[:50]:  # Limit to 50 most recent entries per feed
                            # Extract IOCs from entry title and summary using regex
                            import re
                            text = f"{entry.get('title', '')} {entry.get('summary', '')}"

                            # Extract IPs
                            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                            ips = re.findall(ip_pattern, text)

                            # Extract domains (simple pattern)
                            domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
                            domains = re.findall(domain_pattern, text)

                            # Extract CVEs
                            cve_pattern = r'CVE-\d{4}-\d{4,7}'
                            cves = re.findall(cve_pattern, text)

                            # Extract URLs
                            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
                            urls = re.findall(url_pattern, text)

                            # Store RSS entry as IOC with type "report"
                            context = {
                                "title": entry.get("title", ""),
                                "link": entry.get("link", ""),
                                "published": entry.get("published", ""),
                                "summary": entry.get("summary", "")[:500],  # Truncate long summaries
                                "feed_url": feed_url,
                                "extracted_ips": ips[:10],  # Limit extracted IOCs
                                "extracted_domains": domains[:10],
                                "extracted_cves": cves,
                                "extracted_urls": urls[:10],
                            }

                            # Use entry link as unique identifier
                            entry_link = entry.get("link", "")
                            if not entry_link:
                                continue

                            existing = self.db.query(ThreatIntel).filter(
                                and_(
                                    ThreatIntel.source == "rss_feed",
                                    ThreatIntel.ioc_value == entry_link
                                )
                            ).first()

                            if not existing:
                                new_ioc = ThreatIntel(
                                    source="rss_feed",
                                    ioc_type="report",  # Special type for threat reports
                                    ioc_value=entry_link,
                                    context=context,
                                    confidence_score=60,  # Lower confidence for RSS feeds
                                    tags=["rss", "threat_intel"]
                                )
                                self.db.add(new_ioc)
                                count += 1

                    except Exception as e:
                        logger.warning(f"Error processing RSS feed {feed_url}: {e}")
                        continue

                self.db.commit()
                logger.info(f"Successfully ingested {count} RSS feed items")

        except Exception as e:
            logger.error(f"Error ingesting RSS feeds: {e}")
            self.db.rollback()

        return count
