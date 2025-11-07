"""CVE correlation service for linking vulnerabilities with exploit activity and TTPs."""

import logging
import re
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import httpx
from sqlalchemy.orm import Session
from sqlalchemy import or_
from ..models.cve import CVE
from ..models.threat_intel import ThreatIntel
from ..models.mitre import MitreTechnique

logger = logging.getLogger(__name__)


class CVECorrelationService:
    """Service for correlating CVEs with exploits, IOCs, and MITRE techniques."""

    def __init__(self, db: Session):
        self.db = db

        # Common CVE-to-technique mappings (can be expanded)
        self.cve_technique_patterns = {
            "injection": ["T1190", "T1059"],  # Exploit Public-Facing, Command Execution
            "overflow": ["T1203"],  # Exploitation for Client Execution
            "authentication": ["T1078", "T1110"],  # Valid Accounts, Brute Force
            "privilege": ["T1068"],  # Exploitation for Privilege Escalation
            "bypass": ["T1211"],  # Exploitation for Defense Evasion
            "disclosure": ["T1005", "T1083"],  # Data from Local System, File Discovery
            "remote code execution": ["T1203", "T1190"],
            "sql injection": ["T1190"],
            "xss": ["T1189"],  # Drive-by Compromise
            "csrf": ["T1189"],
            "deserialization": ["T1203"],
        }

    async def correlate_cve_with_exploits(self, cve_id: str) -> Dict:
        """Correlate a CVE with known exploits and proof-of-concepts.

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)

        Returns:
            Dictionary with exploit correlation data
        """
        logger.info(f"Correlating {cve_id} with exploit data")

        cve = self.db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if not cve:
            logger.warning(f"CVE {cve_id} not found in database")
            return {"error": "CVE not found"}

        # Search for related IOCs mentioning this CVE
        related_iocs = self._find_related_iocs(cve_id)

        # Infer MITRE techniques from CVE description
        inferred_techniques = self._infer_techniques_from_description(
            cve.description or ""
        )

        # Check for exploit availability via GitHub (PoC search)
        exploit_repos = await self._search_github_exploits(cve_id)

        # Update CVE with findings
        if exploit_repos:
            cve.exploit_available = True

        if related_iocs:
            cve.exploited_in_wild = True

        if inferred_techniques and not cve.associated_techniques:
            cve.associated_techniques = inferred_techniques

        self.db.commit()

        return {
            "cve_id": cve_id,
            "related_iocs": len(related_iocs),
            "inferred_techniques": inferred_techniques,
            "exploit_repos_found": len(exploit_repos),
            "exploited_in_wild": cve.exploited_in_wild,
            "exploit_available": cve.exploit_available,
        }

    def _find_related_iocs(self, cve_id: str) -> List[ThreatIntel]:
        """Find IOCs that mention this CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            List of related ThreatIntel objects
        """
        # Search in context JSON for CVE mentions
        iocs = self.db.query(ThreatIntel).all()
        related = []

        for ioc in iocs:
            if ioc.context and isinstance(ioc.context, dict):
                # Convert context to string for searching
                context_str = str(ioc.context).lower()
                if cve_id.lower() in context_str:
                    related.append(ioc)

        return related

    def _infer_techniques_from_description(self, description: str) -> List[str]:
        """Infer MITRE techniques from CVE description using keyword matching.

        Args:
            description: CVE description text

        Returns:
            List of inferred technique IDs
        """
        if not description:
            return []

        description_lower = description.lower()
        techniques = set()

        # Check for keyword patterns
        for keyword, technique_ids in self.cve_technique_patterns.items():
            if keyword in description_lower:
                techniques.update(technique_ids)

        return list(techniques)

    async def _search_github_exploits(self, cve_id: str) -> List[Dict]:
        """Search GitHub for PoC exploits for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            List of repository information
        """
        try:
            async with httpx.AsyncClient() as client:
                # GitHub search API (no auth required for basic search)
                url = "https://api.github.com/search/repositories"
                params = {
                    "q": f"{cve_id} exploit OR poc",
                    "sort": "stars",
                    "order": "desc"
                }

                response = await client.get(url, params=params, timeout=10.0)
                if response.status_code == 200:
                    data = response.json()
                    repos = []
                    for item in data.get("items", [])[:5]:  # Top 5 results
                        repos.append({
                            "name": item.get("name"),
                            "url": item.get("html_url"),
                            "stars": item.get("stargazers_count"),
                            "description": item.get("description"),
                        })
                    return repos
        except Exception as e:
            logger.warning(f"Error searching GitHub for {cve_id}: {e}")

        return []

    async def correlate_all_cves(self, limit: Optional[int] = None) -> int:
        """Correlate all CVEs in database with exploits and techniques.

        Args:
            limit: Maximum number of CVEs to process (None for all)

        Returns:
            Number of CVEs correlated
        """
        logger.info("Starting bulk CVE correlation")

        query = self.db.query(CVE)
        if limit:
            query = query.limit(limit)

        cves = query.all()
        count = 0

        for cve in cves:
            try:
                await self.correlate_cve_with_exploits(cve.cve_id)
                count += 1
                if count % 10 == 0:
                    logger.info(f"Correlated {count} CVEs...")
            except Exception as e:
                logger.error(f"Error correlating {cve.cve_id}: {e}")
                continue

        logger.info(f"Completed correlation of {count} CVEs")
        return count

    def get_high_risk_cves(self, limit: int = 50) -> List[CVE]:
        """Get high-risk CVEs (exploited in wild or ransomware-used).

        Args:
            limit: Maximum number to return

        Returns:
            List of high-risk CVEs
        """
        return self.db.query(CVE).filter(
            or_(
                CVE.exploited_in_wild == True,
                CVE.ransomware_use == True
            )
        ).order_by(CVE.cvss_score.desc()).limit(limit).all()

    def get_cves_by_technique(self, technique_id: str) -> List[CVE]:
        """Get CVEs associated with a MITRE technique.

        Args:
            technique_id: MITRE ATT&CK technique ID

        Returns:
            List of CVEs
        """
        return self.db.query(CVE).filter(
            CVE.associated_techniques.contains([technique_id])
        ).all()

    def get_cves_requiring_remediation(self) -> List[CVE]:
        """Get CVEs requiring immediate remediation.

        Returns:
            List of CVEs with upcoming or past due remediation deadlines
        """
        now = datetime.utcnow()
        future = now + timedelta(days=30)

        return self.db.query(CVE).filter(
            CVE.remediation_required == True,
            CVE.remediation_deadline <= future
        ).order_by(CVE.remediation_deadline.asc()).all()

    async def enrich_cve_from_nvd(self, cve_id: str) -> bool:
        """Enrich CVE data from NVD API.

        Args:
            cve_id: CVE identifier

        Returns:
            True if enrichment successful
        """
        logger.info(f"Enriching {cve_id} from NVD")

        try:
            async with httpx.AsyncClient() as client:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                params = {"cveId": cve_id}

                response = await client.get(url, params=params, timeout=10.0)
                if response.status_code != 200:
                    return False

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    return False

                vuln_data = vulnerabilities[0].get("cve", {})

                # Get or create CVE
                cve = self.db.query(CVE).filter(CVE.cve_id == cve_id).first()
                if not cve:
                    cve = CVE(cve_id=cve_id)
                    self.db.add(cve)

                # Update with NVD data
                descriptions = vuln_data.get("descriptions", [])
                if descriptions:
                    cve.description = descriptions[0].get("value")

                # CVSS scores
                metrics = vuln_data.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    cve.cvss_score = cvss_data.get("baseScore")
                    cve.severity = cvss_data.get("baseSeverity")

                # Dates
                cve.published_date = datetime.fromisoformat(
                    vuln_data.get("published", "").replace("Z", "+00:00")
                )
                cve.last_modified = datetime.fromisoformat(
                    vuln_data.get("lastModified", "").replace("Z", "+00:00")
                )

                # References
                references = vuln_data.get("references", [])
                cve.references = [ref.get("url") for ref in references]

                self.db.commit()
                logger.info(f"Successfully enriched {cve_id} from NVD")
                return True

        except Exception as e:
            logger.error(f"Error enriching {cve_id} from NVD: {e}")
            return False
