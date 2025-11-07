"""TTP extraction service using NLP for extracting techniques from unstructured text."""

import logging
import re
from typing import List, Dict, Optional, Tuple
from sqlalchemy.orm import Session
from ..models.mitre import MitreTechnique
from ..models.threat_intel import ThreatIntel
from ..models.ioc_enrichment import IOCEnrichment

logger = logging.getLogger(__name__)


class TTPExtractionService:
    """Service for extracting MITRE ATT&CK techniques from unstructured text using NLP."""

    def __init__(self, db: Session):
        self.db = db
        self._load_techniques()
        self._build_keyword_mappings()

    def _load_techniques(self):
        """Load all MITRE techniques from database for reference."""
        techniques = self.db.query(MitreTechnique).all()
        self.techniques_by_id = {t.technique_id: t for t in techniques}
        self.techniques_by_name = {t.name.lower(): t for t in techniques}

    def _build_keyword_mappings(self):
        """Build keyword-to-technique mappings for extraction."""
        self.keyword_mappings = {
            # Command Execution
            "powershell": ["T1059.001"],
            "cmd.exe": ["T1059.003"],
            "bash": ["T1059.004"],
            "python script": ["T1059.006"],
            "javascript": ["T1059.007"],

            # Credential Access
            "credential dump": ["T1003"],
            "lsass": ["T1003.001"],
            "mimikatz": ["T1003"],
            "password spray": ["T1110.003"],
            "brute force": ["T1110"],
            "keylog": ["T1056.001"],

            # Persistence
            "scheduled task": ["T1053.005"],
            "registry run": ["T1547.001"],
            "startup folder": ["T1547.001"],
            "service creation": ["T1543.003"],
            "dll hijack": ["T1574.001"],

            # Defense Evasion
            "obfuscat": ["T1027"],
            "disable av": ["T1562.001"],
            "disable firewall": ["T1562.004"],
            "process injection": ["T1055"],
            "reflective dll": ["T1055.001"],

            # Discovery
            "network scan": ["T1046"],
            "port scan": ["T1046"],
            "enumerate": ["T1087"],
            "whoami": ["T1033"],
            "ipconfig": ["T1016"],

            # Lateral Movement
            "rdp": ["T1021.001"],
            "ssh": ["T1021.004"],
            "psexec": ["T1021.002"],
            "wmi": ["T1047"],
            "pass the hash": ["T1550.002"],

            # Collection
            "screen capture": ["T1113"],
            "clipboard": ["T1115"],
            "archive": ["T1560"],

            # Exfiltration
            "exfiltrat": ["T1041"],
            "data transfer": ["T1041"],
            "cloud storage": ["T1567.002"],

            # Impact
            "ransomware": ["T1486"],
            "encrypt": ["T1486"],
            "delete": ["T1485"],
            "wiper": ["T1485"],
        }

    def extract_techniques_from_text(
        self, text: str, confidence_threshold: float = 0.5
    ) -> List[Tuple[str, float]]:
        """Extract MITRE techniques from unstructured text.

        Args:
            text: Text to analyze (threat report, blog post, etc.)
            confidence_threshold: Minimum confidence for extraction (0-1)

        Returns:
            List of tuples (technique_id, confidence_score)
        """
        if not text:
            return []

        text_lower = text.lower()
        extracted = {}

        # Method 1: Direct technique ID matching (highest confidence)
        technique_ids = re.findall(r'\bT\d{4}(?:\.\d{3})?\b', text, re.IGNORECASE)
        for tid in technique_ids:
            tid_upper = tid.upper()
            if tid_upper in self.techniques_by_id:
                extracted[tid_upper] = 1.0  # Highest confidence

        # Method 2: Technique name matching (high confidence)
        for name, technique in self.techniques_by_name.items():
            if name in text_lower and len(name) > 5:  # Avoid very short names
                extracted[technique.technique_id] = 0.9

        # Method 3: Keyword matching (medium confidence)
        for keyword, technique_ids in self.keyword_mappings.items():
            if keyword in text_lower:
                for tid in technique_ids:
                    if tid not in extracted:
                        extracted[tid] = 0.7

        # Method 4: Behavioral pattern matching (lower confidence)
        behavioral_patterns = self._extract_behavioral_patterns(text_lower)
        for tid, confidence in behavioral_patterns:
            if tid not in extracted:
                extracted[tid] = confidence

        # Filter by confidence threshold and sort
        results = [
            (tid, conf) for tid, conf in extracted.items()
            if conf >= confidence_threshold
        ]
        results.sort(key=lambda x: x[1], reverse=True)

        return results

    def _extract_behavioral_patterns(self, text: str) -> List[Tuple[str, float]]:
        """Extract techniques based on behavioral descriptions.

        Args:
            text: Lowercase text to analyze

        Returns:
            List of tuples (technique_id, confidence_score)
        """
        patterns = []

        # File operations suggesting specific techniques
        if re.search(r'creat.*\.exe|drop.*file|write.*disk', text):
            patterns.append(("T1105", 0.6))  # Ingress Tool Transfer

        # Network patterns
        if re.search(r'c2|command.{1,10}control|beacon|callback', text):
            patterns.append(("T1071", 0.6))  # Application Layer Protocol

        # Execution patterns
        if re.search(r'execute|run|launch|spawn', text):
            if 'remote' in text:
                patterns.append(("T1203", 0.6))  # Exploitation for Client Execution
            else:
                patterns.append(("T1106", 0.5))  # Native API

        # Privilege patterns
        if re.search(r'elevat.*privilege|gain.*admin|uac bypass', text):
            patterns.append(("T1068", 0.7))  # Exploitation for Privilege Escalation

        # Persistence indicators
        if re.search(r'persist|maintain.{1,10}access|backdoor', text):
            patterns.append(("T1547", 0.5))  # Boot or Logon Autostart

        return patterns

    def enrich_ioc_with_ttps(self, ioc_value: str) -> Optional[IOCEnrichment]:
        """Extract and add TTPs to an IOC's enrichment data.

        Args:
            ioc_value: IOC value to enrich

        Returns:
            Updated IOCEnrichment object
        """
        # Get the IOC
        ioc = self.db.query(ThreatIntel).filter(
            ThreatIntel.ioc_value == ioc_value
        ).first()

        if not ioc:
            return None

        # Get or create enrichment
        enrichment = self.db.query(IOCEnrichment).filter(
            IOCEnrichment.ioc_value == ioc_value
        ).first()

        if not enrichment:
            logger.warning(f"No enrichment found for {ioc_value}")
            return None

        # Extract text from IOC context
        context_text = ""
        if ioc.context:
            # Combine relevant context fields
            for key in ["description", "pulse_name", "short_description", "threat"]:
                if key in ioc.context and ioc.context[key]:
                    context_text += f" {ioc.context[key]}"

        if not context_text:
            return enrichment

        # Extract TTPs
        extracted_ttps = self.extract_techniques_from_text(context_text)

        if extracted_ttps:
            # Update enrichment
            enrichment.extracted_ttps = [
                {"technique_id": tid, "confidence": conf}
                for tid, conf in extracted_ttps
            ]

            # Calculate average confidence
            avg_confidence = sum(conf for _, conf in extracted_ttps) / len(extracted_ttps)
            enrichment.extraction_confidence = avg_confidence

            # Add to associated techniques if confidence is high
            for tid, conf in extracted_ttps:
                if conf >= 0.7:  # High confidence threshold
                    if tid not in (enrichment.associated_techniques or []):
                        if enrichment.associated_techniques:
                            enrichment.associated_techniques.append(tid)
                        else:
                            enrichment.associated_techniques = [tid]

            self.db.commit()
            logger.info(f"Enriched {ioc_value} with {len(extracted_ttps)} TTPs")

        return enrichment

    def extract_ttps_from_report(self, report_text: str, report_metadata: Optional[Dict] = None) -> Dict:
        """Extract comprehensive TTP analysis from a threat report.

        Args:
            report_text: Full text of the threat report
            report_metadata: Optional metadata (title, author, date, etc.)

        Returns:
            Dictionary with extracted TTPs and analysis
        """
        # Extract techniques
        techniques = self.extract_techniques_from_text(report_text)

        # Group by tactic
        tactics_map = {}
        for tid, confidence in techniques:
            technique = self.techniques_by_id.get(tid)
            if technique and technique.tactics:
                for tactic in technique.tactics:
                    if tactic not in tactics_map:
                        tactics_map[tactic] = []
                    tactics_map[tactic].append({
                        "technique_id": tid,
                        "technique_name": technique.name,
                        "confidence": confidence
                    })

        # Extract behavioral tags
        behavioral_tags = self._extract_behavioral_tags(report_text)

        # Identify kill chain phases
        kill_chain_phases = self._identify_kill_chain_phases(techniques)

        return {
            "techniques": [
                {
                    "technique_id": tid,
                    "technique_name": self.techniques_by_id.get(tid, {}).name if tid in self.techniques_by_id else "Unknown",
                    "confidence": confidence
                }
                for tid, confidence in techniques
            ],
            "tactics": tactics_map,
            "behavioral_tags": behavioral_tags,
            "kill_chain_phases": kill_chain_phases,
            "metadata": report_metadata or {},
            "summary": {
                "total_techniques": len(techniques),
                "high_confidence_count": sum(1 for _, c in techniques if c >= 0.8),
                "tactics_covered": list(tactics_map.keys())
            }
        }

    def _extract_behavioral_tags(self, text: str) -> List[str]:
        """Extract behavioral tags from text.

        Args:
            text: Text to analyze

        Returns:
            List of behavioral tags
        """
        tags = []
        text_lower = text.lower()

        tag_keywords = {
            "credential_theft": ["credential", "password", "lsass", "mimikatz"],
            "lateral_movement": ["lateral", "rdp", "psexec", "smb"],
            "data_exfiltration": ["exfiltrat", "upload", "transfer", "steal"],
            "ransomware": ["ransomware", "encrypt", "ransom"],
            "c2_communication": ["c2", "command and control", "beacon"],
            "defense_evasion": ["evade", "bypass", "disable av", "obfuscate"],
            "reconnaissance": ["scan", "enumerate", "discover", "recon"],
        }

        for tag, keywords in tag_keywords.items():
            if any(kw in text_lower for kw in keywords):
                tags.append(tag)

        return tags

    def _identify_kill_chain_phases(self, techniques: List[Tuple[str, float]]) -> List[str]:
        """Identify Lockheed Martin Cyber Kill Chain phases from techniques.

        Args:
            techniques: List of (technique_id, confidence) tuples

        Returns:
            List of kill chain phases
        """
        # Map tactics to kill chain phases
        tactic_to_killchain = {
            "Reconnaissance": "reconnaissance",
            "Resource Development": "weaponization",
            "Initial Access": "delivery",
            "Execution": "exploitation",
            "Persistence": "installation",
            "Privilege Escalation": "installation",
            "Defense Evasion": "installation",
            "Credential Access": "actions_on_objectives",
            "Discovery": "actions_on_objectives",
            "Lateral Movement": "actions_on_objectives",
            "Collection": "actions_on_objectives",
            "Command and Control": "command_and_control",
            "Exfiltration": "actions_on_objectives",
            "Impact": "actions_on_objectives",
        }

        phases = set()
        for tid, _ in techniques:
            technique = self.techniques_by_id.get(tid)
            if technique and technique.tactics:
                for tactic in technique.tactics:
                    if tactic in tactic_to_killchain:
                        phases.add(tactic_to_killchain[tactic])

        return sorted(list(phases))

    def bulk_enrich_iocs(self, limit: Optional[int] = None) -> int:
        """Enrich multiple IOCs with TTP extraction.

        Args:
            limit: Maximum number of IOCs to process

        Returns:
            Number of IOCs enriched
        """
        query = self.db.query(ThreatIntel)
        if limit:
            query = query.limit(limit)

        iocs = query.all()
        count = 0

        for ioc in iocs:
            try:
                self.enrich_ioc_with_ttps(ioc.ioc_value)
                count += 1
                if count % 50 == 0:
                    logger.info(f"TTP extraction: processed {count} IOCs...")
            except Exception as e:
                logger.error(f"Error extracting TTPs for {ioc.ioc_value}: {e}")
                continue

        logger.info(f"Completed TTP extraction for {count} IOCs")
        return count
