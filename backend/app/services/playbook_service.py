"""Threat actor playbook service."""

from typing import List, Dict, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from ..models import ThreatActorPlaybook, PlaybookExecution, HuntCampaign, ThreatActor
from .enhanced_query_generator import EnhancedQueryGenerator


class PlaybookService:
    """Manage and execute threat actor playbooks."""

    # Pre-built playbooks for known threat actors
    KNOWN_PLAYBOOKS = {
        "APT29": {
            "aliases": ["Cozy Bear", "The Dukes", "YTTRIUM"],
            "description": "Russian state-sponsored APT targeting government, diplomatic, and energy sectors",
            "techniques": [
                "T1566.001",  # Spearphishing Attachment
                "T1059.001",  # PowerShell
                "T1053.005",  # Scheduled Task
                "T1071.001",  # Web Protocols
                "T1003.001",  # LSASS Memory
                "T1021.002",  # SMB/Windows Admin Shares
                "T1547.001",  # Registry Run Keys
            ],
            "techniques_timeline": [
                {
                    "phase": "Initial Access",
                    "techniques": ["T1566.001"],
                    "description": "Spearphishing campaigns with malicious attachments"
                },
                {
                    "phase": "Execution",
                    "techniques": ["T1059.001", "T1059.003"],
                    "description": "PowerShell and WMI for execution"
                },
                {
                    "phase": "Persistence",
                    "techniques": ["T1053.005", "T1547.001"],
                    "description": "Scheduled tasks and registry persistence"
                },
                {
                    "phase": "Credential Access",
                    "techniques": ["T1003.001", "T1003.002"],
                    "description": "Credential dumping via LSASS and Security Hive"
                },
                {
                    "phase": "Lateral Movement",
                    "techniques": ["T1021.002"],
                    "description": "SMB and WMI for lateral movement"
                },
                {
                    "phase": "Command and Control",
                    "techniques": ["T1071.001", "T1573.001"],
                    "description": "HTTP/HTTPS C2 with encryption"
                }
            ],
            "target_industries": ["Government", "Defense", "Energy", "Healthcare"],
            "target_countries": ["USA", "UK", "Ukraine", "EU Nations"],
            "tools": ["WellMess", "WellMail", "Sunburst", "TEARDROP", "Cobalt Strike"],
            "campaigns": ["SolarWinds Supply Chain", "COVID-19 Vaccine Research"],
            "confidence": "high"
        },
        "Lazarus Group": {
            "aliases": ["HIDDEN COBRA", "Zinc", "APT38"],
            "description": "North Korean state-sponsored group targeting financial institutions and cryptocurrency",
            "techniques": [
                "T1566.001",  # Spearphishing
                "T1204.002",  # User Execution: Malicious File
                "T1059.003",  # Windows Command Shell
                "T1055",      # Process Injection
                "T1070.004",  # File Deletion
                "T1486",      # Data Encrypted for Impact
                "T1041",      # Exfiltration Over C2
            ],
            "techniques_timeline": [
                {
                    "phase": "Initial Access",
                    "techniques": ["T1566.001", "T1189"],
                    "description": "Spearphishing and watering hole attacks"
                },
                {
                    "phase": "Execution",
                    "techniques": ["T1204.002", "T1059.003"],
                    "description": "User execution of malicious payloads"
                },
                {
                    "phase": "Defense Evasion",
                    "techniques": ["T1055", "T1070.004", "T1562.001"],
                    "description": "Process injection and log deletion"
                },
                {
                    "phase": "Impact",
                    "techniques": ["T1486", "T1489"],
                    "description": "Ransomware deployment (WannaCry, etc.)"
                },
                {
                    "phase": "Exfiltration",
                    "techniques": ["T1041", "T1567"],
                    "description": "Data exfiltration over C2 channels"
                }
            ],
            "target_industries": ["Financial Services", "Cryptocurrency", "Defense", "Media"],
            "target_countries": ["South Korea", "USA", "Global"],
            "tools": ["WannaCry", "FastCash", "AppleJeus", "HOPLIGHT", "Volgmer"],
            "campaigns": ["Sony Pictures", "WannaCry", "Bangladesh Bank Heist"],
            "confidence": "high"
        },
        "FIN7": {
            "aliases": ["Carbanak Group", "Carbon Spider"],
            "description": "Financially motivated cybercrime group targeting retail and hospitality",
            "techniques": [
                "T1566.001",  # Spearphishing
                "T1059.003",  # Windows Command Shell
                "T1059.005",  # VBScript
                "T1055",      # Process Injection
                "T1003.001",  # LSASS Memory
                "T1560.001",  # Archive via Utility
                "T1041",      # Exfiltration Over C2
            ],
            "techniques_timeline": [
                {
                    "phase": "Initial Access",
                    "techniques": ["T1566.001"],
                    "description": "Spearphishing with malicious attachments targeting POS systems"
                },
                {
                    "phase": "Execution",
                    "techniques": ["T1059.003", "T1059.005"],
                    "description": "Script-based execution and fileless malware"
                },
                {
                    "phase": "Credential Access",
                    "techniques": ["T1003.001", "T1056.001"],
                    "description": "Credential dumping and keylogging"
                },
                {
                    "phase": "Collection",
                    "techniques": ["T1560.001", "T1005"],
                    "description": "Archive and collect payment card data"
                },
                {
                    "phase": "Exfiltration",
                    "techniques": ["T1041"],
                    "description": "Exfiltrate stolen payment data"
                }
            ],
            "target_industries": ["Retail", "Hospitality", "Restaurants", "Gaming"],
            "target_countries": ["USA", "UK", "Australia"],
            "tools": ["Carbanak", "GRIFFON", "POWERSOURCE", "Cobalt Strike"],
            "campaigns": ["Point-of-Sale Compromises", "Retail Sector Targeting"],
            "confidence": "high"
        },
        "APT28": {
            "aliases": ["Fancy Bear", "Sofacy", "STRONTIUM"],
            "description": "Russian military intelligence (GRU) affiliated group",
            "techniques": [
                "T1566.001",  # Spearphishing
                "T1203",      # Exploitation for Client Execution
                "T1059.001",  # PowerShell
                "T1071.001",  # Web Protocols
                "T1003",      # Credential Dumping
                "T1083",      # File and Directory Discovery
            ],
            "techniques_timeline": [
                {
                    "phase": "Initial Access",
                    "techniques": ["T1566.001", "T1203"],
                    "description": "Spearphishing with exploits"
                },
                {
                    "phase": "Execution",
                    "techniques": ["T1059.001"],
                    "description": "PowerShell-based malware"
                },
                {
                    "phase": "Credential Access",
                    "techniques": ["T1003", "T1056.001"],
                    "description": "Credential harvesting"
                },
                {
                    "phase": "Command and Control",
                    "techniques": ["T1071.001"],
                    "description": "HTTP/HTTPS C2"
                }
            ],
            "target_industries": ["Government", "Military", "Defense", "Media"],
            "target_countries": ["USA", "Ukraine", "EU Nations", "Georgia"],
            "tools": ["X-Agent", "X-Tunnel", "Sofacy", "Zebrocy"],
            "campaigns": ["DNC Hack", "Olympic Destroyer", "German Parliament Hack"],
            "confidence": "high"
        },
        "Emotet": {
            "aliases": ["Geodo", "Mealybug"],
            "description": "Malware-as-a-service botnet operation, often delivering ransomware",
            "techniques": [
                "T1566.001",  # Spearphishing Attachment
                "T1204.002",  # Malicious File
                "T1059.003",  # Command Shell
                "T1547.001",  # Registry Run Keys
                "T1003.001",  # LSASS Memory
                "T1059.001",  # PowerShell
            ],
            "techniques_timeline": [
                {
                    "phase": "Initial Access",
                    "techniques": ["T1566.001"],
                    "description": "Email campaigns with malicious Office documents"
                },
                {
                    "phase": "Execution",
                    "techniques": ["T1204.002", "T1059.003"],
                    "description": "Macro-enabled documents executing malware"
                },
                {
                    "phase": "Persistence",
                    "techniques": ["T1547.001", "T1053.005"],
                    "description": "Registry and scheduled task persistence"
                },
                {
                    "phase": "Credential Access",
                    "techniques": ["T1003.001", "T1555.003"],
                    "description": "Credential and browser data theft"
                }
            ],
            "target_industries": ["All sectors", "SMB", "Enterprise"],
            "target_countries": ["Global"],
            "tools": ["Emotet", "TrickBot", "Ryuk", "QakBot"],
            "campaigns": ["Emotet Distribution Network"],
            "confidence": "high"
        }
    }

    def __init__(self, db: Session):
        self.db = db
        self.query_generator = EnhancedQueryGenerator(db)

    def initialize_playbooks(self) -> Dict:
        """Initialize pre-built playbooks in the database."""
        created = []
        updated = []

        for actor_name, playbook_data in self.KNOWN_PLAYBOOKS.items():
            existing = self.db.query(ThreatActorPlaybook).filter(
                ThreatActorPlaybook.threat_actor == actor_name
            ).first()

            if existing:
                # Update existing playbook
                existing.aliases = playbook_data["aliases"]
                existing.description = playbook_data["description"]
                existing.techniques = playbook_data["techniques"]
                existing.techniques_timeline = playbook_data["techniques_timeline"]
                existing.target_industries = playbook_data["target_industries"]
                existing.target_countries = playbook_data["target_countries"]
                existing.tools = playbook_data["tools"]
                existing.campaigns = playbook_data["campaigns"]
                existing.confidence = playbook_data["confidence"]
                existing.updated_at = datetime.utcnow()
                updated.append(actor_name)
            else:
                # Create new playbook
                new_playbook = ThreatActorPlaybook(
                    threat_actor=actor_name,
                    aliases=playbook_data["aliases"],
                    description=playbook_data["description"],
                    techniques=playbook_data["techniques"],
                    techniques_timeline=playbook_data["techniques_timeline"],
                    target_industries=playbook_data["target_industries"],
                    target_countries=playbook_data["target_countries"],
                    tools=playbook_data["tools"],
                    campaigns=playbook_data["campaigns"],
                    confidence=playbook_data["confidence"],
                    active=True
                )
                self.db.add(new_playbook)
                created.append(actor_name)

        self.db.commit()

        return {
            "created": created,
            "updated": updated,
            "total": len(created) + len(updated)
        }

    def get_playbook(self, threat_actor: str) -> Optional[Dict]:
        """Get a threat actor playbook."""
        playbook = self.db.query(ThreatActorPlaybook).filter(
            ThreatActorPlaybook.threat_actor == threat_actor
        ).first()

        if not playbook:
            return None

        return self._playbook_to_dict(playbook)

    def list_playbooks(
        self,
        active_only: bool = True,
        industry: Optional[str] = None
    ) -> List[Dict]:
        """List all threat actor playbooks."""
        query = self.db.query(ThreatActorPlaybook)

        if active_only:
            query = query.filter(ThreatActorPlaybook.active == True)

        if industry:
            query = query.filter(ThreatActorPlaybook.target_industries.contains([industry]))

        playbooks = query.all()
        return [self._playbook_to_dict(pb) for pb in playbooks]

    def execute_playbook(
        self,
        threat_actor: str,
        platforms: List[str],
        analyst: str,
        create_campaign: bool = True
    ) -> Dict:
        """
        Execute a threat actor playbook by generating hunt campaigns.

        Args:
            threat_actor: Threat actor name
            platforms: EDR platforms to generate queries for
            analyst: Analyst executing the playbook
            create_campaign: Whether to create a hunt campaign

        Returns:
            Execution results with generated queries
        """
        playbook = self.db.query(ThreatActorPlaybook).filter(
            ThreatActorPlaybook.threat_actor == threat_actor
        ).first()

        if not playbook:
            return {"error": f"Playbook not found for {threat_actor}"}

        # Create execution record
        execution = PlaybookExecution(
            playbook_id=playbook.id,
            executed_by=analyst,
            execution_status="in_progress",
            started_at=datetime.utcnow()
        )
        self.db.add(execution)
        self.db.commit()

        try:
            # Generate hunt campaign
            campaign_data = {
                "name": f"{threat_actor} Hunt Campaign",
                "description": f"Automated hunt campaign for {threat_actor} TTPs. {playbook.description}",
                "threat_actor": threat_actor,
                "techniques": playbook.techniques,
                "platforms": platforms,
                "analyst": analyst
            }

            campaign_id = None
            if create_campaign:
                campaign_result = self.query_generator.generate_hunt_campaign(
                    technique_ids=playbook.techniques,
                    platforms=platforms,
                    campaign_name=campaign_data["name"],
                    description=campaign_data["description"],
                    threat_actor=threat_actor,
                    analyst=analyst
                )
                campaign_id = campaign_result.get("campaign_id")
                execution.campaign_id = campaign_id

            # Update execution status
            execution.execution_status = "completed"
            execution.completed_at = datetime.utcnow()
            execution.queries_generated = len(playbook.techniques) * len(platforms)
            self.db.commit()

            return {
                "success": True,
                "execution_id": execution.id,
                "campaign_id": campaign_id,
                "threat_actor": threat_actor,
                "techniques_count": len(playbook.techniques),
                "queries_generated": execution.queries_generated,
                "timeline": playbook.techniques_timeline
            }

        except Exception as e:
            execution.execution_status = "failed"
            execution.completed_at = datetime.utcnow()
            execution.notes = str(e)
            self.db.commit()
            return {"error": str(e), "execution_id": execution.id}

    def get_ttp_timeline(self, threat_actor: str) -> List[Dict]:
        """Get TTP timeline for visualization."""
        playbook = self.db.query(ThreatActorPlaybook).filter(
            ThreatActorPlaybook.threat_actor == threat_actor
        ).first()

        if not playbook:
            return []

        return playbook.techniques_timeline or []

    def search_playbooks_by_technique(self, technique_id: str) -> List[Dict]:
        """Search playbooks that use a specific technique."""
        playbooks = self.db.query(ThreatActorPlaybook).filter(
            ThreatActorPlaybook.techniques.contains([technique_id])
        ).all()

        return [self._playbook_to_dict(pb) for pb in playbooks]

    def _playbook_to_dict(self, playbook: ThreatActorPlaybook) -> Dict:
        """Convert playbook model to dictionary."""
        return {
            "id": playbook.id,
            "threat_actor": playbook.threat_actor,
            "aliases": playbook.aliases,
            "description": playbook.description,
            "techniques": playbook.techniques,
            "techniques_timeline": playbook.techniques_timeline,
            "target_industries": playbook.target_industries,
            "target_countries": playbook.target_countries,
            "tools": playbook.tools,
            "campaigns": playbook.campaigns,
            "first_seen": playbook.first_seen.isoformat() if playbook.first_seen else None,
            "last_activity": playbook.last_activity.isoformat() if playbook.last_activity else None,
            "active": playbook.active,
            "confidence": playbook.confidence,
            "created_at": playbook.created_at.isoformat() if playbook.created_at else None,
            "updated_at": playbook.updated_at.isoformat() if playbook.updated_at else None
        }
