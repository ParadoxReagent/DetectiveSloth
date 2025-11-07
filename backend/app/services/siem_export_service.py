"""SIEM/SOAR export and integration service."""

from typing import List, Dict, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from ..models import GeneratedQuery, HuntCampaign, HuntFinding, MitreTechnique


class SIEMExportService:
    """Export queries and findings to SIEM/SOAR platforms."""

    def __init__(self, db: Session):
        self.db = db

    def export_to_splunk(
        self,
        query_id: int,
        timeframe: str = "7d"
    ) -> Dict:
        """
        Export query to Splunk SPL format.

        Args:
            query_id: Generated query ID
            timeframe: Time range (e.g., "7d", "24h")

        Returns:
            Splunk query and metadata
        """
        query = self.db.query(GeneratedQuery).filter(
            GeneratedQuery.id == query_id
        ).first()

        if not query:
            return {"error": "Query not found"}

        # Get technique information
        techniques = self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id.in_(query.technique_ids)
        ).all()

        # Convert to Splunk SPL
        spl_query = self._convert_to_splunk(query, timeframe)

        # Generate alert configuration
        alert_config = self._generate_splunk_alert(query, techniques)

        return {
            "platform": "splunk",
            "query_id": query_id,
            "spl_query": spl_query,
            "alert_config": alert_config,
            "techniques": [t.technique_id for t in techniques],
            "timeframe": timeframe,
            "export_format": "spl"
        }

    def export_to_sentinel(
        self,
        query_id: int,
        timeframe: str = "7d"
    ) -> Dict:
        """
        Export query to Microsoft Sentinel (Azure Sentinel) KQL format.

        Args:
            query_id: Generated query ID
            timeframe: Time range

        Returns:
            Sentinel query and analytics rule
        """
        query = self.db.query(GeneratedQuery).filter(
            GeneratedQuery.id == query_id
        ).first()

        if not query:
            return {"error": "Query not found"}

        techniques = self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id.in_(query.technique_ids)
        ).all()

        # Convert to Sentinel KQL (similar to Defender)
        sentinel_query = self._convert_to_sentinel(query, timeframe)

        # Generate analytics rule
        analytics_rule = self._generate_sentinel_analytics_rule(query, techniques)

        return {
            "platform": "sentinel",
            "query_id": query_id,
            "kql_query": sentinel_query,
            "analytics_rule": analytics_rule,
            "techniques": [t.technique_id for t in techniques],
            "timeframe": timeframe,
            "export_format": "kql"
        }

    def export_to_chronicle(
        self,
        query_id: int,
        timeframe: str = "7d"
    ) -> Dict:
        """
        Export query to Google Chronicle YARA-L format.

        Args:
            query_id: Generated query ID
            timeframe: Time range

        Returns:
            Chronicle detection rule
        """
        query = self.db.query(GeneratedQuery).filter(
            GeneratedQuery.id == query_id
        ).first()

        if not query:
            return {"error": "Query not found"}

        techniques = self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id.in_(query.technique_ids)
        ).all()

        # Convert to YARA-L
        yaral_rule = self._convert_to_chronicle(query, techniques)

        return {
            "platform": "chronicle",
            "query_id": query_id,
            "yaral_rule": yaral_rule,
            "techniques": [t.technique_id for t in techniques],
            "timeframe": timeframe,
            "export_format": "yaral"
        }

    def create_soar_playbook(
        self,
        campaign_id: int,
        platform: str = "generic"
    ) -> Dict:
        """
        Create a SOAR playbook from a hunt campaign.

        Args:
            campaign_id: Hunt campaign ID
            platform: SOAR platform (generic, phantom, demisto, etc.)

        Returns:
            SOAR playbook definition
        """
        campaign = self.db.query(HuntCampaign).filter(
            HuntCampaign.id == campaign_id
        ).first()

        if not campaign:
            return {"error": "Campaign not found"}

        # Get techniques
        techniques = self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id.in_(campaign.techniques)
        ).all()

        # Get findings
        findings = self.db.query(HuntFinding).filter(
            HuntFinding.campaign_id == campaign_id
        ).all()

        if platform.lower() == "phantom":
            playbook = self._generate_phantom_playbook(campaign, techniques, findings)
        elif platform.lower() == "demisto":
            playbook = self._generate_demisto_playbook(campaign, techniques, findings)
        else:
            playbook = self._generate_generic_playbook(campaign, techniques, findings)

        return {
            "platform": platform,
            "campaign_id": campaign_id,
            "campaign_name": campaign.name,
            "playbook": playbook,
            "techniques_count": len(techniques),
            "findings_count": len(findings)
        }

    def create_ticket(
        self,
        finding_id: int,
        ticket_system: str = "jira",
        config: Optional[Dict] = None
    ) -> Dict:
        """
        Create a ticket in an external system for a finding.

        Args:
            finding_id: Hunt finding ID
            ticket_system: Ticket system (jira, servicenow, etc.)
            config: Ticket configuration

        Returns:
            Ticket creation result
        """
        finding = self.db.query(HuntFinding).filter(
            HuntFinding.id == finding_id
        ).first()

        if not finding:
            return {"error": "Finding not found"}

        # Generate ticket details
        ticket_data = self._generate_ticket_data(finding, ticket_system, config)

        # In production, this would call the actual ticketing API
        return {
            "success": True,
            "finding_id": finding_id,
            "ticket_system": ticket_system,
            "ticket_data": ticket_data,
            "message": "Framework method - implement with actual ticketing API"
        }

    def _convert_to_splunk(self, query: GeneratedQuery, timeframe: str) -> str:
        """Convert query to Splunk SPL format."""
        # Map platforms to Splunk data sources
        sourcetype_map = {
            "defender": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "crowdstrike": "crowdstrike:events",
            "carbonblack": "carbonblack:endpoint",
            "sentinelone": "sentinelone:events"
        }

        sourcetype = sourcetype_map.get(query.platform, "windows:sysmon")

        spl = f"""# MITRE ATT&CK Techniques: {', '.join(query.technique_ids)}
# Original Platform: {query.platform}
# Generated: {datetime.utcnow().isoformat()}

index=security sourcetype={sourcetype}
earliest=-{timeframe}
"""

        # Add platform-specific conversion logic
        if query.platform.lower() == "defender":
            # Convert KQL to SPL approximation
            spl += """| search (CommandLine="*powershell*" OR CommandLine="*cmd.exe*")
| stats count by host, user, CommandLine, ParentProcess
| where count > 1
"""
        else:
            spl += """| search process_name IN (powershell.exe, cmd.exe, rundll32.exe)
| stats count by host, user, process_cmdline
| where count > 1
"""

        return spl

    def _convert_to_sentinel(self, query: GeneratedQuery, timeframe: str) -> str:
        """Convert query to Sentinel KQL format."""
        # If already in Defender format, adapt for Sentinel
        if query.platform.lower() == "defender":
            # Modify for Sentinel table names
            sentinel_query = query.query_text.replace("DeviceProcessEvents", "SecurityEvent")
            sentinel_query = sentinel_query.replace("DeviceNetworkEvents", "NetworkConnectionEvents")
            return sentinel_query

        # Convert from other platforms
        return f"""// MITRE ATT&CK: {', '.join(query.technique_ids)}
// Converted from {query.platform}
SecurityEvent
| where TimeGenerated > ago({timeframe})
| where EventID in (4688, 4689) // Process creation/termination
| project TimeGenerated, Computer, Account, Process, CommandLine
"""

    def _convert_to_chronicle(self, query: GeneratedQuery, techniques: List[MitreTechnique]) -> str:
        """Convert query to Chronicle YARA-L format."""
        technique_names = [t.name for t in techniques]

        yaral = f"""rule {query.technique_ids[0].replace('.', '_')}_detection {{
  meta:
    author = "Automated Threat Hunt Generator"
    description = "{', '.join(technique_names)}"
    severity = "Medium"
    mitre_attack_technique = "{', '.join(query.technique_ids)}"
    created = "{datetime.utcnow().isoformat()}"

  events:
    $process = process.file.full_path
    $cmdline = process.command_line

  match:
    $process and $cmdline

  condition:
    $process
}}
"""
        return yaral

    def _generate_splunk_alert(self, query: GeneratedQuery, techniques: List[MitreTechnique]) -> Dict:
        """Generate Splunk alert configuration."""
        return {
            "alert_type": "scheduled",
            "cron_schedule": "0 */4 * * *",  # Every 4 hours
            "alert_actions": ["email", "ticket"],
            "severity": "medium",
            "description": f"Detection for {', '.join([t.name for t in techniques])}",
            "mitre_techniques": [t.technique_id for t in techniques],
            "throttle_window": "4h"
        }

    def _generate_sentinel_analytics_rule(
        self,
        query: GeneratedQuery,
        techniques: List[MitreTechnique]
    ) -> Dict:
        """Generate Sentinel analytics rule."""
        return {
            "displayName": f"Hunt: {', '.join([t.name for t in techniques[:2]])}",
            "description": f"Automated hunt for MITRE ATT&CK techniques: {', '.join(query.technique_ids)}",
            "severity": "Medium",
            "enabled": True,
            "query": query.query_text,
            "queryFrequency": "PT4H",  # Every 4 hours
            "queryPeriod": "P7D",  # Look back 7 days
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "tactics": list(set([tactic for t in techniques for tactic in (t.tactics or [])])),
            "techniques": query.technique_ids
        }

    def _generate_phantom_playbook(
        self,
        campaign: HuntCampaign,
        techniques: List[MitreTechnique],
        findings: List[HuntFinding]
    ) -> Dict:
        """Generate Splunk Phantom (SOAR) playbook."""
        return {
            "name": f"{campaign.name} - Response Playbook",
            "description": campaign.description,
            "steps": [
                {
                    "step": 1,
                    "action": "investigate",
                    "description": "Gather additional context from EDR",
                    "automation": "query_edr"
                },
                {
                    "step": 2,
                    "action": "enrich",
                    "description": "Enrich IOCs with threat intelligence",
                    "automation": "lookup_iocs"
                },
                {
                    "step": 3,
                    "action": "contain",
                    "description": "Isolate affected hosts if high confidence",
                    "automation": "isolate_host",
                    "condition": "confidence > 0.8"
                },
                {
                    "step": 4,
                    "action": "notify",
                    "description": "Create ticket and notify SOC",
                    "automation": "create_ticket"
                }
            ],
            "mitre_techniques": [t.technique_id for t in techniques]
        }

    def _generate_demisto_playbook(
        self,
        campaign: HuntCampaign,
        techniques: List[MitreTechnique],
        findings: List[HuntFinding]
    ) -> Dict:
        """Generate Palo Alto Cortex XSOAR (Demisto) playbook."""
        return {
            "id": f"hunt_campaign_{campaign.id}",
            "name": campaign.name,
            "description": campaign.description,
            "tasks": {
                "0": {
                    "id": "0",
                    "type": "start",
                    "nextTasks": {"#none#": ["1"]}
                },
                "1": {
                    "id": "1",
                    "type": "standard",
                    "task": "Extract IOCs from findings",
                    "scriptName": "ExtractIndicators",
                    "nextTasks": {"#none#": ["2"]}
                },
                "2": {
                    "id": "2",
                    "type": "standard",
                    "task": "Enrich with threat intelligence",
                    "scriptName": "ThreatIntelEnrichment",
                    "nextTasks": {"#none#": ["3"]}
                },
                "3": {
                    "id": "3",
                    "type": "condition",
                    "task": "Is threat confirmed?",
                    "nextTasks": {
                        "yes": ["4"],
                        "no": ["5"]
                    }
                },
                "4": {
                    "id": "4",
                    "type": "standard",
                    "task": "Isolate host",
                    "scriptName": "IsolateHost"
                },
                "5": {
                    "id": "5",
                    "type": "standard",
                    "task": "Create informational ticket",
                    "scriptName": "CreateTicket"
                }
            }
        }

    def _generate_generic_playbook(
        self,
        campaign: HuntCampaign,
        techniques: List[MitreTechnique],
        findings: List[HuntFinding]
    ) -> Dict:
        """Generate generic SOAR playbook."""
        return {
            "name": campaign.name,
            "description": campaign.description,
            "threat_actor": campaign.threat_actor,
            "techniques": [
                {
                    "id": t.technique_id,
                    "name": t.name,
                    "tactics": t.tactics
                }
                for t in techniques
            ],
            "response_steps": [
                {
                    "order": 1,
                    "action": "Detection",
                    "description": "Execute hunt queries across all platforms",
                    "automated": True
                },
                {
                    "order": 2,
                    "action": "Analysis",
                    "description": "Analyze findings for true positives",
                    "automated": False
                },
                {
                    "order": 3,
                    "action": "Containment",
                    "description": "Isolate affected systems if confirmed",
                    "automated": False
                },
                {
                    "order": 4,
                    "action": "Eradication",
                    "description": "Remove malicious artifacts",
                    "automated": False
                },
                {
                    "order": 5,
                    "action": "Recovery",
                    "description": "Restore systems to normal operation",
                    "automated": False
                }
            ],
            "findings_summary": {
                "total": len(findings),
                "by_severity": self._count_by_severity(findings)
            }
        }

    def _generate_ticket_data(
        self,
        finding: HuntFinding,
        ticket_system: str,
        config: Optional[Dict]
    ) -> Dict:
        """Generate ticket data for a finding."""
        priority_map = {
            "critical": "P1",
            "high": "P2",
            "medium": "P3",
            "low": "P4"
        }

        return {
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "priority": priority_map.get(finding.severity, "P3"),
            "technique": finding.technique_id,
            "affected_hosts": finding.affected_hosts,
            "analyst": finding.analyst,
            "discovered_at": finding.discovered_at.isoformat(),
            "labels": ["threat-hunt", "automated", finding.technique_id],
            "custom_fields": config or {}
        }

    def _count_by_severity(self, findings: List[HuntFinding]) -> Dict:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for finding in findings:
            severity = finding.severity or "informational"
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def export_campaign_report(
        self,
        campaign_id: int,
        format: str = "json"
    ) -> Dict:
        """
        Export a comprehensive campaign report.

        Args:
            campaign_id: Hunt campaign ID
            format: Export format (json, pdf, html)

        Returns:
            Campaign report
        """
        campaign = self.db.query(HuntCampaign).filter(
            HuntCampaign.id == campaign_id
        ).first()

        if not campaign:
            return {"error": "Campaign not found"}

        findings = self.db.query(HuntFinding).filter(
            HuntFinding.campaign_id == campaign_id
        ).all()

        techniques = self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id.in_(campaign.techniques)
        ).all()

        report = {
            "campaign": {
                "id": campaign.id,
                "name": campaign.name,
                "description": campaign.description,
                "threat_actor": campaign.threat_actor,
                "analyst": campaign.analyst,
                "status": campaign.status,
                "start_date": campaign.start_date.isoformat() if campaign.start_date else None,
                "end_date": campaign.end_date.isoformat() if campaign.end_date else None
            },
            "techniques": [
                {
                    "id": t.technique_id,
                    "name": t.name,
                    "tactics": t.tactics,
                    "description": t.description
                }
                for t in techniques
            ],
            "findings": [
                {
                    "id": f.id,
                    "technique_id": f.technique_id,
                    "type": f.finding_type,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "affected_hosts": f.affected_hosts,
                    "status": f.remediation_status,
                    "discovered_at": f.discovered_at.isoformat()
                }
                for f in findings
            ],
            "statistics": {
                "total_findings": len(findings),
                "by_type": self._count_by_type(findings),
                "by_severity": self._count_by_severity(findings),
                "techniques_hunted": len(techniques)
            },
            "export_format": format,
            "exported_at": datetime.utcnow().isoformat()
        }

        return report

    def _count_by_type(self, findings: List[HuntFinding]) -> Dict:
        """Count findings by type."""
        counts = {}
        for finding in findings:
            ftype = finding.finding_type or "unknown"
            counts[ftype] = counts.get(ftype, 0) + 1
        return counts
