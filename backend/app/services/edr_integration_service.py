"""EDR platform integration service."""

from typing import List, Dict, Optional
from datetime import datetime
import hashlib
import json
from sqlalchemy.orm import Session
from ..models import EDRExecution, GeneratedQuery


class EDRIntegrationService:
    """
    Integration framework for EDR platforms.

    Note: This is a framework for EDR integration. Actual API implementations
    would require platform-specific credentials and API clients.
    """

    def __init__(self, db: Session):
        self.db = db
        self.platform_configs = {}

    def configure_platform(
        self,
        platform: str,
        config: Dict
    ) -> Dict:
        """
        Configure EDR platform connection.

        Args:
            platform: Platform name (defender, crowdstrike, carbonblack, sentinelone)
            config: Platform configuration (API endpoints, credentials, etc.)

        Returns:
            Configuration status
        """
        required_fields = {
            "defender": ["tenant_id", "client_id", "client_secret"],
            "crowdstrike": ["client_id", "client_secret", "base_url"],
            "carbonblack": ["api_key", "api_id", "org_key", "base_url"],
            "sentinelone": ["api_token", "base_url"]
        }

        platform_lower = platform.lower()
        if platform_lower not in required_fields:
            return {"error": f"Unsupported platform: {platform}"}

        # Validate required fields
        missing_fields = [
            field for field in required_fields[platform_lower]
            if field not in config
        ]

        if missing_fields:
            return {
                "error": f"Missing required fields: {', '.join(missing_fields)}",
                "required_fields": required_fields[platform_lower]
            }

        # Store config (in production, encrypt sensitive data)
        self.platform_configs[platform_lower] = config

        return {
            "success": True,
            "platform": platform,
            "configured": True,
            "message": f"{platform} configured successfully"
        }

    def execute_query(
        self,
        query_id: int,
        execute_immediately: bool = False
    ) -> Dict:
        """
        Execute a query on the configured EDR platform.

        Args:
            query_id: ID of the generated query
            execute_immediately: Whether to execute now or schedule

        Returns:
            Execution status
        """
        query = self.db.query(GeneratedQuery).filter(
            GeneratedQuery.id == query_id
        ).first()

        if not query:
            return {"error": "Query not found"}

        platform = query.platform.lower()
        if platform not in self.platform_configs:
            return {
                "error": f"Platform {platform} not configured",
                "message": "Please configure the platform first using configure_platform()"
            }

        # Create execution record
        execution = EDRExecution(
            query_id=query_id,
            platform=platform,
            execution_status="pending" if not execute_immediately else "running",
            started_at=datetime.utcnow() if execute_immediately else None
        )
        self.db.add(execution)
        self.db.commit()

        if execute_immediately:
            # In production, this would call the actual EDR API
            result = self._execute_on_platform(query, platform, execution.id)
            return result
        else:
            return {
                "success": True,
                "execution_id": execution.id,
                "status": "scheduled",
                "message": "Query execution scheduled"
            }

    def _execute_on_platform(
        self,
        query: GeneratedQuery,
        platform: str,
        execution_id: int
    ) -> Dict:
        """
        Execute query on specific platform (framework method).

        In production, this would implement actual API calls.
        """
        execution = self.db.query(EDRExecution).filter(
            EDRExecution.id == execution_id
        ).first()

        try:
            # Platform-specific execution logic would go here
            if platform == "defender":
                result = self._execute_defender_query(query)
            elif platform == "crowdstrike":
                result = self._execute_crowdstrike_query(query)
            elif platform == "carbonblack":
                result = self._execute_carbonblack_query(query)
            elif platform == "sentinelone":
                result = self._execute_sentinelone_query(query)
            else:
                raise ValueError(f"Unsupported platform: {platform}")

            # Update execution record
            execution.execution_status = "completed"
            execution.completed_at = datetime.utcnow()
            execution.results = result
            execution.results_count = result.get("count", 0)
            execution.findings = result.get("findings", [])
            self.db.commit()

            return {
                "success": True,
                "execution_id": execution_id,
                "results_count": execution.results_count,
                "findings": execution.findings
            }

        except Exception as e:
            import logging
            execution.execution_status = "failed"
            execution.completed_at = datetime.utcnow()
            execution.error_message = str(e)
            self.db.commit()
            logging.error(f"EDR query execution failed: {e}", exc_info=True)
            return {
                "success": False,
                "execution_id": execution_id,
                "error": "Internal platform execution error"
            }

    def _execute_defender_query(self, query: GeneratedQuery) -> Dict:
        """Execute query on Microsoft Defender (framework)."""
        # In production: Use Microsoft Graph API or Defender API
        # from azure.identity import ClientSecretCredential
        # from msgraph import GraphServiceClient

        return {
            "platform": "defender",
            "count": 0,
            "findings": [],
            "message": "Framework method - implement with actual Defender API"
        }

    def _execute_crowdstrike_query(self, query: GeneratedQuery) -> Dict:
        """Execute query on CrowdStrike (framework)."""
        # In production: Use CrowdStrike Falcon API
        # from falconpy import EventStreams

        return {
            "platform": "crowdstrike",
            "count": 0,
            "findings": [],
            "message": "Framework method - implement with actual CrowdStrike API"
        }

    def _execute_carbonblack_query(self, query: GeneratedQuery) -> Dict:
        """Execute query on Carbon Black (framework)."""
        # In production: Use Carbon Black Cloud API
        # from cbapi import CbResponseAPI

        return {
            "platform": "carbonblack",
            "count": 0,
            "findings": [],
            "message": "Framework method - implement with actual Carbon Black API"
        }

    def _execute_sentinelone_query(self, query: GeneratedQuery) -> Dict:
        """Execute query on SentinelOne (framework)."""
        # In production: Use SentinelOne API

        return {
            "platform": "sentinelone",
            "count": 0,
            "findings": [],
            "message": "Framework method - implement with actual SentinelOne API"
        }

    def collect_results(
        self,
        execution_id: int
    ) -> Dict:
        """
        Collect results from an EDR execution.

        Args:
            execution_id: Execution ID

        Returns:
            Execution results
        """
        execution = self.db.query(EDRExecution).filter(
            EDRExecution.id == execution_id
        ).first()

        if not execution:
            return {"error": "Execution not found"}

        return {
            "execution_id": execution_id,
            "query_id": execution.query_id,
            "platform": execution.platform,
            "status": execution.execution_status,
            "started_at": execution.started_at.isoformat() if execution.started_at else None,
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
            "results_count": execution.results_count,
            "findings": execution.findings,
            "deduplicated": execution.deduplicated,
            "error": execution.error_message
        }

    def deduplicate_findings(
        self,
        execution_ids: List[int]
    ) -> Dict:
        """
        Deduplicate findings across multiple executions.

        Args:
            execution_ids: List of execution IDs to deduplicate

        Returns:
            Deduplicated findings
        """
        executions = self.db.query(EDRExecution).filter(
            EDRExecution.id.in_(execution_ids)
        ).all()

        if not executions:
            return {"error": "No executions found"}

        all_findings = []
        for execution in executions:
            findings = execution.findings or []
            for finding in findings:
                finding["source_execution_id"] = execution.id
                finding["source_platform"] = execution.platform
                all_findings.append(finding)

        # Deduplicate based on key attributes
        deduplicated = self._deduplicate_findings_list(all_findings)

        # Mark executions as deduplicated
        for execution in executions:
            execution.deduplicated = True
        self.db.commit()

        return {
            "total_findings": len(all_findings),
            "unique_findings": len(deduplicated),
            "duplicates_removed": len(all_findings) - len(deduplicated),
            "findings": deduplicated
        }

    def _deduplicate_findings_list(self, findings: List[Dict]) -> List[Dict]:
        """Deduplicate a list of findings."""
        seen_hashes = set()
        unique_findings = []

        for finding in findings:
            # Create a hash based on key attributes
            finding_hash = self._hash_finding(finding)

            if finding_hash not in seen_hashes:
                seen_hashes.add(finding_hash)
                unique_findings.append(finding)
            else:
                # Add source platform to existing finding
                for existing in unique_findings:
                    if self._hash_finding(existing) == finding_hash:
                        if "detected_on_platforms" not in existing:
                            existing["detected_on_platforms"] = [existing.get("source_platform")]
                        if finding.get("source_platform") not in existing["detected_on_platforms"]:
                            existing["detected_on_platforms"].append(finding.get("source_platform"))
                        break

        return unique_findings

    def _hash_finding(self, finding: Dict) -> str:
        """Create a hash for a finding based on key attributes."""
        # Use key attributes for deduplication
        key_attrs = {
            "hostname": finding.get("hostname", ""),
            "timestamp": finding.get("timestamp", ""),
            "process_name": finding.get("process_name", ""),
            "command_line": finding.get("command_line", ""),
            "user": finding.get("user", ""),
            "ip_address": finding.get("ip_address", "")
        }

        # Create hash
        hash_str = json.dumps(key_attrs, sort_keys=True)
        return hashlib.sha256(hash_str.encode()).hexdigest()

    def get_execution_status(
        self,
        query_id: int
    ) -> List[Dict]:
        """Get all execution statuses for a query."""
        executions = self.db.query(EDRExecution).filter(
            EDRExecution.query_id == query_id
        ).order_by(EDRExecution.started_at.desc()).all()

        return [{
            "execution_id": ex.id,
            "platform": ex.platform,
            "status": ex.execution_status,
            "started_at": ex.started_at.isoformat() if ex.started_at else None,
            "completed_at": ex.completed_at.isoformat() if ex.completed_at else None,
            "results_count": ex.results_count,
            "error": ex.error_message
        } for ex in executions]

    def bulk_execute(
        self,
        query_ids: List[int]
    ) -> Dict:
        """Execute multiple queries in bulk."""
        results = []
        errors = []

        for query_id in query_ids:
            result = self.execute_query(query_id, execute_immediately=False)
            if result.get("success"):
                results.append(result)
            else:
                errors.append({"query_id": query_id, "error": result.get("error")})

        return {
            "total": len(query_ids),
            "scheduled": len(results),
            "failed": len(errors),
            "executions": results,
            "errors": errors
        }
