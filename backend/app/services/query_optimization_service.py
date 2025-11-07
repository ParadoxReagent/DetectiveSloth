"""Query optimization service."""

from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..models import GeneratedQuery, QueryEffectiveness, DetectionTemplate


class QueryOptimizationService:
    """Analyze and optimize threat hunting queries."""

    def __init__(self, db: Session):
        self.db = db

    def analyze_query_performance(self, query_id: int) -> Dict:
        """
        Analyze performance of a specific query.

        Args:
            query_id: ID of the generated query

        Returns:
            Performance analysis
        """
        query = self.db.query(GeneratedQuery).filter(
            GeneratedQuery.id == query_id
        ).first()

        if not query:
            return {"error": "Query not found"}

        # Get effectiveness metrics
        effectiveness = self.db.query(QueryEffectiveness).filter(
            QueryEffectiveness.query_id == query_id
        ).first()

        analysis = {
            "query_id": query_id,
            "platform": query.platform,
            "techniques": query.technique_ids,
            "created_at": query.created_at.isoformat(),
        }

        if effectiveness:
            analysis.update({
                "execution_count": effectiveness.execution_count,
                "true_positives": effectiveness.true_positive_count,
                "false_positives": effectiveness.false_positive_count,
                "precision": round(effectiveness.precision, 3) if effectiveness.precision else None,
                "avg_execution_time": round(effectiveness.avg_execution_time, 2) if effectiveness.avg_execution_time else None,
                "performance_score": round(effectiveness.performance_score, 2) if effectiveness.performance_score else None,
                "last_execution": effectiveness.last_execution.isoformat() if effectiveness.last_execution else None
            })

            # Generate recommendations
            recommendations = self._generate_optimization_recommendations(query, effectiveness)
            analysis["recommendations"] = recommendations
        else:
            analysis["status"] = "never_executed"
            analysis["recommendations"] = [
                "Execute this query to gather performance metrics",
                "Monitor for false positives during initial runs"
            ]

        return analysis

    def suggest_index_improvements(self, platform: str) -> List[Dict]:
        """
        Suggest database index improvements for better query performance.

        Args:
            platform: EDR platform

        Returns:
            List of index suggestions
        """
        suggestions = []

        # Platform-specific index suggestions
        platform_indexes = {
            "defender": [
                {
                    "table": "DeviceProcessEvents",
                    "columns": ["Timestamp", "ProcessCommandLine", "InitiatingProcessFileName"],
                    "reason": "Improves process execution query performance",
                    "priority": "high"
                },
                {
                    "table": "DeviceNetworkEvents",
                    "columns": ["Timestamp", "RemoteIP", "RemoteUrl"],
                    "reason": "Speeds up C2 detection queries",
                    "priority": "medium"
                },
                {
                    "table": "DeviceFileEvents",
                    "columns": ["Timestamp", "FileName", "SHA256"],
                    "reason": "Optimizes file-based IOC searches",
                    "priority": "high"
                }
            ],
            "crowdstrike": [
                {
                    "table": "ProcessRollup2",
                    "columns": ["@timestamp", "CommandLine", "ImageFileName"],
                    "reason": "Improves process query performance",
                    "priority": "high"
                },
                {
                    "table": "NetworkConnectIP4",
                    "columns": ["@timestamp", "RemoteAddressIP4", "RemotePort"],
                    "reason": "Optimizes network connection queries",
                    "priority": "medium"
                }
            ],
            "carbonblack": [
                {
                    "field": "process_name",
                    "reason": "Index on process names for faster searching",
                    "priority": "high"
                },
                {
                    "field": "process_cmdline",
                    "reason": "Full-text index for command line searches",
                    "priority": "high"
                }
            ],
            "sentinelone": [
                {
                    "table": "ProcessEvents",
                    "columns": ["Timestamp", "SrcProcCmdLine", "SrcProcName"],
                    "reason": "Speeds up process hunting queries",
                    "priority": "high"
                }
            ]
        }

        platform_lower = platform.lower()
        if platform_lower in platform_indexes:
            suggestions = platform_indexes[platform_lower]

        return suggestions

    def combine_related_queries(
        self,
        technique_ids: List[str],
        platform: str
    ) -> Dict:
        """
        Combine multiple related queries into a single optimized query.

        Args:
            technique_ids: List of MITRE technique IDs
            platform: Target platform

        Returns:
            Combined query optimization
        """
        # Get all queries for the techniques
        queries = self.db.query(GeneratedQuery).filter(
            GeneratedQuery.platform == platform,
            GeneratedQuery.technique_ids.overlap(technique_ids)
        ).all()

        if not queries:
            return {
                "error": "No queries found for the specified techniques",
                "technique_ids": technique_ids,
                "platform": platform
            }

        # Analyze commonalities
        common_patterns = self._find_common_patterns(queries)

        # Generate optimization strategy
        strategy = {
            "original_queries_count": len(queries),
            "techniques": technique_ids,
            "platform": platform,
            "common_patterns": common_patterns,
            "optimization_approach": self._determine_optimization_approach(platform, common_patterns),
            "estimated_performance_gain": self._estimate_performance_gain(len(queries)),
            "combined_query_suggestion": self._generate_combined_query_suggestion(platform, queries)
        }

        return strategy

    def benchmark_query(
        self,
        query_text: str,
        platform: str,
        estimated_time: Optional[float] = None
    ) -> Dict:
        """
        Benchmark a query and provide optimization suggestions.

        Args:
            query_text: The query to benchmark
            platform: Platform (defender, crowdstrike, etc.)
            estimated_time: Optional estimated execution time

        Returns:
            Benchmark results and suggestions
        """
        # Analyze query complexity
        complexity = self._analyze_query_complexity(query_text, platform)

        # Generate optimization suggestions
        suggestions = self._generate_query_specific_optimizations(query_text, platform, complexity)

        return {
            "platform": platform,
            "complexity_score": complexity["score"],
            "complexity_factors": complexity["factors"],
            "estimated_time": estimated_time,
            "optimization_suggestions": suggestions,
            "best_practices": self._get_platform_best_practices(platform)
        }

    def _generate_optimization_recommendations(
        self,
        query: GeneratedQuery,
        effectiveness: QueryEffectiveness
    ) -> List[str]:
        """Generate query-specific optimization recommendations."""
        recommendations = []

        # Check precision
        if effectiveness.precision is not None and effectiveness.precision < 0.5:
            recommendations.append(
                "Low precision detected. Consider adding more specific filters to reduce false positives."
            )

        # Check execution time
        if effectiveness.avg_execution_time and effectiveness.avg_execution_time > 30:
            recommendations.append(
                f"Query takes {effectiveness.avg_execution_time:.1f}s on average. Consider:\n"
                "  - Adding time range filters\n"
                "  - Reducing the scope of wildcard searches\n"
                "  - Using indexed columns for filtering"
            )

        # Check execution count
        if effectiveness.execution_count > 10:
            if effectiveness.true_positive_count == 0:
                recommendations.append(
                    "No true positives found after multiple executions. Consider archiving or revising this query."
                )
            elif effectiveness.performance_score and effectiveness.performance_score < 50:
                recommendations.append(
                    "Low performance score. Review query logic and adjust thresholds."
                )

        # Platform-specific recommendations
        if query.platform.lower() == "defender":
            if "contains" in query.query_text.lower():
                recommendations.append(
                    "Consider using 'has' or 'has_any' operators instead of 'contains' for better performance in KQL."
                )

        if not recommendations:
            recommendations.append("Query performance is within acceptable parameters.")

        return recommendations

    def _find_common_patterns(self, queries: List[GeneratedQuery]) -> List[str]:
        """Find common patterns across queries."""
        patterns = []

        # Extract common elements from query texts
        all_texts = [q.query_text for q in queries]

        # Common data sources
        data_sources = set()
        for text in all_texts:
            if "DeviceProcessEvents" in text:
                data_sources.add("DeviceProcessEvents")
            if "DeviceNetworkEvents" in text:
                data_sources.add("DeviceNetworkEvents")
            if "DeviceFileEvents" in text:
                data_sources.add("DeviceFileEvents")

        if data_sources:
            patterns.append(f"Common data sources: {', '.join(data_sources)}")

        # Common filters
        if all("Timestamp" in text for text in all_texts):
            patterns.append("All queries use time-based filtering")

        return patterns

    def _determine_optimization_approach(self, platform: str, patterns: List[str]) -> str:
        """Determine the best optimization approach."""
        if platform.lower() == "defender":
            if any("DeviceProcessEvents" in p for p in patterns):
                return "Combine process queries using union operator and shared filters"
        elif platform.lower() == "crowdstrike":
            return "Use single query with multiple event types in OR conditions"

        return "Combine queries with shared time ranges and common filters"

    def _estimate_performance_gain(self, query_count: int) -> str:
        """Estimate performance gain from combining queries."""
        if query_count <= 2:
            return "10-20% improvement"
        elif query_count <= 5:
            return "20-40% improvement"
        else:
            return "40-60% improvement"

    def _generate_combined_query_suggestion(
        self,
        platform: str,
        queries: List[GeneratedQuery]
    ) -> str:
        """Generate a suggestion for combining queries."""
        if platform.lower() == "defender":
            return (
                "Consider combining queries using the KQL 'union' operator:\n"
                "union DeviceProcessEvents, DeviceNetworkEvents\n"
                "| where Timestamp > ago(7d)\n"
                "| where (condition1) or (condition2) or (condition3)"
            )
        elif platform.lower() == "crowdstrike":
            return (
                "Combine event types in a single query:\n"
                "#event_simpleName IN (ProcessRollup2, NetworkConnectIP4)\n"
                "| (condition1 OR condition2 OR condition3)"
            )
        else:
            return "Combine related searches with OR operators for similar data sources"

    def _analyze_query_complexity(self, query_text: str, platform: str) -> Dict:
        """Analyze query complexity."""
        score = 0
        factors = []

        # Check length
        if len(query_text) > 1000:
            score += 3
            factors.append("Long query (>1000 chars)")
        elif len(query_text) > 500:
            score += 2
            factors.append("Medium-length query")
        else:
            score += 1
            factors.append("Short query")

        # Check for wildcards
        wildcard_count = query_text.count("*")
        if wildcard_count > 5:
            score += 3
            factors.append(f"Many wildcards ({wildcard_count})")
        elif wildcard_count > 2:
            score += 2
            factors.append(f"Some wildcards ({wildcard_count})")

        # Check for regex
        if "regex" in query_text.lower() or "matches" in query_text.lower():
            score += 2
            factors.append("Uses regex matching")

        # Check for joins
        if "join" in query_text.lower():
            score += 2
            factors.append("Contains joins")

        # Check for time range
        if "ago(" not in query_text.lower() and "timestamp" not in query_text.lower():
            score += 2
            factors.append("No time range filter (inefficient)")

        return {
            "score": min(score, 10),
            "factors": factors
        }

    def _generate_query_specific_optimizations(
        self,
        query_text: str,
        platform: str,
        complexity: Dict
    ) -> List[str]:
        """Generate specific optimization suggestions."""
        suggestions = []

        # Time range optimization
        if "No time range filter" in str(complexity["factors"]):
            suggestions.append("Add a time range filter to limit the search scope")

        # Wildcard optimization
        if "wildcard" in str(complexity["factors"]).lower():
            suggestions.append("Reduce wildcard usage or make them more specific")

        # Platform-specific
        if platform.lower() == "defender":
            if "contains" in query_text.lower():
                suggestions.append("Replace 'contains' with 'has' for exact token matching (faster)")
            if "where" not in query_text.lower():
                suggestions.append("Add 'where' clauses to filter early in the pipeline")

        if platform.lower() == "crowdstrike":
            if "groupBy" in query_text:
                suggestions.append("Ensure groupBy operations are done after filtering")

        if not suggestions:
            suggestions.append("Query structure appears optimized")

        return suggestions

    def _get_platform_best_practices(self, platform: str) -> List[str]:
        """Get platform-specific best practices."""
        practices = {
            "defender": [
                "Use time range filters (ago()) to limit search scope",
                "Use 'has' instead of 'contains' for exact matches",
                "Filter early in the pipeline with 'where' clauses",
                "Use indexed columns (Timestamp, DeviceName) in filters",
                "Limit result sets with 'top' or 'take' operators"
            ],
            "crowdstrike": [
                "Filter on event_simpleName early",
                "Use ComputerName and timestamp for better performance",
                "Limit groupBy operations and do them after filtering",
                "Use specific field names instead of wildcards"
            ],
            "carbonblack": [
                "Use indexed fields (process_name, process_cmdline)",
                "Combine conditions with AND/OR efficiently",
                "Avoid leading wildcards in searches",
                "Use specific time ranges"
            ],
            "sentinelone": [
                "Filter on EventType first",
                "Use specific field comparisons",
                "Limit wildcard usage in string searches",
                "Apply time filters"
            ]
        }

        return practices.get(platform.lower(), [
            "Use time-based filtering",
            "Filter on indexed fields when possible",
            "Limit result sets",
            "Avoid excessive wildcard usage"
        ])
