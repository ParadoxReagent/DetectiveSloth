"""Hypothesis generation service for threat hunting."""

from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from ..models import MitreTechnique, DetectionTemplate, GeneratedQuery, QueryEffectiveness


class HypothesisService:
    """Generate hypotheses and recommend related techniques for threat hunting."""

    # MITRE ATT&CK kill chain phases in order
    KILL_CHAIN_ORDER = [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact"
    ]

    # Common technique relationships (technique_id -> related_technique_ids)
    TECHNIQUE_RELATIONSHIPS = {
        # Process injection often leads to credential access
        "T1055": ["T1003", "T1071", "T1140"],
        # Credential dumping often precedes lateral movement
        "T1003": ["T1021", "T1550", "T1078"],
        # Lateral movement techniques
        "T1021": ["T1053", "T1059", "T1569"],
        # PowerShell execution
        "T1059.001": ["T1140", "T1105", "T1071"],
        # Scheduled tasks for persistence
        "T1053": ["T1055", "T1547", "T1059"],
        # Registry persistence
        "T1547": ["T1112", "T1055", "T1059"],
        # Defense evasion techniques
        "T1070": ["T1562", "T1027", "T1564"],
        # Discovery techniques
        "T1087": ["T1069", "T1018", "T1083"],
        # Collection and exfiltration
        "T1560": ["T1041", "T1567"],
    }

    def __init__(self, db: Session):
        self.db = db

    def suggest_related_techniques(
        self,
        technique_id: str,
        limit: int = 5
    ) -> List[Dict]:
        """
        Suggest related techniques based on various factors.

        Args:
            technique_id: MITRE technique ID
            limit: Maximum number of suggestions

        Returns:
            List of related technique suggestions with reasoning
        """
        suggestions = []

        # Get the base technique
        base_technique = self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id == technique_id
        ).first()

        if not base_technique:
            return suggestions

        # 1. Check predefined relationships
        if technique_id in self.TECHNIQUE_RELATIONSHIPS:
            related_ids = self.TECHNIQUE_RELATIONSHIPS[technique_id]
            related = self.db.query(MitreTechnique).filter(
                MitreTechnique.technique_id.in_(related_ids)
            ).all()

            for tech in related:
                suggestions.append({
                    "technique_id": tech.technique_id,
                    "name": tech.name,
                    "tactics": tech.tactics,
                    "reason": "Commonly observed together in attack chains",
                    "confidence": "high",
                    "relationship_type": "sequential"
                })

        # 2. Find techniques sharing the same tactics
        if base_technique.tactics:
            same_tactic = self.db.query(MitreTechnique).filter(
                and_(
                    MitreTechnique.technique_id != technique_id,
                    MitreTechnique.tactics.overlap(base_technique.tactics)
                )
            ).limit(3).all()

            for tech in same_tactic:
                if not any(s["technique_id"] == tech.technique_id for s in suggestions):
                    suggestions.append({
                        "technique_id": tech.technique_id,
                        "name": tech.name,
                        "tactics": tech.tactics,
                        "reason": f"Shares tactics: {', '.join(set(base_technique.tactics) & set(tech.tactics))}",
                        "confidence": "medium",
                        "relationship_type": "same_tactic"
                    })

        # 3. Find next kill chain phase techniques
        next_phase_techs = self._get_next_kill_chain_techniques(base_technique)
        for tech in next_phase_techs:
            if not any(s["technique_id"] == tech.technique_id for s in suggestions):
                suggestions.append({
                    "technique_id": tech.technique_id,
                    "name": tech.name,
                    "tactics": tech.tactics,
                    "reason": "Logical next step in attack progression",
                    "confidence": "medium",
                    "relationship_type": "kill_chain_progression"
                })

        return suggestions[:limit]

    def recommend_hunt_sequence(
        self,
        technique_ids: List[str]
    ) -> List[Dict]:
        """
        Recommend an optimal hunting sequence based on kill chain order.

        Args:
            technique_ids: List of MITRE technique IDs

        Returns:
            Ordered list of techniques with hunt recommendations
        """
        techniques = self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id.in_(technique_ids)
        ).all()

        if not techniques:
            return []

        # Sort techniques by kill chain order
        sorted_techniques = self._sort_by_kill_chain(techniques)

        sequence = []
        for idx, tech in enumerate(sorted_techniques):
            # Determine hunt priority based on position
            if idx == 0:
                priority = "high"
                rationale = "Initial access or early-stage technique - start here"
            elif idx < len(sorted_techniques) - 1:
                priority = "medium"
                rationale = "Mid-stage technique - hunt after earlier phases"
            else:
                priority = "low"
                rationale = "Late-stage technique - hunt after establishing earlier activity"

            # Check if we have effective queries
            template_count = self.db.query(func.count(DetectionTemplate.id)).filter(
                DetectionTemplate.technique_id == tech.technique_id
            ).scalar()

            sequence.append({
                "order": idx + 1,
                "technique_id": tech.technique_id,
                "name": tech.name,
                "tactics": tech.tactics,
                "priority": priority,
                "rationale": rationale,
                "templates_available": template_count,
                "hunt_ready": template_count > 0
            })

        return sequence

    def identify_coverage_gaps(
        self,
        tactic: Optional[str] = None
    ) -> Dict:
        """
        Identify gaps in detection coverage.

        Args:
            tactic: Optional tactic to focus on

        Returns:
            Coverage gap analysis
        """
        # Get all techniques
        query = self.db.query(MitreTechnique)
        if tactic:
            query = query.filter(MitreTechnique.tactics.contains([tactic]))

        all_techniques = query.all()
        total_techniques = len(all_techniques)

        # Get techniques with templates
        covered_technique_ids = self.db.query(DetectionTemplate.technique_id.distinct()).all()
        covered_ids = {tid[0] for tid in covered_technique_ids}

        covered_count = len(covered_ids)
        coverage_percentage = (covered_count / total_techniques * 100) if total_techniques > 0 else 0

        # Find gaps (techniques without templates)
        gaps = []
        for tech in all_techniques:
            if tech.technique_id not in covered_ids:
                gaps.append({
                    "technique_id": tech.technique_id,
                    "name": tech.name,
                    "tactics": tech.tactics,
                    "platforms": tech.platforms,
                    "priority": self._calculate_gap_priority(tech)
                })

        # Sort gaps by priority
        gaps.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}[x["priority"]])

        # Get tactics breakdown
        tactics_coverage = {}
        if all_techniques:
            for tech in all_techniques:
                for tactic_item in tech.tactics or []:
                    if tactic_item not in tactics_coverage:
                        tactics_coverage[tactic_item] = {"total": 0, "covered": 0}
                    tactics_coverage[tactic_item]["total"] += 1
                    if tech.technique_id in covered_ids:
                        tactics_coverage[tactic_item]["covered"] += 1

        for tactic_key in tactics_coverage:
            total = tactics_coverage[tactic_key]["total"]
            covered = tactics_coverage[tactic_key]["covered"]
            tactics_coverage[tactic_key]["percentage"] = (covered / total * 100) if total > 0 else 0

        return {
            "total_techniques": total_techniques,
            "covered_techniques": covered_count,
            "coverage_percentage": round(coverage_percentage, 2),
            "gaps_count": len(gaps),
            "gaps": gaps[:20],  # Limit to top 20 gaps
            "tactics_coverage": tactics_coverage,
            "tactic_filter": tactic
        }

    def _sort_by_kill_chain(self, techniques: List[MitreTechnique]) -> List[MitreTechnique]:
        """Sort techniques by kill chain order."""
        def get_min_phase_index(tech: MitreTechnique) -> int:
            """Get the earliest kill chain phase index for a technique."""
            if not tech.tactics:
                return 999  # Put techniques without tactics at the end

            min_index = 999
            for tactic in tech.tactics:
                tactic_lower = tactic.lower().replace(" ", "-")
                if tactic_lower in self.KILL_CHAIN_ORDER:
                    idx = self.KILL_CHAIN_ORDER.index(tactic_lower)
                    min_index = min(min_index, idx)
            return min_index

        return sorted(techniques, key=get_min_phase_index)

    def _get_next_kill_chain_techniques(
        self,
        technique: MitreTechnique,
        limit: int = 3
    ) -> List[MitreTechnique]:
        """Get techniques from the next kill chain phases."""
        if not technique.tactics:
            return []

        # Find the current phase
        current_phases = [t.lower().replace(" ", "-") for t in technique.tactics]
        current_indices = [
            self.KILL_CHAIN_ORDER.index(p)
            for p in current_phases
            if p in self.KILL_CHAIN_ORDER
        ]

        if not current_indices:
            return []

        # Get next 1-2 phases
        max_current = max(current_indices)
        next_phases = []
        for i in range(max_current + 1, min(max_current + 3, len(self.KILL_CHAIN_ORDER))):
            phase = self.KILL_CHAIN_ORDER[i]
            # Convert back to display format
            display_phase = phase.replace("-", " ").title()
            next_phases.append(display_phase)

        if not next_phases:
            return []

        # Query techniques in next phases
        next_techniques = self.db.query(MitreTechnique).filter(
            MitreTechnique.tactics.overlap(next_phases)
        ).limit(limit).all()

        return next_techniques

    def _calculate_gap_priority(self, technique: MitreTechnique) -> str:
        """Calculate priority for a coverage gap."""
        # High priority tactics
        high_priority_tactics = [
            "initial-access",
            "execution",
            "persistence",
            "privilege-escalation",
            "credential-access",
            "lateral-movement"
        ]

        if not technique.tactics:
            return "low"

        tactics_lower = [t.lower().replace(" ", "-") for t in technique.tactics]

        # Check if technique is in high priority tactics
        for tactic in tactics_lower:
            if tactic in high_priority_tactics:
                # Critical if in initial access or execution
                if tactic in ["initial-access", "execution"]:
                    return "critical"
                return "high"

        return "medium"

    def generate_hypothesis(
        self,
        technique_id: str,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Generate a comprehensive hunting hypothesis.

        Args:
            technique_id: MITRE technique ID
            context: Optional context (threat actor, recent intel, etc.)

        Returns:
            Comprehensive hunting hypothesis
        """
        technique = self.db.query(MitreTechnique).filter(
            MitreTechnique.technique_id == technique_id
        ).first()

        if not technique:
            return {"error": "Technique not found"}

        # Get related techniques
        related = self.suggest_related_techniques(technique_id, limit=5)

        # Get hunt sequence
        sequence = self.recommend_hunt_sequence([technique_id] + [r["technique_id"] for r in related[:3]])

        # Generate hypothesis narrative
        hypothesis_text = self._generate_hypothesis_narrative(technique, related, context)

        return {
            "technique": {
                "id": technique.technique_id,
                "name": technique.name,
                "tactics": technique.tactics,
                "description": technique.description
            },
            "hypothesis": hypothesis_text,
            "related_techniques": related,
            "recommended_hunt_sequence": sequence,
            "context": context or {}
        }

    def _generate_hypothesis_narrative(
        self,
        technique: MitreTechnique,
        related: List[Dict],
        context: Optional[Dict]
    ) -> str:
        """Generate a narrative hypothesis for hunting."""
        narrative = f"If adversaries are using {technique.name} ({technique.technique_id}), "

        if context and context.get("threat_actor"):
            narrative += f"particularly in the context of {context['threat_actor']} activity, "

        narrative += "we should also investigate the following:\n\n"

        if related:
            narrative += "Related Techniques:\n"
            for idx, rel in enumerate(related[:3], 1):
                narrative += f"{idx}. {rel['name']} ({rel['technique_id']}) - {rel['reason']}\n"

        narrative += "\nThis hypothesis is based on common attack patterns and kill chain progression."

        return narrative
