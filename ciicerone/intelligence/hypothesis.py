"""Hypothesis Validation Pipeline for Blue Team threat hunting.

Scores hunting hypotheses by likelihood, impact, and detectability
to prioritize the most promising leads for investigation.

Issue: Hypothesis validation pipeline (scores by likelihood, impact, detectability)
Owner: David Onoja (@ocheme1107)
Track: Blue Team / Detection Engineering
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from .mitre_attack import (
    MITREATTACKEngine,
    ATTACKTechnique,
    ATTACKGroup,
    ATTACKMatrix,
    ENTERPRISE_TACTICS,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Enums & Constants
# ============================================================================


class HypothesisStatus(str, Enum):
    DRAFT = "draft"
    VALIDATED = "validated"
    IN_PROGRESS = "in_progress"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"


class LikelihoodFactor(str, Enum):
    THREAT_ACTOR_USAGE = "threat_actor_usage"
    TECHNIQUE_PREVALENCE = "technique_prevalence"
    HISTORICAL_INCIDENTS = "historical_incidents"
    CURRENT_THREAT_LANDSCAPE = "current_threat_landscape"
    PLATFORM_RELEVANCE = "platform_relevance"
    INDUSTRY_TARGETING = "industry_targeting"
    RECENT_CAMPAIGNS = "recent_campaigns"
    TOOL_AVAILABILITY = "tool_availability"
    PUBLIC_EXPLOITS = "public_exploits"
    EASE_OF_EXECUTION = "ease_of_execution"


class ImpactFactor(str, Enum):
    DATA_EXFILTRATION = "data_exfiltration"
    SYSTEM_COMPROMISE = "system_compromise"
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    BUSINESS_IMPACT = "business_impact"
    REGULATORY_VIOLATION = "regulatory_violation"
    REPUTATIONAL_DAMAGE = "reputational_damage"
    FINANCIAL_LOSS = "financial_loss"


class DetectabilityFactor(str, Enum):
    DATA_SOURCE_AVAILABILITY = "data_source_availability"
    DETECTION_RULE_COVERAGE = "detection_rule_coverage"
    SIGNAL_TO_NOISE_RATIO = "signal_to_noise_ratio"
    DETECTION_COMPLEXITY = "detection_complexity"
    FALSE_POSITIVE_RATE = "false_positive_rate"
    REQUIRED_TOOLING = "required_tooling"
    ANALYST_SKILL_LEVEL = "analyst_skill_level"
    CORRELATION_REQUIRED = "correlation_required"


class HypothesisSource(str, Enum):
    MITRE_TECHNIQUE = "mitre_technique"
    THREAT_INTEL = "threat_intel"
    HISTORICAL_INCIDENT = "historical_incident"
    USER_BEHAVIOR_ANALYTICS = "user_behavior_analytics"
    NETWORK_ANOMALY = "network_anomaly"
    THREAT_HUNTING = "threat_hunting"
    INTELLIGENCE_FEED = "intelligence_feed"
    MANUAL = "manual"


class ValidationStatus(str, Enum):
    PENDING = "pending"
    VALIDATED = "validated"
    REJECTED = "rejected"
    ESCALATED = "escalated"


# ============================================================================
# Scoring Models
# ============================================================================


@dataclass
class LikelihoodScore:
    score: float
    factors: Dict[LikelihoodFactor, float]
    reasoning: str

    def __post_init__(self):
        self.score = max(0.0, min(1.0, self.score))


@dataclass
class ImpactScore:
    score: float
    factors: Dict[ImpactFactor, float]
    reasoning: str

    def __post_init__(self):
        self.score = max(0.0, min(1.0, self.score))


@dataclass
class DetectabilityScore:
    score: float
    factors: Dict[DetectabilityFactor, float]
    reasoning: str

    def __post_init__(self):
        self.score = max(0.0, min(1.0, self.score))


@dataclass
class HypothesisValidationResult:
    hypothesis_id: str
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    likelihood: LikelihoodScore
    impact: ImpactScore
    detectability: DetectabilityScore
    overall_score: float
    priority: str
    recommendation: str
    supporting_evidence: List[str]
    related_groups: List[str]
    related_software: List[str]
    mitre_mitigations: List[str]
    status: ValidationStatus
    validated_at: datetime
    source: HypothesisSource
    ttl_hours: int

    @property
    def risk_score(self) -> float:
        return self.likelihood.score * self.impact.score

    @property
    def hunt_priority(self) -> float:
        return self.overall_score * (1 - self.detectability.score)

    @property
    def summary(self) -> str:
        return (
            f"[{self.priority}] {self.technique_id} - {self.technique_name} "
            f"(L:{self.likelihood.score:.2f} I:{self.impact.score:.2f} "
            f"D:{self.detectability.score:.2f} | Overall: {self.overall_score:.2f})"
        )


# ============================================================================
# Likelihood Scoring Engine
# ============================================================================


class LikelihoodScorer:
    def __init__(self, mitre_engine: MITREATTACKEngine):
        self._mitre = mitre_engine

    def score(self, technique_id: str, tactic: str) -> LikelihoodScore:
        technique = self._mitre.get_technique(technique_id)
        if not technique:
            return LikelihoodScore(
                score=0.3,
                factors={},
                reasoning=f"Technique {technique_id} not found in MITRE data; defaulting to medium-low likelihood"
            )

        factors: Dict[LikelihoodFactor, float] = {}
        reasoning_parts: List[str] = []

        factor = self._score_threat_actor_usage(technique_id)
        factors[LikelihoodFactor.THREAT_ACTOR_USAGE] = factor
        if factor >= 0.7:
            reasoning_parts.append(f"Widely used by threat actors (score: {factor:.2f})")
        elif factor >= 0.4:
            reasoning_parts.append(f"Moderate threat actor adoption (score: {factor:.2f})")
        else:
            reasoning_parts.append(f"Limited threat actor usage (score: {factor:.2f})")

        factor = self._score_technique_prevalence(technique)
        factors[LikelihoodFactor.TECHNIQUE_PREVALENCE] = factor
        if factor >= 0.7:
            reasoning_parts.append(f"Highly prevalent technique (score: {factor:.2f})")
        elif factor >= 0.4:
            reasoning_parts.append(f"Moderately prevalent technique (score: {factor:.2f})")
        else:
            reasoning_parts.append(f"Less common technique (score: {factor:.2f})")

        factor = self._score_platform_relevance(technique)
        factors[LikelihoodFactor.PLATFORM_RELEVANCE] = factor
        if factor >= 0.7:
            reasoning_parts.append(f"High platform relevance (score: {factor:.2f})")
        elif factor >= 0.4:
            reasoning_parts.append(f"Moderate platform relevance (score: {factor:.2f})")
        else:
            reasoning_parts.append(f"Limited platform relevance (score: {factor:.2f})")

        factor = self._score_industry_targeting(technique_id)
        factors[LikelihoodFactor.INDUSTRY_TARGETING] = factor
        if factor >= 0.7:
            reasoning_parts.append(f"Commonly targeted industry technique (score: {factor:.2f})")
        elif factor >= 0.4:
            reasoning_parts.append(f"Occasionally targeted industry technique (score: {factor:.2f})")
        else:
            reasoning_parts.append(f"Broad or non-specific targeting (score: {factor:.2f})")

        factor = self._score_ease_of_execution(technique)
        factors[LikelihoodFactor.EASE_OF_EXECUTION] = factor
        if factor >= 0.7:
            reasoning_parts.append(f"Easy to execute — low skill barrier (score: {factor:.2f})")
        elif factor >= 0.4:
            reasoning_parts.append(f"Moderate execution complexity (score: {factor:.2f})")
        else:
            reasoning_parts.append(f"Complex execution — requires advanced skills (score: {factor:.2f})")

        weights = {
            LikelihoodFactor.THREAT_ACTOR_USAGE: 0.25,
            LikelihoodFactor.TECHNIQUE_PREVALENCE: 0.20,
            LikelihoodFactor.PLATFORM_RELEVANCE: 0.15,
            LikelihoodFactor.INDUSTRY_TARGETING: 0.15,
            LikelihoodFactor.EASE_OF_EXECUTION: 0.25,
        }

        weighted_score = sum(
            factors.get(factor, 0.0) * weight
            for factor, weight in weights.items()
        )

        return LikelihoodScore(
            score=weighted_score,
            factors=factors,
            reasoning="; ".join(reasoning_parts)
        )

    def _score_threat_actor_usage(self, technique_id: str) -> float:
        groups = self._mitre.get_groups_using_technique(technique_id)
        if not groups:
            return 0.2
        count = len(groups)
        if count >= 10:
            return 0.95
        elif count >= 5:
            return 0.80
        elif count >= 3:
            return 0.65
        elif count >= 1:
            return 0.50
        return 0.2

    def _score_technique_prevalence(self, technique: ATTACKTechnique) -> float:
        if not technique:
            return 0.3
        platforms = len(technique.platforms)
        sub_count = len(technique.sub_techniques)
        base = 0.3
        base += min(platforms * 0.08, 0.35)
        base += min(sub_count * 0.05, 0.20)
        return min(base, 0.95)

    def _score_platform_relevance(self, technique: ATTACKTechnique) -> float:
        if not technique or not technique.platforms:
            return 0.3
        common_platforms = {"windows", "linux", "macos", "cloud", "network"}
        relevant = sum(1 for p in technique.platforms if p.lower() in common_platforms)
        if not technique.platforms:
            return 0.3
        ratio = relevant / len(technique.platforms)
        return 0.3 + (ratio * 0.6)

    def _score_industry_targeting(self, technique_id: str) -> float:
        groups = self._mitre.get_groups_using_technique(technique_id)
        if not groups:
            return 0.3
        high_profile_groups = sum(1 for g in groups if g.name and len(g.aliases) > 2)
        if high_profile_groups >= 5:
            return 0.85
        elif high_profile_groups >= 3:
            return 0.70
        elif high_profile_groups >= 1:
            return 0.55
        return 0.3

    def _score_ease_of_execution(self, technique: ATTACKTechnique) -> float:
        if not technique:
            return 0.5
        low_barrier_tactics = {
            "initial-access", "execution", "persistence",
            "defense-evasion", "discovery", "collection"
        }
        has_low_barrier = any(t in low_barrier_tactics for t in technique.tactics)
        has_multi_platform = len(technique.platforms) >= 3
        has_subtechniques = len(technique.sub_techniques) > 0
        score = 0.3
        if has_low_barrier:
            score += 0.25
        if has_multi_platform:
            score += 0.20
        if has_subtechniques:
            score += 0.15
        return min(score, 0.95)


# ============================================================================
# Impact Scoring Engine
# ============================================================================


class ImpactScorer:
    HIGH_IMPACT_TACTICS = {
        "impact", "exfiltration", "credential-access",
        "lateral-movement", "privilege-escalation"
    }
    MEDIUM_IMPACT_TACTICS = {
        "persistence", "defense-evasion", "collection",
        "command-and-control"
    }

    TACTIC_IMPACT_WEIGHTS = {
        "impact": 0.95,
        "exfiltration": 0.90,
        "credential-access": 0.85,
        "lateral-movement": 0.80,
        "privilege-escalation": 0.75,
        "persistence": 0.60,
        "defense-evasion": 0.55,
        "collection": 0.50,
        "command-and-control": 0.50,
        "execution": 0.45,
        "initial-access": 0.40,
        "discovery": 0.30,
        "reconnaissance": 0.20,
        "resource-development": 0.15,
    }

    def __init__(self, mitre_engine: MITREATTACKEngine):
        self._mitre = mitre_engine

    def score(self, technique_id: str) -> ImpactScore:
        technique = self._mitre.get_technique(technique_id)
        if not technique:
            return ImpactScore(
                score=0.3,
                factors={},
                reasoning=f"Technique {technique_id} not found; defaulting to medium impact"
            )

        factors: Dict[ImpactFactor, float] = {}
        reasoning_parts: List[str] = []

        factor = self._score_data_exfiltration(technique)
        factors[ImpactFactor.DATA_EXFILTRATION] = factor
        if factor >= 0.7:
            reasoning_parts.append(f"High data exfiltration potential (score: {factor:.2f})")
        elif factor >= 0.4:
            reasoning_parts.append(f"Moderate data exfiltration potential (score: {factor:.2f})")
        else:
            reasoning_parts.append(f"Low data exfiltration potential (score: {factor:.2f})")

        factor = self._score_system_compromise(technique)
        factors[ImpactFactor.SYSTEM_COMPROMISE] = factor
        if factor >= 0.7:
            reasoning_parts.append(f"High system compromise risk (score: {factor:.2f})")
        elif factor >= 0.4:
            reasoning_parts.append(f"Moderate system compromise risk (score: {factor:.2f})")
        else:
            reasoning_parts.append(f"Low system compromise risk (score: {factor:.2f})")

        factor = self._score_credential_theft(technique)
        factors[ImpactFactor.CREDENTIAL_THEFT] = factor
        if factor >= 0.7:
            reasoning_parts.append(f"High credential theft risk (score: {factor:.2f})")
        elif factor >= 0.4:
            reasoning_parts.append(f"Moderate credential theft risk (score: {factor:.2f})")
        else:
            reasoning_parts.append(f"Low credential theft risk (score: {factor:.2f})")

        factor = self._score_lateral_movement(technique)
        factors[ImpactFactor.LATERAL_MOVEMENT] = factor
        if factor >= 0.7:
            reasoning_parts.append(f"High lateral movement potential (score: {factor:.2f})")
        elif factor >= 0.4:
            reasoning_parts.append(f"Moderate lateral movement potential (score: {factor:.2f})")
        else:
            reasoning_parts.append(f"Low lateral movement potential (score: {factor:.2f})")

        factor = self._score_business_impact(technique)
        factors[ImpactFactor.BUSINESS_IMPACT] = factor
        if factor >= 0.7:
            reasoning_parts.append(f"High business impact (score: {factor:.2f})")
        elif factor >= 0.4:
            reasoning_parts.append(f"Moderate business impact (score: {factor:.2f})")
        else:
            reasoning_parts.append(f"Low business impact (score: {factor:.2f})")

        weights = {
            ImpactFactor.DATA_EXFILTRATION: 0.20,
            ImpactFactor.SYSTEM_COMPROMISE: 0.20,
            ImpactFactor.CREDENTIAL_THEFT: 0.20,
            ImpactFactor.LATERAL_MOVEMENT: 0.15,
            ImpactFactor.BUSINESS_IMPACT: 0.25,
        }

        weighted_score = sum(
            factors.get(factor, 0.0) * weight
            for factor, weight in weights.items()
        )

        return ImpactScore(
            score=weighted_score,
            factors=factors,
            reasoning="; ".join(reasoning_parts)
        )

    def _score_data_exfiltration(self, technique: ATTACKTechnique) -> float:
        if not technique:
            return 0.3
        exfil_tactics = {"exfiltration", "collection"}
        has_exfil = any(t in exfil_tactics for t in technique.tactics)
        if has_exfil:
            return 0.85
        if "credential-access" in technique.tactics:
            return 0.70
        return 0.25

    def _score_system_compromise(self, technique: ATTACKTechnique) -> float:
        if not technique:
            return 0.3
        compromise_tactics = {"execution", "persistence", "privilege-escalation"}
        has_compromise = any(t in compromise_tactics for t in technique.tactics)
        if has_compromise and "defense-evasion" in technique.tactics:
            return 0.90
        if has_compromise:
            return 0.70
        if "initial-access" in technique.tactics:
            return 0.50
        return 0.20

    def _score_credential_theft(self, technique: ATTACKTechnique) -> float:
        if not technique:
            return 0.3
        if "credential-access" in technique.tactics:
            return 0.90
        if "initial-access" in technique.tactics:
            return 0.55
        if "lateral-movement" in technique.tactics:
            return 0.50
        return 0.20

    def _score_lateral_movement(self, technique: ATTACKTechnique) -> float:
        if not technique:
            return 0.3
        if "lateral-movement" in technique.tactics:
            return 0.85
        if "credential-access" in technique.tactics:
            return 0.60
        if "execution" in technique.tactics:
            return 0.45
        return 0.20

    def _score_business_impact(self, technique: ATTACKTechnique) -> float:
        if not technique:
            return 0.3
        score = 0.2
        for tactic in technique.tactics:
            tactic_score = self.TACTIC_IMPACT_WEIGHTS.get(tactic, 0.0)
            score = max(score, tactic_score)
        if technique.platforms:
            score += min(len(technique.platforms) * 0.03, 0.15)
        return min(score, 0.95)


# ============================================================================
# Detectability Scoring Engine
# ============================================================================


class DetectabilityScorer:
    HIGH_DETECTABILITY_TACTICS = {
        "reconnaissance", "resource-development", "initial-access",
        "execution", "discovery"
    }
    LOW_DETECTABILITY_TACTICS = {
        "defense-evasion", "persistence", "privilege-escalation",
        "credential-access", "exfiltration"
    }

    def __init__(self, mitre_engine: MITREATTACKEngine):
        self._mitre = mitre_engine

    def score(self, technique_id: str) -> DetectabilityScore:
        technique = self._mitre.get_technique(technique_id)
        if not technique:
            return DetectabilityScore(
                score=0.5,
                factors={},
                reasoning=f"Technique {technique_id} not found; defaulting to medium detectability"
            )

        factors: Dict[DetectabilityFactor, float] = {}
        reasoning_parts: List[str] = []

        factor = self._score_data_source_availability(technique)
        factors[DetectabilityFactor.DATA_SOURCE_AVAILABILITY] = factor
        if factor >= 0.7:
            reasoning_parts.append(f"Good data source coverage (score: {factor:.2f})")
        elif factor >= 0.4:
            reasoning_parts.append(f"Partial data source coverage (score: {factor:.2f})")
        else:
            reasoning_parts.append(f"Limited data source coverage (score: {factor:.2f})")

        factor = self._score_detection_complexity(technique)
        factors[DetectabilityFactor.DETECTION_COMPLEXITY] = factor
        if factor >= 0.7:
            reasoning_parts.append(f"Easy to detect (score: {factor:.2f})")
        elif factor >= 0.4:
            reasoning_parts.append(f"Moderately detectable (score: {factor:.2f})")
        else:
            reasoning_parts.append(f"Difficult to detect (score: {factor:.2f})")

        factor = self._score_signal_to_noise(technique)
        factors[DetectabilityFactor.SIGNAL_TO_NOISE_RATIO] = factor
        if factor >= 0.7:
            reasoning_parts.append(f"High signal-to-noise ratio (score: {factor:.2f})")
        elif factor >= 0.4:
            reasoning_parts.append(f"Moderate signal-to-noise ratio (score: {factor:.2f})")
        else:
            reasoning_parts.append(f"Low signal-to-noise ratio (score: {factor:.2f})")

        factor = self._score_correlation_requirement(technique)
        factors[DetectabilityFactor.CORRELATION_REQUIRED] = factor
        if factor >= 0.7:
            reasoning_parts.append(f"Single-source detection possible (score: {factor:.2f})")
        elif factor >= 0.4:
            reasoning_parts.append(f"Multi-source correlation needed (score: {factor:.2f})")
        else:
            reasoning_parts.append(f"Complex correlation required (score: {factor:.2f})")

        weights = {
            DetectabilityFactor.DATA_SOURCE_AVAILABILITY: 0.30,
            DetectabilityFactor.DETECTION_COMPLEXITY: 0.30,
            DetectabilityFactor.SIGNAL_TO_NOISE_RATIO: 0.20,
            DetectabilityFactor.CORRELATION_REQUIRED: 0.20,
        }

        weighted_score = sum(
            factors.get(factor, 0.0) * weight
            for factor, weight in weights.items()
        )

        return DetectabilityScore(
            score=weighted_score,
            factors=factors,
            reasoning="; ".join(reasoning_parts)
        )

    def _score_data_source_availability(self, technique: ATTACKTechnique) -> float:
        if not technique:
            return 0.3
        data_sources = technique.data_sources
        if not data_sources:
            return 0.2
        high_value_sources = {"process", "command", "file", "network", "module", "registry"}
        matched = sum(1 for ds in data_sources if any(hv in ds.lower() for hv in high_value_sources))
        ratio = matched / len(data_sources) if data_sources else 0
        return 0.2 + (ratio * 0.7)

    def _score_detection_complexity(self, technique: ATTACKTechnique) -> float:
        if not technique:
            return 0.5
        has_high_detect = any(t in self.HIGH_DETECTABILITY_TACTICS for t in technique.tactics)
        has_low_detect = any(t in self.LOW_DETECTABILITY_TACTICS for t in technique.tactics)
        if has_high_detect and not has_low_detect:
            return 0.80
        if has_high_detect and has_low_detect:
            return 0.50
        if has_low_detect and not has_high_detect:
            return 0.30
        return 0.50

    def _score_signal_to_noise(self, technique: ATTACKTechnique) -> float:
        if not technique:
            return 0.5
        noisy_tactics = {"discovery", "reconnaissance", "execution"}
        stealthy_tactics = {"defense-evasion", "persistence", "credential-access"}
        is_noisy = any(t in noisy_tactics for t in technique.tactics)
        is_stealthy = any(t in stealthy_tactics for t in technique.tactics)
        if is_noisy and not is_stealthy:
            return 0.75
        if is_noisy and is_stealthy:
            return 0.50
        if is_stealthy and not is_noisy:
            return 0.30
        return 0.50

    def _score_correlation_requirement(self, technique: ATTACKTechnique) -> float:
        if not technique:
            return 0.5
        data_sources = technique.data_sources
        if not data_sources:
            return 0.3
        single_source_tactics = {"reconnaissance", "discovery", "execution"}
        multi_source_tactics = {"defense-evasion", "persistence", "exfiltration"}
        has_single = any(t in single_source_tactics for t in technique.tactics)
        has_multi = any(t in multi_source_tactics for t in technique.tactics)
        if has_single and not has_multi:
            return 0.80
        if has_single and has_multi:
            return 0.55
        if has_multi and not has_single:
            return 0.30
        return 0.50


# ============================================================================
# Hypothesis Validation Pipeline
# ============================================================================


@dataclass
class RawHypothesis:
    technique_id: str
    tactic: str
    description: str
    source: HypothesisSource = HypothesisSource.MITRE_TECHNIQUE
    context: Dict[str, Any] = field(default_factory=dict)


class HypothesisValidationPipeline:
    LIKELIHOOD_WEIGHT = 0.35
    IMPACT_WEIGHT = 0.40
    DETECTABILITY_WEIGHT = 0.25

    PRIORITY_THRESHOLDS = [
        (0.80, "critical"),
        (0.65, "high"),
        (0.45, "medium"),
        (0.25, "low"),
    ]

    def __init__(
        self,
        mitre_engine: MITREATTACKEngine,
        likelihood_scorer: Optional[LikelihoodScorer] = None,
        impact_scorer: Optional[ImpactScorer] = None,
        detectability_scorer: Optional[DetectabilityScorer] = None,
    ):
        self._mitre = mitre_engine
        self._likelihood_scorer = likelihood_scorer or LikelihoodScorer(mitre_engine)
        self._impact_scorer = impact_scorer or ImpactScorer(mitre_engine)
        self._detectability_scorer = detectability_scorer or DetectabilityScorer(mitre_engine)
        self._validation_history: Dict[str, HypothesisValidationResult] = {}

    def validate(self, hypothesis: RawHypothesis) -> HypothesisValidationResult:
        technique = self._mitre.get_technique(hypothesis.technique_id)
        if not technique:
            return HypothesisValidationResult(
                hypothesis_id=str(uuid4()),
                technique_id=hypothesis.technique_id,
                technique_name=hypothesis.technique_id,
                tactic=hypothesis.tactic,
                description=hypothesis.description,
                likelihood=LikelihoodScore(0.3, {}, "Technique not found in MITRE data"),
                impact=ImpactScore(0.3, {}, "Technique not found in MITRE data"),
                detectability=DetectabilityScore(0.5, {}, "Technique not found in MITRE data"),
                overall_score=0.3,
                priority="low",
                recommendation="Validate technique ID and re-submit",
                supporting_evidence=[],
                related_groups=[],
                related_software=[],
                mitre_mitigations=[],
                status=ValidationStatus.REJECTED,
                validated_at=datetime.utcnow(),
                source=hypothesis.source,
                ttl_hours=24,
            )

        likelihood = self._likelihood_scorer.score(technique_id, hypothesis.tactic)
        impact = self._impact_scorer.score(technique_id)
        detectability = self._detectability_scorer.score(technique_id)

        overall = (
            likelihood.score * self.LIKELIHOOD_WEIGHT
            + impact.score * self.IMPACT_WEIGHT
            + detectability.score * self.DETECTABILITY_WEIGHT
        )

        priority = "low"
        for threshold, label in self.PRIORITY_THRESHOLDS:
            if overall >= threshold:
                priority = label
                break

        recommendation = self._generate_recommendation(
            likelihood, impact, detectability, overall, technique
        )

        groups = self._mitre.get_groups_using_technique(technique_id)
        software = self._mitre.get_software_using_technique(technique_id)
        mitigations = self._mitre.get_mitigations_for_technique(technique_id)

        evidence = self._build_evidence(technique, likelihood, impact, detectability)

        result = HypothesisValidationResult(
            hypothesis_id=str(uuid4()),
            technique_id=technique_id,
            technique_name=technique.name if technique else technique_id,
            tactic=hypothesis.tactic,
            description=hypothesis.description,
            likelihood=likelihood,
            impact=impact,
            detectability=detectability,
            overall_score=overall,
            priority=priority,
            recommendation=recommendation,
            supporting_evidence=evidence,
            related_groups=[g.name for g in groups],
            related_software=[s.name for s in software],
            mitre_mitigations=[m.name for m in mitigations],
            status=ValidationStatus.VALIDATED,
            validated_at=datetime.utcnow(),
            source=hypothesis.source,
            ttl_hours=48,
        )

        self._validation_history[result.hypothesis_id] = result
        return result

    def validate_batch(
        self,
        hypotheses: List[RawHypothesis],
        max_results: Optional[int] = None
    ) -> List[HypothesisValidationResult]:
        results = [self.validate(h) for h in hypotheses]
        results.sort(key=lambda r: r.overall_score, reverse=True)
        if max_results:
            results = results[:max_results]
        return results

    def get_validation_history(
        self,
        min_score: float = 0.0,
        status: Optional[ValidationStatus] = None,
        limit: int = 50
    ) -> List[HypothesisValidationResult]:
        results = list(self._validation_history.values())
        if min_score > 0.0:
            results = [r for r in results if r.overall_score >= min_score]
        if status:
            results = [r for r in results if r.status == status]
        results.sort(key=lambda r: r.overall_score, reverse=True)
        return results[:limit]

    def _generate_recommendation(
        self,
        likelihood: LikelihoodScore,
        impact: ImpactScore,
        detectability: DetectabilityScore,
        overall: float,
        technique: Optional[ATTACKTechnique],
    ) -> str:
        if overall >= 0.80:
            return (
                f"High-priority hunt: technique has {self._describe_score(likelihood.score)} likelihood, "
                f"{self._describe_score(impact.score)} impact, and is "
                f"{'readily detectable' if detectability.score >= 0.6 else 'challenging to detect'}. "
                f"Begin immediate investigation with available detection rules."
            )
        elif overall >= 0.60:
            return (
                f"Medium-high priority: {self._describe_score(likelihood.score)} likelihood with "
                f"{self._describe_score(impact.score)} impact. "
                f"Review existing detection coverage before initiating hunt."
            )
        elif overall >= 0.40:
            return (
                f"Moderate priority: technique warrants periodic review. "
                f"Likelihood is {self._describe_score(likelihood.score)} and impact is "
                f"{self._describe_score(impact.score)}. Schedule for next hunt cycle."
            )
        else:
            return (
                f"Low priority: {self._describe_score(likelihood.score)} likelihood and "
                f"{self._describe_score(impact.score)} impact. Log for trend analysis."
            )

    def _build_evidence(
        self,
        technique: Optional[ATTACKTechnique],
        likelihood: LikelihoodScore,
        impact: ImpactScore,
        detectability: DetectabilityScore,
    ) -> List[str]:
        evidence = []
        if technique:
            evidence.append(f"MITRE ATT&CK technique: {technique.id} - {technique.name}")
            evidence.append(f"Tactics: {', '.join(technique.tactics)}")
            evidence.append(f"Platforms: {', '.join(technique.platforms)}")
            if technique.data_sources:
                evidence.append(f"Data sources: {', '.join(technique.data_sources)}")
        evidence.append(f"Likelihood factors: {likelihood.reasoning}")
        evidence.append(f"Impact factors: {impact.reasoning}")
        evidence.append(f"Detectability factors: {detectability.reasoning}")
        return evidence

    def _describe_score(self, score: float) -> str:
        if score >= 0.80:
            return "very high"
        elif score >= 0.60:
            return "high"
        elif score >= 0.40:
            return "moderate"
        elif score >= 0.20:
            return "low"
        return "very low"


# ============================================================================
# Convenience Factory
# ============================================================================


def create_hypothesis_validation_pipeline(
    mitre_engine: MITREATTACKEngine,
) -> HypothesisValidationPipeline:
    return HypothesisValidationPipeline(mitre_engine)
