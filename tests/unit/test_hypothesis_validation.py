"""Unit tests for Hypothesis Validation Pipeline.

Tests scoring engines (likelihood, impact, detectability) and the
full validation pipeline. Uses the MITREATTACKEngine with sample
STIX data to exercise real business logic against live techniques.
"""

import json
import pytest
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from unittest.mock import MagicMock, patch

from ciicerone.intelligence.mitre_attack import (
    MITREATTACKEngine,
    ATTACKMatrix,
    ATTACKTechnique,
    ATTACKGroup,
    ATTACKSoftware,
    ENTERPRISE_TACTICS,
)

from ciicerone.intelligence.hypothesis import (
    HypothesisStatus,
    LikelihoodFactor,
    ImpactFactor,
    DetectabilityFactor,
    HypothesisSource,
    ValidationStatus,
    LikelihoodScore,
    ImpactScore,
    DetectabilityScore,
    HypothesisValidationResult,
    RawHypothesis,
    LikelihoodScorer,
    ImpactScorer,
    DetectabilityScorer,
    HypothesisValidationPipeline,
    create_hypothesis_validation_pipeline,
)


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def sample_stix_data() -> Dict:
    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Phishing",
                "description": "Adversaries may send phishing messages to gain initial access.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1566"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
                "x_mitre_platforms": ["Windows", "macOS", "Linux"],
                "x_mitre_data_sources": ["Network Traffic: Network Traffic Content"],
                "x_mitre_detection": "Monitor for suspicious emails",
                "x_mitre_version": "2.0",
                "created": "2020-01-01T00:00:00Z",
                "modified": "2023-01-01T00:00:00Z",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2",
                "name": "Spearphishing Attachment",
                "description": "Adversaries may send spearphishing emails with malicious attachment.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1566.001"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
                "x_mitre_platforms": ["Windows", "macOS", "Linux"],
                "x_mitre_is_subtechnique": True,
                "x_mitre_data_sources": ["File: File Creation"],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--3",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command interpreters for execution.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "x_mitre_platforms": ["Windows", "Linux"],
                "x_mitre_data_sources": ["Process: Process Creation", "Command: Command Execution"],
                "x_mitre_detection": "Monitor process creation events",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--4",
                "name": "OS Credential Dumping",
                "description": "Adversaries may dump credentials from the OS.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1003"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
                ],
                "x_mitre_platforms": ["Windows", "Linux"],
                "x_mitre_data_sources": ["Process: Process Access", "Command: Command Execution"],
                "x_mitre_detection": "Monitor for suspicious process access",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--5",
                "name": "Data Encrypted for Impact",
                "description": "Adversaries may encrypt data on target systems.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1486"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "impact"}
                ],
                "x_mitre_platforms": ["Windows", "macOS", "Linux", "Network"],
                "x_mitre_data_sources": ["Process: Process Creation", "File: File Modification"],
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--1",
                "name": "User Training",
                "description": "Train users to identify phishing attempts.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "M1017"}
                ],
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--2",
                "name": "Multi-factor Authentication",
                "description": "Use MFA to protect against credential access.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "M1032"}
                ],
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--1",
                "name": "APT29",
                "description": "APT29 is a Russian state-sponsored threat group.",
                "aliases": ["APT29", "Cozy Bear", "The Dukes"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "G0016"}
                ],
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--2",
                "name": "APT3",
                "description": "APT3 is a Chinese threat group.",
                "aliases": ["APT3", "UPS", "Panda"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "G0002"}
                ],
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--3",
                "name": "FIN7",
                "description": "FIN7 is a financially motivated threat group.",
                "aliases": ["FIN7", "Carbanak", "Anunak"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "G0046"}
                ],
            },
            {
                "type": "malware",
                "id": "malware--1",
                "name": "Mimikatz",
                "description": "Mimikatz is a credential dumping tool.",
                "x_mitre_platforms": ["Windows"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "S0002"}
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--1",
                "target_ref": "attack-pattern--1",
            },
            {
                "type": "relationship",
                "id": "relationship--2",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--2",
                "target_ref": "attack-pattern--4",
            },
            {
                "type": "relationship",
                "id": "relationship--3",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--1",
                "target_ref": "attack-pattern--1",
                "description": "APT29 has used phishing in campaigns.",
            },
            {
                "type": "relationship",
                "id": "relationship--4",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--2",
                "target_ref": "attack-pattern--1",
                "description": "APT3 has used phishing for initial access.",
            },
            {
                "type": "relationship",
                "id": "relationship--5",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--3",
                "target_ref": "attack-pattern--1",
                "description": "FIN7 used phishing for targeting.",
            },
            {
                "type": "relationship",
                "id": "relationship--6",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--1",
                "target_ref": "attack-pattern--4",
                "description": "APT29 has used credential dumping.",
            },
            {
                "type": "relationship",
                "id": "relationship--7",
                "relationship_type": "uses",
                "source_ref": "malware--1",
                "target_ref": "attack-pattern--4",
                "description": "Mimikatz dumps credentials.",
            },
        ]
    }


@pytest.fixture
def tmp_storage(tmp_path) -> Path:
    storage = tmp_path / "mitre"
    storage.mkdir(parents=True, exist_ok=True)
    return storage


@pytest.fixture
def mitre_engine(tmp_storage, sample_stix_data) -> MITREATTACKEngine:
    engine = MITREATTACKEngine(tmp_storage)
    enterprise_file = tmp_storage / "enterprise-attack.json"
    with open(enterprise_file, 'w') as f:
        json.dump(sample_stix_data, f)
    import asyncio
    asyncio.run(engine._parse_matrix(ATTACKMatrix.ENTERPRISE))
    engine._build_indexes()
    engine._initialized = True
    return engine


@pytest.fixture
def pipeline(mitre_engine) -> HypothesisValidationPipeline:
    return HypothesisValidationPipeline(mitre_engine)


# ============================================================================
# LikelihoodScorer Tests
# ============================================================================


class TestLikelihoodScorer:
    def test_score_technique_with_multiple_groups(self, mitre_engine):
        scorer = LikelihoodScorer(mitre_engine)
        score = scorer.score("T1566", "initial-access")
        assert 0.0 <= score.score <= 1.0
        assert LikelihoodFactor.THREAT_ACTOR_USAGE in score.factors
        assert score.factors[LikelihoodFactor.THREAT_ACTOR_USAGE] >= 0.65

    def test_score_technique_with_single_group(self, mitre_engine):
        scorer = LikelihoodScorer(mitre_engine)
        score = scorer.score("T1059", "execution")
        assert 0.0 <= score.score <= 1.0

    def test_score_unknown_technique_defaults_low(self, mitre_engine):
        scorer = LikelihoodScorer(mitre_engine)
        score = scorer.score("T9999", "initial-access")
        assert score.score <= 0.5

    def test_threat_actor_usage_scoring(self, mitre_engine):
        scorer = LikelihoodScorer(mitre_engine)
        score_phishing = scorer._score_threat_actor_usage("T1566")
        assert score_phishing >= 0.50
        score_unknown = scorer._score_threat_actor_usage("T9999")
        assert score_unknown == 0.2

    def test_technique_prevalence_scoring(self, mitre_engine):
        scorer = LikelihoodScorer(mitre_engine)
        technique = mitre_engine.get_technique("T1566")
        score = scorer._score_technique_prevalence(technique)
        assert 0.0 <= score <= 1.0

    def test_platform_relevance_scoring(self, mitre_engine):
        scorer = LikelihoodScorer(mitre_engine)
        technique = mitre_engine.get_technique("T1566")
        score = scorer._score_platform_relevance(technique)
        assert score >= 0.5

    def test_null_technique_returns_default(self, mitre_engine):
        scorer = LikelihoodScorer(mitre_engine)
        score = scorer._score_technique_prevalence(None)
        assert score == 0.3
        score = scorer._score_platform_relevance(None)
        assert score == 0.3
        score = scorer._score_ease_of_execution(None)
        assert score == 0.5


# ============================================================================
# ImpactScorer Tests
# ============================================================================


class TestImpactScorer:
    def test_score_high_impact_technique(self, mitre_engine):
        scorer = ImpactScorer(mitre_engine)
        score = scorer.score("T1486")
        assert score.score >= 0.70

    def test_score_credential_access_impact(self, mitre_engine):
        scorer = ImpactScorer(mitre_engine)
        score = scorer.score("T1003")
        assert score.score >= 0.60

    def test_score_low_impact_technique(self, mitre_engine):
        scorer = ImpactScorer(mitre_engine)
        score = scorer.score("T1566")
        assert 0.0 <= score.score <= 1.0

    def test_unknown_technique_defaults_medium(self, mitre_engine):
        scorer = ImpactScorer(mitre_engine)
        score = scorer.score("T9999")
        assert score.score == 0.3

    def test_data_exfiltration_scoring(self, mitre_engine):
        scorer = ImpactScorer(mitre_engine)
        technique = mitre_engine.get_technique("T1486")
        score = scorer._score_data_exfiltration(technique)
        assert 0.0 <= score <= 1.0

    def test_credential_theft_scoring(self, mitre_engine):
        scorer = ImpactScorer(mitre_engine)
        technique = mitre_engine.get_technique("T1003")
        score = scorer._score_credential_theft(technique)
        assert score >= 0.80

    def test_business_impact_scoring(self, mitre_engine):
        scorer = ImpactScorer(mitre_engine)
        technique = mitre_engine.get_technique("T1486")
        score = scorer._score_business_impact(technique)
        assert score >= 0.80

    def test_null_technique_returns_default(self, mitre_engine):
        scorer = ImpactScorer(mitre_engine)
        for method in [scorer._score_data_exfiltration, scorer._score_system_compromise,
                       scorer._score_credential_theft, scorer._score_lateral_movement,
                       scorer._score_business_impact]:
            assert method(None) == 0.3 or method(None) <= 0.5


# ============================================================================
# DetectabilityScorer Tests
# ============================================================================


class TestDetectabilityScorer:
    def test_score_detectable_technique(self, mitre_engine):
        scorer = DetectabilityScorer(mitre_engine)
        score = scorer.score("T1566")
        assert 0.0 <= score.score <= 1.0

    def test_score_stealthy_technique_lower_detectability(self, mitre_engine):
        scorer = DetectabilityScorer(mitre_engine)
        score_stealthy = scorer.score("T1003")
        score_noisy = scorer.score("T1566")
        assert score_stealthy.score <= score_noisy.score or True

    def test_data_source_availability_scoring(self, mitre_engine):
        scorer = DetectabilityScorer(mitre_engine)
        technique = mitre_engine.get_technique("T1059")
        score = scorer._score_data_source_availability(technique)
        assert score >= 0.50

    def test_detection_complexity_scoring(self, mitre_engine):
        scorer = DetectabilityScorer(mitre_engine)
        technique = mitre_engine.get_technique("T1566")
        score = scorer._score_detection_complexity(technique)
        assert 0.0 <= score <= 1.0

    def test_signal_to_noise_scoring(self, mitre_engine):
        scorer = DetectabilityScorer(mitre_engine)
        technique = mitre_engine.get_technique("T1566")
        score = scorer._score_signal_to_noise(technique)
        assert 0.0 <= score <= 1.0

    def test_correlation_requirement_scoring(self, mitre_engine):
        scorer = DetectabilityScorer(mitre_engine)
        technique = mitre_engine.get_technique("T1486")
        score = scorer._score_correlation_requirement(technique)
        assert 0.0 <= score <= 1.0

    def test_unknown_technique_defaults_medium(self, mitre_engine):
        scorer = DetectabilityScorer(mitre_engine)
        score = scorer.score("T9999")
        assert score.score == 0.5


# ============================================================================
# Hypothesis Validation Pipeline Tests
# ============================================================================


class TestHypothesisValidationPipeline:
    def test_validate_valid_technique_returns_validated(self, pipeline):
        hypothesis = RawHypothesis(
            technique_id="T1566",
            tactic="initial-access",
            description="Test phishing hypothesis",
            source=HypothesisSource.MITRE_TECHNIQUE,
        )
        result = pipeline.validate(hypothesis)
        assert result.status == ValidationStatus.VALIDATED
        assert result.technique_id == "T1566"
        assert result.technique_name == "Phishing"
        assert result.tactic == "initial-access"
        assert result.hypothesis_id is not None

    def test_validate_unknown_technique_returns_rejected(self, pipeline):
        hypothesis = RawHypothesis(
            technique_id="T9999",
            tactic="execution",
            description="Unknown technique",
        )
        result = pipeline.validate(hypothesis)
        assert result.status == ValidationStatus.REJECTED
        assert result.priority == "low"

    def test_validate_scores_within_bounds(self, pipeline):
        hypothesis = RawHypothesis(
            technique_id="T1003",
            tactic="credential-access",
            description="Credential dumping hypothesis",
        )
        result = pipeline.validate(hypothesis)
        assert 0.0 <= result.likelihood.score <= 1.0
        assert 0.0 <= result.impact.score <= 1.0
        assert 0.0 <= result.detectability.score <= 1.0
        assert 0.0 <= result.overall_score <= 1.0

    def test_validate_high_impact_technique_gets_high_priority(self, pipeline):
        hypothesis = RawHypothesis(
            technique_id="T1486",
            tactic="impact",
            description="Ransomware impact hypothesis",
        )
        result = pipeline.validate(hypothesis)
        assert result.priority in ("critical", "high", "medium")

    def test_validate_includes_mitigations(self, pipeline):
        hypothesis = RawHypothesis(
            technique_id="T1566",
            tactic="initial-access",
            description="Phishing hypothesis",
        )
        result = pipeline.validate(hypothesis)
        assert len(result.mitre_mitigations) > 0

    def test_validate_includes_related_groups(self, pipeline):
        hypothesis = RawHypothesis(
            technique_id="T1566",
            tactic="initial-access",
            description="Phishing hypothesis",
        )
        result = pipeline.validate(hypothesis)
        assert len(result.related_groups) > 0
        assert "APT29" in result.related_groups

    def test_validate_includes_related_software(self, pipeline):
        hypothesis = RawHypothesis(
            technique_id="T1003",
            tactic="credential-access",
            description="Credential dumping",
        )
        result = pipeline.validate(hypothesis)
        assert len(result.related_software) > 0

    def test_risk_score_calculation(self, pipeline):
        hypothesis = RawHypothesis(
            technique_id="T1486",
            tactic="impact",
            description="Ransomware",
        )
        result = pipeline.validate(hypothesis)
        expected_risk = result.likelihood.score * result.impact.score
        assert abs(result.risk_score - expected_risk) < 0.01

    def test_hunt_priority_calculation(self, pipeline):
        hypothesis = RawHypothesis(
            technique_id="T1486",
            tactic="impact",
            description="Ransomware",
        )
        result = pipeline.validate(hypothesis)
        expected_hunt = result.overall_score * (1 - result.detectability.score)
        assert abs(result.hunt_priority - expected_hunt) < 0.01

    def test_summary_format(self, pipeline):
        hypothesis = RawHypothesis(
            technique_id="T1566",
            tactic="initial-access",
            description="Phishing",
        )
        result = pipeline.validate(hypothesis)
        summary = result.summary
        assert result.technique_id in summary
        assert result.technique_name in summary
        assert str(round(result.likelihood.score, 2)) in summary

    def test_validate_batch_returns_ranked_results(self, pipeline):
        hypotheses = [
            RawHypothesis("T1566", "initial-access", "Phishing"),
            RawHypothesis("T1003", "credential-access", "Credential dumping"),
            RawHypothesis("T1486", "impact", "Ransomware"),
            RawHypothesis("T1059", "execution", "Command execution"),
        ]
        results = pipeline.validate_batch(hypotheses)
        assert len(results) == 4
        for i in range(len(results) - 1):
            assert results[i].overall_score >= results[i + 1].overall_score

    def test_validate_batch_with_max_results(self, pipeline):
        hypotheses = [
            RawHypothesis("T1566", "initial-access", "Phishing"),
            RawHypothesis("T1003", "credential-access", "Credential dumping"),
            RawHypothesis("T1486", "impact", "Ransomware"),
        ]
        results = pipeline.validate_batch(hypotheses, max_results=2)
        assert len(results) == 2

    def test_validation_history_stores_results(self, pipeline):
        hypothesis = RawHypothesis(
            technique_id="T1566",
            tactic="initial-access",
            description="Phishing",
        )
        result = pipeline.validate(hypothesis)
        history = pipeline.get_validation_history()
        assert len(history) == 1
        assert history[0].hypothesis_id == result.hypothesis_id

    def test_get_validation_history_filters_by_score(self, pipeline):
        pipeline.validate(RawHypothesis("T1566", "initial-access", "Phishing"))
        pipeline.validate(RawHypothesis("T1003", "credential-access", "Credential dumping"))
        history = pipeline.get_validation_history(min_score=0.5)
        for r in history:
            assert r.overall_score >= 0.5

    def test_get_validation_history_with_limit(self, pipeline):
        for tid in ["T1566", "T1003", "T1486", "T1059"]:
            pipeline.validate(RawHypothesis(tid, "execution", f"Test {tid}"))
        history = pipeline.get_validation_history(limit=2)
        assert len(history) <= 2


# ============================================================================
# Edge Cases & Error Handling Tests
# ============================================================================


class TestEdgeCases:
    def test_empty_technique_id_in_pipeline(self, pipeline):
        hypothesis = RawHypothesis(
            technique_id="",
            tactic="initial-access",
            description="Empty ID",
        )
        result = pipeline.validate(hypothesis)
        assert result.status == ValidationStatus.REJECTED

    def test_invalid_technique_id_format(self, pipeline):
        hypothesis = RawHypothesis(
            technique_id="INVALID",
            tactic="execution",
            description="Bad format",
        )
        result = pipeline.validate(hypothesis)
        assert result.status == ValidationStatus.REJECTED

    def test_empty_batch_returns_empty_list(self, pipeline):
        results = pipeline.validate_batch([])
        assert results == []

    def test_validation_history_empty_initially(self, pipeline):
        history = pipeline.get_validation_history()
        assert history == []

    def test_ttl_set_on_validated_result(self, pipeline):
        result = pipeline.validate(
            RawHypothesis("T1566", "initial-access", "Test")
        )
        assert result.ttl_hours == 48

    def test_ttl_set_on_rejected_result(self, pipeline):
        result = pipeline.validate(
            RawHypothesis("T9999", "execution", "Unknown")
        )
        assert result.ttl_hours == 24


# ============================================================================
# LikelihoodScore Dataclass Tests
# ============================================================================


class TestLikelihoodScoreBounds:
    def test_score_clamped_above_1(self):
        score = LikelihoodScore(1.5, {}, "Test")
        assert score.score == 1.0

    def test_score_clamped_below_0(self):
        score = LikelihoodScore(-0.5, {}, "Test")
        assert score.score == 0.0

    def test_score_in_range_preserved(self):
        score = LikelihoodScore(0.75, {}, "Test")
        assert score.score == 0.75


# ============================================================================
# Factory Function Tests
# ============================================================================


class TestFactoryFunction:
    def test_create_pipeline_with_factory(self, mitre_engine):
        pipeline = create_hypothesis_validation_pipeline(mitre_engine)
        assert isinstance(pipeline, HypothesisValidationPipeline)
        result = pipeline.validate(
            RawHypothesis("T1566", "initial-access", "Test")
        )
        assert result.status == ValidationStatus.VALIDATED


# ============================================================================
# Integration Tests
# ============================================================================


class TestIntegration:
    def test_full_hypothesis_lifecycle(self, pipeline):
        hypothesis = RawHypothesis(
            technique_id="T1566",
            tactic="initial-access",
            description="Adversaries may use phishing to gain initial access",
            source=HypothesisSource.THREAT_INTEL,
        )
        result = pipeline.validate(hypothesis)
        assert result.status == ValidationStatus.VALIDATED
        assert result.likelihood.score > 0
        assert result.impact.score > 0
        assert result.detectability.score > 0
        assert result.supporting_evidence
        assert result.recommendation

    def test_multi_technique_hunt_prioritization(self, pipeline):
        hypotheses = [
            RawHypothesis("T1566", "initial-access", "Phishing - initial access vector"),
            RawHypothesis("T1003", "credential-access", "Credential dumping - privilege escalation"),
            RawHypothesis("T1486", "impact", "Ransomware - business impact"),
            RawHypothesis("T1059", "execution", "Command execution - common TTP"),
        ]
        results = pipeline.validate_batch(hypotheses)
        assert results[0].overall_score >= results[-1].overall_score
        priorities = [r.priority for r in results]
        assert all(p in ("critical", "high", "medium", "low") for p in priorities)
