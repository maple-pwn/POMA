"""Tests for poma/evaluation/analyzer.py — Steps 7, 8, 9."""

import json
from pathlib import Path

import pytest

from poma.evaluation.analyzer import ResultAnalyzer, PhaseStatistics, ModelProfile
from poma.schemas.models import AblationCondition


def _make_experiment_json(
    challenge_id="L1-01",
    model_name="test-model",
    ablation="full_pipeline",
    success=False,
    phase_0_score=None,
    phase_1_score=None,
    phase_1_response="",
    iterations=None,
):
    """Build a minimal experiment result JSON dict for testing."""
    if phase_0_score is None:
        phase_0_score = {
            "architecture_protection": 2,
            "program_understanding": 2,
            "key_points_identification": 2,
            "libc_environment": 1,
        }
    if phase_1_score is None:
        phase_1_score = {
            "vulnerability_type": 2,
            "location_precision": 2,
            "root_cause_analysis": 1,
            "trigger_condition": 1,
            "boundary_violation": False,
        }
    return {
        "experiment_id": f"exp-{challenge_id}-{ablation}",
        "challenge_id": challenge_id,
        "model_name": model_name,
        "model_version": "",
        "ablation_condition": ablation,
        "success": success,
        "total_duration_ms": 1000,
        "phase_results": {
            "phase_0": {
                "prompt": "p0",
                "response": "phase 0 output",
                "score": phase_0_score,
                "latency_ms": 100,
                "input_tokens": 50,
                "output_tokens": 200,
            },
            "phase_1": {
                "prompt": "p1",
                "response": phase_1_response,
                "score": phase_1_score,
                "latency_ms": 150,
                "input_tokens": 60,
                "output_tokens": 250,
            },
        },
        "iterations": iterations or [],
    }


# ── Step 9: _parse_result full parsing ────────────────────────────────


class TestParseResult:
    """Step 9: _parse_result correctly parses phase_results and iterations."""

    def test_phase_scores_parsed(self, tmp_path):
        data = _make_experiment_json()
        (tmp_path / "exp1.json").write_text(json.dumps(data))

        analyzer = ResultAnalyzer(tmp_path)
        analyzer.load_results()

        assert len(analyzer._results) == 1
        result = analyzer._results[0]
        assert "phase_0" in result.phase_results
        assert "phase_1" in result.phase_results
        p0 = result.phase_results["phase_0"]
        assert hasattr(p0.score, "total")
        assert p0.score.architecture_protection == 2

    def test_iterations_parsed(self, tmp_path):
        iters = [
            {
                "iteration_number": 1,
                "exploit_code": "print('hi')",
                "execution_output": "error",
                "error_type": "syntax_error",
                "diagnosis_accurate": False,
                "fix_effective": False,
            },
        ]
        data = _make_experiment_json(iterations=iters)
        (tmp_path / "exp1.json").write_text(json.dumps(data))

        analyzer = ResultAnalyzer(tmp_path)
        analyzer.load_results()

        result = analyzer._results[0]
        assert len(result.iterations) == 1
        assert result.iterations[0].error_type == "syntax_error"


# ── Step 7: H2 hypothesis validation ─────────────────────────────────


class TestH2PatternMatching:
    """Step 7: H2 compares textbook vs variant vuln scores in Phase 1."""

    def test_textbook_vs_variant(self, tmp_path):
        # Textbook: stack buffer overflow
        d1 = _make_experiment_json(
            challenge_id="L1-01",
            ablation="full_pipeline",
            phase_1_response="Found a stack buffer overflow vulnerability",
            phase_1_score={
                "vulnerability_type": 3,
                "location_precision": 3,
                "root_cause_analysis": 3,
                "trigger_condition": 3,
                "boundary_violation": False,
            },
        )
        # Variant: heap overflow
        d2 = _make_experiment_json(
            challenge_id="L2-01",
            ablation="full_pipeline",
            phase_1_response="Found a heap overflow in custom allocator",
            phase_1_score={
                "vulnerability_type": 1,
                "location_precision": 1,
                "root_cause_analysis": 1,
                "trigger_condition": 1,
                "boundary_violation": False,
            },
        )
        (tmp_path / "exp1.json").write_text(json.dumps(d1))
        (tmp_path / "exp2.json").write_text(json.dumps(d2))

        analyzer = ResultAnalyzer(tmp_path)
        analyzer.load_results()
        h2 = analyzer._validate_h2_pattern_matching()

        assert h2["textbook_count"] >= 1
        assert h2["variant_count"] >= 1
        assert h2["hypothesis_supported"] is True


# ── Step 8: H5 hypothesis validation ─────────────────────────────────


class TestH5ErrorPropagation:
    """Step 8: H5 compares condition A vs D success rates."""

    def test_amplification_computed(self, tmp_path):
        # Condition A: full_pipeline, low success
        d1 = _make_experiment_json(
            challenge_id="L1-01",
            ablation="full_pipeline",
            success=False,
        )
        d2 = _make_experiment_json(
            challenge_id="L1-02",
            ablation="full_pipeline",
            success=False,
        )
        # Condition D: gt_phase0_1_2, higher success
        d3 = _make_experiment_json(
            challenge_id="L1-01",
            ablation="gt_phase0_1_2",
            success=True,
        )
        d4 = _make_experiment_json(
            challenge_id="L1-02",
            ablation="gt_phase0_1_2",
            success=True,
        )

        for i, d in enumerate([d1, d2, d3, d4]):
            (tmp_path / f"exp{i}.json").write_text(json.dumps(d))

        analyzer = ResultAnalyzer(tmp_path)
        analyzer.load_results()
        h5 = analyzer._validate_h5_error_propagation()

        assert h5["condition_a_success_rate"] == 0.0
        assert h5["condition_d_success_rate"] == 100.0
        assert h5["hypothesis_supported"] is True
        assert h5["amplification_coefficient"] == 1.0

    def test_insufficient_data(self, tmp_path):
        # Only condition A, no condition D
        d1 = _make_experiment_json(ablation="full_pipeline")
        (tmp_path / "exp1.json").write_text(json.dumps(d1))

        analyzer = ResultAnalyzer(tmp_path)
        analyzer.load_results()
        h5 = analyzer._validate_h5_error_propagation()

        assert h5["status"] == "insufficient_data"
