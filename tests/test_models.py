"""Tests for poma/schemas/models.py — Step 6."""

from poma.schemas.models import ExperimentConfig, AblationCondition


class TestExperimentConfigNumRuns:
    """Step 6: ExperimentConfig has num_runs field."""

    def test_default_num_runs(self):
        cfg = ExperimentConfig(name="test")
        assert cfg.num_runs == 1

    def test_custom_num_runs(self):
        cfg = ExperimentConfig(name="test", num_runs=5)
        assert cfg.num_runs == 5

    def test_to_dict_includes_num_runs(self):
        cfg = ExperimentConfig(name="test", num_runs=3)
        d = cfg.to_dict()
        assert "num_runs" in d
        assert d["num_runs"] == 3
